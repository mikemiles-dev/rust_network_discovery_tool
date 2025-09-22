use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use tokio::task;

use crate::db::new_connection;
use crate::network::endpoint::EndPoint;

static MDNS_LOOKUPS: OnceLock<std::sync::RwLock<HashMap<String, String>>> = OnceLock::new();

pub struct MDnsLookup;

impl MDnsLookup {
    pub fn start_daemon() {
        let mdns = ServiceDaemon::new().expect("Failed to create mDNS daemon");

        let service_type = "_smb._tcp.local.";
        let receiver = mdns
            .browse(service_type)
            .expect("Failed to browse for services");

        let conn = new_connection();

        task::spawn_blocking(move || {
            loop {
                for event in receiver.iter() {
                    match event {
                        ServiceEvent::ServiceFound(_service, _full) => (),
                        ServiceEvent::ServiceResolved(service_info) => {
                            let mut host = service_info.get_hostname().to_string();
                            if host.ends_with('.') {
                                host.pop();
                            }

                            println!("addressed are: {:?}", service_info.get_addresses());
                            for addr in service_info.get_addresses() {
                                let addr = addr.to_ip_addr().to_string();
                                if let Ok(mut lookups) = MDNS_LOOKUPS
                                    .get_or_init(|| RwLock::new(HashMap::new()))
                                    .write()
                                {
                                    lookups.insert(addr.to_string(), host.to_string());
                                    println!("mDNS lookup added: {} -> {}", addr, host);
                                    match EndPoint::update_hostname_by_ip(
                                        &conn,
                                        Some(addr.to_string()),
                                        Some(host.to_string()),
                                    ) {
                                        Ok(_) => {
                                            println!(
                                                "Successfully updated hostname for {}: {}",
                                                addr, host
                                            );
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "Failed to update hostname for {}: {}",
                                                addr, e
                                            )
                                        }
                                    }
                                }
                            }
                            // Check if the service's IP addresses match our target
                            //println!("Discovered service: {:?}", service_info);
                            // if service_info.addresses.iter().any(|scoped_ip| {
                            //     println!("Checking scoped IP: {}", scoped_ip);
                            //     scoped_ip.to_string() == ip
                            // }) {
                            //     println!(
                            //         "Service resolved: {}",
                            //         service_info.get_hostname().to_string()
                            //     );
                            // }
                        }
                        ServiceEvent::SearchStopped(_) => break,
                        _ => {}
                    }
                }
                println!("Sleeping for 1 seconds before restarting mDNS browse...");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });
    }

    pub fn lookup(ip: &str) -> Option<String> {
        println!("Looking up mDNS for IP: {}", ip);
        let lookups = MDNS_LOOKUPS.get_or_init(|| RwLock::new(HashMap::new()));
        let map = lookups.read().ok()?;
        map.get(ip).cloned()
    }
}
