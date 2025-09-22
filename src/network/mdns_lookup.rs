use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use tokio::task;

static MDNS_LOOKUPS: OnceLock<std::sync::RwLock<HashMap<String, String>>> = OnceLock::new();

pub struct MDnsLookup;

impl MDnsLookup {
    pub fn start_daemon() {
        let mdns = ServiceDaemon::new().expect("Failed to create mDNS daemon");

        let services_to_browse = [
            "_afpovertcp._tcp.local.",
            "_http._udp.local.",
            "_http._tcp.local.",
            "_https._udp.local.",
            "_https._tcp.local.",
            "_ssh._tcp.local.",
            "_smb._tcp.local.",
            "_homesharing._tcp.local.",
            "_hap._tcp.local.",
            "_ipp._tcp.local.",
            "_airplay._tcp.local.",
            "_googlecast._tcp.local.",
            "_workstation._tcp.local.",
            "_services._dns-sd._udp.local.",
            "_immich._tcp.local.",
        ];

        for service in services_to_browse.iter() {
            let service_type = service;
            let receiver = mdns
                .browse(service_type)
                .expect("Failed to browse for services");

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

                                for addr in service_info.get_addresses() {
                                    let addr = addr.to_ip_addr().to_string();
                                    if let Ok(mut lookups) = MDNS_LOOKUPS
                                        .get_or_init(|| RwLock::new(HashMap::new()))
                                        .write()
                                    {
                                        lookups.insert(addr.to_string(), host.to_string());
                                        println!("mDNS lookup added: {} -> {}", addr, host);
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
    }

    pub fn lookup(ip: &str) -> Option<String> {
        let lookups = MDNS_LOOKUPS.get_or_init(|| RwLock::new(HashMap::new()));
        let map = lookups.read().ok()?;
        map.get(ip).cloned()
    }
}
