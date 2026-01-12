use dns_lookup::get_hostname;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use pnet::datalink;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{OnceLock, RwLock};
use std::time::SystemTime;
use tokio::task;

static MDNS_LOOKUPS: OnceLock<std::sync::RwLock<HashMap<String, String>>> = OnceLock::new();
static MDNS_SERVICES: OnceLock<std::sync::RwLock<HashMap<String, HashSet<String>>>> =
    OnceLock::new();

/// Get the local machine's hostname (cached)
fn get_local_hostname() -> Option<String> {
    static LOCAL_HOSTNAME: OnceLock<Option<String>> = OnceLock::new();
    LOCAL_HOSTNAME
        .get_or_init(|| get_hostname().ok().map(|h| h.to_lowercase()))
        .clone()
}

/// Get all local IP addresses (cached)
fn get_local_ips() -> HashSet<String> {
    static LOCAL_IPS: OnceLock<HashSet<String>> = OnceLock::new();
    LOCAL_IPS
        .get_or_init(|| {
            datalink::interfaces()
                .into_iter()
                .flat_map(|iface| iface.ips)
                .map(|ip| ip.ip().to_string())
                .collect()
        })
        .clone()
}

/// Check if a hostname or IP belongs to the local machine
fn is_local_machine(hostname: &str, ip: &str) -> bool {
    // Check if IP is local
    let local_ips = get_local_ips();
    if local_ips.contains(ip) {
        return true;
    }

    // Check if hostname matches local hostname
    if let Some(local_hostname) = get_local_hostname() {
        let host_lower = hostname.to_lowercase();
        // Strip .local suffix for comparison
        let host_base = host_lower
            .strip_suffix(".local")
            .unwrap_or(&host_lower);
        let local_base = local_hostname
            .strip_suffix(".local")
            .unwrap_or(&local_hostname);

        if host_base == local_base {
            return true;
        }
    }

    false
}

#[derive(Clone)]
pub struct DnsEntry {
    pub ip: String,
    pub hostname: String,
    pub services: Vec<String>,
    pub timestamp: SystemTime,
}

// Maximum number of DNS entries to keep (circular buffer)
const MAX_DNS_ENTRIES: usize = 10000;

static DNS_ENTRIES: OnceLock<RwLock<VecDeque<DnsEntry>>> = OnceLock::new();

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
            // TV and streaming devices
            "_raop._tcp.local.",            // AirPlay audio
            "_roku._tcp.local.",            // Roku devices
            "_spotify-connect._tcp.local.", // Spotify Connect
            // Smart home devices
            "_homekit._tcp.local.",     // HomeKit
            "_smartthings._tcp.local.", // Samsung SmartThings
            // Printers
            "_printer._tcp.local.",
            "_pdl-datastream._tcp.local.", // Print Data Language
        ];

        for service in services_to_browse.iter() {
            let service_type = service.to_string();
            let receiver = mdns
                .browse(&service_type)
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

                                // Extract service name (e.g., "_googlecast._tcp.local.")
                                let service_name = service_type
                                    .strip_suffix(".local.")
                                    .unwrap_or(&service_type)
                                    .to_string();

                                for addr in service_info.get_addresses() {
                                    let addr = addr.to_ip_addr().to_string();

                                    // Store hostname lookup (always store for name resolution)
                                    if let Ok(mut lookups) = MDNS_LOOKUPS
                                        .get_or_init(|| RwLock::new(HashMap::new()))
                                        .write()
                                    {
                                        lookups.insert(addr.to_string(), host.to_string());
                                    }

                                    // Store service type (always store for device classification)
                                    if let Ok(mut services) = MDNS_SERVICES
                                        .get_or_init(|| RwLock::new(HashMap::new()))
                                        .write()
                                    {
                                        services
                                            .entry(addr.to_string())
                                            .or_insert_with(HashSet::new)
                                            .insert(service_name.clone());
                                    }

                                    // Skip adding to DNS entries log if this is the local machine
                                    // (reduces clutter in the mDNS tab)
                                    if is_local_machine(&host, &addr) {
                                        continue;
                                    }

                                    // Add to DNS entries log (bounded circular buffer)
                                    if let Ok(mut entries) = DNS_ENTRIES
                                        .get_or_init(|| RwLock::new(VecDeque::new()))
                                        .write()
                                    {
                                        // Remove oldest entries if at capacity
                                        while entries.len() >= MAX_DNS_ENTRIES {
                                            entries.pop_front();
                                        }
                                        entries.push_back(DnsEntry {
                                            ip: addr.to_string(),
                                            hostname: host.to_string(),
                                            services: vec![service_name.clone()],
                                            timestamp: SystemTime::now(),
                                        });
                                    }
                                }
                            }
                            ServiceEvent::SearchStopped(_) => break,
                            _ => {}
                        }
                    }
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

    pub fn get_services(ip: &str) -> Vec<String> {
        let services = MDNS_SERVICES.get_or_init(|| RwLock::new(HashMap::new()));
        if let Ok(map) = services.read() {
            map.get(ip)
                .cloned()
                .map(|set| set.into_iter().collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    pub fn get_all_entries() -> Vec<DnsEntry> {
        let entries = DNS_ENTRIES.get_or_init(|| RwLock::new(VecDeque::new()));
        if let Ok(deque) = entries.read() {
            // Convert VecDeque to Vec (most recent entries last)
            deque.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }
}
