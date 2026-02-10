//! mDNS service discovery. Handles multicast DNS hostname resolution, service browsing,
//! and result caching with local machine detection to avoid self-discovery.

use dns_lookup::{get_hostname, lookup_addr};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use pnet::datalink;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{OnceLock, RwLock};
use std::time::SystemTime;
use tokio::task;

use super::endpoint::is_valid_display_name;

static MDNS_LOOKUPS: OnceLock<std::sync::RwLock<HashMap<String, String>>> = OnceLock::new();
static MDNS_SERVICES: OnceLock<std::sync::RwLock<HashMap<String, HashSet<String>>>> =
    OnceLock::new();
// Keep the ServiceDaemon alive for the lifetime of the application
// If dropped, all mDNS browses stop receiving events
static MDNS_DAEMON: OnceLock<ServiceDaemon> = OnceLock::new();

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
        let host_base = host_lower.strip_suffix(".local").unwrap_or(&host_lower);
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
        // Store the daemon in a static to keep it alive - dropping it stops all browses
        let mdns =
            MDNS_DAEMON.get_or_init(|| ServiceDaemon::new().expect("Failed to create mDNS daemon"));

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
            // iOS/iPadOS devices (iPhones, iPads)
            "_companion-link._tcp.local.", // iOS companion link (AirDrop, Handoff)
            "_apple-mobdev2._tcp.local.",  // Apple mobile device service
            "_sleep-proxy._udp.local.",    // Sleep proxy (iOS devices)
            "_rdlink._tcp.local.",         // Remote desktop link
            // LG ThinQ appliances (dishwashers, washers, dryers, etc.)
            "_lge._tcp.local.",   // LG ThinQ general
            "_lge._udp.local.",   // LG ThinQ UDP
            "_xbcs._tcp.local.",  // LG ThinQ appliances
            "_webos._tcp.local.", // LG WebOS TVs
            // Additional smart home and IoT services
            "_matter._tcp.local.",      // Matter smart home protocol
            "_amzn-alexa._tcp.local.",  // Amazon Alexa devices
            "_device-info._tcp.local.", // Device info (many Apple/smart devices)
            "_dyson_mqtt._tcp.local.",  // Dyson devices (fans, purifiers)
            "_eero._tcp.local.",        // Eero routers/mesh
            // Gaming consoles
            "_xbox._tcp.local.",     // Xbox consoles
            "_psn._tcp.local.",      // PlayStation Network
            "_nintendo._tcp.local.", // Nintendo devices
            // Media servers and speakers
            "_sonos._tcp.local.", // Sonos speakers
            "_daap._tcp.local.",  // iTunes/Apple Music sharing
            "_plex._tcp.local.",  // Plex Media Server
            // More smart home
            "_hue._tcp.local.",              // Philips Hue bridges
            "_nanoleaf._tcp.local.",         // Nanoleaf lights
            "_wemo._tcp.local.",             // Belkin Wemo devices
            "_tplink-smarthome._tcp.local.", // TP-Link Kasa/Tapo
            "_tuya._tcp.local.",             // Tuya IoT devices
            "_ecobee._tcp.local.",           // Ecobee thermostats
            "_ring._tcp.local.",             // Ring doorbells/cameras
            // NAS devices
            "_synology._tcp.local.", // Synology NAS
            "_qnap._tcp.local.",     // QNAP NAS
            "_adisk._tcp.local.",    // Apple Time Machine/AirPort Disk
            // Network equipment
            "_ubnt._tcp.local.", // Ubiquiti devices
            // Remote access
            "_vnc._tcp.local.", // VNC remote desktop
            "_rfb._tcp.local.", // Remote framebuffer (VNC)
            // Apple services
            "_airdrop._tcp.local.",    // Apple AirDrop
            "_continuity._tcp.local.", // Apple Continuity/Handoff
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
                                // Strip .local suffix and normalize to lowercase
                                host = host.strip_suffix(".local").unwrap_or(&host).to_lowercase();

                                // Extract service name (e.g., "_googlecast._tcp.local.")
                                let service_name = service_type
                                    .strip_suffix(".local.")
                                    .unwrap_or(&service_type)
                                    .to_string();

                                for addr in service_info.get_addresses() {
                                    let ip_addr = addr.to_ip_addr();

                                    // Skip invalid/unspecified addresses (0.0.0.0, ::, etc.)
                                    if ip_addr.is_unspecified() {
                                        continue;
                                    }

                                    let addr = ip_addr.to_string();

                                    // Store hostname lookup (always store for name resolution)
                                    let is_new_hostname = if let Ok(mut lookups) = MDNS_LOOKUPS
                                        .get_or_init(|| RwLock::new(HashMap::new()))
                                        .write()
                                    {
                                        let existing = lookups.get(&addr);
                                        let is_new = existing.map(|e| e != &host).unwrap_or(true);
                                        lookups.insert(addr.to_string(), host.to_string());
                                        is_new
                                    } else {
                                        false
                                    };

                                    // Persist hostname to database if it's a new discovery
                                    // Only update if hostname is a valid display name
                                    // Use a static connection to avoid opening too many connections
                                    if is_new_hostname && is_valid_display_name(&host) {
                                        use std::sync::Mutex;
                                        use std::sync::OnceLock;
                                        static MDNS_DB_CONN: OnceLock<
                                            Mutex<Option<rusqlite::Connection>>,
                                        > = OnceLock::new();

                                        let conn_mutex = MDNS_DB_CONN.get_or_init(|| {
                                            Mutex::new(crate::db::new_connection_result().ok())
                                        });

                                        if let Ok(mut guard) = conn_mutex.lock() {
                                            // Reconnect if connection was lost
                                            if guard.is_none() {
                                                *guard = crate::db::new_connection_result().ok();
                                            }

                                            if let Some(conn) = guard.as_ref() {
                                                // Check if an endpoint exists for this IP
                                                let endpoint_exists: bool = conn
                                                    .query_row(
                                                        "SELECT EXISTS(SELECT 1 FROM endpoint_attributes WHERE ip = ?1)",
                                                        [&addr],
                                                        |row| row.get(0),
                                                    )
                                                    .unwrap_or(false);

                                                if endpoint_exists {
                                                    // Update existing endpoint_attributes
                                                    let _ = conn.execute(
                                                        "UPDATE endpoint_attributes SET hostname = ?1
                                                         WHERE ip = ?2 AND (hostname IS NULL OR hostname = ?2
                                                         OR hostname LIKE '%:%' OR hostname GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*')",
                                                        rusqlite::params![host, addr],
                                                    );

                                                    // Also update endpoints.name if it's currently just an IP
                                                    let _ = conn.execute(
                                                        "UPDATE endpoints SET name = ?1
                                                         WHERE id IN (
                                                             SELECT endpoint_id FROM endpoint_attributes WHERE ip = ?2
                                                         )
                                                         AND (name IS NULL OR name = ?2 OR name LIKE '%:%'
                                                              OR name GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*')
                                                         AND custom_name IS NULL",
                                                        rusqlite::params![host, addr],
                                                    );

                                                    // Try to merge: if this IP's endpoint has only randomized MACs,
                                                    // and another endpoint already has this hostname, merge into it
                                                    Self::try_merge_by_hostname_for_ip(
                                                        conn, &addr, &host,
                                                    );
                                                } else {
                                                    // Create new endpoint from mDNS discovery
                                                    let now = chrono::Utc::now().timestamp();
                                                    if conn.execute(
                                                        "INSERT INTO endpoints (created_at, name) VALUES (?1, ?2)",
                                                        rusqlite::params![now, host],
                                                    ).is_ok() {
                                                        let endpoint_id = conn.last_insert_rowid();
                                                        // Create endpoint_attributes entry
                                                        let _ = conn.execute(
                                                            "INSERT INTO endpoint_attributes (created_at, endpoint_id, ip, hostname)
                                                             VALUES (?1, ?2, ?3, ?4)",
                                                            rusqlite::params![now, endpoint_id, addr, host],
                                                        );
                                                        eprintln!(
                                                            "Created endpoint '{}' from mDNS discovery ({})",
                                                            host, addr
                                                        );
                                                    }
                                                }
                                            }
                                        }
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

    /// Actively probe for a device's hostname using reverse DNS lookup
    /// This works for devices that register with local DNS or respond to PTR queries
    pub fn probe_hostname(ip: &str) -> Option<String> {
        // First check our mDNS cache
        if let Some(hostname) = Self::lookup(ip) {
            return Some(hostname);
        }

        // Try reverse DNS lookup (works for mDNS .local addresses too)
        if let Ok(addr) = ip.parse::<IpAddr>()
            && let Ok(hostname) = lookup_addr(&addr)
        {
            // Cache the result
            if let Ok(mut lookups) = MDNS_LOOKUPS
                .get_or_init(|| RwLock::new(HashMap::new()))
                .write()
            {
                lookups.insert(ip.to_string(), hostname.clone());
            }
            return Some(hostname);
        }

        None
    }

    /// Merge a bare-IP/randomized-MAC endpoint into an existing endpoint with the same hostname.
    /// Called from mDNS discovery when a hostname is resolved for an IP.
    fn try_merge_by_hostname_for_ip(conn: &rusqlite::Connection, ip: &str, hostname: &str) {
        // Find the endpoint ID for this IP
        let source_id: Option<i64> = conn
            .query_row(
                "SELECT endpoint_id FROM endpoint_attributes WHERE ip = ?1 LIMIT 1",
                rusqlite::params![ip],
                |row| row.get(0),
            )
            .ok();

        let Some(source_id) = source_id else {
            return;
        };

        // Check if this endpoint has any real (non-randomized) MAC
        let has_real_mac: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM endpoint_attributes
                    WHERE endpoint_id = ?1
                    AND mac IS NOT NULL AND mac != ''
                    AND UPPER(SUBSTR(mac, 2, 1)) NOT IN ('2', '6', 'A', 'E')
                )",
                rusqlite::params![source_id],
                |row| row.get(0),
            )
            .unwrap_or(true);

        if has_real_mac {
            return;
        }

        // Find another endpoint with the same name or custom_name
        let target_id: Option<i64> = conn
            .query_row(
                "SELECT id FROM endpoints
                 WHERE id != ?1
                 AND (LOWER(name) = LOWER(?2) OR LOWER(custom_name) = LOWER(?2))
                 LIMIT 1",
                rusqlite::params![source_id, hostname],
                |row| row.get(0),
            )
            .ok();

        let Some(target_id) = target_id else {
            return;
        };

        // Preserve user fields (custom_name, custom_vendor, manual_device_type) before merge
        let _ = conn.execute(
            "UPDATE endpoints SET
                custom_name = COALESCE(custom_name, (SELECT custom_name FROM endpoints WHERE id = ?2)),
                custom_vendor = COALESCE(custom_vendor, (SELECT custom_vendor FROM endpoints WHERE id = ?2)),
                manual_device_type = COALESCE(manual_device_type, (SELECT manual_device_type FROM endpoints WHERE id = ?2))
             WHERE id = ?1",
            rusqlite::params![target_id, source_id],
        );

        // Merge source into target
        let _ = conn.execute(
            "UPDATE OR IGNORE endpoint_attributes SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![target_id, source_id],
        );
        let _ = conn.execute(
            "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
            [source_id],
        );
        let _ = conn.execute(
            "UPDATE OR IGNORE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
            rusqlite::params![target_id, source_id],
        );
        let _ = conn.execute(
            "UPDATE OR IGNORE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
            rusqlite::params![target_id, source_id],
        );
        let _ = conn.execute(
            "DELETE FROM communications WHERE src_endpoint_id = ?1 OR dst_endpoint_id = ?1",
            [source_id],
        );
        let _ = conn.execute(
            "UPDATE OR IGNORE open_ports SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![target_id, source_id],
        );
        let _ = conn.execute("DELETE FROM open_ports WHERE endpoint_id = ?1", [source_id]);
        let _ = conn.execute(
            "UPDATE scan_results SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![target_id, source_id],
        );
        let _ = conn.execute("DELETE FROM endpoints WHERE id = ?1", [source_id]);
        eprintln!(
            "mDNS: Merged endpoint {} into {} (same hostname: {})",
            source_id, target_id, hostname
        );
    }

    /// Spawn a background task to probe for hostname and cache it
    /// This is non-blocking and runs in the background
    pub fn probe_hostname_async(ip: String, _endpoint_id: i64) {
        // Check if there's a Tokio runtime available before spawning
        // This prevents panics when called from non-async tests
        if tokio::runtime::Handle::try_current().is_ok() {
            task::spawn_blocking(move || {
                // Small delay to avoid hammering the network
                std::thread::sleep(std::time::Duration::from_millis(100));

                // Just probe and cache - the result is stored in MDNS_LOOKUPS by probe_hostname()
                // Database updates removed to avoid lock contention with SQLWriter
                let _ = Self::probe_hostname(&ip);
            });
        }
        // If no runtime available, silently skip the async probe
    }
}
