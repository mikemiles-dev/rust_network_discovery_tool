use dns_lookup::{get_hostname, lookup_addr};
use pnet::datalink::interfaces;
use pnet::ipnetwork::IpNetwork;
use rusqlite::{Connection, Result, params};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::network::endpoint_attribute::EndPointAttribute;
use crate::network::mdns_lookup::MDnsLookup;

// Simple DNS cache to avoid repeated slow lookups
lazy_static::lazy_static! {
    static ref DNS_CACHE: Arc<Mutex<HashMap<String, (String, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref GATEWAY_INFO: Arc<Mutex<Option<(String, Instant)>>> = Arc::new(Mutex::new(None));
}

// Cache for local network CIDR blocks (computed once at startup)
static LOCAL_NETWORKS: OnceLock<Vec<IpNetwork>> = OnceLock::new();

fn get_local_networks() -> &'static Vec<IpNetwork> {
    LOCAL_NETWORKS.get_or_init(|| {
        interfaces()
            .into_iter()
            .flat_map(|iface| iface.ips)
            .collect()
    })
}

const DNS_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes
const GATEWAY_CACHE_TTL: Duration = Duration::from_secs(60); // 1 minute

// Classification type constants
const CLASSIFICATION_GATEWAY: &str = "gateway";
const CLASSIFICATION_INTERNET: &str = "internet";
const CLASSIFICATION_PRINTER: &str = "printer";
const CLASSIFICATION_TV: &str = "tv";
const CLASSIFICATION_GAMING: &str = "gaming";
const CLASSIFICATION_VIRTUALIZATION: &str = "virtualization";
const CLASSIFICATION_SOUNDBAR: &str = "soundbar";
const CLASSIFICATION_APPLIANCE: &str = "appliance";
const CLASSIFICATION_PHONE: &str = "phone";

// Device detection patterns
const PRINTER_PATTERNS: &[&str] = &[
    "printer",
    "print",
    "hp-",
    "canon",
    "epson",
    "brother",
    "lexmark",
    "xerox",
    "ricoh",
    "laserjet",
    "officejet",
    "pixma",
    "mfc-",
    "dcp-",
    "hpcolor",
    "hplaserjet",
    "designjet",
    "colorjet",
    "scanjet",
];
const PRINTER_PREFIXES: &[&str] = &["hp", "npi", "np", "brn", "brw", "epson"];

const TV_PATTERNS: &[&str] = &[
    "tv",
    "samsung",
    "lg-",
    "sony",
    "vizio",
    "roku",
    "chromecast",
    "appletv",
    "apple-tv",
    "firetv",
    "fire-tv",
    "shield",
    "androidtv",
];
const TV_PREFIXES: &[&str] = &["lg"];

const GAMING_PATTERNS: &[&str] = &[
    "xbox",
    "playstation",
    "ps4",
    "ps5",
    "nintendo",
    "switch",
    "steamdeck",
    "steam-deck",
];

const PHONE_PATTERNS: &[&str] = &[
    "iphone", "ipad", "ipod", "oneplus", "motorola", "oppo", "vivo", "realme", "redmi", "poco",
];
const PHONE_PREFIXES: &[&str] = &["sm-", "moto"];
const PHONE_CONDITIONAL: &[(&str, &str)] = &[
    ("galaxy", "tv"),
    ("pixel", "tv"),
    ("xiaomi", "tv"),
    ("huawei", "tv"),
    ("nokia", "tv"),
];

const VM_PATTERNS: &[&str] = &[
    "vmware",
    "esxi",
    "vcenter",
    "proxmox",
    "hyper-v",
    "hyperv",
    "virtualbox",
    "vbox",
    "kvm",
    "qemu",
    "xen",
    "docker",
    "container",
    "k8s",
    "kubernetes",
    "rancher",
    "portainer",
];

const SOUNDBAR_PATTERNS: &[&str] = &[
    "soundbar",
    "sound-bar",
    "sonos",
    "bose",
    "playbar",
    "playbase",
    "beam",
];

const APPLIANCE_PATTERNS: &[&str] = &[
    "dishwasher",
    "washer",
    "dryer",
    "washing",
    "laundry",
    "refrigerator",
    "fridge",
    "oven",
    "range",
    "microwave",
    "maytag",
    "miele",
    "electrolux",
    "kenmore",
    "kitchenaid",
];
const LG_APPLIANCE_PREFIXES: &[&str] = &["lma", "lmw", "ldf", "ldt", "ldp", "dle", "dlex", "lrmv"];

// mDNS service types for device classification
const TV_SERVICES: &[&str] = &[
    "_googlecast._tcp",
    "_airplay._tcp",
    "_raop._tcp",
    "_roku._tcp",
    "_spotify-connect._tcp",
];
const PRINTER_SERVICES: &[&str] = &["_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp"];

/// Check if hostname matches any pattern in list
fn matches_pattern(hostname: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| hostname.contains(p))
}

/// Check if hostname starts with any prefix in list
fn matches_prefix(hostname: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| hostname.starts_with(p))
}

/// Check if hostname matches pattern but not exclusion
fn matches_conditional(hostname: &str, conditionals: &[(&str, &str)]) -> bool {
    conditionals
        .iter()
        .any(|(pattern, exclude)| hostname.contains(pattern) && !hostname.contains(exclude))
}

/// Check if hostname indicates a printer
fn is_printer_hostname(hostname: &str) -> bool {
    matches_pattern(hostname, PRINTER_PATTERNS) || matches_prefix(hostname, PRINTER_PREFIXES)
}

/// Check if hostname indicates a TV/streaming device
fn is_tv_hostname(hostname: &str) -> bool {
    matches_pattern(hostname, TV_PATTERNS) || matches_prefix(hostname, TV_PREFIXES)
}

/// Check if hostname indicates a gaming console
fn is_gaming_hostname(hostname: &str) -> bool {
    matches_pattern(hostname, GAMING_PATTERNS)
}

/// Check if hostname indicates a phone/tablet
fn is_phone_hostname(hostname: &str) -> bool {
    if matches_pattern(hostname, PHONE_PATTERNS) || matches_prefix(hostname, PHONE_PREFIXES) {
        return true;
    }
    if matches_conditional(hostname, PHONE_CONDITIONAL) {
        return true;
    }
    // Special case: android but not androidtv
    if hostname.contains("android") && !hostname.contains("androidtv") && !hostname.contains("tv") {
        return true;
    }
    // Special case: asus phone
    if hostname.contains("asus") && (hostname.contains("phone") || hostname.contains("zenfone")) {
        return true;
    }
    false
}

/// Check if hostname indicates a VM/container
fn is_vm_hostname(hostname: &str) -> bool {
    matches_pattern(hostname, VM_PATTERNS)
        || hostname.starts_with("vm-")
        || hostname.ends_with("-vm")
}

/// Check if hostname indicates a soundbar
fn is_soundbar_hostname(hostname: &str) -> bool {
    if matches_pattern(hostname, SOUNDBAR_PATTERNS) {
        return true;
    }
    // Sonos Arc special case
    if hostname.contains("arc") && (hostname.contains("sonos") || hostname.contains("sound")) {
        return true;
    }
    // Brand + sound combinations
    let sound_brands = ["yamaha", "samsung", "lg", "vizio"];
    if sound_brands.iter().any(|b| hostname.contains(b)) && hostname.contains("sound") {
        return true;
    }
    // JBL bar
    if hostname.contains("jbl") && hostname.contains("bar") {
        return true;
    }
    false
}

/// Check if hostname indicates an appliance
fn is_appliance_hostname(hostname: &str) -> bool {
    if matches_pattern(hostname, APPLIANCE_PATTERNS) {
        return true;
    }
    // Whirlpool (but not router)
    if hostname.contains("whirlpool") && !hostname.contains("router") {
        return true;
    }
    // GE appliance
    if hostname.contains("ge-") && hostname.contains("appliance") {
        return true;
    }
    // Bosch washer/dishwasher
    if hostname.contains("bosch") && (hostname.contains("wash") || hostname.contains("dish")) {
        return true;
    }
    false
}

/// Check if hostname indicates an LG ThinQ appliance
fn is_lg_appliance(hostname: &str) -> bool {
    if matches_prefix(hostname, LG_APPLIANCE_PREFIXES) {
        return true;
    }
    // WM with digit as third character (washer model)
    if hostname.starts_with("wm")
        && let Some(c) = hostname.chars().nth(2)
        && c.is_ascii_digit()
    {
        return true;
    }
    false
}

/// Check mDNS services for device type
fn classify_by_services(services: &[String]) -> Option<&'static str> {
    for service in services {
        if TV_SERVICES.contains(&service.as_str()) {
            return Some(CLASSIFICATION_TV);
        }
        if PRINTER_SERVICES.contains(&service.as_str()) {
            return Some(CLASSIFICATION_PRINTER);
        }
    }
    None
}

/// Classify by port number
fn classify_by_port(port: u16) -> Option<&'static str> {
    match port {
        // Printer ports
        9100 | 631 | 515 => Some(CLASSIFICATION_PRINTER),
        // TV/Streaming ports
        8008 | 8009 => Some(CLASSIFICATION_TV), // Chromecast
        7000 | 7001 | 8001 | 8002 => Some(CLASSIFICATION_TV), // Samsung TV
        3000 | 3001 => Some(CLASSIFICATION_TV), // LG WebOS
        6467 | 6466 => Some(CLASSIFICATION_TV), // Roku
        // VM/Container ports
        902 | 903 => Some(CLASSIFICATION_VIRTUALIZATION), // VMware ESXi
        8006 => Some(CLASSIFICATION_VIRTUALIZATION),      // Proxmox
        2179 => Some(CLASSIFICATION_VIRTUALIZATION),      // Hyper-V
        2375 | 2376 => Some(CLASSIFICATION_VIRTUALIZATION), // Docker API
        6443 => Some(CLASSIFICATION_VIRTUALIZATION),      // Kubernetes API
        10250 => Some(CLASSIFICATION_VIRTUALIZATION),     // Kubelet
        9000 => Some(CLASSIFICATION_VIRTUALIZATION),      // Portainer
        _ => None,
    }
}

#[derive(Debug)]
pub enum InsertEndpointError {
    BothMacAndIpNone,
    ConstraintViolation,
    DatabaseError(rusqlite::Error),
}

impl From<rusqlite::Error> for InsertEndpointError {
    fn from(err: rusqlite::Error) -> Self {
        match err {
            rusqlite::Error::SqliteFailure(err, Some(_))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                InsertEndpointError::ConstraintViolation
            }
            _ => InsertEndpointError::DatabaseError(err),
        }
    }
}

#[derive(Default, Debug)]
pub struct EndPoint;

impl EndPoint {
    /// Classify an endpoint as Gateway, Internet, or LocalNetwork based on IP address and hostname
    pub fn classify_endpoint(ip: Option<String>, hostname: Option<String>) -> Option<&'static str> {
        // Check if it's the default gateway
        if let Some(ref ip_str) = ip {
            if let Some(gateway_ip) = Self::get_default_gateway()
                && gateway_ip == *ip_str
            {
                return Some(CLASSIFICATION_GATEWAY);
            }

            // Check if it's a common router IP
            if Self::is_common_router_ip(ip_str) {
                return Some(CLASSIFICATION_GATEWAY);
            }

            // Check if it's on the local network
            if !Self::is_on_local_network(ip_str) {
                return Some(CLASSIFICATION_INTERNET);
            }
        }

        // Check if hostname indicates a router/gateway
        if let Some(ref hostname_str) = hostname
            && Self::is_router_hostname(hostname_str)
        {
            return Some(CLASSIFICATION_GATEWAY);
        }

        // Local network device, no special classification
        None
    }

    /// Check if IP is a common router/gateway address
    fn is_common_router_ip(ip: &str) -> bool {
        matches!(
            ip,
            "192.168.0.1"
                | "192.168.1.1"
                | "192.168.2.1"
                | "192.168.1.254"
                | "10.0.0.1"
                | "10.0.1.1"
                | "10.1.1.1"
                | "10.10.1.1"
                | "172.16.0.1"
                | "172.16.1.1"
                | "192.168.0.254"
                | "192.168.1.253"
                | "192.168.100.1"
                | "192.168.254.254"
        )
    }

    /// Check if hostname indicates a router or gateway
    fn is_router_hostname(hostname: &str) -> bool {
        let lower = hostname.to_lowercase();
        lower.contains("router")
            || lower.contains("gateway")
            || lower.contains("-gw")
            || lower.starts_with("gw-")
            || lower.starts_with("gw.")
            || lower == "gw"
            || lower.contains(".gateway.")
            || lower.contains(".gw.")
            || lower.contains("firewall")
            || lower.contains("pfsense")
            || lower.contains("opnsense")
            || lower.contains("ubiquiti")
            || lower.contains("unifi")
            || lower.contains("edgerouter")
            || lower.contains("mikrotik")
    }

    /// Classify device type based on hostname, ports, and mDNS services
    /// Returns device-specific classification (printer, tv, gaming) or None
    /// This is separate from network-level classification (gateway, internet)
    pub fn classify_device_type(
        hostname: Option<&str>,
        ip: Option<&str>,
        ports: &[u16],
    ) -> Option<&'static str> {
        // Pre-compute lowercase hostname once
        let lower_hostname = hostname.map(|h| h.to_lowercase());
        let lower = lower_hostname.as_deref();

        // Check for LG ThinQ appliances FIRST (they advertise AirPlay but aren't TVs)
        if let Some(h) = lower
            && is_lg_appliance(h)
        {
            return Some(CLASSIFICATION_APPLIANCE);
        }

        // Check mDNS service advertisements (most reliable for smart devices)
        if let Some(ip_str) = ip {
            let services = crate::network::mdns_lookup::MDnsLookup::get_services(ip_str);
            if let Some(classification) = classify_by_services(&services) {
                return Some(classification);
            }
        }

        // Check hostname patterns
        if let Some(h) = lower {
            // Order matters: check more specific patterns first
            if is_printer_hostname(h) {
                return Some(CLASSIFICATION_PRINTER);
            }
            if is_tv_hostname(h) {
                return Some(CLASSIFICATION_TV);
            }
            if is_gaming_hostname(h) {
                return Some(CLASSIFICATION_GAMING);
            }
            if is_phone_hostname(h) {
                return Some(CLASSIFICATION_PHONE);
            }
            if is_vm_hostname(h) {
                return Some(CLASSIFICATION_VIRTUALIZATION);
            }
            if is_soundbar_hostname(h) {
                return Some(CLASSIFICATION_SOUNDBAR);
            }
            if is_appliance_hostname(h) {
                return Some(CLASSIFICATION_APPLIANCE);
            }
        }

        // Port-based detection (less reliable, fallback)
        for &port in ports {
            if let Some(classification) = classify_by_port(port) {
                return Some(classification);
            }
        }

        None
    }

    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL,
                name TEXT
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_created_at ON endpoints (created_at);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_name ON endpoints (name);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_name_lower ON endpoints (LOWER(name));",
            [],
        )?;
        // Migration: Add manual_device_type column if it doesn't exist
        let has_column: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'manual_device_type'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_column {
            conn.execute(
                "ALTER TABLE endpoints ADD COLUMN manual_device_type TEXT",
                [],
            )?;
        }
        Ok(())
    }

    /// Set the manual device type for an endpoint by name
    /// Pass None to clear the manual override and revert to automatic classification
    pub fn set_manual_device_type(
        conn: &Connection,
        endpoint_name: &str,
        device_type: Option<&str>,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET manual_device_type = ? WHERE LOWER(name) = LOWER(?)",
            params![device_type, endpoint_name],
        )
    }

    /// Get all manual device types as a HashMap
    pub fn get_all_manual_device_types(conn: &Connection) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT name, manual_device_type FROM endpoints WHERE manual_device_type IS NOT NULL AND name IS NOT NULL",
        ) && let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                map.insert(row.0, row.1);
            }
        }
        map
    }

    fn insert_endpoint(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        hostname: Option<String>,
    ) -> Result<i64, InsertEndpointError> {
        conn.execute(
            "INSERT INTO endpoints (created_at) VALUES (strftime('%s', 'now'))",
            params![],
        )?;
        let endpoint_id = conn.last_insert_rowid();
        let hostname = hostname.unwrap_or(ip.clone().unwrap_or_default());
        EndPointAttribute::insert_endpoint_attribute(conn, endpoint_id, mac, ip, hostname)?;
        Ok(endpoint_id)
    }

    pub fn get_or_insert_endpoint(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        protocol: Option<String>,
        payload: &[u8],
    ) -> Result<i64, InsertEndpointError> {
        // Filter out broadcast/multicast MACs - these aren't real endpoints
        if let Some(ref mac_addr) = mac
            && Self::is_broadcast_or_multicast_mac(mac_addr)
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        // Filter out multicast/broadcast IPs - these aren't real endpoints
        if let Some(ref ip_addr) = ip
            && Self::is_multicast_or_broadcast_ip(ip_addr)
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        if (mac.is_none() || mac == Some("00:00:00:00:00:00".to_string())) && ip.is_none() {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }
        let hostname = Self::lookup_hostname(ip.clone(), mac.clone(), protocol.clone(), payload);
        let endpoint_id = match EndPointAttribute::find_existing_endpoint_id(
            conn,
            mac.clone(),
            ip.clone(),
            hostname.clone(),
        ) {
            Some(id) => {
                // Always try to insert new hostname if it's different from IP
                // This captures all hostnames seen at this endpoint (remote or local)
                if ip != hostname && hostname.is_some() {
                    // Attempt to insert - will be ignored if duplicate due to UNIQUE constraint
                    let _ = EndPointAttribute::insert_endpoint_attribute(
                        conn,
                        id,
                        mac,
                        ip.clone(),
                        hostname.clone().unwrap_or(ip.clone().unwrap_or_default()),
                    );
                }
                id
            }
            _ => Self::insert_endpoint(conn, mac.clone(), ip.clone(), hostname.clone())?,
        };
        Self::check_and_update_endpoint_name(
            conn,
            endpoint_id,
            hostname.clone().unwrap_or_default(),
        )?;
        Ok(endpoint_id)
    }

    fn check_and_update_endpoint_name(
        conn: &Connection,
        endpoint_id: i64,
        hostname: String,
    ) -> Result<(), InsertEndpointError> {
        if hostname.is_empty() {
            return Ok(());
        }
        // Check if endpoint exists with null hostname
        if conn.query_row(
            "SELECT COUNT(*) FROM endpoints WHERE id = ? AND (name IS NULL OR name = '')",
            params![endpoint_id],
            |row| row.get::<_, i64>(0),
        )? > 0
        {
            conn.execute(
                "UPDATE endpoints SET name = ? where id = ?",
                params![hostname, endpoint_id],
            )?;
        } else if hostname.parse::<std::net::IpAddr>().is_err() {
            // Only update if hostname is not an IPv4 or IPv6 address
            // First check if current name is an IP address
            let current_name: String = conn.query_row(
                "SELECT COALESCE(name, '') FROM endpoints WHERE id = ?",
                params![endpoint_id],
                |row| row.get(0),
            )?;

            if current_name.is_empty() || current_name.parse::<std::net::IpAddr>().is_ok() {
                conn.execute(
                    "UPDATE endpoints SET name = ? WHERE id = ?",
                    params![hostname, endpoint_id],
                )?;
            }
        }

        Ok(())
    }

    fn parse_windows_gateway(output: &str) -> Option<String> {
        output.lines().find_map(|line| {
            // Look for "0.0.0.0          0.0.0.0     <gateway_ip>"
            if !line.contains("0.0.0.0") || line.split_whitespace().count() < 3 {
                return None;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                Some(parts[2].to_string())
            } else {
                None
            }
        })
    }

    fn parse_macos_gateway(output: &str) -> Option<String> {
        output.lines().find_map(|line| {
            if line.contains("gateway:") {
                line.split_whitespace().nth(1).map(String::from)
            } else {
                None
            }
        })
    }

    fn parse_linux_gateway(output: &str) -> Option<String> {
        // Expected format: "default via <gateway_ip> dev <interface>"
        output
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(2).map(String::from))
    }

    fn parse_linux_route_n(output: &str) -> Option<String> {
        output.lines().find_map(|line| {
            if line.starts_with("0.0.0.0") {
                line.split_whitespace().nth(1).map(String::from)
            } else {
                None
            }
        })
    }

    fn get_default_gateway() -> Option<String> {
        // Check cache first
        if let Ok(cache) = GATEWAY_INFO.lock()
            && let Some((gateway_ip, cached_time)) = cache.as_ref()
            && cached_time.elapsed() < GATEWAY_CACHE_TTL
        {
            return Some(gateway_ip.clone());
        }

        // Get default gateway using system commands
        let gateway_ip = if cfg!(target_os = "windows") {
            std::process::Command::new("route")
                .args(["print", "0.0.0.0"])
                .output()
                .ok()
                .and_then(|output| {
                    Self::parse_windows_gateway(&String::from_utf8_lossy(&output.stdout))
                })
        } else if cfg!(target_os = "macos") {
            std::process::Command::new("route")
                .args(["-n", "get", "default"])
                .output()
                .ok()
                .and_then(|output| {
                    Self::parse_macos_gateway(&String::from_utf8_lossy(&output.stdout))
                })
        } else {
            // Linux: try ip route first, fallback to route -n
            std::process::Command::new("ip")
                .args(["route", "show", "default"])
                .output()
                .ok()
                .and_then(|output| {
                    Self::parse_linux_gateway(&String::from_utf8_lossy(&output.stdout))
                })
                .or_else(|| {
                    std::process::Command::new("route")
                        .args(["-n"])
                        .output()
                        .ok()
                        .and_then(|output| {
                            Self::parse_linux_route_n(&String::from_utf8_lossy(&output.stdout))
                        })
                })
        };

        // Cache the result
        if let Some(ref gw) = gateway_ip
            && let Ok(mut cache) = GATEWAY_INFO.lock()
        {
            *cache = Some((gw.clone(), Instant::now()));
        }

        gateway_ip
    }

    pub fn is_on_local_network(ip: &str) -> bool {
        // Parse the IP address
        let ip_addr: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        // Special case: loopback addresses are always local
        if ip_addr.is_loopback() {
            return true;
        }

        // Check cached local networks (computed once at startup)
        for ip_network in get_local_networks() {
            if ip_network.contains(ip_addr) {
                return true;
            }
        }

        false
    }

    fn lookup_dns(ip: Option<String>, mac: Option<String>) -> Option<String> {
        let ip_str = ip?;
        let mac_str = mac?;
        let ip_addr = ip_str.parse().ok()?;
        let is_local = Self::is_local(ip_str.clone(), mac_str.clone());
        let local_hostname = get_hostname().unwrap_or_default();

        // Check cache first to avoid slow DNS lookups
        if let Ok(cache) = DNS_CACHE.lock()
            && let Some((cached_name, cached_time)) = cache.get(&ip_str)
            && cached_time.elapsed() < DNS_CACHE_TTL
        {
            return Some(cached_name.clone());
        }

        // Get hostname via DNS or fallback to mDNS/IP
        let hostname = match lookup_addr(&ip_addr) {
            Ok(name) if name != ip_str && !is_local => name,
            _ => MDnsLookup::lookup(&ip_str).unwrap_or(ip_str.clone()),
        };

        // Use local hostname for local IPs with different names
        let final_hostname = if is_local && !hostname.eq_ignore_ascii_case(&local_hostname) {
            local_hostname
        } else {
            hostname
        };

        // Cache the result
        if let Ok(mut cache) = DNS_CACHE.lock() {
            cache.insert(ip_str, (final_hostname.clone(), Instant::now()));
            // LRU-style eviction: remove oldest entries instead of clearing all
            if cache.len() > 10000 {
                // Find and remove the 1000 oldest entries
                let mut entries: Vec<_> = cache.iter().map(|(k, (_, t))| (k.clone(), *t)).collect();
                entries.sort_by_key(|(_, t)| *t);
                for (key, _) in entries.into_iter().take(1000) {
                    cache.remove(&key);
                }
            }
        }

        Some(final_hostname)
    }

    fn lookup_hostname(
        ip: Option<String>,
        mac: Option<String>,
        protocol: Option<String>,
        payload: &[u8],
    ) -> Option<String> {
        match protocol.as_deref() {
            Some("HTTP") => Self::get_http_host(payload),
            Some("HTTPS") => Self::find_sni(payload),
            _ => Self::lookup_dns(ip.clone(), mac.clone()),
        }
    }

    fn get_http_host(payload: &[u8]) -> Option<String> {
        let payload_str = String::from_utf8_lossy(payload);

        let mut host = None;

        for line in payload_str.lines() {
            let line = line.to_lowercase();
            if let Some(header_value) = line.strip_prefix("host:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("server:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("location:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("x-host:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("x-forwarded-host:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("x-forwarded-server:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("referer:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("report-uri:") {
                host = Some(header_value.trim().to_string());
                break;
            }
        }
        host.map(|host| Self::remove_all_but_alphanumeric_and_dots(host.as_str()))
    }

    fn remove_all_but_alphanumeric_and_dots(hostname: &str) -> String {
        let mut s = String::new();
        for h in hostname.chars() {
            if h.is_ascii_alphanumeric() || h == '.' || h == '-' {
                s.push(h);
            } else {
                s.clear();
            }
        }
        s
    }

    // Parse TLS ClientHello to extract SNI (Server Name Indication)
    fn find_sni(payload: &[u8]) -> Option<String> {
        // Minimum TLS ClientHello size
        if payload.len() < 44 {
            return None;
        }

        // Check for TLS Handshake (0x16) and version (0x03 0x01, 0x03 0x02, or 0x03 0x03)
        if payload[0] != 0x16 || payload[1] != 0x03 {
            return None;
        }

        // Check for ClientHello (0x01)
        if payload[5] != 0x01 {
            return None;
        }

        // Skip to extensions section
        // TLS record: 5 bytes
        // Handshake header: 4 bytes
        // Client version: 2 bytes
        // Random: 32 bytes
        let mut offset = 43;

        // Session ID length (1 byte) + session ID
        if offset >= payload.len() {
            return None;
        }
        let session_id_len = payload[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suites length (2 bytes) + cipher suites
        if offset + 2 > payload.len() {
            return None;
        }
        let cipher_suites_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
        offset += 2 + cipher_suites_len;

        // Compression methods length (1 byte) + compression methods
        if offset + 1 > payload.len() {
            return None;
        }
        let compression_methods_len = payload[offset] as usize;
        offset += 1 + compression_methods_len;

        // Extensions length (2 bytes)
        if offset + 2 > payload.len() {
            return None;
        }
        let extensions_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
        offset += 2;

        let extensions_end = offset + extensions_len;
        if extensions_end > payload.len() {
            return None;
        }

        // Parse extensions
        while offset + 4 <= extensions_end {
            let ext_type = ((payload[offset] as u16) << 8) | (payload[offset + 1] as u16);
            let ext_len = ((payload[offset + 2] as usize) << 8) | (payload[offset + 3] as usize);
            offset += 4;

            // Server Name extension (0x0000)
            if ext_type == 0x0000 && offset + ext_len <= extensions_end {
                // Server Name List Length (2 bytes)
                if ext_len < 5 || offset + 2 > extensions_end {
                    return None;
                }
                let _list_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
                offset += 2;

                // Server Name Type (1 byte, 0x00 for hostname)
                if payload[offset] != 0x00 {
                    return None;
                }
                offset += 1;

                // Server Name Length (2 bytes)
                if offset + 2 > extensions_end {
                    return None;
                }
                let name_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
                offset += 2;

                // Extract hostname
                if offset + name_len <= extensions_end
                    && let Ok(hostname) =
                        String::from_utf8(payload[offset..offset + name_len].to_vec())
                {
                    let cleaned = Self::remove_all_but_alphanumeric_and_dots(hostname.as_str());
                    if !cleaned.is_empty() {
                        return Some(cleaned);
                    }
                }
                return None;
            }

            offset += ext_len;
        }

        None
    }

    fn is_broadcast_or_multicast_mac(mac: &str) -> bool {
        let mac_lower = mac.to_lowercase();

        // Broadcast address
        if mac_lower == "ff:ff:ff:ff:ff:ff" {
            return true;
        }

        // Check if first octet indicates multicast (LSB of first byte is 1)
        // Multicast MACs: 01:xx:xx:xx:xx:xx, 03:xx:xx:xx:xx:xx, etc.
        if let Some(first_octet) = mac_lower.split(':').next()
            && let Ok(byte) = u8::from_str_radix(first_octet, 16)
        {
            // If LSB of first byte is 1, it's multicast
            if (byte & 0x01) == 0x01 {
                return true;
            }
        }

        false
    }

    fn is_multicast_or_broadcast_ip(ip: &str) -> bool {
        // Try to parse as IP address
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            match addr {
                std::net::IpAddr::V4(ipv4) => {
                    // IPv4 multicast: 224.0.0.0 - 239.255.255.255
                    if ipv4.is_multicast() {
                        return true;
                    }
                    // IPv4 broadcast
                    if ipv4.is_broadcast() {
                        return true;
                    }
                }
                std::net::IpAddr::V6(ipv6) => {
                    // IPv6 multicast: ff00::/8
                    if ipv6.is_multicast() {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn is_local(target_ip: String, mac: String) -> bool {
        // Check definitive loopback addresses first
        if target_ip == "127.0.0.1"
            || target_ip == "::1"
            || target_ip == "localhost"
            || target_ip == "::ffff:"
            || target_ip == "0:0:0:0:0:0:0:1"
        {
            return true; // Loopback addresses are always local
        }

        // For :: (unspecified address), verify MAC matches local interface
        let is_unspecified = target_ip == "::";

        for interface in interfaces() {
            if let Some(iface_mac) = interface.mac {
                if iface_mac.to_string() == mac {
                    return true; // MAC address matches a local interface
                }
            } else if interface
                .ips
                .iter()
                .any(|ip| ip.ip().to_string() == target_ip)
            {
                return true; // IP address matches a local interface
            }
        }

        // Only treat :: as local if we didn't find a matching MAC
        // If MAC didn't match any local interface, :: is NOT local
        if is_unspecified {
            return false;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_test_connection;

    #[test]
    fn test_classify_common_router_ip() {
        // Common router IPs should be classified as gateway
        let classification = EndPoint::classify_endpoint(Some("192.168.1.1".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));

        let classification = EndPoint::classify_endpoint(Some("10.0.0.1".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));
    }

    #[test]
    fn test_classify_router_hostname() {
        // Hostnames with router keywords should be classified as gateway
        let classification = EndPoint::classify_endpoint(None, Some("my-router.local".to_string()));
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));

        let classification =
            EndPoint::classify_endpoint(None, Some("gateway.example.com".to_string()));
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));

        let classification = EndPoint::classify_endpoint(None, Some("pfsense.local".to_string()));
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));
    }

    #[test]
    fn test_classify_internet_endpoint() {
        // Public IPs should be classified as internet
        let classification = EndPoint::classify_endpoint(Some("8.8.8.8".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_INTERNET));

        let classification = EndPoint::classify_endpoint(Some("1.1.1.1".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_INTERNET));
    }

    #[test]
    fn test_classify_local_endpoint() {
        // Loopback should return None as it's not gateway or internet (it's local)
        let classification = EndPoint::classify_endpoint(Some("127.0.0.1".to_string()), None);
        assert_eq!(classification, None);

        // Note: 192.168.x.x may be classified as internet in test environment
        // without configured network interfaces, which is expected behavior
    }

    #[test]
    fn test_classify_none_ip() {
        let classification = EndPoint::classify_endpoint(None, None);
        assert_eq!(classification, None);
    }

    #[test]
    fn test_endpoint_insertion() {
        let conn = new_test_connection();

        // Insert an endpoint
        let result = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            Some("192.168.1.100".to_string()),
            None,
            &[],
        );

        assert!(result.is_ok());
        let endpoint_id = result.unwrap();
        assert!(endpoint_id > 0);

        // Verify endpoint exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM endpoints WHERE id = ?1",
                [endpoint_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_duplicate_endpoint_returns_same_id() {
        let conn = new_test_connection();

        // Insert endpoint first time
        let id1 = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            Some("192.168.1.100".to_string()),
            None,
            &[],
        )
        .unwrap();

        // Insert same endpoint again
        let id2 = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            Some("192.168.1.100".to_string()),
            None,
            &[],
        )
        .unwrap();

        // Should return the same ID
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_is_multicast_or_broadcast_ip() {
        assert!(EndPoint::is_multicast_or_broadcast_ip("224.0.0.1"));
        assert!(EndPoint::is_multicast_or_broadcast_ip("255.255.255.255"));
        assert!(!EndPoint::is_multicast_or_broadcast_ip("192.168.1.1"));
        assert!(!EndPoint::is_multicast_or_broadcast_ip("8.8.8.8"));
    }

    #[test]
    fn test_is_broadcast_or_multicast_mac() {
        assert!(EndPoint::is_broadcast_or_multicast_mac("ff:ff:ff:ff:ff:ff"));
        assert!(EndPoint::is_broadcast_or_multicast_mac("01:00:5e:00:00:01"));
        assert!(!EndPoint::is_broadcast_or_multicast_mac(
            "00:11:22:33:44:55"
        ));
    }

    // Device classification tests
    #[test]
    fn test_classify_printer() {
        use super::*;

        // Hostname patterns
        assert_eq!(is_printer_hostname("hp-laserjet-pro"), true);
        assert_eq!(is_printer_hostname("canon-mx920"), true);
        assert_eq!(is_printer_hostname("epson-wf-7720"), true);
        assert_eq!(is_printer_hostname("brother-mfc-9340cdw"), true);
        assert_eq!(is_printer_hostname("npi123456"), true);
        assert_eq!(is_printer_hostname("brn001122334455"), true);

        // Non-printers
        assert_eq!(is_printer_hostname("my-laptop"), false);
        assert_eq!(is_printer_hostname("iphone"), false);
    }

    #[test]
    fn test_classify_tv() {
        use super::*;

        // Hostname patterns
        assert_eq!(is_tv_hostname("samsung-tv"), true);
        assert_eq!(is_tv_hostname("roku-ultra"), true);
        assert_eq!(is_tv_hostname("chromecast-living-room"), true);
        assert_eq!(is_tv_hostname("appletv"), true);
        assert_eq!(is_tv_hostname("lg-oled55"), true);
        assert_eq!(is_tv_hostname("firetv-stick"), true);

        // Non-TVs
        assert_eq!(is_tv_hostname("my-laptop"), false);
        assert_eq!(is_tv_hostname("printer"), false);
    }

    #[test]
    fn test_classify_gaming() {
        use super::*;

        assert_eq!(is_gaming_hostname("xbox-series-x"), true);
        assert_eq!(is_gaming_hostname("playstation-5"), true);
        assert_eq!(is_gaming_hostname("nintendo-switch"), true);
        assert_eq!(is_gaming_hostname("steamdeck"), true);

        assert_eq!(is_gaming_hostname("my-pc"), false);
    }

    #[test]
    fn test_classify_phone() {
        use super::*;

        assert_eq!(is_phone_hostname("iphone-14-pro"), true);
        assert_eq!(is_phone_hostname("ipad-mini"), true);
        assert_eq!(is_phone_hostname("galaxy-s23"), true);
        assert_eq!(is_phone_hostname("pixel-7"), true);
        assert_eq!(is_phone_hostname("sm-g991u"), true);
        assert_eq!(is_phone_hostname("oneplus-11"), true);
        assert_eq!(is_phone_hostname("moto-g-power"), true);

        // Should NOT match TV variants
        assert_eq!(is_phone_hostname("galaxy-tv"), false);
        assert_eq!(is_phone_hostname("androidtv"), false);
    }

    #[test]
    fn test_classify_vm() {
        use super::*;

        assert_eq!(is_vm_hostname("vmware-esxi-01"), true);
        assert_eq!(is_vm_hostname("proxmox-server"), true);
        assert_eq!(is_vm_hostname("docker-host"), true);
        assert_eq!(is_vm_hostname("kubernetes-node-1"), true);
        assert_eq!(is_vm_hostname("vm-ubuntu-22"), true);
        assert_eq!(is_vm_hostname("webserver-vm"), true);

        assert_eq!(is_vm_hostname("my-laptop"), false);
    }

    #[test]
    fn test_classify_soundbar() {
        use super::*;

        assert_eq!(is_soundbar_hostname("sonos-beam"), true);
        assert_eq!(is_soundbar_hostname("bose-soundbar-700"), true);
        assert_eq!(is_soundbar_hostname("samsung-sound-plus"), true);
        assert_eq!(is_soundbar_hostname("jbl-bar-5.1"), true);

        assert_eq!(is_soundbar_hostname("samsung-tv"), false);
    }

    #[test]
    fn test_classify_appliance() {
        use super::*;

        assert_eq!(is_appliance_hostname("lg-dishwasher"), true);
        assert_eq!(is_appliance_hostname("samsung-washer"), true);
        assert_eq!(is_appliance_hostname("whirlpool-dryer"), true);
        assert_eq!(is_appliance_hostname("bosch-dishwasher-500"), true);

        // LG ThinQ appliances
        assert_eq!(is_lg_appliance("ldf7774st"), true);
        assert_eq!(is_lg_appliance("wm3900hwa"), true);
        assert_eq!(is_lg_appliance("dlex3900w"), true);

        assert_eq!(is_appliance_hostname("my-laptop"), false);
    }

    #[test]
    fn test_classify_by_port() {
        use super::*;

        // Printer ports
        assert_eq!(classify_by_port(9100), Some(CLASSIFICATION_PRINTER));
        assert_eq!(classify_by_port(631), Some(CLASSIFICATION_PRINTER));

        // TV ports
        assert_eq!(classify_by_port(8008), Some(CLASSIFICATION_TV)); // Chromecast
        assert_eq!(classify_by_port(8001), Some(CLASSIFICATION_TV)); // Samsung
        assert_eq!(classify_by_port(6467), Some(CLASSIFICATION_TV)); // Roku

        // VM ports
        assert_eq!(classify_by_port(8006), Some(CLASSIFICATION_VIRTUALIZATION)); // Proxmox
        assert_eq!(classify_by_port(2375), Some(CLASSIFICATION_VIRTUALIZATION)); // Docker

        // Unknown
        assert_eq!(classify_by_port(80), None);
        assert_eq!(classify_by_port(443), None);
    }

    #[test]
    fn test_classify_device_type_integration() {
        // Full integration test of classify_device_type
        assert_eq!(
            EndPoint::classify_device_type(Some("hp-laserjet"), None, &[]),
            Some("printer")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("roku-ultra"), None, &[]),
            Some("tv")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("unknown-device"), None, &[9100]),
            Some("printer")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("my-laptop"), None, &[80, 443]),
            None
        );
    }
}
