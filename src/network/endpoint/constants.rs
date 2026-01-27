use pnet::datalink::interfaces;
use pnet::ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

// Simple DNS cache to avoid repeated slow lookups
lazy_static::lazy_static! {
    pub(crate) static ref DNS_CACHE: Arc<Mutex<HashMap<String, (String, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
    pub(crate) static ref GATEWAY_INFO: Arc<Mutex<Option<(String, Instant)>>> = Arc::new(Mutex::new(None));
}

// Cache for local network CIDR blocks (computed once at startup)
static LOCAL_NETWORKS: OnceLock<Vec<IpNetwork>> = OnceLock::new();

/// Common local network hostname suffixes to strip
const LOCAL_SUFFIXES: &[&str] = &[
    ".local",
    ".lan",
    ".home",
    ".internal",
    ".localdomain",
    ".localhost",
];

/// Strip common local network suffixes from a hostname
pub fn strip_local_suffix(hostname: &str) -> String {
    let lower = hostname.to_lowercase();
    for suffix in LOCAL_SUFFIXES {
        if lower.ends_with(suffix) {
            return hostname[..hostname.len() - suffix.len()].to_string();
        }
    }
    hostname.to_string()
}

/// Check if a string looks like a UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
/// UUIDs are not good display names for devices, so we skip them
pub fn is_uuid_like(s: &str) -> bool {
    // UUID format: 8-4-4-4-12 hex chars with dashes (36 chars total)
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    // Check expected lengths: 8-4-4-4-12
    let expected_lengths = [8, 4, 4, 4, 12];
    for (part, expected_len) in parts.iter().zip(expected_lengths.iter()) {
        if part.len() != *expected_len {
            return false;
        }
        // Check all chars are hex digits
        if !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

/// Check if a string is a valid display name for an endpoint.
/// Rejects: empty strings, UUIDs, IPv4 addresses, IPv6 addresses.
/// This is the SINGLE SOURCE OF TRUTH for display name validation.
pub fn is_valid_display_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    // Reject UUIDs (e.g., "34887b21-9413-022c-352a-67966809b46c")
    if is_uuid_like(name) {
        return false;
    }
    // Reject IPv6 addresses (contain colons)
    if name.contains(':') {
        return false;
    }
    // Reject IPv4 addresses (all digits and dots, 4 octets)
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return false;
    }
    true
}

pub(crate) fn get_local_networks() -> &'static Vec<IpNetwork> {
    LOCAL_NETWORKS.get_or_init(|| {
        interfaces()
            .into_iter()
            .flat_map(|iface| iface.ips)
            .filter(|network| {
                // Filter out catch-all networks (0.0.0.0/0 and ::/0) that match everything
                // These are not actual local networks
                let is_catch_all = match network.ip() {
                    IpAddr::V4(ipv4) => ipv4.is_unspecified() && network.prefix() == 0,
                    IpAddr::V6(ipv6) => ipv6.is_unspecified() && network.prefix() == 0,
                };
                !is_catch_all
            })
            .collect()
    })
}

pub(crate) const DNS_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes
pub(crate) const GATEWAY_CACHE_TTL: Duration = Duration::from_secs(60); // 1 minute

/// Check if a MAC address is locally administered (randomized/private)
/// Locally administered addresses have the second-least-significant bit of the first octet set to 1
/// This means the second hex digit of the first octet is 2, 6, A, or E
pub fn is_locally_administered_mac(mac: &str) -> bool {
    let mac_lower = mac.to_lowercase();
    // Get the second character of the MAC (after potential delimiter handling)
    let chars: Vec<char> = mac_lower
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if chars.len() < 2 {
        return false;
    }
    // The second hex digit determines if it's locally administered
    // 2, 6, A, E have the second-least-significant bit set
    matches!(chars[1], '2' | '6' | 'a' | 'e')
}

/// Check if an IP address is an IPv6 link-local address (fe80::)
pub fn is_ipv6_link_local(ip: &str) -> bool {
    use std::net::Ipv6Addr;
    if let Ok(addr) = ip.parse::<Ipv6Addr>() {
        // Link-local addresses start with fe80::/10
        let segments = addr.segments();
        (segments[0] & 0xffc0) == 0xfe80
    } else {
        false
    }
}

/// Extract MAC address from IPv6 EUI-64 interface identifier
/// Works with link-local (fe80::) and other IPv6 addresses that use EUI-64 format
/// The EUI-64 format inserts ff:fe in the middle of the MAC and flips the 7th bit
/// Example: fe80::d48f:2ff:fefb:b5 -> d6:8f:02:fb:00:b5
pub fn extract_mac_from_ipv6_eui64(ip: &str) -> Option<String> {
    use std::net::Ipv6Addr;

    let addr: Ipv6Addr = ip.parse().ok()?;
    let segments = addr.segments();

    // Interface identifier is the last 4 segments (64 bits)
    // EUI-64 format has ff:fe in the middle (bytes 3-4 of the interface ID)
    // segments[4]:segments[5]:segments[6]:segments[7]
    // In bytes: [4h][4l]:[5h][5l]:[6h][6l]:[7h][7l]
    // EUI-64:   [mac0][mac1]:[mac2][ff]:[fe][mac3]:[mac4][mac5]

    let seg5 = segments[5];
    let seg6 = segments[6];

    // Check for ff:fe pattern: low byte of seg5 should be 0xff, high byte of seg6 should be 0xfe
    let byte3 = (seg5 & 0x00ff) as u8; // Low byte of segments[5]
    let byte4 = (seg6 >> 8) as u8; // High byte of segments[6]

    if byte3 != 0xff || byte4 != 0xfe {
        return None; // Not EUI-64 format
    }

    // Extract MAC bytes
    let mac0 = (segments[4] >> 8) as u8;
    let mac1 = (segments[4] & 0x00ff) as u8;
    let mac2 = (seg5 >> 8) as u8;
    // bytes 3-4 are ff:fe, skip them
    let mac3 = (seg6 & 0x00ff) as u8;
    let mac4 = (segments[7] >> 8) as u8;
    let mac5 = (segments[7] & 0x00ff) as u8;

    // Flip the 7th bit (Universal/Local bit) of the first byte
    let mac0_flipped = mac0 ^ 0x02;

    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac0_flipped, mac1, mac2, mac3, mac4, mac5
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_mac_from_ipv6_eui64() {
        // Standard EUI-64 link-local address
        assert_eq!(
            extract_mac_from_ipv6_eui64("fe80::d48f:2ff:fefb:b5"),
            Some("d6:8f:02:fb:00:b5".to_string())
        );

        // Another example with different MAC
        assert_eq!(
            extract_mac_from_ipv6_eui64("fe80::1234:56ff:fe78:9abc"),
            Some("10:34:56:78:9a:bc".to_string())
        );

        // Full form address (no ::)
        assert_eq!(
            extract_mac_from_ipv6_eui64("fe80:0000:0000:0000:0211:22ff:fe33:4455"),
            Some("00:11:22:33:44:55".to_string())
        );

        // Non-EUI-64 address (no ff:fe pattern) should return None
        assert_eq!(extract_mac_from_ipv6_eui64("fe80::1"), None);

        // Global IPv6 with EUI-64 should also work
        assert_eq!(
            extract_mac_from_ipv6_eui64("2001:db8::0211:22ff:fe33:4455"),
            Some("00:11:22:33:44:55".to_string())
        );

        // Invalid IP should return None
        assert_eq!(extract_mac_from_ipv6_eui64("not-an-ip"), None);

        // IPv4 should return None
        assert_eq!(extract_mac_from_ipv6_eui64("192.168.1.1"), None);
    }
}
