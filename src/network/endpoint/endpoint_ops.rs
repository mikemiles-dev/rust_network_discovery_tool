//! Core endpoint operations. Device type classification, endpoint name management,
//! gateway detection, and network locality checks.

use pnet::datalink::interfaces;
use rusqlite::{Connection, params};
use std::net::IpAddr;
use std::time::Instant;

use super::EndPoint;
use super::classify::{
    is_appliance_mac, is_gaming_mac, is_gateway_mac, is_lg_appliance, is_phone_mac,
    is_soundbar_model, is_tv_mac, is_tv_model,
};
use super::classify_hostname::{
    is_appliance_hostname, is_gaming_hostname, is_phone_hostname, is_printer_hostname,
    is_soundbar_hostname, is_tv_hostname, is_vm_hostname,
};
use super::classify_services::{classify_by_port, classify_by_services, is_computer_by_ports};
use super::constants::{
    GATEWAY_CACHE_TTL, GATEWAY_INFO, get_local_networks, is_valid_display_name, strip_local_suffix,
};
use super::patterns::{
    CLASSIFICATION_APPLIANCE, CLASSIFICATION_COMPUTER, CLASSIFICATION_GAMING,
    CLASSIFICATION_GATEWAY, CLASSIFICATION_INTERNET, CLASSIFICATION_PHONE, CLASSIFICATION_PRINTER,
    CLASSIFICATION_SOUNDBAR, CLASSIFICATION_TV, CLASSIFICATION_VIRTUALIZATION,
};
use super::types::InsertEndpointError;

impl EndPoint {
    /// Classify device type based on hostname, ports, MACs, and mDNS services
    /// Returns device-specific classification (printer, tv, gaming) or None
    /// This is separate from network-level classification (gateway, internet)
    pub fn classify_device_type(
        hostname: Option<&str>,
        ips: &[String],
        ports: &[u16],
        macs: &[String],
        model: Option<&str>,
    ) -> Option<&'static str> {
        // Pre-compute lowercase hostname once
        let lower_hostname = hostname.map(|h| h.to_lowercase());
        let lower = lower_hostname.as_deref();

        // Check SSDP/UPnP model first - most reliable for identifying device type
        if let Some(m) = model
            && is_soundbar_model(m)
        {
            return Some(CLASSIFICATION_SOUNDBAR);
        }

        // Check for TV models (Samsung Frame, QLED, LG OLED, etc.)
        if let Some(m) = model
            && is_tv_model(m)
        {
            return Some(CLASSIFICATION_TV);
        }

        // Check for LG ThinQ appliances FIRST (they advertise AirPlay but aren't TVs)
        if let Some(h) = lower
            && is_lg_appliance(h)
        {
            return Some(CLASSIFICATION_APPLIANCE);
        }

        // Check hostname patterns FIRST - most reliable for user devices
        // This prevents mDNS services from misclassifying computers/phones as TVs
        if let Some(h) = lower {
            // Order matters: check more specific patterns first
            if is_printer_hostname(h) {
                return Some(CLASSIFICATION_PRINTER);
            }
            if is_phone_hostname(h) {
                return Some(CLASSIFICATION_PHONE);
            }
            if is_gaming_hostname(h) {
                return Some(CLASSIFICATION_GAMING);
            }
            if is_tv_hostname(h) {
                return Some(CLASSIFICATION_TV);
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

        // Check mDNS service advertisements for ALL IPs
        // This catches smart devices that don't have distinctive hostnames
        for ip_str in ips {
            let services = crate::network::mdns_lookup::MDnsLookup::get_services(ip_str);
            if let Some(classification) = classify_by_services(&services, lower) {
                return Some(classification);
            }
        }

        // MAC-based detection (identifies devices by vendor OUI)
        // Check gateway first - networking equipment vendors
        if is_gateway_mac(macs) {
            return Some(CLASSIFICATION_GATEWAY);
        }
        // Check phone - Apple devices without desktop services are likely iPhones/iPads
        if is_phone_mac(macs, ips, lower) {
            return Some(CLASSIFICATION_PHONE);
        }
        if is_gaming_mac(macs) {
            return Some(CLASSIFICATION_GAMING);
        }
        if is_tv_mac(macs) {
            return Some(CLASSIFICATION_TV);
        }
        if is_appliance_mac(macs) {
            return Some(CLASSIFICATION_APPLIANCE);
        }

        // Computer detection based on port combinations
        // RDP (3389) or VNC (5900) combined with file sharing ports indicates a computer
        if is_computer_by_ports(ports) {
            return Some(CLASSIFICATION_COMPUTER);
        }

        // Port-based detection (less reliable, fallback)
        for &port in ports {
            if let Some(classification) = classify_by_port(port) {
                return Some(classification);
            }
        }

        None
    }

    pub(super) fn check_and_update_endpoint_name(
        conn: &Connection,
        endpoint_id: i64,
        hostname: String,
    ) -> Result<(), InsertEndpointError> {
        // Strip local suffixes like .local, .lan, .home and normalize to lowercase
        let hostname = strip_local_suffix(&hostname).to_lowercase();

        // Only accept valid display names (not empty, not UUID, not IP)
        if !is_valid_display_name(&hostname) {
            return Ok(());
        }

        // Get current name
        let current_name: String = conn.query_row(
            "SELECT COALESCE(name, '') FROM endpoints WHERE id = ?",
            params![endpoint_id],
            |row| row.get(0),
        )?;

        // Update if current name is invalid (empty, UUID, IP) and new name is valid
        let current_is_valid = is_valid_display_name(&current_name);
        let should_update = !current_is_valid;

        if should_update {
            conn.execute(
                "UPDATE endpoints SET name = ? WHERE id = ?",
                params![hostname, endpoint_id],
            )?;
            // When updating to a valid hostname, try to merge other IPv6 endpoints on same prefix
            Self::merge_ipv6_siblings_into_endpoint(conn, endpoint_id);
            // Try to merge this endpoint into an existing one with the same hostname
            Self::try_merge_by_hostname(conn, endpoint_id, &hostname);
        }

        Ok(())
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

    pub(super) fn is_broadcast_or_multicast_mac(mac: &str) -> bool {
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

    pub(super) fn is_multicast_or_broadcast_ip(ip: &str) -> bool {
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

    pub(super) fn is_local(target_ip: String, mac: String) -> bool {
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

    /// Classify an endpoint as Gateway, Internet, or LocalNetwork based on IP address and hostname
    pub fn classify_endpoint(ip: Option<String>, hostname: Option<String>) -> Option<&'static str> {
        let ip_is_local = ip
            .as_ref()
            .is_some_and(|ip_str| Self::is_on_local_network(ip_str));

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

            // Check if it's on the local network - if not, it's internet
            if !ip_is_local {
                return Some(CLASSIFICATION_INTERNET);
            }
        }

        // Check if hostname indicates a router/gateway
        if let Some(ref hostname_str) = hostname {
            if Self::is_router_hostname(hostname_str) {
                return Some(CLASSIFICATION_GATEWAY);
            }

            // Only check hostname for internet classification if we don't have a local IP
            // If the IP is local, trust the IP - hostname suffix doesn't matter
            // This prevents ISP-specific suffixes (like .attlocal.net) from being misclassified
            if !ip_is_local && Self::is_internet_hostname(hostname_str) {
                return Some(CLASSIFICATION_INTERNET);
            }
        }

        // Local network device, no special classification
        None
    }

    /// Check if hostname looks like an internet domain
    fn is_internet_hostname(hostname: &str) -> bool {
        // Skip if it looks like an IP address
        if hostname.contains(':') || hostname.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return false;
        }
        // Skip local hostnames
        let lower = hostname.to_lowercase();
        if lower.ends_with(".local")
            || lower.ends_with(".lan")
            || lower.ends_with(".home")
            || lower.ends_with(".internal")
            || lower.ends_with(".localdomain")
            || lower.ends_with(".attlocal.net") // AT&T local network suffix
            || lower.ends_with(".home.arpa")    // RFC 8375 home network
            || lower.ends_with(".mynetwork")
            || lower.ends_with(".homenet")
            || lower.ends_with(".router")
            || !lower.contains('.')
        {
            return false;
        }
        // Has a dot and a TLD-like suffix - likely internet
        true
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
            // Ubiquiti Dream Machine variants
            || lower.starts_with("udm-")
            || lower.starts_with("udm.")
            || lower == "udm"
            || lower.starts_with("udmpro")
            || lower.starts_with("udm-pro")
            || lower.starts_with("udm-se")
            // Linksys/Netgear/Asus patterns
            || lower.contains("linksys")
            || lower.contains("netgear")
            || lower.starts_with("asus-rt")
            || lower.starts_with("rt-") // Asus RT- series routers
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
}

#[cfg(test)]
mod tests {
    use super::super::EndPoint;

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

    #[test]
    fn test_classify_device_type_integration() {
        // Full integration test of classify_device_type
        assert_eq!(
            EndPoint::classify_device_type(Some("hp-laserjet"), &[], &[], &[], None),
            Some("printer")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("roku-ultra"), &[], &[], &[], None),
            Some("tv")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("unknown-device"), &[], &[9100], &[], None),
            Some("printer")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("my-laptop"), &[], &[80, 443], &[], None),
            None
        );
        // SSDP model-based classification
        assert_eq!(
            EndPoint::classify_device_type(Some("samsung-tv"), &[], &[], &[], Some("HW-MS750")),
            Some("soundbar")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("lg-device"), &[], &[], &[], Some("SL8YG")),
            Some("soundbar")
        );
    }

    #[test]
    fn test_classify_by_mac() {
        // Amazon device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                &[],
                &[],
                &["3c:5c:c4:90:a2:93".to_string()],
                None
            ),
            Some("appliance")
        );
        // Google/Nest device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("192.168.1.50"),
                &[],
                &[],
                &["18:d6:c7:12:34:56".to_string()],
                None
            ),
            Some("appliance")
        );
        // Ring device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                &[],
                &[],
                &["34:3e:a4:00:00:00".to_string()],
                None
            ),
            Some("appliance")
        );
        // Apple MAC without desktop services = phone (iPhone/iPad)
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                &[],
                &[],
                &["a4:83:e7:12:34:56".to_string()],
                None
            ),
            Some("phone")
        );
        // Hostname takes precedence over MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("hp-printer"),
                &[],
                &[],
                &["3c:5c:c4:90:a2:93".to_string()],
                None
            ),
            Some("printer")
        );
        // eero mesh router MAC = gateway
        assert_eq!(
            EndPoint::classify_device_type(
                Some("eero-2b09"),
                &[],
                &[],
                &["00:ab:48:12:34:56".to_string()],
                None
            ),
            Some("gateway")
        );
        // WiZ smart lighting MAC = appliance
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                &[],
                &[],
                &["d8:a0:11:12:34:56".to_string()],
                None
            ),
            Some("appliance")
        );
    }
}
