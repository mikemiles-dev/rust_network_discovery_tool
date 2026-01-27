//! Device classification by MAC and services. Identifies device types (printers, TVs,
//! phones, gaming consoles, computers) using MAC vendor lookups and open port/service analysis.

use super::detection::matches_prefix;
use super::patterns::{
    APPLIANCE_SERVICES, APPLIANCE_VENDORS, CLASSIFICATION_APPLIANCE, CLASSIFICATION_GAMING,
    CLASSIFICATION_PHONE, CLASSIFICATION_PRINTER, CLASSIFICATION_SOUNDBAR, CLASSIFICATION_TV,
    CLASSIFICATION_VIRTUALIZATION, GAMING_VENDORS, GATEWAY_VENDORS, LG_APPLIANCE_PREFIXES,
    MAC_DESKTOP_SERVICES, PHONE_SERVICES, PRINTER_SERVICES, SOUNDBAR_SERVICES, TV_SERVICES,
    TV_VENDORS,
};
use super::vendor::get_mac_vendor;

/// Check if any MAC address matches known IoT/appliance vendor OUIs
pub(crate) fn is_appliance_mac(macs: &[String]) -> bool {
    macs.iter().any(|mac| {
        // Check vendor list
        if get_mac_vendor(mac).is_some_and(|v| APPLIANCE_VENDORS.contains(&v)) {
            return true;
        }
        // Check SmartThings sensor MAC prefixes (mapped to Samsung vendor)
        let mac_lower = mac.to_lowercase();
        mac_lower.starts_with("70:2c:1f") || mac_lower.starts_with("28:6d:97")
    })
}

/// Check if any MAC address matches known gaming vendor OUIs
pub(crate) fn is_gaming_mac(macs: &[String]) -> bool {
    macs.iter()
        .any(|mac| get_mac_vendor(mac).is_some_and(|v| GAMING_VENDORS.contains(&v)))
}

/// Check if any MAC address matches known TV/streaming vendor OUIs
pub(crate) fn is_tv_mac(macs: &[String]) -> bool {
    macs.iter()
        .any(|mac| get_mac_vendor(mac).is_some_and(|v| TV_VENDORS.contains(&v)))
}

/// Check if any MAC address is from Apple
pub(crate) fn is_apple_mac(macs: &[String]) -> bool {
    macs.iter()
        .any(|mac| get_mac_vendor(mac).is_some_and(|v| v == "Apple"))
}

/// Check if any MAC address matches known gateway/router vendor OUIs
pub(crate) fn is_gateway_mac(macs: &[String]) -> bool {
    macs.iter()
        .any(|mac| get_mac_vendor(mac).is_some_and(|v| GATEWAY_VENDORS.contains(&v)))
}

/// Check if device is likely a phone based on MAC and services
/// Apple devices that don't advertise file sharing services are likely iPhones/iPads
/// Check if hostname indicates a Mac computer (not a phone)
pub(crate) fn is_mac_computer_hostname(hostname: &str) -> bool {
    let mac_patterns = [
        "macbook",
        "mac-book",
        "imac",
        "i-mac",
        "mac-mini",
        "macmini",
        "mac-pro",
        "macpro",
        "mac-studio",
        "macstudio",
    ];
    mac_patterns.iter().any(|p| hostname.contains(p))
}

pub(crate) fn is_phone_mac(macs: &[String], ips: &[String], hostname: Option<&str>) -> bool {
    // Only applies to Apple devices (iPhones/iPads)
    if !is_apple_mac(macs) {
        return false;
    }

    // Never classify Mac computers as phones based on hostname
    if let Some(h) = hostname {
        let lower = h.to_lowercase();
        if is_mac_computer_hostname(&lower) {
            return false;
        }
    }

    // Check if device advertises any desktop/Mac services
    for ip_str in ips {
        let services = crate::network::mdns_lookup::MDnsLookup::get_services(ip_str);
        for service in &services {
            if MAC_DESKTOP_SERVICES.contains(&service.as_str()) {
                // This is a Mac (desktop), not a phone
                return false;
            }
        }
    }

    // Apple device without desktop services = likely iPhone/iPad
    true
}

/// Check if hostname indicates an LG ThinQ appliance
pub(crate) fn is_lg_appliance(hostname: &str) -> bool {
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
pub(crate) fn classify_by_services(
    services: &[String],
    hostname: Option<&str>,
) -> Option<&'static str> {
    for service in services {
        let s = service.as_str();
        // Check more specific types first
        if APPLIANCE_SERVICES.contains(&s) {
            return Some(CLASSIFICATION_APPLIANCE);
        }
        // Skip phone classification for Mac computers (they also advertise _companion-link._tcp)
        if PHONE_SERVICES.contains(&s) {
            if let Some(h) = hostname
                && is_mac_computer_hostname(h)
            {
                continue;
            }
            return Some(CLASSIFICATION_PHONE);
        }
        if SOUNDBAR_SERVICES.contains(&s) {
            return Some(CLASSIFICATION_SOUNDBAR);
        }
        if PRINTER_SERVICES.contains(&s) {
            return Some(CLASSIFICATION_PRINTER);
        }
        if TV_SERVICES.contains(&s) {
            return Some(CLASSIFICATION_TV);
        }
    }
    None
}

/// Check if port combination indicates a computer (laptop/desktop)
/// Computers typically have remote access ports (RDP/VNC) combined with file sharing
pub(crate) fn is_computer_by_ports(ports: &[u16]) -> bool {
    let has_remote_access = ports.contains(&3389)  // RDP (Windows Remote Desktop)
        || ports.contains(&5900)                    // VNC
        || ports.contains(&22); // SSH

    let has_file_sharing = ports.contains(&445)    // SMB (Windows file sharing)
        || ports.contains(&548)                     // AFP (Apple file sharing)
        || ports.contains(&139); // NetBIOS

    // Must have both remote access AND file sharing to be classified as computer
    // This avoids false positives from devices that just have SSH
    has_remote_access && has_file_sharing
}

/// Classify by port number
pub(crate) fn classify_by_port(port: u16) -> Option<&'static str> {
    match port {
        // Printer ports
        9100 | 631 | 515 => Some(CLASSIFICATION_PRINTER),
        // Gaming console ports (check BEFORE TV ports)
        9295..=9297 => Some(CLASSIFICATION_GAMING), // PlayStation Remote Play
        3478..=3480 => Some(CLASSIFICATION_GAMING), // PlayStation Network
        3074 => Some(CLASSIFICATION_GAMING),        // Xbox Live
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lg_appliance() {
        assert_eq!(is_lg_appliance("ldf7774st"), true);
        assert_eq!(is_lg_appliance("wm3900hwa"), true);
        assert_eq!(is_lg_appliance("dlex3900w"), true);
    }

    #[test]
    fn test_classify_by_port() {
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
}
