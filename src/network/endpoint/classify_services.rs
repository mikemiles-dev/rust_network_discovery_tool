//! Service and port-based device classification. Identifies device types by
//! matching mDNS service names and open TCP port numbers against known
//! signatures for printers, TVs, gaming consoles, phones, soundbars,
//! appliances, and virtualization platforms.

use super::classify::is_mac_computer_hostname;
use super::patterns::{
    APPLIANCE_SERVICES, CLASSIFICATION_APPLIANCE, CLASSIFICATION_GAMING, CLASSIFICATION_PHONE,
    CLASSIFICATION_PRINTER, CLASSIFICATION_SOUNDBAR, CLASSIFICATION_TV,
    CLASSIFICATION_VIRTUALIZATION, PHONE_SERVICES, PRINTER_SERVICES, SOUNDBAR_SERVICES,
    TV_SERVICES,
};

/// Service-to-classification mapping, checked in priority order
const SERVICE_CLASSIFICATIONS: &[(&[&str], &str)] = &[
    (APPLIANCE_SERVICES, CLASSIFICATION_APPLIANCE),
    (PHONE_SERVICES, CLASSIFICATION_PHONE),
    (SOUNDBAR_SERVICES, CLASSIFICATION_SOUNDBAR),
    (PRINTER_SERVICES, CLASSIFICATION_PRINTER),
    (TV_SERVICES, CLASSIFICATION_TV),
];

/// Check mDNS services for device type
pub(crate) fn classify_by_services(
    services: &[String],
    hostname: Option<&str>,
) -> Option<&'static str> {
    for service in services {
        let s = service.as_str();
        for &(svc_list, classification) in SERVICE_CLASSIFICATIONS {
            if svc_list.contains(&s) {
                // Skip phone classification for Mac computers
                // (they also advertise _companion-link._tcp)
                if classification == CLASSIFICATION_PHONE
                    && let Some(h) = hostname
                    && is_mac_computer_hostname(h)
                {
                    continue;
                }
                return Some(classification);
            }
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
    use super::super::patterns::{
        CLASSIFICATION_PRINTER, CLASSIFICATION_TV, CLASSIFICATION_VIRTUALIZATION,
    };

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
