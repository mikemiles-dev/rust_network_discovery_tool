//! Gateway and router classification logic. Detects default gateways,
//! common router IPs, and router-like hostnames.

use std::time::Instant;

use super::EndPoint;
use super::constants::{GATEWAY_CACHE_TTL, GATEWAY_INFO};
use super::patterns::{CLASSIFICATION_GATEWAY, CLASSIFICATION_INTERNET};

impl EndPoint {
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
    use super::super::patterns::{CLASSIFICATION_GATEWAY, CLASSIFICATION_INTERNET};

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
}
