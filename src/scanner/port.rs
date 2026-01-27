//! TCP port scanner. Performs async connect-based port scanning with semaphore-limited
//! concurrency and service name resolution for well-known ports.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use super::PortResult;

/// Map well-known port numbers to service names
fn port_to_service_name(port: u16) -> Option<String> {
    match port {
        22 => Some("SSH".to_string()),
        80 => Some("HTTP".to_string()),
        443 => Some("HTTPS".to_string()),
        445 => Some("SMB".to_string()),
        3389 => Some("RDP".to_string()),
        5353 => Some("mDNS".to_string()),
        5900 => Some("VNC".to_string()),
        8080 => Some("HTTP-Alt".to_string()),
        8443 => Some("HTTPS-Alt".to_string()),
        9100 => Some("Printer".to_string()),
        21 => Some("FTP".to_string()),
        23 => Some("Telnet".to_string()),
        25 => Some("SMTP".to_string()),
        53 => Some("DNS".to_string()),
        3306 => Some("MySQL".to_string()),
        5432 => Some("PostgreSQL".to_string()),
        6379 => Some("Redis".to_string()),
        27017 => Some("MongoDB".to_string()),
        _ => None,
    }
}

/// Default ports to scan
pub const DEFAULT_PORTS: &[u16] = &[
    22,   // SSH
    80,   // HTTP
    443,  // HTTPS
    445,  // SMB
    3389, // RDP
    5353, // mDNS
    5900, // VNC
    8080, // HTTP Alt
    8443, // HTTPS Alt
    9100, // Printer
];

/// TCP port scanner using async connect
pub struct PortScanner {
    timeout_ms: u64,
    max_concurrent: usize,
}

impl PortScanner {
    pub fn new() -> Self {
        Self {
            timeout_ms: 1000,
            max_concurrent: 100,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Scan a single port on an IP
    async fn scan_port(&self, ip: IpAddr, port: u16) -> PortResult {
        let addr = SocketAddr::new(ip, port);
        let timeout_duration = Duration::from_millis(self.timeout_ms);

        let open = match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => true,
            Ok(Err(_)) => false, // Connection refused or other error
            Err(_) => false,     // Timeout
        };

        let service_name = if open {
            port_to_service_name(port)
        } else {
            None
        };

        PortResult {
            ip,
            port,
            open,
            service_name,
        }
    }

    /// Scan multiple IPs for open ports
    pub async fn scan_ips(&self, ips: &[IpAddr], ports: &[u16]) -> Vec<PortResult> {
        let semaphore = std::sync::Arc::new(Semaphore::new(self.max_concurrent));
        let mut handles = Vec::new();

        for &ip in ips {
            for &port in ports {
                let sem = semaphore.clone();
                let scanner_timeout = self.timeout_ms;

                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    let scanner = PortScanner::new().with_timeout(scanner_timeout);
                    scanner.scan_port(ip, port).await
                }));
            }
        }

        let mut results = Vec::new();
        for handle in handles {
            if let Ok(result) = handle.await
                && result.open
            {
                results.push(result);
            }
        }

        results
    }
}

impl Default for PortScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_to_service_name() {
        assert_eq!(port_to_service_name(22), Some("SSH".to_string()));
        assert_eq!(port_to_service_name(80), Some("HTTP".to_string()));
        assert_eq!(port_to_service_name(443), Some("HTTPS".to_string()));
        assert_eq!(port_to_service_name(3389), Some("RDP".to_string()));
        assert_eq!(port_to_service_name(5900), Some("VNC".to_string()));
        assert_eq!(port_to_service_name(9100), Some("Printer".to_string()));

        // Unknown ports
        assert_eq!(port_to_service_name(12345), None);
        assert_eq!(port_to_service_name(1), None);
    }

    #[test]
    fn test_default_ports() {
        // Verify DEFAULT_PORTS contains expected values
        assert!(DEFAULT_PORTS.contains(&22)); // SSH
        assert!(DEFAULT_PORTS.contains(&80)); // HTTP
        assert!(DEFAULT_PORTS.contains(&443)); // HTTPS
        assert!(DEFAULT_PORTS.contains(&8080)); // HTTP Alt
    }

    #[test]
    fn test_scanner_default() {
        let scanner = PortScanner::default();
        assert_eq!(scanner.timeout_ms, 1000);
        assert_eq!(scanner.max_concurrent, 100);
    }

    #[test]
    fn test_scanner_with_timeout() {
        let scanner = PortScanner::new().with_timeout(5000);
        assert_eq!(scanner.timeout_ms, 5000);
    }
}
