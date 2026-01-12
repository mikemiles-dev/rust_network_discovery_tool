use std::net::IpAddr;
use std::time::Duration;

use futures::StreamExt;

use super::SsdpResult;

/// SSDP/UPnP device discovery scanner
pub struct SsdpScanner {
    timeout_secs: u64,
}

impl SsdpScanner {
    pub fn new() -> Self {
        Self { timeout_secs: 3 }
    }

    #[allow(dead_code)]
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Discover SSDP/UPnP devices on the network
    pub async fn discover(&self) -> Vec<SsdpResult> {
        let mut results = Vec::new();
        let search_target = ssdp_client::SearchTarget::RootDevice;

        match ssdp_client::search(
            &search_target,
            Duration::from_secs(self.timeout_secs),
            2,
            None,
        )
        .await
        {
            Ok(mut responses) => {
                while let Some(response_result) = responses.next().await {
                    if let Ok(response) = response_result
                        && let Ok(url) = url::Url::parse(response.location())
                        && let Some(host) = url.host_str()
                        && let Ok(ip) = host.parse::<IpAddr>()
                    {
                        let server_str = response.server();
                        results.push(SsdpResult {
                            ip,
                            location: response.location().to_string(),
                            server: if server_str.is_empty() {
                                None
                            } else {
                                Some(server_str.to_string())
                            },
                            device_type: Some(response.search_target().to_string()),
                            friendly_name: None,
                        });
                    }
                }
            }
            Err(e) => {
                eprintln!("SSDP discovery error: {}", e);
            }
        }

        // Deduplicate by IP (same device may respond multiple times)
        results.sort_by(|a, b| a.ip.cmp(&b.ip));
        results.dedup_by(|a, b| a.ip == b.ip);

        results
    }
}

impl Default for SsdpScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_default() {
        let scanner = SsdpScanner::default();
        assert_eq!(scanner.timeout_secs, 3);
    }

    #[test]
    fn test_result_deduplication() {
        use crate::scanner::SsdpResult;

        let mut results = vec![
            SsdpResult {
                ip: "192.168.1.100".parse().unwrap(),
                location: "http://192.168.1.100:8080/".to_string(),
                server: Some("Test/1.0".to_string()),
                device_type: Some("upnp:rootdevice".to_string()),
                friendly_name: None,
            },
            SsdpResult {
                ip: "192.168.1.100".parse().unwrap(),
                location: "http://192.168.1.100:8080/desc.xml".to_string(),
                server: Some("Test/1.0".to_string()),
                device_type: Some("urn:schemas-upnp-org:device:MediaRenderer:1".to_string()),
                friendly_name: None,
            },
            SsdpResult {
                ip: "192.168.1.101".parse().unwrap(),
                location: "http://192.168.1.101:8080/".to_string(),
                server: None,
                device_type: None,
                friendly_name: None,
            },
        ];

        // Apply same deduplication logic as discover()
        results.sort_by(|a, b| a.ip.cmp(&b.ip));
        results.dedup_by(|a, b| a.ip == b.ip);

        // Should have 2 unique IPs
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].ip.to_string(), "192.168.1.100");
        assert_eq!(results[1].ip.to_string(), "192.168.1.101");
    }
}
