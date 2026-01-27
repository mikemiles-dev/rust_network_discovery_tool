//! Scan orchestration. Manages concurrent scanner execution with configurable scan types,
//! timeout settings, progress tracking, and stop signaling.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use ipnetwork::Ipv4Network;
use pnet::datalink;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc};

use super::arp::ArpScanner;
use super::icmp::IcmpScanner;
use super::ndp::NdpScanner;
use super::netbios::NetBiosScanner;
use super::port::{DEFAULT_PORTS, PortScanner};
use super::snmp::SnmpScanner;
use super::ssdp::SsdpScanner;
use super::{ScanResult, ScanType, check_scan_privileges};

/// Scan status for API responses
#[derive(Debug, Clone, Serialize)]
pub struct ScanStatus {
    pub running: bool,
    pub scan_types: Vec<ScanType>,
    pub progress_percent: u8,
    pub discovered_count: u32,
    pub last_scan_time: Option<i64>,
    pub current_phase: Option<String>,
}

/// Scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub scan_interval_secs: Option<u64>,
    pub enabled_scanners: HashSet<ScanType>,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        let mut enabled = HashSet::new();
        enabled.insert(ScanType::Arp);
        enabled.insert(ScanType::Ndp); // IPv6 neighbor discovery
        enabled.insert(ScanType::NetBios); // NetBIOS name discovery
        enabled.insert(ScanType::Ssdp);
        enabled.insert(ScanType::Snmp); // SNMP device discovery

        Self {
            scan_interval_secs: None,
            enabled_scanners: enabled,
            ports: DEFAULT_PORTS.to_vec(),
            timeout_ms: 1000,
        }
    }
}

/// Manages all scanning operations
pub struct ScanManager {
    status: Arc<RwLock<ScanStatus>>,
    config: Arc<RwLock<ScanConfig>>,
    result_tx: mpsc::Sender<ScanResult>,
    stop_signal: Arc<RwLock<bool>>,
}

impl ScanManager {
    pub fn new(result_tx: mpsc::Sender<ScanResult>) -> Self {
        Self {
            status: Arc::new(RwLock::new(ScanStatus {
                running: false,
                scan_types: Vec::new(),
                progress_percent: 0,
                discovered_count: 0,
                last_scan_time: None,
                current_phase: None,
            })),
            config: Arc::new(RwLock::new(ScanConfig::default())),
            result_tx,
            stop_signal: Arc::new(RwLock::new(false)),
        }
    }

    /// Get current scan status
    pub async fn get_status(&self) -> ScanStatus {
        self.status.read().await.clone()
    }

    /// Get current config
    pub async fn get_config(&self) -> ScanConfig {
        self.config.read().await.clone()
    }

    /// Update config
    pub async fn set_config(&self, config: ScanConfig) {
        *self.config.write().await = config;
    }

    /// Get local subnets to scan
    fn get_local_subnets() -> Vec<Ipv4Network> {
        datalink::interfaces()
            .into_iter()
            .filter(|iface| iface.is_up() && !iface.is_loopback())
            .flat_map(|iface| {
                iface.ips.into_iter().filter_map(|ip| {
                    if let IpAddr::V4(ipv4) = ip.ip() {
                        // Create a /24 network from the IP
                        let prefix = ip.prefix();
                        Ipv4Network::new(ipv4, prefix).ok()
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    /// Start a manual scan
    pub async fn start_scan(&self, scan_types: Vec<ScanType>) -> Result<(), String> {
        // Check if already running
        {
            let status = self.status.read().await;
            if status.running {
                return Err("Scan already in progress".to_string());
            }
        }

        // Reset stop signal
        *self.stop_signal.write().await = false;

        // Update status
        {
            let mut status = self.status.write().await;
            status.running = true;
            status.scan_types = scan_types.clone();
            status.progress_percent = 0;
            status.discovered_count = 0;
            status.current_phase = Some("Starting".to_string());
        }

        let status = self.status.clone();
        let config = self.config.clone();
        let result_tx = self.result_tx.clone();
        let stop_signal = self.stop_signal.clone();

        // Spawn the scan task
        tokio::spawn(async move {
            let cfg = config.read().await.clone();
            let subnets = Self::get_local_subnets();
            let capabilities = check_scan_privileges();

            let total_phases: usize = scan_types.len();
            let mut completed_phases: usize = 0;
            let mut discovered_ips: HashSet<IpAddr> = HashSet::new();

            for scan_type in &scan_types {
                // Check stop signal
                if *stop_signal.read().await {
                    break;
                }

                // Update phase
                {
                    let mut s = status.write().await;
                    s.current_phase = Some(format!("{} scan", scan_type));
                }

                let results: Vec<ScanResult> = match scan_type {
                    ScanType::Arp if capabilities.can_arp => {
                        let mut all_results = Vec::new();
                        for subnet in &subnets {
                            if *stop_signal.read().await {
                                break;
                            }
                            let scanner = ArpScanner::new().with_timeout(cfg.timeout_ms);
                            let results = scanner.scan_subnet(*subnet).await;
                            all_results.extend(results.into_iter().map(ScanResult::Arp));
                        }
                        all_results
                    }
                    ScanType::Icmp if capabilities.can_icmp => {
                        let mut all_ips = Vec::new();
                        for subnet in &subnets {
                            all_ips.extend(subnet.iter().map(IpAddr::V4));
                        }
                        let scanner = IcmpScanner::new().with_timeout(cfg.timeout_ms);
                        scanner
                            .ping_sweep(all_ips)
                            .await
                            .into_iter()
                            .map(ScanResult::Icmp)
                            .collect()
                    }
                    ScanType::Port => {
                        // Port scan known IPs from previous scans
                        // For now, scan subnet
                        let mut all_ips = Vec::new();
                        for subnet in &subnets {
                            all_ips.extend(subnet.iter().map(IpAddr::V4));
                        }
                        let scanner = PortScanner::new().with_timeout(cfg.timeout_ms);
                        scanner
                            .scan_ips(&all_ips, &cfg.ports)
                            .await
                            .into_iter()
                            .map(ScanResult::Port)
                            .collect()
                    }
                    ScanType::Ndp if capabilities.can_ndp => {
                        let scanner = NdpScanner::new().with_timeout(cfg.timeout_ms);
                        scanner
                            .scan()
                            .await
                            .into_iter()
                            .map(ScanResult::Ndp)
                            .collect()
                    }
                    ScanType::Ssdp => {
                        let scanner = SsdpScanner::new();
                        scanner
                            .discover()
                            .await
                            .into_iter()
                            .map(ScanResult::Ssdp)
                            .collect()
                    }
                    ScanType::NetBios if capabilities.can_netbios => {
                        let mut all_ips = Vec::new();
                        for subnet in &subnets {
                            all_ips.extend(subnet.iter().map(IpAddr::V4));
                        }
                        let scanner = NetBiosScanner::new().with_timeout(cfg.timeout_ms);
                        scanner
                            .scan_ips(&all_ips)
                            .await
                            .into_iter()
                            .map(ScanResult::NetBios)
                            .collect()
                    }
                    ScanType::Snmp if capabilities.can_snmp => {
                        let mut all_ips = Vec::new();
                        for subnet in &subnets {
                            all_ips.extend(subnet.iter().map(IpAddr::V4));
                        }
                        let scanner = SnmpScanner::new().with_timeout(cfg.timeout_ms);
                        scanner
                            .scan_ips(&all_ips)
                            .await
                            .into_iter()
                            .map(ScanResult::Snmp)
                            .collect()
                    }
                    _ => Vec::new(), // Skip if no privilege
                };

                // Send results and track unique IPs
                for result in &results {
                    let _ = result_tx.send(result.clone()).await;
                    // Extract IP from result for unique device counting
                    let ip = match result {
                        ScanResult::Arp(r) => r.ip,
                        ScanResult::Icmp(r) => r.ip,
                        ScanResult::Ndp(r) => r.ip,
                        ScanResult::NetBios(r) => r.ip,
                        ScanResult::Port(r) => r.ip,
                        ScanResult::Snmp(r) => r.ip,
                        ScanResult::Ssdp(r) => r.ip,
                    };
                    discovered_ips.insert(ip);
                }

                completed_phases += 1;

                // Update progress (using saturating arithmetic to prevent overflow)
                {
                    let mut s = status.write().await;
                    let percent = completed_phases
                        .saturating_mul(100)
                        .checked_div(total_phases.max(1))
                        .unwrap_or(0)
                        .min(100);
                    s.progress_percent = percent as u8;
                    s.discovered_count = discovered_ips.len().min(u32::MAX as usize) as u32;
                }
            }

            // Mark as complete
            {
                let mut s = status.write().await;
                s.running = false;
                s.progress_percent = 100;
                s.last_scan_time = Some(chrono::Utc::now().timestamp());
                s.current_phase = None;
            }
        });

        Ok(())
    }

    /// Stop the current scan
    pub async fn stop_scan(&self) {
        *self.stop_signal.write().await = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_config_default() {
        let config = ScanConfig::default();

        // Check default values
        assert_eq!(config.scan_interval_secs, None);
        assert_eq!(config.timeout_ms, 1000);
        assert!(!config.ports.is_empty());

        // Check default enabled scanners
        assert!(config.enabled_scanners.contains(&ScanType::Arp));
        assert!(config.enabled_scanners.contains(&ScanType::Ssdp));
        assert!(!config.enabled_scanners.contains(&ScanType::Icmp));
        assert!(!config.enabled_scanners.contains(&ScanType::Port));
    }

    #[test]
    fn test_scan_config_default_ports() {
        let config = ScanConfig::default();

        // Should include common ports
        assert!(config.ports.contains(&22)); // SSH
        assert!(config.ports.contains(&80)); // HTTP
        assert!(config.ports.contains(&443)); // HTTPS
    }

    #[test]
    fn test_get_local_subnets() {
        let subnets = ScanManager::get_local_subnets();

        // Should return at least empty (depending on system config)
        // On most systems with network interfaces, there should be at least one
        // But we can't guarantee this in tests, so just verify it doesn't panic
        for subnet in &subnets {
            // Each subnet should have a valid prefix
            assert!(subnet.prefix() <= 32);
        }
    }

    #[test]
    fn test_scan_type_display() {
        assert_eq!(format!("{}", ScanType::Arp), "arp");
        assert_eq!(format!("{}", ScanType::Icmp), "icmp");
        assert_eq!(format!("{}", ScanType::Port), "port");
        assert_eq!(format!("{}", ScanType::Snmp), "snmp");
        assert_eq!(format!("{}", ScanType::Ssdp), "ssdp");
    }

    #[tokio::test]
    async fn test_scan_manager_initial_status() {
        let (tx, _rx) = mpsc::channel(100);
        let manager = ScanManager::new(tx);

        let status = manager.get_status().await;
        assert!(!status.running);
        assert_eq!(status.progress_percent, 0);
        assert_eq!(status.discovered_count, 0);
        assert!(status.scan_types.is_empty());
        assert!(status.current_phase.is_none());
        assert!(status.last_scan_time.is_none());
    }

    #[tokio::test]
    async fn test_scan_manager_config_roundtrip() {
        let (tx, _rx) = mpsc::channel(100);
        let manager = ScanManager::new(tx);

        // Get default config
        let default_config = manager.get_config().await;
        assert_eq!(default_config.timeout_ms, 1000);

        // Update config
        let mut new_config = default_config.clone();
        new_config.timeout_ms = 5000;
        new_config.scan_interval_secs = Some(300);
        manager.set_config(new_config).await;

        // Verify update
        let updated_config = manager.get_config().await;
        assert_eq!(updated_config.timeout_ms, 5000);
        assert_eq!(updated_config.scan_interval_secs, Some(300));
    }
}
