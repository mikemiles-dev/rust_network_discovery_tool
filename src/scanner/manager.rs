//! Scan orchestration. Manages concurrent scanner execution with configurable scan types,
//! timeout settings, progress tracking, and stop signaling.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use ipnetwork::Ipv4Network;
use pnet::datalink;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinSet;

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

            // Filter to only scan types that can actually run
            let runnable_types: Vec<ScanType> = scan_types
                .into_iter()
                .filter(|t| match t {
                    ScanType::Arp => capabilities.can_arp,
                    ScanType::Icmp => capabilities.can_icmp,
                    ScanType::Ndp => capabilities.can_ndp,
                    ScanType::NetBios => capabilities.can_netbios,
                    ScanType::Snmp => capabilities.can_snmp,
                    ScanType::Port | ScanType::Ssdp => true,
                })
                .collect();

            let total_phases = runnable_types.len().max(1);
            let completed_phases = Arc::new(AtomicU8::new(0));
            let discovered_ips = Arc::new(Mutex::new(HashSet::<IpAddr>::new()));

            // Show all active scan types
            {
                let phase_names: Vec<String> =
                    runnable_types.iter().map(|t| t.to_string()).collect();
                let mut s = status.write().await;
                s.current_phase = Some(format!("{} scan", phase_names.join(", ")));
            }

            let mut join_set = JoinSet::new();

            for scan_type in runnable_types {
                // Check stop signal before spawning each phase
                if *stop_signal.read().await {
                    break;
                }

                let result_tx = result_tx.clone();
                let cfg = cfg.clone();
                let subnets = subnets.clone();
                let status = status.clone();
                let completed_phases = completed_phases.clone();
                let discovered_ips = discovered_ips.clone();

                join_set.spawn(async move {
                    let results: Vec<ScanResult> = match scan_type {
                        ScanType::Arp => {
                            // Scan all subnets concurrently
                            let mut subnet_set = JoinSet::new();
                            for subnet in &subnets {
                                let timeout_ms = cfg.timeout_ms;
                                let subnet = *subnet;
                                subnet_set.spawn(async move {
                                    let scanner = ArpScanner::new().with_timeout(timeout_ms);
                                    scanner
                                        .scan_subnet(subnet)
                                        .await
                                        .into_iter()
                                        .map(ScanResult::Arp)
                                        .collect::<Vec<_>>()
                                });
                            }
                            let mut all_results = Vec::new();
                            while let Some(Ok(results)) = subnet_set.join_next().await {
                                all_results.extend(results);
                            }
                            all_results
                        }
                        ScanType::Icmp => {
                            let all_ips: Vec<IpAddr> = subnets
                                .iter()
                                .flat_map(|s| s.iter().map(IpAddr::V4))
                                .collect();
                            let scanner = IcmpScanner::new().with_timeout(cfg.timeout_ms);
                            scanner
                                .ping_sweep(all_ips)
                                .await
                                .into_iter()
                                .map(ScanResult::Icmp)
                                .collect()
                        }
                        ScanType::Port => {
                            let all_ips: Vec<IpAddr> = subnets
                                .iter()
                                .flat_map(|s| s.iter().map(IpAddr::V4))
                                .collect();
                            let scanner = PortScanner::new().with_timeout(cfg.timeout_ms);
                            scanner
                                .scan_ips(&all_ips, &cfg.ports)
                                .await
                                .into_iter()
                                .map(ScanResult::Port)
                                .collect()
                        }
                        ScanType::Ndp => {
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
                        ScanType::NetBios => {
                            let all_ips: Vec<IpAddr> = subnets
                                .iter()
                                .flat_map(|s| s.iter().map(IpAddr::V4))
                                .collect();
                            let scanner = NetBiosScanner::new().with_timeout(cfg.timeout_ms);
                            scanner
                                .scan_ips(&all_ips)
                                .await
                                .into_iter()
                                .map(ScanResult::NetBios)
                                .collect()
                        }
                        ScanType::Snmp => {
                            let all_ips: Vec<IpAddr> = subnets
                                .iter()
                                .flat_map(|s| s.iter().map(IpAddr::V4))
                                .collect();
                            let scanner = SnmpScanner::new().with_timeout(cfg.timeout_ms);
                            scanner
                                .scan_ips(&all_ips)
                                .await
                                .into_iter()
                                .map(ScanResult::Snmp)
                                .collect()
                        }
                    };

                    // Send results and track unique IPs
                    for result in &results {
                        let _ = result_tx.send(result.clone()).await;
                        let ip = match result {
                            ScanResult::Arp(r) => r.ip,
                            ScanResult::Icmp(r) => r.ip,
                            ScanResult::Ndp(r) => r.ip,
                            ScanResult::NetBios(r) => r.ip,
                            ScanResult::Port(r) => r.ip,
                            ScanResult::Snmp(r) => r.ip,
                            ScanResult::Ssdp(r) => r.ip,
                        };
                        discovered_ips.lock().unwrap().insert(ip);
                    }

                    // Update progress
                    let completed = completed_phases.fetch_add(1, Ordering::Relaxed) + 1;
                    {
                        let mut s = status.write().await;
                        let percent = (completed as usize)
                            .saturating_mul(100)
                            .checked_div(total_phases)
                            .unwrap_or(0)
                            .min(100);
                        s.progress_percent = percent as u8;
                        s.discovered_count =
                            discovered_ips.lock().unwrap().len().min(u32::MAX as usize) as u32;
                    }
                });
            }

            // Wait for all phases to complete
            while join_set.join_next().await.is_some() {}

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
