pub mod arp;
pub mod icmp;
pub mod manager;
pub mod ndp;
pub mod port;
pub mod ssdp;

use std::net::IpAddr;

use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};

/// Types of scanners available
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    Arp,
    Icmp,
    Ndp,
    Port,
    Ssdp,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Arp => write!(f, "arp"),
            ScanType::Icmp => write!(f, "icmp"),
            ScanType::Ndp => write!(f, "ndp"),
            ScanType::Port => write!(f, "port"),
            ScanType::Ssdp => write!(f, "ssdp"),
        }
    }
}

/// Result from any scanner
#[derive(Debug, Clone)]
pub enum ScanResult {
    Arp(ArpResult),
    Icmp(IcmpResult),
    Ndp(NdpResult),
    Port(PortResult),
    Ssdp(SsdpResult),
}

/// ARP scan result
#[derive(Debug, Clone)]
pub struct ArpResult {
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub response_time_ms: u64,
}

/// NDP (IPv6 Neighbor Discovery) scan result
#[derive(Debug, Clone)]
pub struct NdpResult {
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub response_time_ms: u64,
}

/// ICMP ping result
#[derive(Debug, Clone)]
pub struct IcmpResult {
    pub ip: IpAddr,
    pub alive: bool,
    pub rtt_ms: Option<u64>,
    pub ttl: Option<u8>,
}

/// Port scan result
#[derive(Debug, Clone)]
pub struct PortResult {
    pub ip: IpAddr,
    pub port: u16,
    pub open: bool,
    pub service_name: Option<String>,
}

/// SSDP/UPnP discovery result
#[derive(Debug, Clone)]
pub struct SsdpResult {
    pub ip: IpAddr,
    pub location: String,
    pub server: Option<String>,
    pub device_type: Option<String>,
    #[allow(dead_code)]
    pub friendly_name: Option<String>,
}

/// Scan capabilities based on privileges
#[derive(Debug, Clone, Serialize)]
pub struct ScanCapabilities {
    pub can_arp: bool,
    pub can_icmp: bool,
    pub can_ndp: bool,
    pub can_port: bool,
    pub can_ssdp: bool,
}

/// Check what scan types are available based on privileges
pub fn check_scan_privileges() -> ScanCapabilities {
    let can_raw_socket = check_raw_socket_access();

    ScanCapabilities {
        can_arp: can_raw_socket,
        can_icmp: can_raw_socket,
        can_ndp: can_raw_socket, // NDP also requires raw sockets
        can_port: true,          // TCP connect always works
        can_ssdp: true,          // UDP multicast always works
    }
}

/// Check if we have raw socket access (needed for ARP and ICMP)
fn check_raw_socket_access() -> bool {
    // Try to create a raw socket to test privileges
    use socket2::{Domain, Protocol, Socket, Type};
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
}
