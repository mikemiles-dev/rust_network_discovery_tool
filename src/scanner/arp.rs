use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use ipnetwork::Ipv4Network;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::ArpResult;

/// ARP scanner for local subnet device discovery
pub struct ArpScanner {
    timeout_ms: u64,
    delay_ms: u64,
}

impl ArpScanner {
    pub fn new() -> Self {
        Self {
            timeout_ms: 1000,
            delay_ms: 10,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    #[allow(dead_code)]
    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.delay_ms = delay_ms;
        self
    }

    /// Get the best interface for scanning a target network
    fn find_interface_for_network(&self, network: &Ipv4Network) -> Option<NetworkInterface> {
        datalink::interfaces()
            .into_iter()
            .filter(|iface| iface.is_up() && !iface.is_loopback())
            .find(|iface| {
                iface.ips.iter().any(|ip| {
                    if let IpAddr::V4(ipv4) = ip.ip() {
                        network.contains(ipv4)
                    } else {
                        false
                    }
                })
            })
    }

    /// Get the source IP and MAC for an interface
    fn get_interface_info(iface: &NetworkInterface) -> Option<(Ipv4Addr, MacAddr)> {
        let mac = iface.mac?;
        let ip = iface.ips.iter().find_map(|ip| {
            if let IpAddr::V4(ipv4) = ip.ip() {
                Some(ipv4)
            } else {
                None
            }
        })?;
        Some((ip, mac))
    }

    /// Build an ARP request packet
    fn build_arp_request(
        src_mac: MacAddr,
        src_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> Option<Vec<u8>> {
        let mut ethernet_buffer = vec![0u8; 42]; // Ethernet header (14) + ARP packet (28)

        // Build Ethernet frame
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)?;
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(src_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        // Build ARP request
        let mut arp_buffer = vec![0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)?;
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(src_mac);
        arp_packet.set_sender_proto_addr(src_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        // Copy ARP packet into Ethernet payload
        ethernet_packet.set_payload(arp_packet.packet());

        Some(ethernet_buffer)
    }

    /// Scan a subnet for devices using ARP
    pub async fn scan_subnet(&self, network: Ipv4Network) -> Vec<ArpResult> {
        let interface = match self.find_interface_for_network(&network) {
            Some(iface) => iface,
            None => {
                eprintln!("No interface found for network {}", network);
                return Vec::new();
            }
        };

        let (src_ip, src_mac) = match Self::get_interface_info(&interface) {
            Some(info) => info,
            None => {
                eprintln!("Could not get interface info");
                return Vec::new();
            }
        };

        // Create channel
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                eprintln!("Unknown channel type");
                return Vec::new();
            }
            Err(e) => {
                eprintln!("Failed to create datalink channel: {}", e);
                return Vec::new();
            }
        };

        let (result_tx, mut result_rx) = mpsc::channel::<ArpResult>(256);
        let timeout_ms = self.timeout_ms;

        // Spawn receiver task
        let receiver_handle = tokio::task::spawn_blocking(move || {
            let start = Instant::now();
            let timeout_duration = Duration::from_millis(timeout_ms);

            while start.elapsed() < timeout_duration {
                match rx.next() {
                    Ok(packet) => {
                        if let Some(ethernet) = EthernetPacket::new(packet)
                            && ethernet.get_ethertype() == EtherTypes::Arp
                            && let Some(arp) = ArpPacket::new(ethernet.payload())
                            && arp.get_operation() == ArpOperations::Reply
                        {
                            let ip = IpAddr::V4(arp.get_sender_proto_addr());
                            let mac = arp.get_sender_hw_addr();
                            let response_time_ms = start.elapsed().as_millis() as u64;

                            let _ = result_tx.blocking_send(ArpResult {
                                ip,
                                mac,
                                response_time_ms,
                            });
                        }
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        });

        // Send ARP requests
        let delay = Duration::from_millis(self.delay_ms);
        for ip in network.iter() {
            // Skip network and broadcast addresses
            if ip == network.network() || ip == network.broadcast() {
                continue;
            }
            // Skip our own IP
            if ip == src_ip {
                continue;
            }

            if let Some(packet) = Self::build_arp_request(src_mac, src_ip, ip) {
                let _ = tx.send_to(&packet, None);
            }

            tokio::time::sleep(delay).await;
        }

        // Wait for receiver to finish
        let _ = timeout(Duration::from_millis(self.timeout_ms), receiver_handle).await;

        // Collect results
        let mut results = Vec::new();
        while let Ok(result) = result_rx.try_recv() {
            results.push(result);
        }

        // Deduplicate
        results.sort_by(|a, b| a.ip.cmp(&b.ip));
        results.dedup_by(|a, b| a.ip == b.ip);

        results
    }
}

impl Default for ArpScanner {
    fn default() -> Self {
        Self::new()
    }
}
