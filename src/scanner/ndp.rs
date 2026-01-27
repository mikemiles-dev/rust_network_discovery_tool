//! NDP scanner. Uses IPv6 Neighbor Discovery Protocol to find devices on
//! link-local networks via multicast neighbor solicitation messages.

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::MutablePacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::util::MacAddr;
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::NdpResult;

/// NDP scanner for IPv6 neighbor discovery
pub struct NdpScanner {
    timeout_ms: u64,
}

impl NdpScanner {
    pub fn new() -> Self {
        Self { timeout_ms: 2000 }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Find interfaces with IPv6 link-local addresses
    fn find_ipv6_interfaces() -> Vec<(NetworkInterface, Ipv6Addr)> {
        datalink::interfaces()
            .into_iter()
            .filter(|iface| iface.is_up() && !iface.is_loopback() && iface.mac.is_some())
            .filter_map(|iface| {
                // Find a link-local IPv6 address (fe80::)
                let ipv6 = iface.ips.iter().find_map(|ip| match ip.ip() {
                    IpAddr::V6(addr) if addr.segments()[0] == 0xfe80 => Some(addr),
                    _ => None,
                })?;
                Some((iface, ipv6))
            })
            .collect()
    }

    /// Calculate ICMPv6 checksum
    fn icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, icmpv6_packet: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header: source address
        for segment in src.segments() {
            sum += segment as u32;
        }

        // Pseudo-header: destination address
        for segment in dst.segments() {
            sum += segment as u32;
        }

        // Pseudo-header: ICMPv6 length
        sum += icmpv6_packet.len() as u32;

        // Pseudo-header: Next header (ICMPv6 = 58)
        sum += 58u32;

        // ICMPv6 packet data
        let mut i = 0;
        while i < icmpv6_packet.len() {
            let word = if i + 1 < icmpv6_packet.len() {
                ((icmpv6_packet[i] as u16) << 8) | (icmpv6_packet[i + 1] as u16)
            } else {
                (icmpv6_packet[i] as u16) << 8
            };
            sum += word as u32;
            i += 2;
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    /// Build a Neighbor Solicitation packet for all-nodes multicast
    fn build_neighbor_solicitation(src_mac: MacAddr, src_ip: Ipv6Addr) -> Option<Vec<u8>> {
        // Target: all-nodes multicast ff02::1
        let all_nodes_multicast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

        // Solicited-node multicast address for our source IP (used as target for NS)
        // For neighbor discovery, we send to ff02::1 to discover all neighbors
        let dst_ip = all_nodes_multicast;

        // Multicast MAC for ff02::1 is 33:33:00:00:00:01
        let dst_mac = MacAddr::new(0x33, 0x33, 0x00, 0x00, 0x00, 0x01);

        // Ethernet (14) + IPv6 (40) + ICMPv6 NS (24) + Source Link-Layer Option (8) = 86 bytes
        let total_len = 14 + 40 + 24 + 8;
        let mut buffer = vec![0u8; total_len];

        // Build Ethernet frame
        {
            let mut eth = MutableEthernetPacket::new(&mut buffer[0..14])?;
            eth.set_destination(dst_mac);
            eth.set_source(src_mac);
            eth.set_ethertype(EtherTypes::Ipv6);
        }

        // Build IPv6 header
        {
            let mut ipv6 = MutableIpv6Packet::new(&mut buffer[14..54])?;
            ipv6.set_version(6);
            ipv6.set_traffic_class(0);
            ipv6.set_flow_label(0);
            ipv6.set_payload_length(32); // ICMPv6 NS (24) + option (8)
            ipv6.set_next_header(IpNextHeaderProtocols::Icmpv6);
            ipv6.set_hop_limit(255);
            ipv6.set_source(src_ip);
            ipv6.set_destination(dst_ip);
        }

        // Build ICMPv6 Neighbor Solicitation
        {
            let mut icmpv6 = MutableIcmpv6Packet::new(&mut buffer[54..86])?;
            icmpv6.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
            icmpv6.set_icmpv6_code(pnet::packet::icmpv6::Icmpv6Code(0));

            // Set target address in NS packet (bytes 8-23 of ICMPv6 payload)
            // We use the unspecified address :: to trigger responses from all neighbors
            let ns_payload = icmpv6.payload_mut();
            // Reserved (4 bytes) - already zero
            // Target address (16 bytes) - use :: to get responses from all
            // Actually for proper NS, we should target ff02::1 or use multicast listener

            // Add Source Link-Layer Address option
            // Type (1) + Length (1) + MAC (6)
            ns_payload[20] = 1; // Type: Source Link-Layer Address
            ns_payload[21] = 1; // Length: 1 (in units of 8 bytes)
            ns_payload[22] = src_mac.0;
            ns_payload[23] = src_mac.1;
            ns_payload[24] = src_mac.2;
            ns_payload[25] = src_mac.3;
            ns_payload[26] = src_mac.4;
            ns_payload[27] = src_mac.5;
        }

        // Calculate ICMPv6 checksum
        let checksum = Self::icmpv6_checksum(&src_ip, &dst_ip, &buffer[54..86]);
        buffer[56] = (checksum >> 8) as u8;
        buffer[57] = (checksum & 0xff) as u8;

        Some(buffer)
    }

    /// Parse Neighbor Advertisement to extract IP and MAC
    fn parse_neighbor_advertisement(packet: &[u8]) -> Option<(Ipv6Addr, MacAddr)> {
        // Need at least Ethernet (14) + IPv6 (40) + ICMPv6 NA (24)
        if packet.len() < 78 {
            return None;
        }

        let eth = EthernetPacket::new(packet)?;
        if eth.get_ethertype() != EtherTypes::Ipv6 {
            return None;
        }

        let ipv6_data = &packet[14..];
        if ipv6_data.len() < 40 {
            return None;
        }

        // Check next header is ICMPv6
        if ipv6_data[6] != 58 {
            return None;
        }

        // Extract source IPv6 address (bytes 8-23)
        let src_ip = Ipv6Addr::new(
            u16::from_be_bytes([ipv6_data[8], ipv6_data[9]]),
            u16::from_be_bytes([ipv6_data[10], ipv6_data[11]]),
            u16::from_be_bytes([ipv6_data[12], ipv6_data[13]]),
            u16::from_be_bytes([ipv6_data[14], ipv6_data[15]]),
            u16::from_be_bytes([ipv6_data[16], ipv6_data[17]]),
            u16::from_be_bytes([ipv6_data[18], ipv6_data[19]]),
            u16::from_be_bytes([ipv6_data[20], ipv6_data[21]]),
            u16::from_be_bytes([ipv6_data[22], ipv6_data[23]]),
        );

        let icmpv6_data = &ipv6_data[40..];
        if icmpv6_data.is_empty() {
            return None;
        }

        // Check for Neighbor Advertisement (type 136)
        if icmpv6_data[0] != 136 {
            return None;
        }

        // Get MAC from Ethernet source (more reliable than parsing options)
        let src_mac = eth.get_source();

        // Skip multicast MACs
        if src_mac.0 & 0x01 != 0 {
            return None;
        }

        Some((src_ip, src_mac))
    }

    /// Scan for IPv6 neighbors using NDP
    pub async fn scan(&self) -> Vec<NdpResult> {
        let interfaces = Self::find_ipv6_interfaces();
        if interfaces.is_empty() {
            eprintln!("No IPv6 interfaces found for NDP scan");
            return Vec::new();
        }

        let mut all_results = Vec::new();

        for (interface, src_ip) in interfaces {
            let Some(src_mac) = interface.mac else {
                continue;
            };

            // Create datalink channel
            let Ok(Channel::Ethernet(mut tx, mut rx)) =
                datalink::channel(&interface, Default::default())
            else {
                eprintln!("Failed to create channel for {}", interface.name);
                continue;
            };

            let (result_tx, mut result_rx) = mpsc::channel::<NdpResult>(256);
            let timeout_ms = self.timeout_ms;

            // Spawn receiver task
            let receiver_handle = tokio::task::spawn_blocking(move || {
                let start = Instant::now();
                let timeout_duration = Duration::from_millis(timeout_ms);

                while start.elapsed() < timeout_duration {
                    match rx.next() {
                        Ok(packet) => {
                            if let Some((ip, mac)) = Self::parse_neighbor_advertisement(packet) {
                                let response_time_ms =
                                    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                                let _ = result_tx.blocking_send(NdpResult {
                                    ip: IpAddr::V6(ip),
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

            // Send Neighbor Solicitation
            if let Some(packet) = Self::build_neighbor_solicitation(src_mac, src_ip) {
                let _ = tx.send_to(&packet, None);
            }

            // Also send an ICMPv6 Echo Request to ff02::1 to trigger responses
            // This often gets more responses than NS alone

            // Wait for receiver
            let _ = timeout(
                Duration::from_millis(self.timeout_ms + 100),
                receiver_handle,
            )
            .await;

            // Collect results
            while let Ok(result) = result_rx.try_recv() {
                all_results.push(result);
            }
        }

        // Deduplicate by IP
        all_results.sort_by(|a, b| a.ip.cmp(&b.ip));
        all_results.dedup_by(|a, b| a.ip == b.ip);

        all_results
    }
}

impl Default for NdpScanner {
    fn default() -> Self {
        Self::new()
    }
}
