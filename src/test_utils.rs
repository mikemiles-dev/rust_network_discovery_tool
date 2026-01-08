use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, checksum};
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

/// Builder for creating synthetic Ethernet packets for testing
pub struct PacketBuilder;

impl PacketBuilder {
    /// Create a basic TCP packet
    pub fn tcp_packet(
        src_mac: &str,
        dst_mac: &str,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut buffer = vec![0u8; 66]; // Ethernet(14) + IPv4(20) + TCP(20) + some data(12)

        // Ethernet header
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_packet.set_source(src_mac.parse::<MacAddr>().unwrap());
        eth_packet.set_destination(dst_mac.parse::<MacAddr>().unwrap());
        eth_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);

        // IPv4 header
        let mut ip_packet = MutableIpv4Packet::new(&mut buffer[14..]).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5); // 5 * 4 = 20 bytes
        ip_packet.set_total_length(52); // 20 (IP) + 20 (TCP) + 12 (data)
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(src_ip.parse::<Ipv4Addr>().unwrap());
        ip_packet.set_destination(dst_ip.parse::<Ipv4Addr>().unwrap());
        let checksum = checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(checksum);

        // TCP header
        let mut tcp_packet = MutableTcpPacket::new(&mut buffer[34..]).unwrap();
        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_sequence(1000);
        tcp_packet.set_data_offset(5); // 5 * 4 = 20 bytes
        tcp_packet.set_flags(0x02); // SYN flag

        // Add some dummy data
        buffer[54..66].copy_from_slice(b"test_payload");

        buffer
    }

    /// Create a basic UDP packet
    pub fn udp_packet(
        src_mac: &str,
        dst_mac: &str,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut buffer = vec![0u8; 50]; // Ethernet(14) + IPv4(20) + UDP(8) + data(8)

        // Ethernet header
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        eth_packet.set_source(src_mac.parse::<MacAddr>().unwrap());
        eth_packet.set_destination(dst_mac.parse::<MacAddr>().unwrap());
        eth_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);

        // IPv4 header
        let mut ip_packet = MutableIpv4Packet::new(&mut buffer[14..]).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(36); // 20 (IP) + 8 (UDP) + 8 (data)
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_packet.set_source(src_ip.parse::<Ipv4Addr>().unwrap());
        ip_packet.set_destination(dst_ip.parse::<Ipv4Addr>().unwrap());
        let checksum = checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(checksum);

        // UDP header
        let mut udp_packet = MutableUdpPacket::new(&mut buffer[34..]).unwrap();
        udp_packet.set_source(src_port);
        udp_packet.set_destination(dst_port);
        udp_packet.set_length(16); // 8 (UDP header) + 8 (data)

        // Add some dummy data
        buffer[42..50].copy_from_slice(b"udp_data");

        buffer
    }

    /// Create HTTPS packet (TCP port 443)
    pub fn https_packet(src_ip: &str, dst_ip: &str) -> Vec<u8> {
        Self::tcp_packet(
            "00:11:22:33:44:55",
            "aa:bb:cc:dd:ee:ff",
            src_ip,
            dst_ip,
            54321,
            443,
        )
    }

    /// Create HTTP packet (TCP port 80)
    pub fn http_packet(src_ip: &str, dst_ip: &str) -> Vec<u8> {
        Self::tcp_packet(
            "00:11:22:33:44:55",
            "aa:bb:cc:dd:ee:ff",
            src_ip,
            dst_ip,
            54322,
            80,
        )
    }

    /// Create DNS packet (UDP port 53)
    pub fn dns_packet(src_ip: &str, dst_ip: &str) -> Vec<u8> {
        Self::udp_packet(
            "00:11:22:33:44:55",
            "aa:bb:cc:dd:ee:ff",
            src_ip,
            dst_ip,
            54323,
            53,
        )
    }
}

/// Generate a synthetic pcap file for testing
pub fn create_test_pcap(packets: Vec<Vec<u8>>) -> std::io::Result<tempfile::NamedTempFile> {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

    let temp_file = tempfile::NamedTempFile::new()?;
    let file = temp_file.reopen()?;

    let mut pcap_writer = PcapWriter::with_header(
        file,
        PcapHeader {
            datalink: pcap_file::DataLink::ETHERNET,
            ..Default::default()
        },
    )
    .map_err(|e| std::io::Error::other(format!("Pcap write error: {}", e)))?;

    // Write packets
    for (i, packet_data) in packets.iter().enumerate() {
        let packet = PcapPacket {
            timestamp: std::time::Duration::from_secs(1700000000 + i as u64), // Synthetic timestamp
            orig_len: packet_data.len() as u32,
            data: std::borrow::Cow::Borrowed(packet_data),
        };
        pcap_writer
            .write_packet(&packet)
            .map_err(|e| std::io::Error::other(format!("Packet write error: {}", e)))?;
    }

    Ok(temp_file)
}

mod tests {
    use super::*;

    #[test]
    fn test_tcp_packet_creation() {
        let packet = PacketBuilder::tcp_packet(
            "00:11:22:33:44:55",
            "aa:bb:cc:dd:ee:ff",
            "192.168.1.100",
            "8.8.8.8",
            12345,
            443,
        );

        let eth = EthernetPacket::new(&packet).unwrap();
        assert_eq!(eth.get_source().to_string(), "00:11:22:33:44:55");
        assert_eq!(eth.get_destination().to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_udp_packet_creation() {
        let packet = PacketBuilder::udp_packet(
            "00:11:22:33:44:55",
            "aa:bb:cc:dd:ee:ff",
            "192.168.1.100",
            "8.8.8.8",
            54321,
            53,
        );

        let eth = EthernetPacket::new(&packet).unwrap();
        assert_eq!(eth.get_source().to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_pcap_creation() {
        let packets = vec![
            PacketBuilder::https_packet("192.168.1.100", "1.1.1.1"),
            PacketBuilder::http_packet("192.168.1.100", "8.8.8.8"),
            PacketBuilder::dns_packet("192.168.1.100", "8.8.4.4"),
        ];

        let pcap_file = create_test_pcap(packets).unwrap();
        assert!(pcap_file.path().exists());
    }
}
