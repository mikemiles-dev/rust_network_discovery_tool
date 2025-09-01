pub mod communication;
pub mod protocol;

use num_traits::FromPrimitive;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use crate::packet::communication::Communication;
use crate::packet::protocol::ProtocolPort;

#[derive(Debug)]
enum PacketWrapper<'a> {
    Ipv4(Ipv4Packet<'a>),
    Ipv6(Ipv6Packet<'a>),
    Ethernet(EthernetPacket<'a>),
    Unknown,
}

impl<'a> PacketWrapper<'a> {
    fn new(packet: &'a EthernetPacket<'a>) -> PacketWrapper<'a> {
        match packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4_packet) = Ipv4Packet::new(packet.payload()) {
                    PacketWrapper::Ipv4(ipv4_packet)
                } else {
                    PacketWrapper::Unknown
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6_packet) = Ipv6Packet::new(packet.payload()) {
                    PacketWrapper::Ipv6(ipv6_packet)
                } else {
                    PacketWrapper::Unknown
                }
            }
            _ => PacketWrapper::Ethernet(EthernetPacket::new(packet.packet()).unwrap()),
        }
    }

    fn get_source_ip(&self) -> Option<String> {
        match self {
            PacketWrapper::Ipv4(packet) => Some(packet.get_source().to_string()),
            PacketWrapper::Ipv6(packet) => Some(packet.get_source().to_string()),
            PacketWrapper::Ethernet(packet) => Some(packet.get_source().to_string()),
            PacketWrapper::Unknown => None,
        }
    }

    fn get_destination_ip(&self) -> Option<String> {
        match self {
            PacketWrapper::Ipv4(packet) => Some(packet.get_destination().to_string()),
            PacketWrapper::Ipv6(packet) => Some(packet.get_destination().to_string()),
            PacketWrapper::Ethernet(packet) => Some(packet.get_destination().to_string()),
            PacketWrapper::Unknown => None,
        }
    }

    fn get_source_port(&self) -> Option<u16> {
        match self {
            PacketWrapper::Ipv4(packet) => match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    TcpPacket::new(packet.payload()).map(|tcp_packet| tcp_packet.get_source())
                }
                IpNextHeaderProtocols::Udp => {
                    UdpPacket::new(packet.payload()).map(|udp_packet| udp_packet.get_source())
                }
                _ => None,
            },
            PacketWrapper::Ipv6(packet) => match packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    TcpPacket::new(packet.payload()).map(|tcp_packet| tcp_packet.get_source())
                }
                IpNextHeaderProtocols::Udp => {
                    UdpPacket::new(packet.payload()).map(|udp_packet| udp_packet.get_source())
                }
                _ => None,
            },
            PacketWrapper::Ethernet(_) => None,
            PacketWrapper::Unknown => None,
        }
    }

    fn get_destination_port(&self) -> Option<u16> {
        match self {
            PacketWrapper::Ipv4(packet) => match packet.get_next_level_protocol() {
                proto if proto == IpNextHeaderProtocols::Tcp => {
                    TcpPacket::new(packet.payload()).map(|tcp_packet| tcp_packet.get_destination())
                }
                proto if proto == IpNextHeaderProtocols::Udp => {
                    UdpPacket::new(packet.payload()).map(|udp_packet| udp_packet.get_destination())
                }
                _ => None,
            },
            PacketWrapper::Ipv6(packet) => {
                match packet.get_next_header() {
                    IpNextHeaderProtocols::Tcp => TcpPacket::new(packet.payload())
                        .map(|tcp_packet| tcp_packet.get_destination()),
                    IpNextHeaderProtocols::Udp => UdpPacket::new(packet.payload())
                        .map(|udp_packet| udp_packet.get_destination()),
                    _ => None,
                }
            }
            PacketWrapper::Ethernet(_) => None,
            PacketWrapper::Unknown => None,
        }
    }

    fn get_ip_version(&self) -> Option<u8> {
        match self {
            PacketWrapper::Ipv4(_) => Some(4),
            PacketWrapper::Ipv6(_) => Some(6),
            _ => None,
        }
    }

    fn get_header_protocol(&self) -> Option<String> {
        match self {
            PacketWrapper::Ipv4(packet) => Some(format!("{}", packet.get_next_level_protocol())),
            PacketWrapper::Ipv6(packet) => Some(format!("{}", packet.get_next_header())),
            PacketWrapper::Ethernet(packet) => Some(format!("{}", packet.get_ethertype())),
            _ => None,
        }
    }

    fn get_sub_protocol(&self, port: u16) -> String {
        if let Some(protocol_port) = ProtocolPort::from_u16(port) {
            format!("{}", protocol_port)
        } else {
            format!("Unknown ({})", port)
        }
    }
}

impl From<&PacketWrapper<'_>> for Communication {
    fn from(packet_wrapper: &PacketWrapper) -> Self {
        let mut communication = Communication {
            source_ip: packet_wrapper.get_source_ip(),
            destination_ip: packet_wrapper.get_destination_ip(),
            source_port: packet_wrapper.get_source_port(),
            destination_port: packet_wrapper.get_destination_port(),
            ip_version: packet_wrapper.get_ip_version(),
            ip_header_protocol: packet_wrapper.get_header_protocol(),
            sub_protocol: None,
            ..Default::default()
        };
        if communication.ip_header_protocol == Some("Tcp".to_string())
            || communication.ip_header_protocol == Some("Udp".to_string())
        {
            communication.sub_protocol =
                Some(packet_wrapper.get_sub_protocol(communication.destination_port.unwrap_or(0)));
        }

        communication
    }
}
