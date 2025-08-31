use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::{Packet, ip};

use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4, Ipv4Packet};
use pnet::packet::ipv6::{Ipv6, Ipv6Packet};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::env;

fn main() {
    let interface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };
    let mut communications = vec![];
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_packet: EthernetPacket<'_> = EthernetPacket::new(packet).unwrap();
                let communication: Communication = ethernet_packet.into();
                println!("Detected communication: {:?}", communication);
                communications.push(communication);
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                println!("An error occurred while reading: {}", e);
            }
        }
    }
}

impl From<EthernetPacket<'_>> for Communication {
    fn from(ethernet_packet: EthernetPacket<'_>) -> Self {
        let packet_wrapper = PacketWrapper::new(&ethernet_packet);
        let mut communication: Communication = packet_wrapper.into();
        communication.source_mac = Some(ethernet_packet.get_source().to_string());
        communication.destination_mac = Some(ethernet_packet.get_destination().to_string());
        communication
    }
}

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
            //_ => PacketWrapper::Ethernet(packet),
            _ => PacketWrapper::Unknown,
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
                    if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                        Some(tcp_packet.get_source())
                    } else {
                        None
                    }
                }
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_packet) = UdpPacket::new(packet.payload()) {
                        Some(udp_packet.get_source())
                    } else {
                        None
                    }
                }
                _ => None,
            },
            PacketWrapper::Ipv6(packet) => match packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                        Some(tcp_packet.get_source())
                    } else {
                        None
                    }
                }
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_packet) = UdpPacket::new(packet.payload()) {
                        Some(udp_packet.get_source())
                    } else {
                        None
                    }
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
                    if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                        Some(tcp_packet.get_destination())
                    } else {
                        None
                    }
                }
                proto if proto == IpNextHeaderProtocols::Udp => {
                    if let Some(udp_packet) = UdpPacket::new(packet.payload()) {
                        Some(udp_packet.get_destination())
                    } else {
                        None
                    }
                }
                _ => None,
            },
            PacketWrapper::Ipv6(packet) => match packet.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                        Some(tcp_packet.get_destination())
                    } else {
                        None
                    }
                }
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_packet) = UdpPacket::new(packet.payload()) {
                        Some(udp_packet.get_destination())
                    } else {
                        None
                    }
                }
                _ => None,
            },
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

impl From<PacketWrapper<'_>> for Communication {
    fn from(packet_wrapper: PacketWrapper) -> Self {
        let mut communication = Communication::default();

        communication.source_ip = packet_wrapper.get_source_ip();
        communication.destination_ip = packet_wrapper.get_destination_ip();
        communication.source_port = packet_wrapper.get_source_port();
        communication.destination_port = packet_wrapper.get_destination_port();
        communication.ip_version = packet_wrapper.get_ip_version();
        communication.ip_header_protocol = packet_wrapper.get_header_protocol();
        if communication.ip_header_protocol == Some("Tcp".to_string())
            || communication.ip_header_protocol == Some("Udp".to_string())
        {
            communication.sub_protocol =
                Some(packet_wrapper.get_sub_protocol(communication.destination_port.unwrap_or(0)));
        }

        communication
    }
}

#[derive(Default, Debug)]
struct Communication {
    source_mac: Option<String>,
    destination_mac: Option<String>,
    source_ip: Option<String>,
    destination_ip: Option<String>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    ip_version: Option<u8>,
    ip_header_protocol: Option<String>,
    sub_protocol: Option<String>,
}

#[derive(Debug, FromPrimitive)]
enum ProtocolPort {
    // Web protocols
    HTTP = 80,
    HTTPS = 443,
    // File transfer
    FTP = 21,
    FTPS = 990,
    // Email
    SMTP = 25,
    POP3 = 110,
    IMAP = 143,
    // Domain and network services
    DNS = 53,
    DhcpServer = 67,
    DhcpClient = 68,
    NTP = 123,
    // Remote access
    SSH = 22,
    Telnet = 23,
    RDP = 3389,
    // Windows networking
    SMB = 445,
    NetbiosNameService = 137,
    NetbiosDatagramService = 138,
    NetbiosSessionService = 139,
}

impl std::fmt::Display for ProtocolPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolPort::HTTP => write!(f, "HTTP"),
            ProtocolPort::HTTPS => write!(f, "HTTPS"),
            ProtocolPort::FTP => write!(f, "FTP"),
            ProtocolPort::FTPS => write!(f, "FTPS"),
            ProtocolPort::SMTP => write!(f, "SMTP"),
            ProtocolPort::POP3 => write!(f, "POP3"),
            ProtocolPort::IMAP => write!(f, "IMAP"),
            ProtocolPort::DNS => write!(f, "DNS"),
            ProtocolPort::DhcpServer => write!(f, "DHCP Server"),
            ProtocolPort::DhcpClient => write!(f, "DHCP Client"),
            ProtocolPort::NTP => write!(f, "NTP"),
            ProtocolPort::SSH => write!(f, "SSH"),
            ProtocolPort::Telnet => write!(f, "Telnet"),
            ProtocolPort::RDP => write!(f, "RDP"),
            ProtocolPort::SMB => write!(f, "SMB"),
            ProtocolPort::NetbiosNameService => write!(f, "NetBIOS Name Service"),
            ProtocolPort::NetbiosDatagramService => write!(f, "NetBIOS Datagram Service"),
            ProtocolPort::NetbiosSessionService => write!(f, "NetBIOS Session Service"),
        }
    }
}
