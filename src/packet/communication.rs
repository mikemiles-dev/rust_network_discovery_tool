use pnet::util::MacAddr;

use pnet::packet::ethernet::EthernetPacket;

use crate::packet::PacketWrapper;

#[derive(Default, Debug)]
pub struct Communication {
    pub interface: String,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub ip_version: Option<u8>,
    pub ip_header_protocol: Option<String>,
    pub sub_protocol: Option<String>,
}

impl Communication {
    pub fn set_source_and_dest_mac(&mut self, source_mac: MacAddr, dest_mac: MacAddr) {
        self.source_mac = Some(source_mac.to_string());
        self.destination_mac = Some(dest_mac.to_string());
    }
}

impl From<EthernetPacket<'_>> for Communication {
    fn from(ethernet_packet: EthernetPacket<'_>) -> Self {
        let packet_wrapper = &PacketWrapper::new(&ethernet_packet);
        let mut communication: Communication = packet_wrapper.into();
        communication.set_source_and_dest_mac(
            ethernet_packet.get_source(),
            ethernet_packet.get_destination(),
        );
        communication
    }
}
