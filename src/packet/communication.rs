use pnet::packet::ethernet::EthernetPacket;
use pnet::util::MacAddr;
use rusqlite::{Connection, Result, params};

use crate::packet::PacketWrapper;
use crate::writer::SQLWriter;

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

    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS communications (
                id INTEGER PRIMARY KEY,
                interface TEXT,
                created_at INTEGER NOT NULL,
                source_mac TEXT,
                destination_mac TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                ip_version INTEGER,
                ip_header_protocol TEXT,
                sub_protocol TEXT
            )",
            [],
        )?;
        Ok(())
    }

    pub fn insert_communication(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO communications (
                interface,
                created_at,
                source_mac,
                destination_mac,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                ip_version,
                ip_header_protocol,
                sub_protocol
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                self.interface,
                chrono::Utc::now().timestamp(),
                self.source_mac,
                self.destination_mac,
                self.source_ip,
                self.destination_ip,
                self.source_port,
                self.destination_port,
                self.ip_version,
                self.ip_header_protocol,
                self.sub_protocol
            ],
        )?;
        Ok(())
    }

    pub fn write(self, writer: SQLWriter) {
        let sender = writer.sender.clone();
        tokio::spawn(async move {
            if let Err(e) = sender.send(self).await {
                eprintln!("Failed to send communication to SQL writer: {}", e);
            }
        });
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
