use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use rusqlite::{Connection, Result, params};

use crate::network::{
    endpoint::{EndPoint, InsertEndpointError},
    packet_wrapper::PacketWrapper,
};

#[derive(Default, Debug)]
pub struct Communication {
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub ip_version: Option<u8>,
    pub ip_header_protocol: Option<String>,
    pub sub_protocol: Option<String>,
    pub source: Option<String>, // Source of the capture (e.g., "live", "capture.pcap", or custom label)
    pub packet_size: u32,       // Size of the packet in bytes
    // Note: payload is used only for parsing hostnames (SNI/HTTP), not stored in DB
    payload: Vec<u8>,
}

impl Communication {
    pub fn new(ethernet_packet: EthernetPacket) -> Self {
        Self::new_with_source(ethernet_packet, None)
    }

    pub fn new_with_source(ethernet_packet: EthernetPacket, source: Option<String>) -> Self {
        let packet_wrapper = PacketWrapper::new(&ethernet_packet);
        let packet_size = ethernet_packet.packet().len() as u32;

        let mut communication = Communication {
            source_mac: Some(ethernet_packet.get_source().to_string()),
            destination_mac: Some(ethernet_packet.get_destination().to_string()),
            source_ip: packet_wrapper.get_source_ip(),
            destination_ip: packet_wrapper.get_destination_ip(),
            source_port: packet_wrapper.get_source_port(),
            destination_port: packet_wrapper.get_destination_port(),
            ip_version: packet_wrapper.get_ip_version(),
            ip_header_protocol: packet_wrapper.get_header_protocol(),
            sub_protocol: None,
            source,
            packet_size,
            payload: packet_wrapper.get_payload().unwrap_or_default().to_vec(),
        };
        if let Some(ip_header_protocol) = &communication.ip_header_protocol
            && (ip_header_protocol == "Tcp" || ip_header_protocol == "Udp")
        {
            communication.sub_protocol = communication
                .destination_port
                .and_then(|port| packet_wrapper.get_sub_protocol(port))
                .or_else(|| {
                    communication
                        .source_port
                        .and_then(|port| packet_wrapper.get_sub_protocol(port))
                });
        }

        // Clear MAC addresses for internet traffic to prevent grouping remote endpoints under gateway MAC
        // For outbound traffic (local → internet): clear destination_mac
        if let Some(ref dst_ip) = communication.destination_ip
            && !EndPoint::is_on_local_network(dst_ip)
        {
            communication.destination_mac = None;
        }
        // For inbound traffic (internet → local): clear source_mac
        if let Some(ref src_ip) = communication.source_ip
            && !EndPoint::is_on_local_network(src_ip)
        {
            communication.source_mac = None;
        }

        communication
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS communications (
                id INTEGER PRIMARY KEY,
                src_endpoint_id INTEGER,
                dst_endpoint_id INTEGER,
                created_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                packet_count INTEGER DEFAULT 1,
                bytes INTEGER DEFAULT 0,
                source_port INTEGER,
                destination_port INTEGER,
                ip_version INTEGER,
                ip_header_protocol TEXT,
                sub_protocol TEXT,
                source TEXT,
                FOREIGN KEY (src_endpoint_id) REFERENCES endpoints(id),
                FOREIGN KEY (dst_endpoint_id) REFERENCES endpoints(id)
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_communications_created_at ON communications (created_at);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_communications_last_seen_at ON communications (last_seen_at);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_communications_src_endpoint_id ON communications (src_endpoint_id);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_communications_dst_endpoint_id ON communications (dst_endpoint_id);",
            [],
        )?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_communications_unique ON communications (
                src_endpoint_id,
                dst_endpoint_id,
                COALESCE(source_port, 0),
                COALESCE(destination_port, 0),
                COALESCE(ip_header_protocol, ''),
                COALESCE(sub_protocol, '')
            );",
            [],
        )?;
        // Composite indexes for time-range queries (optimization)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_communications_last_seen_src ON communications (last_seen_at, src_endpoint_id);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_communications_last_seen_dst ON communications (last_seen_at, dst_endpoint_id);",
            [],
        )?;
        Ok(())
    }

    /// Check if a port is ephemeral (temporary client-side port)
    /// Using broader range that covers most systems: 32768-65535
    /// - Linux default: 32768-60999
    /// - IANA standard: 49152-65535
    /// - Most systems use ports >= 32768 for ephemeral
    fn is_ephemeral_port(port: Option<u16>) -> bool {
        port.is_some_and(|p| p >= 32768)
    }

    pub fn insert_communication(&self, conn: &Connection) -> Result<()> {
        let src_endpoint_id = match EndPoint::get_or_insert_endpoint(
            conn,
            self.source_mac.clone(),
            self.source_ip.clone(),
            self.sub_protocol.clone(),
            &[],
        ) {
            Ok(id) => id,
            Err(InsertEndpointError::BothMacAndIpNone) => {
                return Ok(()); // Skip insertion if both MAC and IP are None
            }
            Err(InsertEndpointError::ConstraintViolation) => {
                return Ok(()); // Skip insertion on constraint violation
            }
            Err(InsertEndpointError::DatabaseError(e)) => {
                return Err(e);
            }
        };
        let dst_endpoint_id = match EndPoint::get_or_insert_endpoint(
            conn,
            self.destination_mac.clone(),
            self.destination_ip.clone(),
            self.sub_protocol.clone(),
            self.get_payload(),
        ) {
            Ok(id) => id,
            Err(InsertEndpointError::BothMacAndIpNone) => {
                return Ok(()); // Skip insertion if both MAC and IP are None
            }
            Err(InsertEndpointError::ConstraintViolation) => {
                return Ok(()); // Skip insertion on constraint violation
            }
            Err(InsertEndpointError::DatabaseError(e)) => {
                // Handle the database error (e.g., log it, return a specific error, etc.)
                return Err(e);
            }
        };

        let now = chrono::Utc::now().timestamp();

        // Only store destination ports (services being accessed)
        // Source ports are almost always ephemeral and not meaningful
        // Destination ports are stored only if they're well-known/registered (< 32768)
        let source_port: Option<u16> = None; // Always ignore source ports
        let destination_port = if Self::is_ephemeral_port(self.destination_port) {
            None
        } else {
            self.destination_port
        };

        // Use INSERT OR REPLACE to update existing communication or insert new one
        // This deduplicates connections and just updates last_seen_at + packet_count + bytes
        conn.execute(
            "INSERT INTO communications (
                src_endpoint_id,
                dst_endpoint_id,
                created_at,
                last_seen_at,
                packet_count,
                bytes,
                source_port,
                destination_port,
                ip_version,
                ip_header_protocol,
                sub_protocol,
                source
            ) VALUES (?1, ?2, ?3, ?3, 1, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(src_endpoint_id, dst_endpoint_id, COALESCE(source_port, 0), COALESCE(destination_port, 0), COALESCE(ip_header_protocol, ''), COALESCE(sub_protocol, ''))
            DO UPDATE SET
                last_seen_at = ?3,
                packet_count = packet_count + 1,
                bytes = bytes + ?4",
            params![
                src_endpoint_id,
                dst_endpoint_id,
                now,
                self.packet_size,
                source_port,
                destination_port,
                self.ip_version,
                self.ip_header_protocol,
                self.sub_protocol,
                self.source
            ],
        )?;
        Ok(())
    }
}
