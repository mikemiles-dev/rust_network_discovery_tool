use dns_lookup::{get_hostname, lookup_addr};
use pnet::{datalink::interfaces, packet::ethernet::EthernetPacket};
use rusqlite::{Connection, OptionalExtension, Result, params};

use crate::network::PacketWrapper;

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
    pub fn new(ethernet_packet: EthernetPacket, interface: String) -> Self {
        let packet_wrapper = PacketWrapper::new(&ethernet_packet);

        let mut communication = Communication {
            interface,
            source_mac: Some(ethernet_packet.get_source().to_string()),
            destination_mac: Some(ethernet_packet.get_destination().to_string()),
            source_ip: packet_wrapper.get_source_ip(),
            destination_ip: packet_wrapper.get_destination_ip(),
            source_port: packet_wrapper.get_source_port(),
            destination_port: packet_wrapper.get_destination_port(),
            ip_version: packet_wrapper.get_ip_version(),
            ip_header_protocol: packet_wrapper.get_header_protocol(),
            sub_protocol: None,
            ..Default::default()
        };
        if let Some(ip_header_protocol) = &communication.ip_header_protocol {
            if ip_header_protocol == "Tcp" || ip_header_protocol == "Udp" {
                communication.sub_protocol = communication
                    .destination_port
                    .and_then(|port| packet_wrapper.get_sub_protocol(port))
                    .or_else(|| {
                        communication
                            .source_port
                            .and_then(|port| packet_wrapper.get_sub_protocol(port))
                    });
            }
        }
        communication
    }

    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS communications (
                id INTEGER PRIMARY KEY,
                src_endpoint_id INTEGER,
                dst_endpoint_id INTEGER,
                created_at INTEGER NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                ip_version INTEGER,
                ip_header_protocol TEXT,
                sub_protocol TEXT,
                FOREIGN KEY (src_endpoint_id) REFERENCES endpoints(id),
                FOREIGN KEY (dst_endpoint_id) REFERENCES endpoints(id)
            )",
            [],
        )?;
        Ok(())
    }

    fn is_local_ip(target_ip: String, interface: String) -> bool {
        // Find the network interface with the matching name
        let matching_interface = match interfaces()
            .into_iter()
            .find(|iface| iface.name == interface)
        {
            Some(iface) => iface,
            None => return false, // Interface not found
        };

        // Check if the target IP matches any IP on the interface
        matching_interface
            .ips
            .iter()
            .any(|ip_network| ip_network.ip().to_string() == target_ip)
    }

    fn lookup_dns(ip: Option<String>, interface: String) -> Option<String> {
        let ip_str = ip?;
        let ip_addr = ip_str.parse().ok()?;
        let hostname = lookup_addr(&ip_addr).ok()?;
        let local_hostname = get_hostname().ok()?;

        Some(
            if hostname != local_hostname && Self::is_local_ip(ip_str, interface) {
                local_hostname
            } else {
                hostname
            },
        )
    }

    pub fn get_or_insert_endpoint(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        interface: String,
    ) -> Result<i64> {
        let mut stmt = conn
            .prepare("SELECT id FROM endpoints WHERE (mac = ?1 OR ip = ?2) AND interface = ?3")?;
        if let Some(id) = stmt
            .query_row(params![mac, ip, interface], |row| row.get(0))
            .optional()?
        {
            return Ok(id);
        }

        let hostname = Self::lookup_dns(ip.clone(), interface.clone());

        conn.execute(
            "INSERT INTO endpoints (created_at, interface, mac, ip, hostname) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![chrono::Utc::now().timestamp(), interface, mac, ip, hostname],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn insert_communication(&self, conn: &Connection) -> Result<()> {
        let src_endpoint_id = Self::get_or_insert_endpoint(
            conn,
            self.source_mac.clone(),
            self.source_ip.clone(),
            self.interface.clone(),
        )?; // Ensure endpoint exists and get its ID
        let dst_endpoint_id = Self::get_or_insert_endpoint(
            conn,
            self.destination_mac.clone(),
            self.destination_ip.clone(),
            self.interface.clone(),
        )?; // Ensure endpoint exists and get its ID

        conn.execute(
            "INSERT INTO communications (
                src_endpoint_id,
                dst_endpoint_id,
                created_at,
                source_port,
                destination_port,
                ip_version,
                ip_header_protocol,
                sub_protocol
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                src_endpoint_id,
                dst_endpoint_id,
                chrono::Utc::now().timestamp(),
                self.source_port,
                self.destination_port,
                self.ip_version,
                self.ip_header_protocol,
                self.sub_protocol
            ],
        )?;
        Ok(())
    }

    pub async fn write(self, sender: tokio::sync::mpsc::Sender<Communication>) {
        if let Err(e) = sender.send(self).await {
            eprintln!("Failed to send communication to SQL writer: {}", e);
        }
    }
}
