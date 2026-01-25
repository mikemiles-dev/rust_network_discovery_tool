use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use rusqlite::{Connection, Result, params};

use crate::network::{
    endpoint::{EndPoint, InsertEndpointError},
    packet_wrapper::PacketWrapper,
};

/// Parse DHCP options from payload
/// Returns (Option 61: Client ID, Option 60: Vendor Class, Option 12: Hostname)
fn parse_dhcp_options(payload: &[u8]) -> (Option<String>, Option<String>, Option<String>) {
    // DHCP packet structure:
    // - Bytes 0-235: Fixed header
    // - Bytes 236-239: Magic cookie (0x63825363)
    // - Bytes 240+: Options (TLV format)

    if payload.len() < 244 {
        return (None, None, None); // Too short for DHCP with options
    }

    // Verify magic cookie
    if payload[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return (None, None, None);
    }

    let mut client_id = None;
    let mut vendor_class = None;
    let mut hostname = None;

    // Parse options starting at byte 240
    let mut offset = 240;
    while offset < payload.len() {
        let option_type = payload[offset];

        // End option
        if option_type == 255 {
            break;
        }

        // Pad option (no length byte)
        if option_type == 0 {
            offset += 1;
            continue;
        }

        // Make sure we can read the length
        if offset + 1 >= payload.len() {
            break;
        }

        let option_len = payload[offset + 1] as usize;

        // Make sure we can read the value
        if offset + 2 + option_len > payload.len() {
            break;
        }

        let option_data = &payload[offset + 2..offset + 2 + option_len];

        match option_type {
            // Option 12: Hostname
            12 if option_len > 0 => {
                if let Ok(s) = std::str::from_utf8(option_data) {
                    hostname = Some(s.trim_end_matches('\0').to_string());
                }
            }
            // Option 60: Vendor Class Identifier
            // Examples: "samsung:SM-G998B", "HP LaserJet Pro M404", "android-dhcp-13"
            60 if option_len > 0 => {
                if let Ok(s) = std::str::from_utf8(option_data) {
                    vendor_class = Some(s.trim_end_matches('\0').to_string());
                }
            }
            // Option 61: Client Identifier
            61 if option_len > 0 => {
                // Convert to hex string for storage
                let hex_string: String = option_data
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":");
                client_id = Some(hex_string);
            }
            _ => {}
        }

        offset += 2 + option_len;
    }

    (client_id, vendor_class, hostname)
}

/// Extract model from DHCP Vendor Class Identifier (Option 60)
/// Examples:
/// - "samsung:SM-G998B" -> "SM-G998B" (Galaxy S21 Ultra)
/// - "HP LaserJet Pro M404" -> "LaserJet Pro M404"
/// - "android-dhcp-13" -> None (just Android version)
pub fn extract_model_from_vendor_class(vendor_class: &str) -> Option<String> {
    let vc = vendor_class.trim();

    // Samsung format: "samsung:MODEL" or "SAMSUNG:MODEL"
    if let Some(model) = vc
        .strip_prefix("samsung:")
        .or_else(|| vc.strip_prefix("SAMSUNG:"))
    {
        let model = model.trim();
        if !model.is_empty() && model.starts_with("SM-") || model.starts_with("GT-") {
            return Some(model.to_string());
        }
    }

    // HP format: "HP MODEL" or "Hewlett-Packard MODEL"
    if vc.starts_with("HP ") {
        let model = vc.strip_prefix("HP ").unwrap().trim();
        if !model.is_empty() {
            return Some(model.to_string());
        }
    }
    if vc.starts_with("Hewlett-Packard ") {
        let model = vc.strip_prefix("Hewlett-Packard ").unwrap().trim();
        if !model.is_empty() {
            return Some(model.to_string());
        }
    }

    // LG format: "LG-MODEL" or "LGE-MODEL"
    if let Some(model) = vc.strip_prefix("LG-").or_else(|| vc.strip_prefix("LGE-")) {
        let model = model.trim();
        if !model.is_empty() {
            return Some(format!("LG {}", model));
        }
    }

    // Sony/PlayStation format
    if vc.starts_with("PlayStation") || vc.starts_with("PS") {
        return Some(vc.to_string());
    }

    // Xbox format
    if vc.contains("Xbox") {
        return Some(vc.to_string());
    }

    // Generic formats that contain model info (not just OS/DHCP client)
    // Skip things like "android-dhcp-13", "MSFT 5.0", "dhcpcd-8.1.2"
    if vc.starts_with("android-dhcp")
        || vc.starts_with("MSFT ")
        || vc.starts_with("dhcpcd")
        || vc.starts_with("udhcp")
    {
        return None;
    }

    // If it looks like a meaningful vendor class with a model, return it
    // But filter out very short or generic ones
    if vc.len() > 5 && !vc.contains("dhcp") && !vc.contains("DHCP") {
        return Some(vc.to_string());
    }

    None
}

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
    // DHCP Client ID (Option 61) for tracking devices with randomized MACs
    pub dhcp_client_id: Option<String>,
    // DHCP Vendor Class (Option 60) for model identification (e.g., "samsung:SM-G998B")
    pub dhcp_vendor_class: Option<String>,
    // DHCP Hostname (Option 12) - the device's actual hostname from DHCP request
    pub dhcp_hostname: Option<String>,
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

        let payload = packet_wrapper.get_payload().unwrap_or_default().to_vec();

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
            dhcp_client_id: None,
            dhcp_vendor_class: None,
            dhcp_hostname: None,
            payload,
        };
        if let Some(ip_header_protocol) = &communication.ip_header_protocol
            && (ip_header_protocol == "Tcp" || ip_header_protocol == "Udp")
        {
            // Try destination port first (most reliable for client→server requests)
            communication.sub_protocol = communication
                .destination_port
                .and_then(|port| packet_wrapper.get_sub_protocol(port))
                .or_else(|| {
                    // Only fall back to source port if destination is in ephemeral range
                    // This handles server→client responses while avoiding false positives
                    // from ephemeral ports that happen to match well-known service ports
                    let dst_is_ephemeral = communication
                        .destination_port
                        .map(|p| p >= 32768)
                        .unwrap_or(false);
                    if dst_is_ephemeral {
                        communication
                            .source_port
                            .and_then(|port| packet_wrapper.get_sub_protocol(port))
                    } else {
                        None
                    }
                });
        }

        // Parse DHCP options for device tracking and identification (ports 67/68 are DHCP)
        let is_dhcp = communication.source_port == Some(67)
            || communication.source_port == Some(68)
            || communication.destination_port == Some(67)
            || communication.destination_port == Some(68);
        if is_dhcp {
            let (client_id, vendor_class, hostname) = parse_dhcp_options(&communication.payload);
            communication.dhcp_client_id = client_id;
            communication.dhcp_vendor_class = vendor_class;
            communication.dhcp_hostname = hostname;
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
        // Drop old index that included source_port (if exists) and create new one without it
        // This aggregates all communications between endpoints on the same destination port
        conn.execute("DROP INDEX IF EXISTS idx_communications_unique;", [])?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_communications_unique_v2 ON communications (
                src_endpoint_id,
                dst_endpoint_id,
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

    pub fn insert_communication(&self, conn: &Connection) -> Result<()> {
        // For DHCP packets, the source is the client - pass DHCP Client ID, Vendor Class, and Hostname for tracking
        let src_endpoint_id = match EndPoint::get_or_insert_endpoint_with_dhcp(
            conn,
            self.source_mac.clone(),
            self.source_ip.clone(),
            self.sub_protocol.clone(),
            &[],
            self.dhcp_client_id.clone(), // Pass DHCP Client ID for source (client)
            self.dhcp_vendor_class.clone(), // Pass DHCP Vendor Class for model identification
            self.dhcp_hostname.clone(),  // Pass DHCP Hostname (Option 12) - device's actual name
        ) {
            Ok(id) => id,
            Err(InsertEndpointError::BothMacAndIpNone) => {
                return Ok(()); // Skip insertion if both MAC and IP are None
            }
            Err(InsertEndpointError::ConstraintViolation) => {
                return Ok(()); // Skip insertion on constraint violation
            }
            Err(InsertEndpointError::InternetDestination) => {
                return Ok(()); // Skip - internet destinations are tracked separately
            }
            Err(InsertEndpointError::DatabaseError(e)) => {
                return Err(e);
            }
        };
        let dst_endpoint_id = match EndPoint::get_or_insert_endpoint_with_dhcp(
            conn,
            self.destination_mac.clone(),
            self.destination_ip.clone(),
            self.sub_protocol.clone(),
            self.get_payload(),
            None, // Destination doesn't need DHCP Client ID (usually the server)
            None, // Destination doesn't need DHCP Vendor Class
            None, // Destination doesn't need DHCP Hostname
        ) {
            Ok(id) => id,
            Err(InsertEndpointError::BothMacAndIpNone) => {
                return Ok(()); // Skip insertion if both MAC and IP are None
            }
            Err(InsertEndpointError::ConstraintViolation) => {
                return Ok(()); // Skip insertion on constraint violation
            }
            Err(InsertEndpointError::InternetDestination) => {
                return Ok(()); // Skip - internet destinations are tracked separately
            }
            Err(InsertEndpointError::DatabaseError(e)) => {
                return Err(e);
            }
        };

        let now = chrono::Utc::now().timestamp();

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
            ON CONFLICT(src_endpoint_id, dst_endpoint_id, COALESCE(destination_port, 0), COALESCE(ip_header_protocol, ''), COALESCE(sub_protocol, ''))
            DO UPDATE SET
                last_seen_at = ?3,
                packet_count = packet_count + 1,
                bytes = bytes + ?4,
                source_port = COALESCE(source_port, excluded.source_port)",
            params![
                src_endpoint_id,
                dst_endpoint_id,
                now,
                self.packet_size,
                self.source_port,
                self.destination_port,
                self.ip_version,
                self.ip_header_protocol,
                self.sub_protocol,
                self.source
            ],
        )?;
        Ok(())
    }
}
