use dns_lookup::{get_hostname, lookup_addr};
use pnet::datalink::interfaces;
use rusqlite::{Connection, OptionalExtension, Result, params};

use crate::network::mdns_lookup::MDnsLookup;

#[derive(Default, Debug)]
pub struct EndPoint;

impl EndPoint {
    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL,
                interface TEXT,
                mac TEXT,
                ip TEXT,
                hostname TEXT,
                UNIQUE(interface, ip),
                UNIQUE(interface, mac)
            )",
            [],
        )?;
        Ok(())
    }

    pub fn get_or_insert_endpoint(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        interface: String,
        protocol: Option<String>,
        payload: &[u8],
    ) -> Result<i64> {
        let hostname =
            Self::lookup_hostname(ip.clone(), interface.clone(), protocol.clone(), payload);

        match hostname.clone() {
            Some(hostname) => {
                let mut stmt = conn
            .prepare("SELECT id FROM endpoints WHERE (hostname = ?1 OR mac = ?2 OR ip = ?3) AND interface = ?4")?;
                if let Some(id) = stmt
                    .query_row(params![hostname, mac, ip, interface], |row| row.get(0))
                    .optional()?
                {
                    return Ok(id);
                }
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT id FROM endpoints WHERE ( mac = ?1 OR ip = ?2) AND interface = ?3",
                )?;
                if let Some(id) = stmt
                    .query_row(params![mac, ip, interface], |row| row.get(0))
                    .optional()?
                {
                    return Ok(id);
                }
            }
        }

        conn.execute(
            "INSERT INTO endpoints (created_at, interface, mac, ip, hostname) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![chrono::Utc::now().timestamp(), interface, mac, ip, hostname],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_hostname_by_ip(
        conn: &Connection,
        ip: Option<String>,
        hostname: Option<String>,
    ) -> Result<()> {
        if let Some(ip_addr) = ip {
            conn.execute(
                "UPDATE endpoints SET hostname = ?1 WHERE ip = ?2",
                params![hostname, ip_addr],
            )?;
        }
        Ok(())
    }

    fn lookup_dns(ip: Option<String>, interface: String) -> Option<String> {
        let ip_str = ip?;
        let ip_addr = ip_str.parse().ok()?;
        let is_local = Self::is_local_ip(ip_str.clone(), interface);
        let local_hostname = get_hostname().unwrap_or_default();

        // Get hostname via DNS or fallback to mDNS/IP
        let hostname = match lookup_addr(&ip_addr) {
            Ok(name) if name != ip_str && !is_local => name,
            _ => MDnsLookup::lookup(&ip_str).unwrap_or(ip_str),
        };

        // Use local hostname for local IPs with different names
        Some(
            if is_local && !hostname.eq_ignore_ascii_case(&local_hostname) {
                local_hostname
            } else {
                hostname
            },
        )
    }

    fn lookup_hostname(
        ip: Option<String>,
        interface: String,
        protocol: Option<String>,
        payload: &[u8],
    ) -> Option<String> {
        match protocol.as_deref() {
            Some("HTTP") => Self::get_http_host(payload),
            Some("HTTPS") => {
                let result = Self::find_sni(payload);
                println!("Found SNI: {:?}", result);
                result
            },
            _ => Self::lookup_dns(ip.clone(), interface.clone()),
        }
    }

    fn get_http_host(payload: &[u8]) -> Option<String> {
        let payload_str = String::from_utf8_lossy(payload);
        for line in payload_str.lines() {
            if line.to_lowercase().starts_with("host:") {
                return Some(line[5..].trim().to_string());
            } else if line.to_lowercase().starts_with("x-host:") {
                return Some(line[7..].trim().to_string());
            } else if line.to_lowercase().starts_with("x-forwarded-host:") {
                return Some(line[17..].trim().to_string());
            } else if line.to_lowercase().starts_with("x-forwarded-server:") {
                return Some(line[18..].trim().to_string());
            } else if line.to_lowercase().starts_with("referer:") {
                // Extract hostname from referer URL
                if let Ok(url) = url::Url::parse(line[8..].trim()) {
                    if let Some(host) = url.host_str() {
                        return Some(host.to_string());
                    }
                }
            } else if line.to_lowercase().starts_with("report-uri") {
                // Extract hostname from report-uri URL
                if let Ok(url) = url::Url::parse(line[10..].trim()) {
                    if let Some(host) = url.host_str() {
                        return Some(host.to_string());
                    }
                }
            }
        }
        None
    }

    // This is a simplified function to find the SNI.
    // The real implementation would be more robust.
    fn find_sni(payload: &[u8]) -> Option<String> {
        // The TLS Client Hello message starts with specific bytes.
        // This is a simplified check. A full parser would be more complex.
        if payload.len() > 5 && payload[0] == 0x16 && payload[1] == 0x03 {
            // Find the "server_name" extension (type 0x0000)
            // This is a simplified search for the extension type in the raw payload.
            if let Some(pos) = payload.windows(2).position(|window| window == [0x00, 0x00]) {
                let offset = pos + 2; // Move past the extension type bytes
                if payload.len() > offset + 2 {
                    let name_len = (payload[offset] as usize) << 8 | (payload[offset + 1] as usize);
                    let name_start = offset + 2;
                    let name_end = name_start + name_len;
                    if payload.len() >= name_end {
                        return String::from_utf8(payload[name_start..name_end].to_vec()).ok();
                    }
                }
            }
        }
        None
    }

    fn is_local_ip(target_ip: String, interface: String) -> bool {
        if target_ip == "127.0.0.1"
            || target_ip == "::1"
            || target_ip == "localhost"
            || target_ip == "::ffff:"
            || target_ip == "0:0:0:0:0:0:0:1"
            || target_ip == "::"
        {
            return true; // Loopback addresses are always local
        }

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
}
