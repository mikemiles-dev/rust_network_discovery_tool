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
    ) -> Result<i64> {
        let mut stmt = conn
            .prepare("SELECT id FROM endpoints WHERE (mac = ?1 OR ip = ?2) AND interface = ?3")?;
        if let Some(id) = stmt
            .query_row(params![mac, ip, interface], |row| row.get(0))
            .optional()?
        {
            return Ok(id);
        }

        let hostname = Self::lookup_hostname(ip.clone(), interface.clone(), protocol.clone());

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
    ) -> Option<String> {
        match protocol.as_deref() {
            Some("HTTP") | Some("HTTPS") => None,
            _ => Self::lookup_dns(ip.clone(), interface.clone()),
        }
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
