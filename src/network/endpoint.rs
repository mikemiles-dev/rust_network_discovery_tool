use dns_lookup::{get_hostname, lookup_addr};
use pnet::datalink::interfaces;
use rusqlite::{Connection, OptionalExtension, Result, params};

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

    fn lookup_dns(ip: Option<String>, interface: String) -> Option<String> {
        let ip_str = ip?;
        let ip_addr = ip_str.parse().ok()?;
        let hostname = lookup_addr(&ip_addr).ok()?;
        let local_hostname = get_hostname().ok()?;

        Some(
            if hostname.to_lowercase() != local_hostname.to_lowercase()
                && Self::is_local_ip(ip_str, interface)
            {
                local_hostname
            } else {
                hostname
            },
        )
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
