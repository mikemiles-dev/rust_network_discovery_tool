use rusqlite::{Connection, OptionalExtension, Result, params};

#[derive(Default, Debug)]
pub struct EndPointAttribute;

impl EndPointAttribute {
    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS endpoint_attributes (
                id INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL,
                endpoint_id INTEGER NOT NULL,
                mac TEXT NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(id),
                UNIQUE(mac, ip, hostname)
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoint_attributes_endpoint_id ON endpoint_attributes (endpoint_id);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoint_attributes_hostname ON endpoint_attributes (hostname);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoint_attributes_mac ON endpoint_attributes (mac);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoint_attributes_ip ON endpoint_attributes (ip);",
            [],
        )?;
        Ok(())
    }

    pub fn find_existing_endpoint_id(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        _hostname: Option<String>,
    ) -> Option<i64> {
        // Strategy: Match by MAC first (most reliable), then IP if no MAC
        // Never match by hostname alone (too unreliable - collisions common)

        // Try 1: Match by MAC (best identifier)
        if let Some(ref mac_addr) = mac
            && let Ok(mut stmt) = conn.prepare(
                "SELECT endpoint_id FROM endpoint_attributes WHERE LOWER(mac) = LOWER(?1) LIMIT 1",
            )
            && let Ok(Some(id)) = stmt.query_row([mac_addr], |row| row.get(0)).optional()
        {
            return Some(id);
        }

        // Try 2: Match by IP if no MAC match (less reliable - DHCP can reuse IPs)
        if let Some(ref ip_addr) = ip
            && let Ok(mut stmt) = conn.prepare(
                "SELECT endpoint_id FROM endpoint_attributes WHERE LOWER(ip) = LOWER(?1) LIMIT 1",
            )
            && let Ok(Some(id)) = stmt.query_row([ip_addr], |row| row.get(0)).optional()
        {
            return Some(id);
        }

        // No match found
        None
    }

    pub fn insert_endpoint_attribute(
        conn: &Connection,
        endpoint_id: i64,
        mac: Option<String>,
        ip: Option<String>,
        hostname: String,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO endpoint_attributes (created_at, endpoint_id, mac, ip, hostname) VALUES (strftime('%s', 'now'), ?1, ?2, ?3, ?4)",
            params![endpoint_id, mac, ip, hostname],
        )?;
        Ok(())
    }
}
