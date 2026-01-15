use rusqlite::{Connection, OptionalExtension, Result, params};

use super::endpoint::strip_local_suffix;

#[derive(Default, Debug)]
pub struct EndPointAttribute;

impl EndPointAttribute {
    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS endpoint_attributes (
                id INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL,
                endpoint_id INTEGER NOT NULL,
                mac TEXT,
                ip TEXT NOT NULL,
                hostname TEXT,
                dhcp_client_id TEXT,
                dhcp_vendor_class TEXT,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(id),
                UNIQUE(mac, ip, hostname)
            )",
            [],
        )?;
        // Add dhcp_client_id column if it doesn't exist (migration for existing DBs)
        let _ = conn.execute(
            "ALTER TABLE endpoint_attributes ADD COLUMN dhcp_client_id TEXT",
            [],
        );
        // Add dhcp_vendor_class column if it doesn't exist (migration for existing DBs)
        let _ = conn.execute(
            "ALTER TABLE endpoint_attributes ADD COLUMN dhcp_vendor_class TEXT",
            [],
        );
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
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoint_attributes_dhcp_client_id ON endpoint_attributes (dhcp_client_id);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoint_attributes_dhcp_vendor_class ON endpoint_attributes (dhcp_vendor_class);",
            [],
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn find_existing_endpoint_id(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        _hostname: Option<String>,
    ) -> Option<i64> {
        Self::find_existing_endpoint_id_with_dhcp(conn, mac, ip, _hostname, None)
    }

    pub fn find_existing_endpoint_id_with_dhcp(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        _hostname: Option<String>,
        dhcp_client_id: Option<String>,
    ) -> Option<i64> {
        // Strategy: Match by MAC first (most reliable), then DHCP Client ID, then IP if no MAC
        // Never match by hostname alone (too unreliable - collisions common)
        // CRITICAL: Prevent DHCP IP reuse from merging different physical devices

        // Try 1: Match by MAC (best identifier for physical devices)
        // Prefer endpoints with non-empty names over those with empty names
        if let Some(ref mac_addr) = mac
            && let Ok(mut stmt) = conn.prepare(
                "SELECT ea.endpoint_id
                 FROM endpoint_attributes ea
                 JOIN endpoints e ON ea.endpoint_id = e.id
                 WHERE LOWER(ea.mac) = LOWER(?1)
                 ORDER BY
                   CASE WHEN e.name IS NOT NULL AND e.name != '' THEN 0 ELSE 1 END,
                   ea.endpoint_id ASC
                 LIMIT 1",
            )
            && let Ok(Some(id)) = stmt.query_row([mac_addr], |row| row.get(0)).optional()
        {
            // If we found a match, check for duplicates and merge them
            Self::merge_duplicate_endpoints_by_mac(conn, mac_addr).ok();
            return Some(id);
        }

        // Try 2: Match by DHCP Client ID (for devices with randomized MACs)
        if let Some(ref dhcp_id) = dhcp_client_id
            && let Ok(mut stmt) = conn.prepare(
                "SELECT ea.endpoint_id
                 FROM endpoint_attributes ea
                 JOIN endpoints e ON ea.endpoint_id = e.id
                 WHERE LOWER(ea.dhcp_client_id) = LOWER(?1)
                 ORDER BY
                   CASE WHEN e.name IS NOT NULL AND e.name != '' THEN 0 ELSE 1 END,
                   ea.endpoint_id ASC
                 LIMIT 1",
            )
            && let Ok(Some(id)) = stmt.query_row([dhcp_id], |row| row.get(0)).optional()
        {
            return Some(id);
        }

        // Try 3: Match by IP ONLY if we don't have a MAC or DHCP Client ID
        // This prevents DHCP IP reuse from incorrectly merging different devices
        // If we have a MAC but didn't match above, this is a new device
        if mac.is_none()
            && dhcp_client_id.is_none()
            && let Some(ref ip_addr) = ip
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

    /// Merge duplicate endpoints that share the same MAC address
    /// Keeps the endpoint with a non-empty name (or lowest ID if all empty)
    fn merge_duplicate_endpoints_by_mac(conn: &Connection, mac: &str) -> Result<()> {
        // Find all endpoints with this MAC
        let mut stmt = conn.prepare(
            "SELECT DISTINCT ea.endpoint_id, COALESCE(e.name, '') as name
             FROM endpoint_attributes ea
             JOIN endpoints e ON ea.endpoint_id = e.id
             WHERE LOWER(ea.mac) = LOWER(?1)
             ORDER BY
               CASE WHEN e.name IS NOT NULL AND e.name != '' THEN 0 ELSE 1 END,
               ea.endpoint_id ASC",
        )?;

        let endpoint_ids: Vec<(i64, String)> = stmt
            .query_map([mac], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        // If only one endpoint, nothing to merge
        if endpoint_ids.len() <= 1 {
            return Ok(());
        }

        // Keep the first one (has non-empty name or lowest ID)
        let keep_id = endpoint_ids[0].0;
        let merge_ids: Vec<i64> = endpoint_ids.iter().skip(1).map(|(id, _)| *id).collect();

        // Merge communications
        for merge_id in &merge_ids {
            conn.execute(
                "UPDATE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
                params![keep_id, merge_id],
            )?;
            conn.execute(
                "UPDATE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
                params![keep_id, merge_id],
            )?;
        }

        // Copy unique attributes from duplicates to kept endpoint
        for merge_id in &merge_ids {
            // Use INSERT OR IGNORE to skip duplicates
            conn.execute(
                "INSERT OR IGNORE INTO endpoint_attributes (created_at, endpoint_id, mac, ip, hostname)
                 SELECT created_at, ?1, mac, ip, hostname
                 FROM endpoint_attributes
                 WHERE endpoint_id = ?2",
                params![keep_id, merge_id],
            )?;

            // Delete duplicate attributes
            conn.execute(
                "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
                params![merge_id],
            )?;

            // Delete duplicate endpoint
            conn.execute("DELETE FROM endpoints WHERE id = ?1", params![merge_id])?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn insert_endpoint_attribute(
        conn: &Connection,
        endpoint_id: i64,
        mac: Option<String>,
        ip: Option<String>,
        hostname: String,
    ) -> Result<()> {
        Self::insert_endpoint_attribute_with_dhcp(conn, endpoint_id, mac, ip, hostname, None, None)
    }

    pub fn insert_endpoint_attribute_with_dhcp(
        conn: &Connection,
        endpoint_id: i64,
        mac: Option<String>,
        ip: Option<String>,
        hostname: String,
        dhcp_client_id: Option<String>,
        dhcp_vendor_class: Option<String>,
    ) -> Result<()> {
        // Strip local suffixes like .local, .lan, .home
        let hostname = strip_local_suffix(&hostname);
        conn.execute(
            "INSERT INTO endpoint_attributes (created_at, endpoint_id, mac, ip, hostname, dhcp_client_id, dhcp_vendor_class) VALUES (strftime('%s', 'now'), ?1, ?2, ?3, ?4, ?5, ?6)",
            params![endpoint_id, mac, ip, hostname, dhcp_client_id, dhcp_vendor_class],
        )?;
        Ok(())
    }

    /// Update DHCP Client ID for an endpoint
    pub fn update_dhcp_client_id(
        conn: &Connection,
        endpoint_id: i64,
        dhcp_client_id: &str,
    ) -> Result<()> {
        conn.execute(
            "UPDATE endpoint_attributes SET dhcp_client_id = ?1 WHERE endpoint_id = ?2 AND dhcp_client_id IS NULL",
            params![dhcp_client_id, endpoint_id],
        )?;
        Ok(())
    }

    /// Update DHCP Vendor Class for an endpoint
    pub fn update_dhcp_vendor_class(
        conn: &Connection,
        endpoint_id: i64,
        dhcp_vendor_class: &str,
    ) -> Result<()> {
        conn.execute(
            "UPDATE endpoint_attributes SET dhcp_vendor_class = ?1 WHERE endpoint_id = ?2 AND dhcp_vendor_class IS NULL",
            params![dhcp_vendor_class, endpoint_id],
        )?;
        Ok(())
    }

    /// Get DHCP Vendor Class for an endpoint
    #[allow(dead_code)]
    pub fn get_dhcp_vendor_class(conn: &Connection, endpoint_id: i64) -> Option<String> {
        conn.query_row(
            "SELECT dhcp_vendor_class FROM endpoint_attributes WHERE endpoint_id = ?1 AND dhcp_vendor_class IS NOT NULL LIMIT 1",
            params![endpoint_id],
            |row| row.get(0),
        ).ok()
    }
}
