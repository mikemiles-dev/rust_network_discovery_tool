use std::net::Ipv4Addr;

use rusqlite::{Connection, OptionalExtension, Result, params};

use super::endpoint::{get_mac_vendor, is_uuid_like, strip_local_suffix};

/// Check if MAC is from a gateway/router vendor (for similar-MAC merging)
/// These vendors often have multiple NICs with sequential MACs on the same device
fn is_gateway_vendor_mac(mac: &str) -> bool {
    const GATEWAY_MERGE_VENDORS: &[&str] = &[
        "Commscope",
        "ARRIS",
        "Netgear",
        "Linksys",
        "Ubiquiti",
        "MikroTik",
        "Cisco",
        "Juniper",
        "Fortinet",
        "TP-Link",
        "Asus",
        "D-Link",
        "Belkin",
        "ZyXEL",
        "Huawei",
    ];

    get_mac_vendor(mac).is_some_and(|v| GATEWAY_MERGE_VENDORS.contains(&v))
}

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
        // Clean up any existing duplicates before creating the unique index
        // Keep only the most recent row for each unique combination
        let _ = conn.execute(
            "DELETE FROM endpoint_attributes WHERE id NOT IN (
                SELECT MAX(id) FROM endpoint_attributes
                GROUP BY endpoint_id, COALESCE(mac, ''), ip, COALESCE(hostname, '')
            )",
            [],
        );
        // Create unique index that handles NULLs properly using COALESCE
        // This prevents duplicate rows even when mac or hostname is NULL
        let _ = conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_attributes_unique_combo ON endpoint_attributes (endpoint_id, COALESCE(mac, ''), ip, COALESCE(hostname, ''));",
            [],
        );
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

        // Try 1.5: Match by similar MAC (same first 5 bytes) for multi-interface devices
        // Routers/modems often have multiple NICs with sequential MACs (e.g., :50, :51, :52)
        // Only do this for gateway vendors to avoid false merges
        if let Some(ref mac_addr) = mac
            && mac_addr.len() >= 14  // xx:xx:xx:xx:xx format minimum
            && is_gateway_vendor_mac(mac_addr)
        {
            // Get the MAC prefix (first 5 bytes: xx:xx:xx:xx:xx)
            let mac_prefix = &mac_addr[..14].to_lowercase();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT ea.endpoint_id
                 FROM endpoint_attributes ea
                 JOIN endpoints e ON ea.endpoint_id = e.id
                 WHERE LOWER(SUBSTR(ea.mac, 1, 14)) = ?1
                   AND ea.mac IS NOT NULL
                   AND LENGTH(ea.mac) >= 14
                 ORDER BY
                   CASE WHEN e.name IS NOT NULL AND e.name != '' THEN 0 ELSE 1 END,
                   ea.endpoint_id ASC
                 LIMIT 1",
            ) && let Ok(Some(id)) = stmt.query_row([mac_prefix], |row| row.get(0)).optional()
            {
                return Some(id);
            }
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
    /// Only merges if vendors are compatible and IPs are in same subnet
    /// Keeps the endpoint with a non-empty name (or lowest ID if all empty)
    fn merge_duplicate_endpoints_by_mac(conn: &Connection, mac: &str) -> Result<()> {
        // Find all endpoints with this MAC, including their vendor info and IPs
        let mut stmt = conn.prepare(
            "SELECT DISTINCT ea.endpoint_id, COALESCE(e.name, '') as name,
                    COALESCE(e.custom_vendor, '') as custom_vendor,
                    COALESCE(e.manual_device_type, '') as device_type
             FROM endpoint_attributes ea
             JOIN endpoints e ON ea.endpoint_id = e.id
             WHERE LOWER(ea.mac) = LOWER(?1)
             ORDER BY
               CASE WHEN e.name IS NOT NULL AND e.name != '' THEN 0 ELSE 1 END,
               ea.endpoint_id ASC",
        )?;

        let endpoint_ids: Vec<(i64, String, String, String)> = stmt
            .query_map([mac], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        // If only one endpoint, nothing to merge
        if endpoint_ids.len() <= 1 {
            return Ok(());
        }

        // Get the MAC vendor for comparison
        let mac_vendor = get_mac_vendor(mac);

        // Keep the first one (has non-empty name or lowest ID)
        let keep_id = endpoint_ids[0].0;
        let keep_vendor = &endpoint_ids[0].2;
        let keep_device_type = &endpoint_ids[0].3;

        // Get IPs for the endpoint we're keeping
        let keep_ips: Vec<String> = conn
            .prepare("SELECT DISTINCT ip FROM endpoint_attributes WHERE endpoint_id = ?1")?
            .query_map([keep_id], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();

        // Check each candidate for merge compatibility
        let mut merge_ids: Vec<i64> = Vec::new();
        for (id, _name, custom_vendor, device_type) in endpoint_ids.iter().skip(1) {
            // Skip if vendors conflict (both have custom vendors set and they differ)
            if !keep_vendor.is_empty() && !custom_vendor.is_empty() && keep_vendor != custom_vendor
            {
                eprintln!(
                    "Skipping merge of endpoint {} - vendor conflict: '{}' vs '{}'",
                    id, keep_vendor, custom_vendor
                );
                continue;
            }

            // Skip if device types conflict (both set and different)
            if !keep_device_type.is_empty()
                && !device_type.is_empty()
                && keep_device_type != device_type
            {
                eprintln!(
                    "Skipping merge of endpoint {} - device type conflict: '{}' vs '{}'",
                    id, keep_device_type, device_type
                );
                continue;
            }

            // Get IPs for this endpoint
            let other_ips: Vec<String> = conn
                .prepare("SELECT DISTINCT ip FROM endpoint_attributes WHERE endpoint_id = ?1")?
                .query_map([id], |row| row.get(0))?
                .filter_map(|r| r.ok())
                .collect();

            // Check if IPs are in compatible subnets (at least one pair should be in same /24)
            let subnets_compatible = Self::check_subnet_compatibility(&keep_ips, &other_ips);
            if !subnets_compatible && !keep_ips.is_empty() && !other_ips.is_empty() {
                eprintln!(
                    "Skipping merge of endpoint {} - IPs not in compatible subnets: {:?} vs {:?}",
                    id, keep_ips, other_ips
                );
                continue;
            }

            // Check if the other endpoint has MACs with different vendors
            let other_macs: Vec<String> = conn
                .prepare("SELECT DISTINCT mac FROM endpoint_attributes WHERE endpoint_id = ?1 AND mac IS NOT NULL")?
                .query_map([id], |row| row.get(0))?
                .filter_map(|r| r.ok())
                .collect();

            let has_conflicting_mac_vendor = other_macs.iter().any(|other_mac| {
                if let (Some(v1), Some(v2)) = (mac_vendor, get_mac_vendor(other_mac)) {
                    v1 != v2
                } else {
                    false
                }
            });

            if has_conflicting_mac_vendor {
                eprintln!(
                    "Skipping merge of endpoint {} - conflicting MAC vendors detected",
                    id
                );
                continue;
            }

            merge_ids.push(*id);
        }

        // If nothing to merge after filtering, return
        if merge_ids.is_empty() {
            return Ok(());
        }

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

            // Move open_ports (ignore duplicates)
            conn.execute(
                "UPDATE OR IGNORE open_ports SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                params![keep_id, merge_id],
            )?;
            conn.execute(
                "DELETE FROM open_ports WHERE endpoint_id = ?1",
                params![merge_id],
            )?;

            // Move scan_results
            conn.execute(
                "UPDATE scan_results SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                params![keep_id, merge_id],
            )?;

            // Delete duplicate endpoint
            conn.execute("DELETE FROM endpoints WHERE id = ?1", params![merge_id])?;
        }

        Ok(())
    }

    /// Check if two sets of IPs have at least one pair in the same /24 subnet
    fn check_subnet_compatibility(ips1: &[String], ips2: &[String]) -> bool {
        for ip1 in ips1 {
            if let Ok(addr1) = ip1.parse::<Ipv4Addr>() {
                let subnet1 = u32::from(addr1) & 0xFFFFFF00; // /24 mask
                for ip2 in ips2 {
                    if let Ok(addr2) = ip2.parse::<Ipv4Addr>() {
                        let subnet2 = u32::from(addr2) & 0xFFFFFF00;
                        if subnet1 == subnet2 {
                            return true;
                        }
                    }
                }
            }
        }
        // If we couldn't parse IPs (e.g., IPv6), allow merge
        // TODO: Add IPv6 subnet compatibility check
        ips1.iter().any(|ip| ip.contains(':')) || ips2.iter().any(|ip| ip.contains(':'))
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
        // Strip local suffixes like .local, .lan, .home and normalize to lowercase
        let hostname = strip_local_suffix(&hostname).to_lowercase();
        // Filter out UUID-like hostnames - they're not useful display names
        let hostname = if is_uuid_like(&hostname) {
            String::new()
        } else {
            hostname
        };
        // Use INSERT OR IGNORE to skip duplicates (UNIQUE constraint may not catch NULLs)
        conn.execute(
            "INSERT OR IGNORE INTO endpoint_attributes (created_at, endpoint_id, mac, ip, hostname, dhcp_client_id, dhcp_vendor_class) VALUES (strftime('%s', 'now'), ?1, ?2, ?3, ?4, ?5, ?6)",
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
