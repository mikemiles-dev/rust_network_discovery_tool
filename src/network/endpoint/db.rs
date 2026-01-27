//! Database schema and CRUD operations for endpoints and internet destinations.

use rusqlite::{Connection, Result, params};
use std::collections::HashMap;

use super::EndPoint;
use super::types::InternetDestination;

impl EndPoint {
    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL,
                name TEXT
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_created_at ON endpoints (created_at);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_name ON endpoints (name);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_name_lower ON endpoints (LOWER(name));",
            [],
        )?;
        // Migration: Add manual_device_type column if it doesn't exist
        let has_column: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'manual_device_type'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_column {
            conn.execute(
                "ALTER TABLE endpoints ADD COLUMN manual_device_type TEXT",
                [],
            )?;
        }
        // Migration: Add custom_name column if it doesn't exist
        let has_custom_name_column: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'custom_name'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_custom_name_column {
            conn.execute("ALTER TABLE endpoints ADD COLUMN custom_name TEXT", [])?;
        }

        // Migration: Add ssdp_model column for UPnP model name
        let has_ssdp_model: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'ssdp_model'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_ssdp_model {
            conn.execute("ALTER TABLE endpoints ADD COLUMN ssdp_model TEXT", [])?;
        }

        // Migration: Add ssdp_friendly_name column for UPnP friendly name
        let has_ssdp_friendly_name: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'ssdp_friendly_name'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_ssdp_friendly_name {
            conn.execute(
                "ALTER TABLE endpoints ADD COLUMN ssdp_friendly_name TEXT",
                [],
            )?;
        }

        // Migration: Add custom_model column for manual model override
        let has_custom_model: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'custom_model'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_custom_model {
            conn.execute("ALTER TABLE endpoints ADD COLUMN custom_model TEXT", [])?;
        }

        // Migration: Add custom_vendor column for manual vendor override
        let has_custom_vendor: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'custom_vendor'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_custom_vendor {
            conn.execute("ALTER TABLE endpoints ADD COLUMN custom_vendor TEXT", [])?;
        }

        // Migration: Add auto_device_type column for persisting auto-detected device type
        let has_auto_device_type: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'auto_device_type'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_auto_device_type {
            conn.execute("ALTER TABLE endpoints ADD COLUMN auto_device_type TEXT", [])?;
        }

        // Migration: Add netbios_name column for NetBIOS discovered names
        let has_netbios_name: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'netbios_name'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_netbios_name {
            conn.execute("ALTER TABLE endpoints ADD COLUMN netbios_name TEXT", [])?;
        }

        // Create internet_destinations table for tracking external hosts
        conn.execute(
            "CREATE TABLE IF NOT EXISTS internet_destinations (
                id INTEGER PRIMARY KEY,
                hostname TEXT NOT NULL UNIQUE,
                first_seen_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                packet_count INTEGER DEFAULT 1,
                bytes_in INTEGER DEFAULT 0,
                bytes_out INTEGER DEFAULT 0
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_internet_destinations_hostname ON internet_destinations (hostname);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_internet_destinations_last_seen ON internet_destinations (last_seen_at);",
            [],
        )?;

        Ok(())
    }

    /// Insert or update an internet destination (external host)
    /// This is called when traffic is detected to/from a non-local IP
    pub fn insert_or_update_internet_destination(
        conn: &Connection,
        hostname: &str,
        bytes: i64,
        is_outbound: bool,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Try to insert a new record
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO internet_destinations (hostname, first_seen_at, last_seen_at, packet_count, bytes_in, bytes_out)
             VALUES (?1, ?2, ?2, 1, ?3, ?4)",
            params![
                hostname,
                now,
                if is_outbound { 0i64 } else { bytes },
                if is_outbound { bytes } else { 0i64 }
            ],
        )?;

        // If insert was ignored (record exists), update instead
        if inserted == 0 {
            if is_outbound {
                conn.execute(
                    "UPDATE internet_destinations SET last_seen_at = ?1, packet_count = packet_count + 1, bytes_out = bytes_out + ?2 WHERE hostname = ?3",
                    params![now, bytes, hostname],
                )?;
            } else {
                conn.execute(
                    "UPDATE internet_destinations SET last_seen_at = ?1, packet_count = packet_count + 1, bytes_in = bytes_in + ?2 WHERE hostname = ?3",
                    params![now, bytes, hostname],
                )?;
            }
        }

        Ok(())
    }

    /// Get all internet destinations sorted by last_seen_at descending
    pub fn get_internet_destinations(conn: &Connection) -> Result<Vec<InternetDestination>> {
        let mut stmt = conn.prepare(
            "SELECT id, hostname, first_seen_at, last_seen_at, packet_count, bytes_in, bytes_out
             FROM internet_destinations
             WHERE hostname NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
               AND hostname NOT LIKE '%:%'
               AND hostname NOT LIKE '%.local'
               AND hostname LIKE '%.%'
             ORDER BY last_seen_at DESC",
        )?;

        let destinations = stmt
            .query_map([], |row| {
                Ok(InternetDestination {
                    id: row.get(0)?,
                    hostname: row.get(1)?,
                    first_seen_at: row.get(2)?,
                    last_seen_at: row.get(3)?,
                    packet_count: row.get(4)?,
                    bytes_in: row.get(5)?,
                    bytes_out: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(destinations)
    }

    /// Set the manual device type for an endpoint by name or custom_name
    /// Pass None to clear the manual override and revert to automatic classification
    pub fn set_manual_device_type(
        conn: &Connection,
        endpoint_name: &str,
        device_type: Option<&str>,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET manual_device_type = ? WHERE LOWER(name) = LOWER(?) OR LOWER(custom_name) = LOWER(?)",
            params![device_type, endpoint_name, endpoint_name],
        )
    }

    /// Set the auto-detected device type for an endpoint (persists across renames)
    pub fn set_auto_device_type(
        conn: &Connection,
        endpoint_name: &str,
        device_type: &str,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET auto_device_type = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![device_type, endpoint_name],
        )
    }

    /// Get all auto-detected device types (for endpoints without manual overrides)
    /// Returns a map of display_name -> auto_device_type
    pub fn get_all_auto_device_types(conn: &Connection) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT COALESCE(custom_name, name), auto_device_type FROM endpoints WHERE auto_device_type IS NOT NULL AND auto_device_type != '' AND (name IS NOT NULL OR custom_name IS NOT NULL)",
        ) && let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                map.insert(row.0, row.1);
            }
        }
        map
    }

    /// Set a custom name for an endpoint by name, existing custom_name, or hostname in endpoint_attributes
    /// Pass None to clear the custom name and revert to auto-discovered hostname
    pub fn set_custom_name(
        conn: &Connection,
        endpoint_name: &str,
        custom_name: Option<&str>,
    ) -> Result<usize> {
        // Must join with endpoint_attributes because endpoints.name may be NULL
        // and the actual hostname is stored in endpoint_attributes.hostname
        conn.execute(
            "UPDATE endpoints SET custom_name = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![custom_name, endpoint_name],
        )
    }

    /// Set a custom model for an endpoint by name, custom_name, or hostname in endpoint_attributes
    /// Pass None to clear the custom model and revert to auto-detected model
    pub fn set_custom_model(
        conn: &Connection,
        endpoint_name: &str,
        custom_model: Option<&str>,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET custom_model = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![custom_model, endpoint_name],
        )
    }

    /// Set a custom vendor for an endpoint by name, custom_name, or hostname in endpoint_attributes
    /// Pass None to clear the custom vendor and revert to auto-detected vendor
    pub fn set_custom_vendor(
        conn: &Connection,
        endpoint_name: &str,
        custom_vendor: Option<&str>,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET custom_vendor = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![custom_vendor, endpoint_name],
        )
    }

    /// Get the original name of an endpoint (the name field, not custom_name)
    /// This is used when clearing a custom name to redirect to the original URL
    pub fn get_original_name(conn: &Connection, endpoint_name: &str) -> Option<String> {
        conn.query_row(
            "SELECT COALESCE(e.name, ea.hostname, ea.ip) FROM endpoints e
             LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
             WHERE LOWER(e.name) = LOWER(?1)
                OR LOWER(e.custom_name) = LOWER(?1)
                OR LOWER(ea.hostname) = LOWER(?1)
                OR LOWER(ea.ip) = LOWER(?1)
             LIMIT 1",
            params![endpoint_name],
            |row| row.get(0),
        )
        .ok()
    }

    /// Get all manual device types as a HashMap
    pub fn get_all_manual_device_types(conn: &Connection) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT COALESCE(custom_name, name), manual_device_type FROM endpoints WHERE manual_device_type IS NOT NULL AND (name IS NOT NULL OR custom_name IS NOT NULL)",
        ) && let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                map.insert(row.0, row.1);
            }
        }
        map
    }
}
