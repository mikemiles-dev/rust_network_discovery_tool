//! Endpoint merge operations. Consolidates duplicate endpoints by merging
//! IPv6 siblings on the same /64 prefix and bare-IP endpoints with matching hostnames.

use rusqlite::{Connection, params};

use super::EndPoint;

impl EndPoint {
    /// Merge other endpoints on the same IPv6 /64 prefix into this endpoint
    /// Called when an endpoint gets a proper hostname, to consolidate IPv6-only duplicates
    pub(super) fn merge_ipv6_siblings_into_endpoint(conn: &Connection, target_endpoint_id: i64) {
        // Get IPv6 addresses for this endpoint
        let ipv6_addrs: Vec<String> = conn
            .prepare(
                "SELECT ip FROM endpoint_attributes WHERE endpoint_id = ?1 AND ip LIKE '%:%:%:%:%'",
            )
            .and_then(|mut stmt| {
                stmt.query_map([target_endpoint_id], |row| row.get(0))
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
            })
            .unwrap_or_default();

        if ipv6_addrs.is_empty() {
            return;
        }

        // Extract /64 prefixes (first 4 groups)
        let prefixes: Vec<String> = ipv6_addrs
            .iter()
            .filter_map(|ip| {
                let parts: Vec<&str> = ip.split(':').collect();
                if parts.len() >= 4 {
                    Some(format!(
                        "{}:{}:{}:{}",
                        parts[0], parts[1], parts[2], parts[3]
                    ))
                } else {
                    None
                }
            })
            .collect();

        if prefixes.is_empty() {
            return;
        }

        // Find other endpoints with IPv6 addresses on the same prefix that have IP-only names
        for prefix in prefixes {
            // Find endpoints with IPv6-like names (containing colons) on the same prefix
            let siblings: Vec<i64> = conn
                .prepare(
                    "SELECT DISTINCT e.id FROM endpoints e
                     JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                     WHERE ea.ip LIKE ?1 || ':%'
                       AND e.id != ?2
                       AND e.name LIKE '%:%'",
                )
                .and_then(|mut stmt| {
                    stmt.query_map(params![prefix, target_endpoint_id], |row| row.get(0))
                        .map(|rows| rows.filter_map(|r| r.ok()).collect())
                })
                .unwrap_or_default();

            for sibling_id in siblings {
                // Merge sibling into target
                let _ = conn.execute(
                    "UPDATE OR IGNORE endpoint_attributes SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute(
                    "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
                    [sibling_id],
                );
                let _ = conn.execute(
                    "UPDATE OR IGNORE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute(
                    "UPDATE OR IGNORE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute(
                    "DELETE FROM communications WHERE src_endpoint_id = ?1 OR dst_endpoint_id = ?1",
                    [sibling_id],
                );
                let _ = conn.execute(
                    "UPDATE OR IGNORE open_ports SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute(
                    "DELETE FROM open_ports WHERE endpoint_id = ?1",
                    [sibling_id],
                );
                let _ = conn.execute(
                    "UPDATE scan_results SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute("DELETE FROM endpoints WHERE id = ?1", [sibling_id]);
                println!(
                    "Merged IPv6 endpoint {} into {} (same /64 prefix: {})",
                    sibling_id, target_endpoint_id, prefix
                );
            }
        }
    }

    /// Merge a bare-IP/randomized-MAC endpoint into an existing endpoint with the same hostname.
    /// Only merges if the current endpoint has no real (non-locally-administered) MAC,
    /// to avoid accidentally merging two well-identified devices.
    pub(super) fn try_merge_by_hostname(conn: &Connection, endpoint_id: i64, hostname: &str) {
        // Check if this endpoint has any real (non-randomized) MAC
        let has_real_mac: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM endpoint_attributes
                    WHERE endpoint_id = ?1
                    AND mac IS NOT NULL AND mac != ''
                    AND UPPER(SUBSTR(mac, 2, 1)) NOT IN ('2', '6', 'A', 'E')
                )",
                params![endpoint_id],
                |row| row.get(0),
            )
            .unwrap_or(true); // Default to true (don't merge) on error

        if has_real_mac {
            return; // Only merge bare-IP or randomized-MAC endpoints
        }

        // Find another endpoint with the same name or custom_name (case-insensitive)
        let target_id: Option<i64> = conn
            .query_row(
                "SELECT id FROM endpoints
                 WHERE id != ?1
                 AND (LOWER(name) = LOWER(?2) OR LOWER(custom_name) = LOWER(?2))
                 LIMIT 1",
                params![endpoint_id, hostname],
                |row| row.get(0),
            )
            .ok();

        let Some(target_id) = target_id else {
            return;
        };

        // Preserve user fields (custom_name, custom_vendor, manual_device_type) before merge
        let _ = conn.execute(
            "UPDATE endpoints SET
                custom_name = COALESCE(custom_name, (SELECT custom_name FROM endpoints WHERE id = ?2)),
                custom_vendor = COALESCE(custom_vendor, (SELECT custom_vendor FROM endpoints WHERE id = ?2)),
                manual_device_type = COALESCE(manual_device_type, (SELECT manual_device_type FROM endpoints WHERE id = ?2))
             WHERE id = ?1",
            params![target_id, endpoint_id],
        );

        // Merge current endpoint INTO the target (keep the older, better-identified one)
        let _ = conn.execute(
            "UPDATE OR IGNORE endpoint_attributes SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            params![target_id, endpoint_id],
        );
        let _ = conn.execute(
            "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
            [endpoint_id],
        );
        let _ = conn.execute(
            "UPDATE OR IGNORE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
            params![target_id, endpoint_id],
        );
        let _ = conn.execute(
            "UPDATE OR IGNORE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
            params![target_id, endpoint_id],
        );
        let _ = conn.execute(
            "DELETE FROM communications WHERE src_endpoint_id = ?1 OR dst_endpoint_id = ?1",
            [endpoint_id],
        );
        let _ = conn.execute(
            "UPDATE OR IGNORE open_ports SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            params![target_id, endpoint_id],
        );
        let _ = conn.execute(
            "DELETE FROM open_ports WHERE endpoint_id = ?1",
            [endpoint_id],
        );
        let _ = conn.execute(
            "UPDATE scan_results SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            params![target_id, endpoint_id],
        );
        let _ = conn.execute("DELETE FROM endpoints WHERE id = ?1", [endpoint_id]);
        println!(
            "Merged endpoint {} into {} (same hostname: {})",
            endpoint_id, target_id, hostname
        );
    }
}
