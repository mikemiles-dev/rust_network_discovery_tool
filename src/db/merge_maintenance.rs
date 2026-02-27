//! General endpoint and communication merge/deduplication logic.
//!
//! Contains functions for merging duplicate communications, endpoints with
//! matching hostnames, and endpoints sharing IPv6 /64 prefixes.

use rusqlite::Connection;

/// Merge duplicate communication records that differ only by source_port
/// This is needed after migrating from the old unique index that included source_port
pub(super) fn merge_duplicate_communications(conn: &Connection) -> rusqlite::Result<usize> {
    // Find groups of communications with same key (excluding source_port)
    let duplicates: Vec<(i64, i64, i64, String, String, String)> = conn
        .prepare(
            "SELECT src_endpoint_id, dst_endpoint_id,
                    COALESCE(destination_port, 0) as dst_port,
                    COALESCE(ip_header_protocol, '') as proto,
                    COALESCE(sub_protocol, '') as sub_proto,
                    GROUP_CONCAT(id) as ids
             FROM communications
             GROUP BY src_endpoint_id, dst_endpoint_id, dst_port, proto, sub_proto
             HAVING COUNT(*) > 1",
        )?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();

    let mut merged_count = 0;

    for (src, dst, dst_port, proto, sub_proto, ids_str) in duplicates {
        let ids: Vec<i64> = ids_str.split(',').filter_map(|s| s.parse().ok()).collect();
        if ids.len() < 2 {
            continue;
        }

        // Keep the first (oldest) record, merge others into it
        let keep_id = ids[0];
        let merge_ids: Vec<i64> = ids[1..].to_vec();

        // Calculate aggregates from records to merge
        let (total_packets, total_bytes, max_last_seen): (i64, i64, i64) = conn.query_row(
            &format!(
                "SELECT SUM(packet_count), SUM(bytes), MAX(last_seen_at)
                 FROM communications WHERE id IN ({})",
                merge_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        // Update the kept record with aggregated values
        conn.execute(
            "UPDATE communications SET
                packet_count = packet_count + ?1,
                bytes = bytes + ?2,
                last_seen_at = MAX(last_seen_at, ?3)
             WHERE id = ?4",
            rusqlite::params![total_packets, total_bytes, max_last_seen, keep_id],
        )?;

        // Delete the merged records
        conn.execute(
            &format!(
                "DELETE FROM communications WHERE id IN ({})",
                merge_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            [],
        )?;

        merged_count += merge_ids.len();

        // Log for debugging
        eprintln!(
            "Merged {} communication records for {}→{} port {} {:?}/{:?}",
            merge_ids.len(),
            src,
            dst,
            dst_port,
            proto,
            sub_proto
        );
    }

    Ok(merged_count)
}

/// Merge duplicate endpoints that have the same hostname (case-insensitive)
pub(super) fn merge_duplicate_endpoints_by_hostname(conn: &Connection) -> rusqlite::Result<usize> {
    let mut merged_count = 0;

    // Find hostnames that have multiple endpoint IDs (case-insensitive duplicates)
    // Also fetch user-identification fields to prefer user-identified endpoints as survivors
    let mut stmt = conn.prepare(
        "SELECT LOWER(name) as lower_name, GROUP_CONCAT(id) as ids, COUNT(*) as cnt
         FROM endpoints
         WHERE name IS NOT NULL AND name != ''
         GROUP BY LOWER(name)
         HAVING cnt > 1",
    )?;

    let duplicates: Vec<(String, String)> = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

    for (_hostname, ids_str) in duplicates {
        let ids: Vec<i64> = ids_str.split(',').filter_map(|s| s.parse().ok()).collect();

        if ids.len() < 2 {
            continue;
        }

        // Prefer a user-identified endpoint as the survivor, then fall back to lowest ID
        let keep_id = ids
            .iter()
            .find(|&&id| {
                conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM endpoints WHERE id = ?1
                     AND (custom_name IS NOT NULL OR custom_vendor IS NOT NULL OR manual_device_type IS NOT NULL))",
                    [id],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap_or(false)
            })
            .copied()
            .unwrap_or(ids[0]);

        let merge_ids: Vec<i64> = ids.iter().copied().filter(|&id| id != keep_id).collect();

        for merge_id in merge_ids {
            merge_endpoint_into(conn, keep_id, merge_id)?;
            merged_count += 1;
        }
    }

    Ok(merged_count)
}

/// Merge endpoints that share the same IPv6 /64 prefix
/// This handles cases where a device has multiple IPv6 addresses (privacy extensions, etc.)
/// and was captured before hostname resolution, creating duplicate endpoints
pub(super) fn merge_endpoints_by_ipv6_prefix(conn: &Connection) -> rusqlite::Result<usize> {
    let mut merged_count = 0;

    // Find endpoints with IPv6 addresses, grouped by their /64 prefix
    // IPv6 /64 prefix is the first 4 colon-separated groups (e.g., "2607:fb90:9b88:4ec6")
    let mut stmt = conn.prepare(
        "SELECT
            substr(ea.ip, 1, instr(ea.ip || ':', ':') - 1) || ':' ||
            substr(substr(ea.ip, instr(ea.ip, ':') + 1), 1, instr(substr(ea.ip, instr(ea.ip, ':') + 1) || ':', ':') - 1) || ':' ||
            substr(substr(substr(ea.ip, instr(ea.ip, ':') + 1), instr(substr(ea.ip, instr(ea.ip, ':') + 1), ':') + 1), 1,
                instr(substr(substr(ea.ip, instr(ea.ip, ':') + 1), instr(substr(ea.ip, instr(ea.ip, ':') + 1), ':') + 1) || ':', ':') - 1) || ':' ||
            substr(substr(substr(substr(ea.ip, instr(ea.ip, ':') + 1), instr(substr(ea.ip, instr(ea.ip, ':') + 1), ':') + 1),
                instr(substr(substr(ea.ip, instr(ea.ip, ':') + 1), instr(substr(ea.ip, instr(ea.ip, ':') + 1), ':') + 1), ':') + 1), 1,
                instr(substr(substr(substr(ea.ip, instr(ea.ip, ':') + 1), instr(substr(ea.ip, instr(ea.ip, ':') + 1), ':') + 1),
                    instr(substr(substr(ea.ip, instr(ea.ip, ':') + 1), instr(substr(ea.ip, instr(ea.ip, ':') + 1), ':') + 1), ':') + 1) || ':', ':') - 1)
            as prefix,
            GROUP_CONCAT(DISTINCT e.id) as endpoint_ids,
            COUNT(DISTINCT e.id) as cnt
         FROM endpoint_attributes ea
         JOIN endpoints e ON ea.endpoint_id = e.id
         WHERE ea.ip LIKE '%:%:%:%:%'  -- Only IPv6 addresses (at least 4 colons)
           AND ea.ip NOT LIKE 'fe80:%'  -- Exclude link-local
         GROUP BY prefix
         HAVING cnt > 1",
    )?;

    let prefixes: Vec<(String, String)> = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

    for (_prefix, ids_str) in prefixes {
        let ids: Vec<i64> = ids_str.split(',').filter_map(|s| s.parse().ok()).collect();

        if ids.len() < 2 {
            continue;
        }

        // Find which endpoint has a proper hostname (not just an IP)
        // Prefer endpoints with hostnames over those with just IPv6 addresses as names
        // Also prefer user-identified endpoints as the survivor
        let mut best_id: Option<i64> = None;
        let mut ipv6_only_ids: Vec<i64> = Vec::new();

        for &id in &ids {
            let is_user_identified: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM endpoints WHERE id = ?1
                     AND (custom_name IS NOT NULL OR custom_vendor IS NOT NULL OR manual_device_type IS NOT NULL))",
                    [id],
                    |row| row.get(0),
                )
                .unwrap_or(false);

            let name: Option<String> = conn
                .query_row("SELECT name FROM endpoints WHERE id = ?1", [id], |row| {
                    row.get(0)
                })
                .ok();

            if is_user_identified {
                // User-identified endpoints always become best_id
                if best_id.is_none() {
                    best_id = Some(id);
                }
            } else if let Some(ref n) = name {
                // If name contains colons, it's likely an IPv6 address
                if n.contains(':') {
                    ipv6_only_ids.push(id);
                } else if best_id.is_none() {
                    best_id = Some(id);
                }
            }
        }

        // If we found a hostname-based endpoint and IPv6-only endpoints, merge them
        if let Some(keep_id) = best_id {
            for merge_id in ipv6_only_ids {
                // Skip deleting user-identified endpoints
                let is_user_identified: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM endpoints WHERE id = ?1
                         AND (custom_name IS NOT NULL OR custom_vendor IS NOT NULL OR manual_device_type IS NOT NULL))",
                        [merge_id],
                        |row| row.get(0),
                    )
                    .unwrap_or(false);
                if is_user_identified {
                    continue;
                }

                merge_endpoint_into(conn, keep_id, merge_id)?;
                merged_count += 1;
            }
        }
    }

    Ok(merged_count)
}

/// After merging endpoint `source_id` into `target_id`, copy any user-set
/// fields (custom_name, custom_vendor, manual_device_type) from source to
/// target if the target doesn't already have them.
fn preserve_user_fields(
    conn: &Connection,
    target_id: i64,
    source_id: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE endpoints SET
            custom_name = COALESCE(custom_name, (SELECT custom_name FROM endpoints WHERE id = ?2)),
            custom_vendor = COALESCE(custom_vendor, (SELECT custom_vendor FROM endpoints WHERE id = ?2)),
            manual_device_type = COALESCE(manual_device_type, (SELECT manual_device_type FROM endpoints WHERE id = ?2))
         WHERE id = ?1",
        rusqlite::params![target_id, source_id],
    )?;
    Ok(())
}

/// Merge endpoint `remove_id` into `keep_id`: preserve user fields, reassign
/// all related rows (attributes, communications, open_ports, scan_results),
/// then delete the source endpoint.
pub(super) fn merge_endpoint_into(
    conn: &Connection,
    keep_id: i64,
    remove_id: i64,
) -> rusqlite::Result<()> {
    // Preserve user fields — log errors but don't abort the merge
    if let Err(e) = preserve_user_fields(conn, keep_id, remove_id) {
        eprintln!(
            "Warning: failed to preserve user fields from endpoint {} into {}: {}",
            remove_id, keep_id, e
        );
    }

    // Move endpoint_attributes (ignore duplicates)
    conn.execute(
        "UPDATE OR IGNORE endpoint_attributes SET endpoint_id = ?1 WHERE endpoint_id = ?2",
        rusqlite::params![keep_id, remove_id],
    )?;
    conn.execute(
        "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
        [remove_id],
    )?;

    // Move communications (ignore duplicates that would violate unique constraint)
    conn.execute(
        "UPDATE OR IGNORE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
        rusqlite::params![keep_id, remove_id],
    )?;
    conn.execute(
        "UPDATE OR IGNORE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
        rusqlite::params![keep_id, remove_id],
    )?;
    conn.execute(
        "DELETE FROM communications WHERE src_endpoint_id = ?1 OR dst_endpoint_id = ?1",
        [remove_id],
    )?;

    // Move open_ports (ignore duplicates)
    conn.execute(
        "UPDATE OR IGNORE open_ports SET endpoint_id = ?1 WHERE endpoint_id = ?2",
        rusqlite::params![keep_id, remove_id],
    )?;
    conn.execute(
        "DELETE FROM open_ports WHERE endpoint_id = ?1",
        [remove_id],
    )?;

    // Move scan_results
    conn.execute(
        "UPDATE scan_results SET endpoint_id = ?1 WHERE endpoint_id = ?2",
        rusqlite::params![keep_id, remove_id],
    )?;

    // Delete the source endpoint
    conn.execute("DELETE FROM endpoints WHERE id = ?1", [remove_id])?;

    Ok(())
}
