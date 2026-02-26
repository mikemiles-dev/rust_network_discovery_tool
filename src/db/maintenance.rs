//! WAL/SHM file cleanup and data maintenance (retention, deduplication, merges).

use rusqlite::Connection;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use super::get_setting_i64;

/// Flag to ensure WAL cleanup only runs once at startup
static WAL_CLEANUP_DONE: AtomicBool = AtomicBool::new(false);

/// Attempt to clean up stale WAL and SHM files from a previous crash.
/// This is especially important on Windows where file locking is stricter.
/// Only runs once at startup - subsequent calls are no-ops.
/// Returns true if cleanup was attempted (files existed), false otherwise.
pub(crate) fn cleanup_stale_wal_files(db_path: &str) -> bool {
    // Only attempt cleanup once at startup
    if WAL_CLEANUP_DONE.swap(true, Ordering::SeqCst) {
        return false;
    }
    // Skip for in-memory databases
    if db_path == ":memory:" || db_path.starts_with("file::memory:") {
        return false;
    }

    let wal_path = format!("{}-wal", db_path);
    let shm_path = format!("{}-shm", db_path);

    let wal_exists = Path::new(&wal_path).exists();
    let shm_exists = Path::new(&shm_path).exists();

    if !wal_exists && !shm_exists {
        return false;
    }

    // Check if the main database file exists - if not, WAL/SHM are definitely orphaned
    let db_exists = Path::new(db_path).exists();

    if !db_exists {
        // Database doesn't exist but WAL/SHM do - definitely orphaned
        eprintln!(
            "Found orphaned WAL/SHM files without main database, cleaning up: {}",
            db_path
        );
        let _ = fs::remove_file(&wal_path);
        let _ = fs::remove_file(&shm_path);
        return true;
    }

    // Try to detect if the WAL file is stale by checking if we can get exclusive access.
    // On Windows, if another process has the file open, this will fail.
    // On Unix, we check file modification time - if WAL is older than a threshold and
    // hasn't been modified, it's likely stale.

    #[cfg(target_os = "windows")]
    {
        // On Windows, file deletion fails if another process has the file open.
        // This is more reliable than checking file access modes.
        // We try to delete both files - if they're in use, the delete will fail
        // and we'll let SQLite handle the existing files normally.

        let mut cleaned = false;

        if wal_exists {
            match fs::remove_file(&wal_path) {
                Ok(()) => {
                    eprintln!("Cleaned up stale WAL file: {}", wal_path);
                    cleaned = true;
                }
                Err(e) => {
                    // File is likely in use by another process
                    eprintln!(
                        "Could not remove WAL file (may be in use): {} - {}",
                        wal_path, e
                    );
                }
            }
        }

        if shm_exists {
            match fs::remove_file(&shm_path) {
                Ok(()) => {
                    eprintln!("Cleaned up stale SHM file: {}", shm_path);
                    cleaned = true;
                }
                Err(e) => {
                    // File is likely in use by another process
                    eprintln!(
                        "Could not remove SHM file (may be in use): {} - {}",
                        shm_path, e
                    );
                }
            }
        }

        cleaned
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On Unix, check if the WAL/SHM files haven't been modified recently.
        // If idle for more than 30 seconds at startup, likely from a crashed process.
        use std::time::{Duration, SystemTime};

        const STALE_THRESHOLD_SECS: u64 = 30;

        // Helper to check if a file is stale
        let is_file_stale = |path: &str| -> bool {
            if let Ok(metadata) = fs::metadata(path)
                && let Ok(modified) = metadata.modified()
                && let Ok(elapsed) = SystemTime::now().duration_since(modified)
            {
                return elapsed > Duration::from_secs(STALE_THRESHOLD_SECS);
            }
            false
        };

        // Check WAL file staleness (primary indicator)
        let wal_stale = wal_exists && is_file_stale(&wal_path);
        // Check SHM file staleness (fallback if WAL doesn't exist)
        let shm_stale = shm_exists && is_file_stale(&shm_path);

        if wal_stale || shm_stale {
            if wal_exists {
                eprintln!("Cleaning up stale WAL file: {}", wal_path);
                let _ = fs::remove_file(&wal_path);
            }
            if shm_exists {
                eprintln!("Cleaning up stale SHM file: {}", shm_path);
                let _ = fs::remove_file(&shm_path);
            }
            return true;
        }

        false
    }
}

pub(crate) fn cleanup_old_data(conn: &Connection) -> rusqlite::Result<()> {
    // Read retention from settings first, then env var, then default to 7 days
    let retention_days = get_setting_i64(
        "data_retention_days",
        std::env::var("DATA_RETENTION_DAYS")
            .ok()
            .and_then(|val| val.parse::<i64>().ok())
            .unwrap_or(7),
    );

    let retention_seconds = retention_days * 24 * 60 * 60;

    // Delete old communications
    let deleted = conn.execute(
        "DELETE FROM communications WHERE created_at < (strftime('%s', 'now') - ?1)",
        [retention_seconds],
    )?;

    if deleted > 0 {
        println!(
            "Cleaned up {} old communication records (retention: {} days)",
            deleted, retention_days
        );
    }

    // Clean up orphaned endpoint attributes (but preserve user-identified endpoints)
    conn.execute(
        "DELETE FROM endpoint_attributes WHERE created_at < (strftime('%s', 'now') - ?1)
         AND endpoint_id NOT IN (
             SELECT DISTINCT src_endpoint_id FROM communications
             UNION
             SELECT DISTINCT dst_endpoint_id FROM communications
         )
         AND endpoint_id NOT IN (
             SELECT id FROM endpoints
             WHERE custom_name IS NOT NULL OR custom_vendor IS NOT NULL OR manual_device_type IS NOT NULL
         )",
        [retention_seconds],
    )?;

    // Deduplicate endpoint_attributes - keep only most recent row per (endpoint_id, ip, hostname) combo
    let deduped = conn.execute(
        "DELETE FROM endpoint_attributes WHERE id NOT IN (
            SELECT MAX(id) FROM endpoint_attributes
            GROUP BY endpoint_id, COALESCE(mac, ''), ip, COALESCE(hostname, '')
        )",
        [],
    )?;

    if deduped > 0 {
        println!("Removed {} duplicate endpoint_attribute rows", deduped);
    }

    // Merge duplicate communications (after removing source_port from unique key)
    // This aggregates records that differ only by source_port
    let comm_merged = merge_duplicate_communications(conn)?;
    if comm_merged > 0 {
        println!("Merged {} duplicate communication records", comm_merged);
    }

    // Merge duplicate endpoints with same hostname (case-insensitive)
    // This handles cases where mDNS discovered the same device with different hostname cases
    let merged = merge_duplicate_endpoints_by_hostname(conn)?;
    if merged > 0 {
        println!("Merged {} duplicate endpoints by hostname", merged);
    }

    // Merge endpoints that share the same IPv6 /64 prefix
    // This handles devices with multiple IPv6 addresses captured before hostname resolution
    let ipv6_merged = merge_endpoints_by_ipv6_prefix(conn)?;
    if ipv6_merged > 0 {
        println!("Merged {} duplicate endpoints by IPv6 prefix", ipv6_merged);
    }

    // Merge hotspot gateway endpoints into phone endpoints
    // This handles the case where an iPhone/Android hotspot creates a separate endpoint
    // for its public IPv6 gateway address
    let hotspot_merged = merge_hotspot_gateways_into_phones(conn)?;
    if hotspot_merged > 0 {
        println!(
            "Merged {} hotspot gateway endpoints into phones",
            hotspot_merged
        );
    }

    // Clean up old dismissed notifications (keep 7 days)
    let dismissed_cleaned = conn.execute(
        "DELETE FROM notifications WHERE dismissed = 1 AND created_at < (strftime('%s', 'now') - ?1)",
        [retention_seconds],
    ).unwrap_or(0);

    if dismissed_cleaned > 0 {
        println!(
            "Cleaned up {} old dismissed notifications",
            dismissed_cleaned
        );
    }

    // Vacuum database occasionally to reclaim space
    if deleted > 1000 || deduped > 1000 || merged > 0 || ipv6_merged > 0 || hotspot_merged > 0 {
        println!("Running VACUUM to reclaim disk space...");
        conn.execute("VACUUM", [])?;
    }

    Ok(())
}

/// Merge duplicate communication records that differ only by source_port
/// This is needed after migrating from the old unique index that included source_port
fn merge_duplicate_communications(conn: &Connection) -> rusqlite::Result<usize> {
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
fn merge_duplicate_endpoints_by_hostname(conn: &Connection) -> rusqlite::Result<usize> {
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
            // Preserve user fields before deleting the source
            preserve_user_fields(conn, keep_id, merge_id);

            // Move endpoint_attributes (ignore duplicates)
            conn.execute(
                "UPDATE OR IGNORE endpoint_attributes SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                rusqlite::params![keep_id, merge_id],
            )?;
            // Delete any that couldn't be moved (duplicates)
            conn.execute(
                "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
                [merge_id],
            )?;

            // Move communications (ignore duplicates that would violate unique constraint)
            conn.execute(
                "UPDATE OR IGNORE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
                rusqlite::params![keep_id, merge_id],
            )?;
            conn.execute(
                "UPDATE OR IGNORE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
                rusqlite::params![keep_id, merge_id],
            )?;
            // Delete any that couldn't be moved (duplicates)
            conn.execute(
                "DELETE FROM communications WHERE src_endpoint_id = ?1 OR dst_endpoint_id = ?1",
                [merge_id],
            )?;

            // Move open_ports (ignore duplicates)
            conn.execute(
                "UPDATE OR IGNORE open_ports SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                rusqlite::params![keep_id, merge_id],
            )?;
            // Delete any that couldn't be moved (duplicates)
            conn.execute("DELETE FROM open_ports WHERE endpoint_id = ?1", [merge_id])?;

            // Move scan_results
            conn.execute(
                "UPDATE scan_results SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                rusqlite::params![keep_id, merge_id],
            )?;

            // Delete the duplicate endpoint
            conn.execute("DELETE FROM endpoints WHERE id = ?1", [merge_id])?;

            merged_count += 1;
        }
    }

    Ok(merged_count)
}

/// Merge endpoints that share the same IPv6 /64 prefix
/// This handles cases where a device has multiple IPv6 addresses (privacy extensions, etc.)
/// and was captured before hostname resolution, creating duplicate endpoints
fn merge_endpoints_by_ipv6_prefix(conn: &Connection) -> rusqlite::Result<usize> {
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

                // Preserve user fields before deleting the source
                preserve_user_fields(conn, keep_id, merge_id);

                // Move endpoint_attributes
                conn.execute(
                    "UPDATE OR IGNORE endpoint_attributes SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                    rusqlite::params![keep_id, merge_id],
                )?;
                conn.execute(
                    "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
                    [merge_id],
                )?;

                // Move communications
                conn.execute(
                    "UPDATE OR IGNORE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
                    rusqlite::params![keep_id, merge_id],
                )?;
                conn.execute(
                    "UPDATE OR IGNORE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
                    rusqlite::params![keep_id, merge_id],
                )?;
                conn.execute(
                    "DELETE FROM communications WHERE src_endpoint_id = ?1 OR dst_endpoint_id = ?1",
                    [merge_id],
                )?;

                // Move open_ports
                conn.execute(
                    "UPDATE OR IGNORE open_ports SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                    rusqlite::params![keep_id, merge_id],
                )?;
                conn.execute("DELETE FROM open_ports WHERE endpoint_id = ?1", [merge_id])?;

                // Move scan_results
                conn.execute(
                    "UPDATE scan_results SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                    rusqlite::params![keep_id, merge_id],
                )?;

                // Delete the duplicate endpoint
                conn.execute("DELETE FROM endpoints WHERE id = ?1", [merge_id])?;

                merged_count += 1;
            }
        }
    }

    Ok(merged_count)
}

/// Check if an endpoint matches the hotspot gateway pattern:
/// 1. Public IPv6 address (not link-local fe80::)
/// 2. No MAC address associated
/// 3. No proper hostname (name is null, empty, or an IPv6 address)
/// 4. Only ICMPv6 traffic (router advertisements, neighbor discovery)
fn is_hotspot_gateway_candidate(conn: &Connection, endpoint_id: i64) -> bool {
    // Check 1: Has public IPv6, no MAC, no proper hostname
    let has_ipv6_no_mac: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM endpoint_attributes ea
                JOIN endpoints e ON e.id = ea.endpoint_id
                WHERE ea.endpoint_id = ?1
                  AND ea.ip LIKE '%:%:%:%:%'
                  AND ea.ip NOT LIKE 'fe80:%'
                  AND (ea.mac IS NULL OR ea.mac = '')
                  AND (e.name IS NULL OR e.name = '' OR e.name LIKE '%:%')
            )",
            [endpoint_id],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if !has_ipv6_no_mac {
        return false;
    }

    // Check 2: Only ICMPv6 traffic (or no traffic at all)
    let has_only_icmpv6: bool = conn
        .query_row(
            "SELECT NOT EXISTS(
                SELECT 1 FROM communications
                WHERE (src_endpoint_id = ?1 OR dst_endpoint_id = ?1)
                  AND ip_header_protocol IS NOT NULL
                  AND ip_header_protocol NOT IN ('Icmpv6', 'Hopopt', '')
            )",
            [endpoint_id],
            |row| row.get(0),
        )
        .unwrap_or(false);

    has_only_icmpv6
}

/// Find a phone endpoint that could be the hotspot host
/// Returns the endpoint ID if found
fn find_phone_for_hotspot_gateway(conn: &Connection, gateway_endpoint_id: i64) -> Option<i64> {
    // Find phone endpoints that could be providing hotspot
    // Criteria:
    // 1. Has a link-local fe80:: address (typical for hotspot phones)
    // 2. Has a phone-like hostname (iphone, ipad, galaxy, pixel, etc.)
    // 3. Different endpoint ID from the gateway
    // Note: We don't require MAC because the phone acting as hotspot gateway
    // may not have its MAC captured - only link-local IPv6 is visible
    conn.query_row(
        "SELECT DISTINCT e.id FROM endpoints e
         JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
         WHERE e.id != ?1
           AND (
               LOWER(e.name) LIKE '%iphone%'
               OR LOWER(e.name) LIKE '%ipad%'
               OR LOWER(e.name) LIKE '%galaxy%'
               OR LOWER(e.name) LIKE '%pixel%'
               OR LOWER(e.name) LIKE '%android%'
               OR LOWER(e.name) LIKE 'sm-%'
           )
           AND ea.ip LIKE 'fe80:%'
         LIMIT 1",
        rusqlite::params![gateway_endpoint_id],
        |row| row.get(0),
    )
    .ok()
}

/// Merge hotspot gateway endpoints into their corresponding phone endpoints
/// Hotspot gateways are identified by:
/// - Public IPv6 address (not fe80::)
/// - No MAC address
/// - No proper hostname
/// - Only ICMPv6 traffic
fn merge_hotspot_gateways_into_phones(conn: &Connection) -> rusqlite::Result<usize> {
    let mut merged_count = 0;

    // Find all endpoints that look like hotspot gateways
    // (no proper hostname, no MAC, public IPv6 address)
    let gateway_candidates: Vec<i64> = conn
        .prepare(
            "SELECT DISTINCT e.id
             FROM endpoints e
             JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
             WHERE (e.name IS NULL OR e.name = '' OR e.name LIKE '%:%')
               AND ea.ip LIKE '%:%:%:%:%'
               AND ea.ip NOT LIKE 'fe80:%'
               AND (ea.mac IS NULL OR ea.mac = '')
               AND e.custom_name IS NULL
               AND e.custom_vendor IS NULL
               AND e.manual_device_type IS NULL",
        )?
        .query_map([], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();

    for gateway_id in gateway_candidates {
        // Verify it matches the full hotspot gateway pattern (ICMPv6 only)
        if !is_hotspot_gateway_candidate(conn, gateway_id) {
            continue;
        }

        // Find a phone to merge into
        let Some(phone_id) = find_phone_for_hotspot_gateway(conn, gateway_id) else {
            continue;
        };

        // Preserve user fields before deleting the gateway
        preserve_user_fields(conn, phone_id, gateway_id);

        // Perform the merge (same pattern as other merge functions)
        // Move endpoint_attributes
        conn.execute(
            "UPDATE OR IGNORE endpoint_attributes SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![phone_id, gateway_id],
        )?;
        conn.execute(
            "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
            [gateway_id],
        )?;

        // Move communications
        conn.execute(
            "UPDATE OR IGNORE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
            rusqlite::params![phone_id, gateway_id],
        )?;
        conn.execute(
            "UPDATE OR IGNORE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
            rusqlite::params![phone_id, gateway_id],
        )?;
        conn.execute(
            "DELETE FROM communications WHERE src_endpoint_id = ?1 OR dst_endpoint_id = ?1",
            [gateway_id],
        )?;

        // Move open_ports
        conn.execute(
            "UPDATE OR IGNORE open_ports SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![phone_id, gateway_id],
        )?;
        conn.execute(
            "DELETE FROM open_ports WHERE endpoint_id = ?1",
            [gateway_id],
        )?;

        // Move scan_results
        conn.execute(
            "UPDATE scan_results SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            rusqlite::params![phone_id, gateway_id],
        )?;

        // Delete the gateway endpoint
        conn.execute("DELETE FROM endpoints WHERE id = ?1", [gateway_id])?;

        // Get phone name for logging
        let phone_name: String = conn
            .query_row(
                "SELECT name FROM endpoints WHERE id = ?1",
                [phone_id],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| format!("endpoint {}", phone_id));

        eprintln!(
            "Merged hotspot gateway into phone endpoint '{}'",
            phone_name
        );
        merged_count += 1;
    }

    Ok(merged_count)
}

/// After merging endpoint `source_id` into `target_id`, copy any user-set
/// fields (custom_name, custom_vendor, manual_device_type) from source to
/// target if the target doesn't already have them.
fn preserve_user_fields(conn: &Connection, target_id: i64, source_id: i64) {
    conn.execute(
        "UPDATE endpoints SET
            custom_name = COALESCE(custom_name, (SELECT custom_name FROM endpoints WHERE id = ?2)),
            custom_vendor = COALESCE(custom_vendor, (SELECT custom_vendor FROM endpoints WHERE id = ?2)),
            manual_device_type = COALESCE(manual_device_type, (SELECT manual_device_type FROM endpoints WHERE id = ?2))
         WHERE id = ?1",
        rusqlite::params![target_id, source_id],
    )
    .ok();
}
