//! WAL/SHM file cleanup and data maintenance (retention, deduplication, merges).

use rusqlite::Connection;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use super::get_setting_i64;
use super::hotspot_merge::merge_hotspot_gateways_into_phones;
use super::merge_maintenance::{
    merge_duplicate_communications, merge_duplicate_endpoints_by_hostname,
    merge_endpoints_by_ipv6_prefix,
};

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
