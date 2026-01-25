use rusqlite::Connection;
use tokio::{sync::mpsc, task};

use std::env;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::network::communication::Communication;
use crate::network::endpoint::EndPoint;
use crate::network::endpoint_attribute::EndPointAttribute;

const MAX_CHANNEL_BUFFER_SIZE: usize = 50_000; // ~25MB at 500 bytes per Communication

/// Flag to ensure WAL cleanup only runs once at startup
static WAL_CLEANUP_DONE: AtomicBool = AtomicBool::new(false);

/// Attempt to clean up stale WAL and SHM files from a previous crash.
/// This is especially important on Windows where file locking is stricter.
/// Only runs once at startup - subsequent calls are no-ops.
/// Returns true if cleanup was attempted (files existed), false otherwise.
fn cleanup_stale_wal_files(db_path: &str) -> bool {
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

/// Result of attempting to process a batch of communications
enum BatchResult {
    Success,
    Retry,
    Failed,
}

pub fn new_connection() -> Connection {
    new_connection_result().expect("Failed to open database")
}

pub fn new_connection_result() -> Result<Connection, rusqlite::Error> {
    let db_url = get_database_url();
    let db_path = db_url.strip_prefix("sqlite://").unwrap_or(&db_url);

    // Attempt to clean up stale WAL/SHM files from previous crashes
    // This is especially important on Windows where file locking is stricter
    cleanup_stale_wal_files(db_path);

    let conn = Connection::open(db_path).map_err(|e| {
        eprintln!(
            "Failed to open database at '{}': {} (cwd: {:?})",
            db_path,
            e,
            std::env::current_dir()
        );
        e
    })?;

    // Set busy timeout first (this doesn't require any locks)
    // 30 seconds to handle heavy contention during scanning
    let _ = conn.execute("PRAGMA busy_timeout = 30000;", []);

    // Try to enable WAL mode (only needs to succeed once per database)
    // This may fail if another connection has an active transaction, which is OK
    let _ = conn.execute("PRAGMA journal_mode = WAL;", []);

    // NORMAL sync is safe with WAL mode
    let _ = conn.execute("PRAGMA synchronous = NORMAL;", []);

    Ok(conn)
}

/// Get a setting value from the database
pub fn get_setting(key: &str) -> Option<String> {
    let conn = new_connection();
    conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
        row.get(0)
    })
    .ok()
}

/// Get a setting value as i64, with a default fallback
pub fn get_setting_i64(key: &str, default: i64) -> i64 {
    get_setting(key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Set a setting value in the database
pub fn set_setting(key: &str, value: &str) -> Result<(), rusqlite::Error> {
    let conn = new_connection();
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, strftime('%s', 'now'))
         ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = strftime('%s', 'now')",
        rusqlite::params![key, value],
    )?;
    Ok(())
}

/// Get all settings as a HashMap
pub fn get_all_settings() -> std::collections::HashMap<String, String> {
    let conn = new_connection();
    let mut settings = std::collections::HashMap::new();

    if let Ok(mut stmt) = conn.prepare("SELECT key, value FROM settings")
        && let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
    {
        for row in rows.flatten() {
            settings.insert(row.0, row.1);
        }
    }

    settings
}

#[cfg(test)]
pub fn new_test_connection() -> Connection {
    let conn = Connection::open_in_memory().expect("Failed to create in-memory database");

    // Set up foreign keys and create tables
    conn.execute("PRAGMA foreign_keys = ON;", [])
        .expect("Failed to set foreign key pragma");

    EndPoint::create_table_if_not_exists(&conn).expect("Failed to create endpoints table");
    EndPointAttribute::create_table_if_not_exists(&conn)
        .expect("Failed to create endpoint_attributes table");
    Communication::create_table_if_not_exists(&conn)
        .expect("Failed to create communications table");

    conn
}

fn get_channel_buffer_size() -> usize {
    env::var("CHANNEL_BUFFER_SIZE")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(MAX_CHANNEL_BUFFER_SIZE) // Default value if env var is not set or invalid
}

static RESOLVED_DB_PATH: OnceLock<String> = OnceLock::new();

fn get_database_url() -> String {
    RESOLVED_DB_PATH
        .get_or_init(|| {
            let db_path = env::var("DATABASE_URL").unwrap_or_else(|_| "test.db".to_string());

            // Convert relative paths to absolute to avoid issues with working directory changes
            if !db_path.starts_with('/')
                && !db_path.starts_with("sqlite://")
                && db_path != ":memory:"
                && let Ok(cwd) = env::current_dir()
            {
                let abs_path = cwd.join(&db_path).to_string_lossy().to_string();
                eprintln!("Database path resolved to: {}", abs_path);
                return abs_path;
            }

            db_path
        })
        .clone()
}

pub struct SQLWriter {
    pub sender: mpsc::Sender<Communication>,
}

impl SQLWriter {
    pub async fn new() -> Self {
        let (tx, mut rx) = mpsc::channel::<Communication>(get_channel_buffer_size());
        println!(
            "SQL Writer started, connecting to database at {}",
            get_database_url()
        );

        task::spawn_blocking(move || {
            let mut conn = new_connection();

            // Execute the PRAGMA foreign_keys = ON; statement
            conn.execute("PRAGMA foreign_keys = ON;", [])
                .expect("Failed to set foreign key pragma");

            EndPoint::create_table_if_not_exists(&conn)
                .expect("Failed to create table if not exists");
            EndPointAttribute::create_table_if_not_exists(&conn)
                .expect("Failed to create table if not exists");
            Communication::create_table_if_not_exists(&conn)
                .expect("Failed to create table if not exists");

            // Create scanner-related tables at startup to avoid schema locks during scanning
            conn.execute(
                "CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY,
                    endpoint_id INTEGER NOT NULL,
                    scan_type TEXT NOT NULL,
                    scanned_at INTEGER NOT NULL,
                    response_time_ms INTEGER,
                    details TEXT,
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
                )",
                [],
            )
            .expect("Failed to create scan_results table");

            conn.execute(
                "CREATE TABLE IF NOT EXISTS open_ports (
                    id INTEGER PRIMARY KEY,
                    endpoint_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT DEFAULT 'tcp',
                    service_name TEXT,
                    last_seen_at INTEGER NOT NULL,
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id),
                    UNIQUE(endpoint_id, port, protocol)
                )",
                [],
            )
            .expect("Failed to create open_ports table");

            // Create settings table for user-configurable options
            conn.execute(
                "CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
                )",
                [],
            )
            .expect("Failed to create settings table");

            // Insert default settings if they don't exist
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES
                    ('cleanup_interval_seconds', '30'),
                    ('data_retention_days', '7')",
                [],
            )
            .expect("Failed to insert default settings");

            const BATCH_SIZE: usize = 100; // Smaller batches to reduce lock time
            const BATCH_TIMEOUT_MS: u64 = 500; // Flush every 0.5 seconds
            let mut batch = Vec::with_capacity(BATCH_SIZE);
            let mut last_flush = std::time::Instant::now();

            loop {
                // Try to receive without blocking
                match rx.try_recv() {
                    Ok(communication) => {
                        batch.push(communication);

                        // Flush if batch is full
                        if batch.len() >= BATCH_SIZE {
                            Self::process_batch(&mut conn, &mut batch);
                            last_flush = std::time::Instant::now();
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        // Flush batch if timeout reached and we have pending items
                        if !batch.is_empty()
                            && last_flush.elapsed().as_millis() >= BATCH_TIMEOUT_MS as u128
                        {
                            Self::process_batch(&mut conn, &mut batch);
                            last_flush = std::time::Instant::now();
                        }
                        // Sleep briefly to avoid busy-waiting
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        // Channel closed, process remaining items and exit
                        if !batch.is_empty() {
                            Self::process_batch(&mut conn, &mut batch);
                        }
                        break;
                    }
                }
            }
        });

        // Spawn separate cleanup task that runs at startup, then at configurable interval
        task::spawn(async {
            // Run cleanup immediately at startup (with small delay to let tables be created)
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            loop {
                let result = task::spawn_blocking(|| {
                    let conn = new_connection();
                    Self::cleanup_old_data(&conn)
                })
                .await;

                if let Ok(Err(e)) = result {
                    eprintln!("Failed to cleanup old data: {}", e);
                }

                // Read cleanup interval from settings (default 30 seconds)
                let interval_secs = get_setting_i64("cleanup_interval_seconds", 30);
                tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs as u64)).await;
            }
        });

        SQLWriter { sender: tx }
    }

    /// Compute exponential backoff delay with jitter to reduce thundering herd.
    /// Uses saturating arithmetic to prevent overflow.
    fn backoff_delay(attempt: u64) -> std::time::Duration {
        const BASE_DELAY_MS: u64 = 50;
        const MAX_DELAY_MS: u64 = 5000;

        // Cap shift amount to prevent overflow: 1 << 6 = 64, so max base = 50 * 64 = 3200
        let shift = attempt.saturating_sub(1).min(6) as u32;
        let base_delay = BASE_DELAY_MS.saturating_mul(1u64 << shift);
        let delay = base_delay.min(MAX_DELAY_MS);

        // Add 0-50% jitter using subsec nanos as pseudo-random source
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        let half_delay = delay / 2;
        let jitter = nanos % (half_delay.saturating_add(1));

        std::time::Duration::from_millis(delay.saturating_add(jitter.min(half_delay)))
    }

    fn process_batch(conn: &mut Connection, batch: &mut Vec<Communication>) {
        if batch.is_empty() {
            return;
        }

        const MAX_RETRIES: u64 = 10;

        for attempt in 1..=MAX_RETRIES {
            match Self::try_process_batch(conn, batch, attempt, MAX_RETRIES) {
                BatchResult::Success => {
                    batch.clear();
                    return;
                }
                BatchResult::Retry => {
                    std::thread::sleep(Self::backoff_delay(attempt));
                    continue;
                }
                BatchResult::Failed => {
                    batch.clear();
                    return;
                }
            }
        }

        batch.clear();
    }

    fn try_process_batch(
        conn: &mut Connection,
        batch: &[Communication],
        attempt: u64,
        max_retries: u64,
    ) -> BatchResult {
        // Use IMMEDIATE to acquire write lock upfront and fail fast if busy
        let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
            Ok(tx) => tx,
            Err(_) if attempt < max_retries => return BatchResult::Retry,
            Err(e) => {
                eprintln!(
                    "Failed to start transaction after {} attempts: {}",
                    attempt, e
                );
                return BatchResult::Failed;
            }
        };

        // Insert all communications, checking for lock errors
        if Self::insert_batch_items(&tx, batch) {
            // Had lock error - drop transaction (auto-rollback) and retry
            drop(tx);
            if attempt < max_retries {
                return BatchResult::Retry;
            }
            eprintln!(
                "Database locked after {} retry attempts, dropping batch of {} items",
                attempt,
                batch.len()
            );
            return BatchResult::Failed;
        }

        // Try to commit
        match tx.commit() {
            Ok(()) => BatchResult::Success,
            Err(e) if e.to_string().contains("database is locked") && attempt < max_retries => {
                BatchResult::Retry
            }
            Err(e) => {
                eprintln!("Failed to commit transaction: {}", e);
                BatchResult::Success // Items were inserted, just commit failed
            }
        }
    }

    /// Insert batch items into transaction. Returns true if a lock error occurred.
    fn insert_batch_items(tx: &rusqlite::Transaction, batch: &[Communication]) -> bool {
        for communication in batch {
            if let Err(e) = communication.insert_communication(tx) {
                if Self::is_lock_error(&e) {
                    return true;
                }
                if !Self::is_constraint_violation(&e) {
                    eprintln!("Failed to insert communication: {}", e);
                }
            }
        }
        false
    }

    fn is_lock_error(e: &rusqlite::Error) -> bool {
        matches!(
            e,
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::DatabaseBusy
        ) || e.to_string().contains("database is locked")
    }

    fn is_constraint_violation(e: &rusqlite::Error) -> bool {
        matches!(
            e,
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation
        )
    }

    fn cleanup_old_data(conn: &Connection) -> rusqlite::Result<()> {
        // Read retention from settings first, then env var, then default to 7 days
        let retention_days = get_setting_i64(
            "data_retention_days",
            env::var("DATA_RETENTION_DAYS")
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

        // Clean up orphaned endpoint attributes
        conn.execute(
            "DELETE FROM endpoint_attributes WHERE created_at < (strftime('%s', 'now') - ?1)
             AND endpoint_id NOT IN (
                 SELECT DISTINCT src_endpoint_id FROM communications
                 UNION
                 SELECT DISTINCT dst_endpoint_id FROM communications
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
        let comm_merged = Self::merge_duplicate_communications(conn)?;
        if comm_merged > 0 {
            println!("Merged {} duplicate communication records", comm_merged);
        }

        // Merge duplicate endpoints with same hostname (case-insensitive)
        // This handles cases where mDNS discovered the same device with different hostname cases
        let merged = Self::merge_duplicate_endpoints_by_hostname(conn)?;
        if merged > 0 {
            println!("Merged {} duplicate endpoints by hostname", merged);
        }

        // Merge endpoints that share the same IPv6 /64 prefix
        // This handles devices with multiple IPv6 addresses captured before hostname resolution
        let ipv6_merged = Self::merge_endpoints_by_ipv6_prefix(conn)?;
        if ipv6_merged > 0 {
            println!("Merged {} duplicate endpoints by IPv6 prefix", ipv6_merged);
        }

        // Merge hotspot gateway endpoints into phone endpoints
        // This handles the case where an iPhone/Android hotspot creates a separate endpoint
        // for its public IPv6 gateway address
        let hotspot_merged = Self::merge_hotspot_gateways_into_phones(conn)?;
        if hotspot_merged > 0 {
            println!(
                "Merged {} hotspot gateway endpoints into phones",
                hotspot_merged
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

            // Keep the first (lowest) ID, merge others into it
            let keep_id = ids[0];
            let merge_ids: Vec<i64> = ids[1..].to_vec();

            for merge_id in merge_ids {
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
            let mut best_id: Option<i64> = None;
            let mut ipv6_only_ids: Vec<i64> = Vec::new();

            for &id in &ids {
                let name: Option<String> = conn
                    .query_row("SELECT name FROM endpoints WHERE id = ?1", [id], |row| {
                        row.get(0)
                    })
                    .ok();

                if let Some(ref n) = name {
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
                   AND (ea.mac IS NULL OR ea.mac = '')",
            )?
            .query_map([], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();

        for gateway_id in gateway_candidates {
            // Verify it matches the full hotspot gateway pattern (ICMPv6 only)
            if !Self::is_hotspot_gateway_candidate(conn, gateway_id) {
                continue;
            }

            // Find a phone to merge into
            let Some(phone_id) = Self::find_phone_for_hotspot_gateway(conn, gateway_id) else {
                continue;
            };

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
}
