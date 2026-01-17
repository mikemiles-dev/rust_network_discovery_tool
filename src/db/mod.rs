use rusqlite::Connection;
use tokio::{sync::mpsc, task};

use std::env;
use std::sync::OnceLock;

use crate::network::communication::Communication;
use crate::network::endpoint::EndPoint;
use crate::network::endpoint_attribute::EndPointAttribute;

const MAX_CHANNEL_BUFFER_SIZE: usize = 50_000; // ~25MB at 500 bytes per Communication

pub fn new_connection() -> Connection {
    new_connection_result().expect("Failed to open database")
}

pub fn new_connection_result() -> Result<Connection, rusqlite::Error> {
    let db_url = get_database_url();
    let db_path = db_url.strip_prefix("sqlite://").unwrap_or(&db_url);
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
    conn.query_row(
        "SELECT value FROM settings WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
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

    fn process_batch(conn: &mut Connection, batch: &mut Vec<Communication>) {
        if batch.is_empty() {
            return;
        }

        const MAX_BATCH_RETRIES: u64 = 10;
        const BASE_DELAY_MS: u64 = 50;
        const MAX_DELAY_MS: u64 = 5000;

        for attempt in 1..=MAX_BATCH_RETRIES {
            // Try to process the entire batch in a transaction
            // Use IMMEDIATE to acquire write lock upfront and fail fast if busy
            let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            {
                Ok(tx) => tx,
                Err(e) => {
                    if attempt < MAX_BATCH_RETRIES {
                        // Exponential backoff with jitter and cap
                        let base_delay = BASE_DELAY_MS * (1 << (attempt - 1).min(6));
                        let delay = base_delay.min(MAX_DELAY_MS);
                        // Add 0-50% jitter to reduce thundering herd (using nanos as pseudo-random source)
                        let nanos = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.subsec_nanos())
                            .unwrap_or(0) as u64;
                        let jitter = (nanos % (delay / 2 + 1)).min(delay / 2);
                        std::thread::sleep(std::time::Duration::from_millis(delay + jitter));
                        continue;
                    }
                    eprintln!(
                        "Failed to start transaction after {} attempts: {}",
                        attempt, e
                    );
                    batch.clear();
                    return;
                }
            };

            let mut had_lock_error = false;

            for communication in batch.iter() {
                if let Err(e) = communication.insert_communication(&tx) {
                    match &e {
                        rusqlite::Error::SqliteFailure(err, _)
                            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                        {
                            // Silently ignore constraint violations (duplicates)
                        }
                        rusqlite::Error::SqliteFailure(err, _)
                            if err.code == rusqlite::ErrorCode::DatabaseBusy =>
                        {
                            // Database locked - will retry the whole batch
                            had_lock_error = true;
                            break;
                        }
                        _ => {
                            // Check if error message contains "database is locked"
                            if e.to_string().contains("database is locked") {
                                had_lock_error = true;
                                break;
                            }
                            eprintln!("Failed to insert communication: {}", e);
                        }
                    }
                }
            }

            if had_lock_error {
                // Rollback happens automatically when tx is dropped
                drop(tx);
                if attempt < MAX_BATCH_RETRIES {
                    // Exponential backoff with jitter and cap
                    let base_delay = BASE_DELAY_MS * (1 << (attempt - 1).min(6));
                    let delay = base_delay.min(MAX_DELAY_MS);
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.subsec_nanos())
                        .unwrap_or(0) as u64;
                    let jitter = (nanos % (delay / 2 + 1)).min(delay / 2);
                    std::thread::sleep(std::time::Duration::from_millis(delay + jitter));
                    continue;
                }
                eprintln!(
                    "Database locked after {} retry attempts, dropping batch of {} items",
                    attempt,
                    batch.len()
                );
                batch.clear();
                return;
            }

            // Success - commit and clear batch
            if let Err(e) = tx.commit() {
                if e.to_string().contains("database is locked") && attempt < MAX_BATCH_RETRIES {
                    let base_delay = BASE_DELAY_MS * (1 << (attempt - 1).min(6));
                    let delay = base_delay.min(MAX_DELAY_MS);
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.subsec_nanos())
                        .unwrap_or(0) as u64;
                    let jitter = (nanos % (delay / 2 + 1)).min(delay / 2);
                    std::thread::sleep(std::time::Duration::from_millis(delay + jitter));
                    continue;
                }
                eprintln!("Failed to commit transaction: {}", e);
            }

            batch.clear();
            return;
        }

        batch.clear();
    }

    fn cleanup_old_data(conn: &Connection) -> rusqlite::Result<()> {
        // Read retention from settings first, then env var, then default to 7 days
        let retention_days = get_setting_i64("data_retention_days",
            env::var("DATA_RETENTION_DAYS")
                .ok()
                .and_then(|val| val.parse::<i64>().ok())
                .unwrap_or(7)
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

        // Vacuum database occasionally to reclaim space
        if deleted > 1000 || deduped > 1000 || merged > 0 || ipv6_merged > 0 {
            println!("Running VACUUM to reclaim disk space...");
            conn.execute("VACUUM", [])?;
        }

        Ok(())
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

                    // Delete the duplicate endpoint
                    conn.execute("DELETE FROM endpoints WHERE id = ?1", [merge_id])?;

                    merged_count += 1;
                }
            }
        }

        Ok(merged_count)
    }
}
