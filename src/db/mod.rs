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

        // Spawn separate cleanup task that runs every hour
        task::spawn(async {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await; // 1 hour

                let result = task::spawn_blocking(|| {
                    let conn = new_connection();
                    Self::cleanup_old_data(&conn)
                })
                .await;

                if let Ok(Err(e)) = result {
                    eprintln!("Failed to cleanup old data: {}", e);
                }
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
        let retention_days = env::var("DATA_RETENTION_DAYS")
            .ok()
            .and_then(|val| val.parse::<i64>().ok())
            .unwrap_or(7); // Default: keep 7 days

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

        // Vacuum database occasionally to reclaim space
        if deleted > 1000 {
            println!("Running VACUUM to reclaim disk space...");
            conn.execute("VACUUM", [])?;
        }

        Ok(())
    }
}
