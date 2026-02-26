//! SQLWriter: channel-based batch writer for communication records.

use rusqlite::Connection;
use tokio::{sync::mpsc, task};

use crate::network::communication::Communication;

use super::maintenance::cleanup_old_data;
use super::schema::initialize_schema;
use super::{get_database_url, get_setting_i64, new_connection};

const MAX_CHANNEL_BUFFER_SIZE: usize = 50_000; // ~25MB at 500 bytes per Communication

/// Result of attempting to process a batch of communications
enum BatchResult {
    Success,
    Retry,
    Failed,
}

fn get_channel_buffer_size() -> usize {
    std::env::var("CHANNEL_BUFFER_SIZE")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(MAX_CHANNEL_BUFFER_SIZE) // Default value if env var is not set or invalid
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

        // Initialize database schema synchronously before starting the receive loop.
        // This ensures all tables exist before the web server or scanners query them.
        task::spawn_blocking(|| {
            let conn = new_connection();
            initialize_schema(&conn);
        })
        .await
        .expect("Database initialization failed");

        // Now spawn the receive loop on a separate blocking thread
        task::spawn_blocking(move || {
            let mut conn = new_connection();

            conn.execute("PRAGMA foreign_keys = ON;", [])
                .expect("Failed to set foreign key pragma");

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
                    cleanup_old_data(&conn)
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
}
