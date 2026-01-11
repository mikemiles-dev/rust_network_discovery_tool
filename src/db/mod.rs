use rusqlite::Connection;
use tokio::{sync::mpsc, task};

use std::env;

use crate::network::communication::Communication;
use crate::network::endpoint::EndPoint;
use crate::network::endpoint_attribute::EndPointAttribute;

const MAX_CHANNEL_BUFFER_SIZE: usize = 50_000; // ~25MB at 500 bytes per Communication

pub fn new_connection() -> Connection {
    let db_url = get_database_url();
    let db_path = db_url.strip_prefix("sqlite://").unwrap_or(&db_url);
    let conn =
        Connection::open(db_path).unwrap_or_else(|_| panic!("Failed to open database: {}", db_url));

    // Set busy timeout first (this doesn't require any locks)
    let _ = conn.execute("PRAGMA busy_timeout = 5000;", []);

    // Try to enable WAL mode (only needs to succeed once per database)
    // This may fail if another connection has an active transaction, which is OK
    let _ = conn.execute("PRAGMA journal_mode = WAL;", []);

    // NORMAL sync is safe with WAL mode
    let _ = conn.execute("PRAGMA synchronous = NORMAL;", []);

    conn
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

fn get_database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| "test.db".to_string())
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

            const BATCH_SIZE: usize = 500;
            const BATCH_TIMEOUT_MS: u64 = 1000; // Flush every 1 second
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

        // Process all communications in a single transaction
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("Failed to start transaction: {}", e);
                batch.clear();
                return;
            }
        };

        for communication in batch.drain(..) {
            if let Err(e) = communication.insert_communication(&tx) {
                match e {
                    rusqlite::Error::SqliteFailure(err, Some(_msg))
                        if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        // Silently ignore constraint violations (duplicates)
                    }
                    _ => {
                        eprintln!("Failed to insert communication: {}", e);
                    }
                }
            }
        }

        if let Err(e) = tx.commit() {
            eprintln!("Failed to commit transaction: {}", e);
        }
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
