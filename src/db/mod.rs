//! Database module. Manages SQLite connections and re-exports sub-module APIs.

mod hotspot_merge;
mod maintenance;
mod merge_maintenance;
mod notifications;
mod schema;
mod settings;
mod writer;

pub use notifications::{insert_notification, insert_notification_with_endpoint_id};
pub use settings::{get_all_settings, get_setting_i64, set_setting};
pub use writer::SQLWriter;

use rusqlite::Connection;
use std::env;
use std::sync::OnceLock;

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

pub fn new_connection() -> Connection {
    new_connection_result().expect("Failed to open database")
}

pub fn new_connection_result() -> Result<Connection, rusqlite::Error> {
    let db_url = get_database_url();
    let db_path = db_url.strip_prefix("sqlite://").unwrap_or(&db_url);

    // Attempt to clean up stale WAL/SHM files from previous crashes
    // This is especially important on Windows where file locking is stricter
    maintenance::cleanup_stale_wal_files(db_path);

    // Retry opening the database with backoff to handle transient CannotOpen errors
    // from concurrent connection storms (e.g., parallel web handler queries)
    let mut last_err = None;
    for attempt in 0..5 {
        match Connection::open(db_path) {
            Ok(conn) => {
                // Set busy timeout first (this doesn't require any locks)
                // 30 seconds to handle heavy contention during scanning
                let _ = conn.execute("PRAGMA busy_timeout = 30000;", []);

                // Try to enable WAL mode (only needs to succeed once per database)
                // This may fail if another connection has an active transaction, which is OK
                let _ = conn.execute("PRAGMA journal_mode = WAL;", []);

                // NORMAL sync is safe with WAL mode
                let _ = conn.execute("PRAGMA synchronous = NORMAL;", []);

                return Ok(conn);
            }
            Err(e) => {
                last_err = Some(e);
                if attempt < 4 {
                    std::thread::sleep(std::time::Duration::from_millis(50 * (1 << attempt)));
                }
            }
        }
    }

    let e = last_err.unwrap();
    eprintln!(
        "Failed to open database at '{}' after 5 attempts: {} (cwd: {:?})",
        db_path,
        e,
        std::env::current_dir()
    );
    Err(e)
}

#[cfg(test)]
pub fn new_test_connection() -> Connection {
    use crate::network::communication::Communication;
    use crate::network::endpoint::EndPoint;
    use crate::network::endpoint_attribute::EndPointAttribute;

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
