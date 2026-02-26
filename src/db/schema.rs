//! Database schema creation and migrations.

use rusqlite::Connection;

use crate::network::communication::Communication;
use crate::network::endpoint::EndPoint;
use crate::network::endpoint_attribute::EndPointAttribute;

/// Initialize all database tables and run any needed migrations.
/// Called once at startup from SQLWriter::new().
pub(crate) fn initialize_schema(conn: &Connection) {
    conn.execute("PRAGMA foreign_keys = ON;", [])
        .expect("Failed to set foreign key pragma");

    EndPoint::create_table_if_not_exists(conn).expect("Failed to create endpoints table");
    EndPointAttribute::create_table_if_not_exists(conn)
        .expect("Failed to create endpoint_attributes table");
    Communication::create_table_if_not_exists(conn)
        .expect("Failed to create communications table");

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

    // Create notifications table for event logging
    conn.execute(
        "CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            details TEXT,
            endpoint_name TEXT,
            endpoint_id INTEGER,
            dismissed INTEGER NOT NULL DEFAULT 0
        )",
        [],
    )
    .expect("Failed to create notifications table");

    // Add endpoint_id column if it doesn't exist (migration for existing databases)
    let _ = conn.execute(
        "ALTER TABLE notifications ADD COLUMN endpoint_id INTEGER",
        [],
    );

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC)",
        [],
    )
    .expect("Failed to create notifications index");

    // Insert default settings if they don't exist
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES
            ('cleanup_interval_seconds', '30'),
            ('data_retention_days', '7')",
        [],
    )
    .expect("Failed to insert default settings");
}
