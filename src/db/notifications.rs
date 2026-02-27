//! Notification helpers for endpoint-related events.

use rusqlite::Connection;

/// Fire-and-forget helper to insert a notification. Errors are logged, never propagated.
pub fn insert_notification(
    conn: &Connection,
    event_type: &str,
    title: &str,
    details: Option<&str>,
    endpoint_name: Option<&str>,
) {
    insert_notification_with_endpoint_id(conn, event_type, title, details, endpoint_name, None);
}

/// Fire-and-forget helper to insert a notification with an endpoint_id for dynamic name resolution.
pub fn insert_notification_with_endpoint_id(
    conn: &Connection,
    event_type: &str,
    title: &str,
    details: Option<&str>,
    endpoint_name: Option<&str>,
    endpoint_id: Option<i64>,
) {
    if let Err(e) = conn.execute(
        "INSERT INTO notifications (event_type, title, details, endpoint_name, endpoint_id) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![event_type, title, details, endpoint_name, endpoint_id],
    ) {
        eprintln!("Failed to insert notification: {}", e);
    }
}
