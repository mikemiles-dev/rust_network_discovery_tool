//! Settings persistence: get/set key-value pairs in the settings table.

use super::new_connection;

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
