use rusqlite::{Connection, Result};

#[derive(Default, Debug)]
pub struct EndPoint {
    interface: String,
    mac: Option<String>,
    ip: Option<String>,
}

impl EndPoint {
    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL,
                interface TEXT,
                mac TEXT,
                ip TEXT,
                UNIQUE(interface, ip),
                UNIQUE(interface, mac)
            )",
            [],
        )?;
        Ok(())
    }
}
