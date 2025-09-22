use rusqlite::{Connection, OptionalExtension, Result, params};

#[derive(Default, Debug)]
pub struct EndPointAttribute;

impl EndPointAttribute {
    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS endpoint_attributes (
                id INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL,
                endpoint_id INTEGER NOT NULL,
                mac TEXT NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT,
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(id),
                UNIQUE(mac, ip, hostname)
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoint_attributes_endpoint_id ON endpoint_attributes (endpoint_id);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoint_attributes_hostname ON endpoint_attributes (hostname);",
            [],
        )?;
        Ok(())
    }

    pub fn find_existing_endpoint_id(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        hostname: Option<String>,
    ) -> Option<i64> {
        let mut stmt =
            conn.prepare("SELECT endpoint_id FROM endpoint_attributes WHERE LOWER(mac) = LOWER(?1) OR LOWER(ip) = LOWER(?2) OR LOWER(hostname) = LOWER(?3)").ok()?;
        stmt.query_row(rusqlite::params![mac, ip, hostname], |row| row.get(0))
            .optional()
            .ok()?
    }

    pub fn insert_endpoint_attribute(
        conn: &Connection,
        endpoint_id: i64,
        mac: Option<String>,
        ip: Option<String>,
        hostname: String,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO endpoint_attributes (created_at, endpoint_id, mac, ip, hostname) VALUES (strftime('%s', 'now'), ?1, ?2, ?3, ?4)",
            params![endpoint_id, mac, ip, hostname],
        )?;
        Ok(())
    }
}
