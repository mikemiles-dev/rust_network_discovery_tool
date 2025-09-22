use rusqlite::Connection;
use tokio::{sync::mpsc, task};

use std::env;

use crate::network::communication::Communication;
use crate::network::endpoint::EndPoint;

const MAX_CHANNEL_BUFFER_SIZE: usize = 10_000_000;

pub fn new_connection() -> Connection {
    let db_url = get_database_url();
    Connection::open("test.db").unwrap_or_else(|_| panic!("Failed to open database: {}", db_url))
}

fn get_channel_buffer_size() -> usize {
    env::var("CHANNEL_BUFFER_SIZE")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(MAX_CHANNEL_BUFFER_SIZE) // Default value if env var is not set or invalid
}

fn get_database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://communications.db".to_string())
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
            let conn = new_connection();

            // Execute the PRAGMA foreign_keys = ON; statement
            conn.execute("PRAGMA foreign_keys = ON;", [])
                .expect("Failed to set foreign key pragma");

            EndPoint::create_table_if_not_exists(&conn)
                .expect("Failed to create table if not exists");
            Communication::create_table_if_not_exists(&conn)
                .expect("Failed to create table if not exists");

            while let Some(communication) = rx.blocking_recv() {
                if let Err(e) = communication.insert_communication(&conn) {
                    match e {
                        rusqlite::Error::SqliteFailure(err, Some(msg))
                            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                        {
                            eprintln!("Constraint violation: {}", msg);
                        }
                        _ => {
                            eprintln!("Failed to insert communication: {}", e);
                        }
                    }
                }
            }
        });

        SQLWriter { sender: tx }
    }
}
