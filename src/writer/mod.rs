use rusqlite::Connection;
use tokio::{sync::mpsc, task};

use std::env;

use crate::network::communication::Communication;
use crate::network::endpoint::EndPoint;

fn get_channel_buffer_size() -> usize {
    env::var("CHANNEL_BUFFER_SIZE")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(100) // Default value if env var is not set or invalid
}

fn get_database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://communications.db".to_string())
}

pub struct SQLWriter {
    pub sender: mpsc::Sender<Communication>,
    pub handle: task::JoinHandle<()>,
}

impl SQLWriter {
    pub async fn new() -> Self {
        let (tx, mut rx) = mpsc::channel::<Communication>(get_channel_buffer_size());
        println!(
            "SQL Writer started, connecting to database at {}",
            get_database_url()
        );

        let handle = task::spawn_blocking(move || {
            let conn = Connection::open("test.db")
                .unwrap_or_else(|_| panic!("Failed to open database: {}", get_database_url()));

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
                        rusqlite::Error::SqliteFailure(err, Some(_msg))
                            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                        {
                            //eprintln!("Constraint violation: {}", msg);
                        }
                        _ => {
                            eprintln!("Failed to insert communication: {}", e);
                        }
                    }
                }
            }
        });

        SQLWriter { sender: tx, handle }
    }
}
