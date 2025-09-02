use rusqlite::Connection;
use tokio::sync::mpsc;

use std::env;

use crate::packet::communication::Communication;

fn get_channel_buffer_size() -> usize {
    env::var("CHANNEL_BUFFER_SIZE")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(100) // Default value if env var is not set or invalid
}

fn get_database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://communications.db".to_string())
}

#[derive(Clone)]
pub struct SQLWriter {
    pub sender: mpsc::Sender<crate::packet::communication::Communication>,
}

impl SQLWriter {
    pub async fn new() -> Self {
        let (tx, mut rx) = mpsc::channel::<Communication>(get_channel_buffer_size());

        tokio::spawn(async move {
            println!(
                "SQL Writer started, connecting to database at {}",
                get_database_url()
            );

            let conn = Connection::open("test.db")
                .unwrap_or_else(|_| panic!("Failed to open database: {}", get_database_url()));

            Communication::create_table_if_not_exists(&conn)
                .expect("Failed to create table if not exists");

            while let Some(communication) = rx.recv().await {
                communication
                    .insert_communication(&conn)
                    .expect("Failed to insert communication");
            }
        });

        SQLWriter { sender: tx }
    }
}
