use std::env;
use tokio::sync::mpsc;

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
    sender: mpsc::Sender<crate::packet::communication::Communication>,
}

impl SQLWriter {
    pub async fn new() -> Self {
        let (tx, mut rx) = mpsc::channel(get_channel_buffer_size());

        tokio::spawn(async move {
            println!(
                "SQL Writer started, connecting to database at {}",
                get_database_url()
            );
            while let Some(communication) = rx.recv().await {
                // Here you would implement the logic to write the communication to the SQL database
                println!("Writing communication to database: {:?}", communication);
            }
        });

        SQLWriter { sender: tx }
    }

    pub fn write_communication(&self, communication: crate::packet::communication::Communication) {
        let sender = self.sender.clone();
        tokio::spawn(async move {
            if let Err(e) = sender.send(communication).await {
                eprintln!("Failed to send communication to SQL writer: {}", e);
            }
        });
    }
}
