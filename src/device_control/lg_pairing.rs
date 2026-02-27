//! LG webOS TV pairing and token management. Handles WebSocket handshake
//! registration, client key storage/retrieval, and interactive pairing prompts.

use super::types::CommandResult;
use std::time::Duration;
use tungstenite::{Message, connect};

/// WebSocket port for LG webOS TVs
const WS_PORT: u16 = 3000;

/// Retrieve a stored pairing key for an LG TV from the database.
pub(crate) fn get_client_key(ip: &str) -> Option<String> {
    use crate::db::new_connection;

    let conn = new_connection();

    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS lg_tokens (
                ip TEXT PRIMARY KEY,
                client_key TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
        [],
    );

    let mut stmt = conn
        .prepare("SELECT client_key FROM lg_tokens WHERE ip = ?")
        .ok()?;
    stmt.query_row([ip], |row| row.get(0)).ok()
}

/// Persist a pairing key for an LG TV to the database.
pub(crate) fn store_client_key(ip: &str, client_key: &str) -> bool {
    use crate::db::new_connection;

    let conn = new_connection();

    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS lg_tokens (
                ip TEXT PRIMARY KEY,
                client_key TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
        [],
    );

    conn.execute(
        "INSERT OR REPLACE INTO lg_tokens (ip, client_key) VALUES (?, ?)",
        [ip, client_key],
    )
    .is_ok()
}

/// Construct the WebSocket registration message with the app manifest.
pub(crate) fn build_handshake(client_key: Option<&str>) -> String {
    let mut payload = serde_json::json!({
        "type": "register",
        "id": "register_0",
        "payload": {
            "forcePairing": false,
            "pairingType": "PROMPT",
            "manifest": {
                "manifestVersion": 1,
                "appVersion": "1.1",
                "signed": {
                    "created": "20140509",
                    "appId": "com.lge.test",
                    "vendorId": "com.lge",
                    "localizedAppNames": {
                        "": "Network Discovery",
                        "en-US": "Network Discovery"
                    },
                    "localizedVendorNames": {
                        "": "LG Electronics"
                    },
                    "permissions": [
                        "LAUNCH",
                        "LAUNCH_WEBAPP",
                        "APP_TO_APP",
                        "CLOSE",
                        "TEST_OPEN",
                        "TEST_PROTECTED",
                        "CONTROL_AUDIO",
                        "CONTROL_DISPLAY",
                        "CONTROL_INPUT_JOYSTICK",
                        "CONTROL_INPUT_MEDIA_RECORDING",
                        "CONTROL_INPUT_MEDIA_PLAYBACK",
                        "CONTROL_INPUT_TV",
                        "CONTROL_POWER",
                        "READ_APP_STATUS",
                        "READ_CURRENT_CHANNEL",
                        "READ_INPUT_DEVICE_LIST",
                        "READ_NETWORK_STATE",
                        "READ_RUNNING_APPS",
                        "READ_TV_CHANNEL_LIST",
                        "WRITE_NOTIFICATION_TOAST",
                        "READ_POWER_STATE",
                        "READ_COUNTRY_INFO"
                    ],
                    "serial": "2f930e2d2cfe083771f68e4fe7bb07"
                },
                "permissions": [
                    "LAUNCH",
                    "LAUNCH_WEBAPP",
                    "APP_TO_APP",
                    "CLOSE",
                    "TEST_OPEN",
                    "TEST_PROTECTED",
                    "CONTROL_AUDIO",
                    "CONTROL_DISPLAY",
                    "CONTROL_INPUT_JOYSTICK",
                    "CONTROL_INPUT_MEDIA_RECORDING",
                    "CONTROL_INPUT_MEDIA_PLAYBACK",
                    "CONTROL_INPUT_TV",
                    "CONTROL_POWER",
                    "READ_APP_STATUS",
                    "READ_CURRENT_CHANNEL",
                    "READ_INPUT_DEVICE_LIST",
                    "READ_NETWORK_STATE",
                    "READ_RUNNING_APPS",
                    "READ_TV_CHANNEL_LIST",
                    "WRITE_NOTIFICATION_TOAST",
                    "READ_POWER_STATE",
                    "READ_COUNTRY_INFO"
                ],
                "signatures": [
                    {
                        "signatureVersion": 1,
                        "signature": "eyJhbGdvcml0aG0iOiJSU0EtU0hBMjU2Iiwia2V5SWQiOiJ0ZXN0LXNpZ25pbmctY2VydCIsInNpZ25hdHVyZVZlcnNpb24iOjF9.hrVRgjCwXVvE2OOSpDZ58hR+59aFNwYDyjQgKk3auukd7pcegmE2CzPCa0bJ0ZsRAcKkCTJrWo5iDzNhMBWRyaMOv5zWSrthlf7G128qvIlpMT0YNY+n/FaOHE73uLrS/g7swl3/qH/BGFG2Hu4RlL48eb3lLKqTt2xKHdCs6Cd4RMfJPYnzgvI4BNrFUKsjkcu+WD4OO2A27Pq1n50cMchmcaXadJhGrOqH5YmHdOCj5NSHzJYrsW0HPlpuAx/ECMeIZYDh6RMqaFM2DXzdKX9NmmyqzJ3o/0lkk/N97gfVRLW5hA29yeAwaCViZNCP8iC9aO0q9fQojoa7NQnAtw=="
                    }
                ]
            }
        }
    });

    if let Some(key) = client_key {
        payload["payload"]["client-key"] = serde_json::Value::String(key.to_string());
    }

    payload.to_string()
}

/// Initiate pairing with an LG TV via WebSocket handshake with prompt handling.
pub(crate) fn pair(ip: &str) -> CommandResult {
    let url = format!("ws://{}:{}", ip, WS_PORT);
    let client_key = get_client_key(ip);

    match connect(&url) {
        Ok((mut socket, _)) => {
            let handshake = build_handshake(client_key.as_deref());
            if let Err(e) = socket.send(Message::Text(handshake)) {
                return CommandResult {
                    success: false,
                    message: format!("Failed to send handshake: {}", e),
                };
            }

            let start = std::time::Instant::now();
            let pair_timeout = Duration::from_secs(30);

            while start.elapsed() < pair_timeout {
                match socket.read() {
                    Ok(msg) => {
                        if let Message::Text(text) = msg
                            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
                        {
                            if let Some(payload) = json.get("payload")
                                && let Some(key) =
                                    payload.get("client-key").and_then(|k| k.as_str())
                            {
                                store_client_key(ip, key);
                                let _ = socket.close(None);
                                return CommandResult {
                                    success: true,
                                    message: "Paired successfully! You can now control this TV."
                                        .to_string(),
                                };
                            }

                            if let Some(msg_type) = json.get("type").and_then(|t| t.as_str())
                                && msg_type == "registered"
                            {
                                if let Some(payload) = json.get("payload")
                                    && let Some(key) =
                                        payload.get("client-key").and_then(|k| k.as_str())
                                {
                                    store_client_key(ip, key);
                                }
                                let _ = socket.close(None);
                                return CommandResult {
                                    success: true,
                                    message: "Paired successfully!".to_string(),
                                };
                            }
                        }
                    }
                    Err(tungstenite::Error::Io(ref e))
                        if e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    Err(_) => break,
                }
            }

            let _ = socket.close(None);
            CommandResult {
                success: false,
                message: "Pairing timed out. Please accept the pairing prompt on your TV."
                    .to_string(),
            }
        }
        Err(e) => CommandResult {
            success: false,
            message: format!("Failed to connect to TV: {}", e),
        },
    }
}
