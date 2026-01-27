//! Samsung Smart TV controller. Communicates via WebSocket on port 8001 for
//! device detection, capability reporting, and remote command execution.

use super::types::{CommandInfo, CommandResult, DeviceCapabilities, DeviceInfo};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::net::TcpStream;
use std::time::Duration;
use tungstenite::{Message, connect};

/// Samsung Smart TV WebSocket API implementation
pub struct SamsungController;

impl SamsungController {
    const WS_PORT: u16 = 8001;
    const APP_NAME: &'static str = "RustNetworkDiscovery";
    const TIMEOUT: Duration = Duration::from_secs(3);

    /// Check if a device is a Samsung TV, with optional hostname hint
    pub fn is_samsung_with_hostname(ip: &str, hostname: Option<&str>) -> bool {
        // If hostname contains "samsung", trust it - user can try pairing
        // even if TV is currently off/in standby
        if let Some(name) = hostname
            && name.to_lowercase().contains("samsung")
        {
            return true;
        }

        // Try to connect to the Samsung TV info endpoint
        let url = format!("http://{}:{}/api/v2/", ip, Self::WS_PORT);

        let client = match reqwest::blocking::Client::builder()
            .timeout(Self::TIMEOUT)
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        match client.get(&url).send() {
            Ok(response) => {
                if let Ok(text) = response.text() {
                    // Samsung TVs return JSON with device info
                    // Be lenient - if it has "device" field, it's likely a Samsung
                    text.contains("\"device\"")
                        || text.contains("Samsung")
                        || text.contains("Tizen")
                } else {
                    false
                }
            }
            Err(_) => {
                // Try port check as last resort
                if let Ok(addr) = format!("{}:{}", ip, Self::WS_PORT).parse() {
                    return TcpStream::connect_timeout(&addr, Self::TIMEOUT).is_ok();
                }
                false
            }
        }
    }

    /// Get device info from Samsung TV
    pub fn get_device_info(ip: &str) -> Option<DeviceInfo> {
        let url = format!("http://{}:{}/api/v2/", ip, Self::WS_PORT);

        let client = reqwest::blocking::Client::builder()
            .timeout(Self::TIMEOUT)
            .build()
            .ok()?;

        let response = client.get(&url).send().ok()?;
        let text = response.text().ok()?;

        // Parse JSON response
        let json: serde_json::Value = serde_json::from_str(&text).ok()?;
        let device = json.get("device")?;

        let model = device
            .get("modelName")
            .or_else(|| device.get("model"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let name = device
            .get("name")
            .or_else(|| device.get("deviceName"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let software_version = device
            .get("firmwareVersion")
            .or_else(|| device.get("version"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Some(DeviceInfo {
            model,
            name,
            software_version,
        })
    }

    /// Get stored token for a Samsung TV
    pub fn get_token(ip: &str) -> Option<String> {
        use crate::db::new_connection;

        let conn = new_connection();

        // Create table if it doesn't exist
        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS samsung_tokens (
                ip TEXT PRIMARY KEY,
                token TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        );

        let mut stmt = conn
            .prepare("SELECT token FROM samsung_tokens WHERE ip = ?")
            .ok()?;
        stmt.query_row([ip], |row| row.get(0)).ok()
    }

    /// Store token for a Samsung TV
    pub fn store_token(ip: &str, token: &str) -> bool {
        use crate::db::new_connection;

        let conn = new_connection();

        // Create table if it doesn't exist
        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS samsung_tokens (
                ip TEXT PRIMARY KEY,
                token TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        );

        conn.execute(
            "INSERT OR REPLACE INTO samsung_tokens (ip, token) VALUES (?, ?)",
            [ip, token],
        )
        .is_ok()
    }

    /// Build WebSocket URL for Samsung TV
    fn build_ws_url(ip: &str, token: Option<&str>) -> String {
        let app_name_b64 = BASE64.encode(Self::APP_NAME);

        match token {
            Some(t) => format!(
                "ws://{}:{}/api/v2/channels/samsung.remote.control?name={}&token={}",
                ip,
                Self::WS_PORT,
                app_name_b64,
                t
            ),
            None => format!(
                "ws://{}:{}/api/v2/channels/samsung.remote.control?name={}",
                ip,
                Self::WS_PORT,
                app_name_b64
            ),
        }
    }

    /// Initiate pairing with Samsung TV (user must approve on TV screen)
    pub fn pair(ip: &str) -> CommandResult {
        let url = Self::build_ws_url(ip, None);

        match connect(&url) {
            Ok((mut socket, _response)) => {
                // Wait for the TV to send a response (either approval or token)
                // The TV will prompt the user to approve the connection

                // Set a longer timeout for user approval
                let start = std::time::Instant::now();
                let pair_timeout = Duration::from_secs(30);

                while start.elapsed() < pair_timeout {
                    match socket.read() {
                        Ok(msg) => {
                            if let Message::Text(text) = msg {
                                // Parse the response to extract token
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                    // Check for token in response
                                    if let Some(data) = json.get("data")
                                        && let Some(token) =
                                            data.get("token").and_then(|t| t.as_str())
                                    {
                                        // Store the token
                                        Self::store_token(ip, token);
                                        let _ = socket.close(None);
                                        return CommandResult {
                                            success: true,
                                            message:
                                                "Paired successfully! You can now control this TV."
                                                    .to_string(),
                                        };
                                    }

                                    // Check if it's a successful connection event
                                    if let Some(event) = json.get("event").and_then(|e| e.as_str())
                                        && event == "ms.channel.connect"
                                    {
                                        // On newer TVs, token might be in the connect event
                                        if let Some(data) = json.get("data")
                                            && let Some(token) =
                                                data.get("token").and_then(|t| t.as_str())
                                        {
                                            Self::store_token(ip, token);
                                            let _ = socket.close(None);
                                            return CommandResult {
                                                success: true,
                                                message: "Paired successfully!".to_string(),
                                            };
                                        }
                                        // Some TVs don't return a token but are still paired
                                        let _ = socket.close(None);
                                        return CommandResult {
                                            success: true,
                                            message: "Connected to TV. If prompted, please approve on your TV screen.".to_string(),
                                        };
                                    }
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
                    message: "Pairing timed out. Please approve the connection on your TV."
                        .to_string(),
                }
            }
            Err(e) => CommandResult {
                success: false,
                message: format!("Failed to connect to TV: {}", e),
            },
        }
    }

    /// Send a key command to Samsung TV
    pub fn send_key(ip: &str, key: &str) -> CommandResult {
        let token = Self::get_token(ip);
        let url = Self::build_ws_url(ip, token.as_deref());

        match connect(&url) {
            Ok((mut socket, _)) => {
                // Build the key command
                let cmd = serde_json::json!({
                    "method": "ms.remote.control",
                    "params": {
                        "Cmd": "Click",
                        "DataOfCmd": key,
                        "Option": "false",
                        "TypeOfRemote": "SendRemoteKey"
                    }
                });

                match socket.send(Message::Text(cmd.to_string())) {
                    Ok(_) => {
                        // Read response
                        let _ = socket.read();
                        let _ = socket.close(None);
                        CommandResult {
                            success: true,
                            message: format!("Sent {} to Samsung TV", key),
                        }
                    }
                    Err(e) => {
                        let _ = socket.close(None);
                        CommandResult {
                            success: false,
                            message: format!("Failed to send command: {}", e),
                        }
                    }
                }
            }
            Err(e) => CommandResult {
                success: false,
                message: format!("Failed to connect: {}. Try pairing again.", e),
            },
        }
    }

    /// Get all available Samsung TV commands
    pub fn get_commands() -> Vec<CommandInfo> {
        vec![
            // Navigation
            CommandInfo {
                id: "KEY_UP".into(),
                name: "Up".into(),
                icon: "\u{2b06}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_DOWN".into(),
                name: "Down".into(),
                icon: "\u{2b07}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_LEFT".into(),
                name: "Left".into(),
                icon: "\u{2b05}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_RIGHT".into(),
                name: "Right".into(),
                icon: "\u{27a1}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_ENTER".into(),
                name: "OK".into(),
                icon: "\u{23fa}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_RETURN".into(),
                name: "Back".into(),
                icon: "\u{21a9}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_HOME".into(),
                name: "Home".into(),
                icon: "\u{1f3e0}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_EXIT".into(),
                name: "Exit".into(),
                icon: "\u{2715}".into(),
                category: "Navigation".into(),
            },
            // Playback
            CommandInfo {
                id: "KEY_PLAY".into(),
                name: "Play".into(),
                icon: "\u{25b6}\u{fe0f}".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "KEY_PAUSE".into(),
                name: "Pause".into(),
                icon: "\u{23f8}\u{fe0f}".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "KEY_STOP".into(),
                name: "Stop".into(),
                icon: "\u{23f9}\u{fe0f}".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "KEY_REWIND".into(),
                name: "Rewind".into(),
                icon: "\u{23ea}".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "KEY_FF".into(),
                name: "Fast Forward".into(),
                icon: "\u{23e9}".into(),
                category: "Playback".into(),
            },
            // Volume & Channel
            CommandInfo {
                id: "KEY_VOLUP".into(),
                name: "Volume Up".into(),
                icon: "\u{1f50a}".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "KEY_VOLDOWN".into(),
                name: "Volume Down".into(),
                icon: "\u{1f509}".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "KEY_MUTE".into(),
                name: "Mute".into(),
                icon: "\u{1f507}".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "KEY_CHUP".into(),
                name: "Channel Up".into(),
                icon: "\u{1f4fa}+".into(),
                category: "Channel".into(),
            },
            CommandInfo {
                id: "KEY_CHDOWN".into(),
                name: "Channel Down".into(),
                icon: "\u{1f4fa}-".into(),
                category: "Channel".into(),
            },
            // Power
            CommandInfo {
                id: "KEY_POWER".into(),
                name: "Power".into(),
                icon: "\u{23fb}".into(),
                category: "Power".into(),
            },
            // Input & Menu
            CommandInfo {
                id: "KEY_SOURCE".into(),
                name: "Source".into(),
                icon: "\u{1f50c}".into(),
                category: "Other".into(),
            },
            CommandInfo {
                id: "KEY_MENU".into(),
                name: "Menu".into(),
                icon: "\u{2630}".into(),
                category: "Other".into(),
            },
            CommandInfo {
                id: "KEY_INFO".into(),
                name: "Info".into(),
                icon: "\u{2139}\u{fe0f}".into(),
                category: "Other".into(),
            },
        ]
    }

    /// Get capabilities for a Samsung TV
    pub fn get_capabilities(ip: &str) -> DeviceCapabilities {
        let device_info = Self::get_device_info(ip);
        let commands = Self::get_commands();
        let has_token = Self::get_token(ip).is_some();

        DeviceCapabilities {
            device_type: "samsung".to_string(),
            can_control: true,
            commands,
            apps: Vec::new(), // Samsung app list requires more complex API calls
            device_info,
            needs_pairing: !has_token,
            is_paired: has_token,
        }
    }
}
