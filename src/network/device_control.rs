use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::time::Duration;
use tungstenite::{Message, connect};

/// Device capabilities that can be controlled
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    pub device_type: String,
    pub can_control: bool,
    pub commands: Vec<CommandInfo>,
    pub apps: Vec<AppInfo>,
    pub device_info: Option<DeviceInfo>,
    #[serde(default)]
    pub needs_pairing: bool,
    #[serde(default)]
    pub is_paired: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInfo {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub id: String,
    pub name: String,
    pub icon_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub model: Option<String>,
    pub name: Option<String>,
    pub software_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub success: bool,
    pub message: String,
}

/// Roku External Control Protocol implementation
pub struct RokuController;

impl RokuController {
    const PORT: u16 = 8060;
    const TIMEOUT: Duration = Duration::from_secs(3);

    /// Check if a device is a Roku by querying its ECP endpoint
    pub fn is_roku(ip: &str) -> bool {
        let url = format!("http://{}:{}/query/device-info", ip, Self::PORT);

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
                    text.contains("<device-info>") || text.contains("Roku")
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    /// Get device info from Roku
    pub fn get_device_info(ip: &str) -> Option<DeviceInfo> {
        let url = format!("http://{}:{}/query/device-info", ip, Self::PORT);

        let client = reqwest::blocking::Client::builder()
            .timeout(Self::TIMEOUT)
            .build()
            .ok()?;

        let response = client.get(&url).send().ok()?;
        let text = response.text().ok()?;

        // Simple XML parsing (avoiding heavy dependencies)
        let model = Self::extract_xml_value(&text, "model-name");
        let name = Self::extract_xml_value(&text, "user-device-name")
            .or_else(|| Self::extract_xml_value(&text, "friendly-device-name"));
        let software_version = Self::extract_xml_value(&text, "software-version");

        Some(DeviceInfo {
            model,
            name,
            software_version,
        })
    }

    /// Get installed apps on Roku
    pub fn get_apps(ip: &str) -> Vec<AppInfo> {
        let url = format!("http://{}:{}/query/apps", ip, Self::PORT);

        let client = match reqwest::blocking::Client::builder()
            .timeout(Self::TIMEOUT)
            .build()
        {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let response = match client.get(&url).send() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let text = match response.text() {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        // Parse apps from XML like: <app id="12" version="...">Netflix</app>
        let mut apps = Vec::new();
        for line in text.lines() {
            if let Some(app) = Self::parse_app_line(line, ip) {
                apps.push(app);
            }
        }

        // Sort by name
        apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        apps
    }

    fn parse_app_line(line: &str, ip: &str) -> Option<AppInfo> {
        // Match: <app id="12345" ...>App Name</app>
        if !line.contains("<app ") || !line.contains("</app>") {
            return None;
        }

        // Extract ID
        let id_start = line.find("id=\"")? + 4;
        let id_end = line[id_start..].find('"')? + id_start;
        let id = line[id_start..id_end].to_string();

        // Extract name (between > and </app>)
        let name_start = line.find('>')? + 1;
        let name_end = line.find("</app>")?;
        let name = line[name_start..name_end].trim().to_string();

        if name.is_empty() {
            return None;
        }

        let icon_url = Some(format!("http://{}:{}/query/icon/{}", ip, Self::PORT, id));

        Some(AppInfo { id, name, icon_url })
    }

    /// Send a keypress command to Roku
    pub fn send_keypress(ip: &str, key: &str) -> CommandResult {
        let url = format!("http://{}:{}/keypress/{}", ip, Self::PORT, key);

        let client = match reqwest::blocking::Client::builder()
            .timeout(Self::TIMEOUT)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                return CommandResult {
                    success: false,
                    message: format!("Failed to create HTTP client: {}", e),
                };
            }
        };

        match client.post(&url).send() {
            Ok(response) => {
                if response.status().is_success() {
                    CommandResult {
                        success: true,
                        message: format!("Sent {} to Roku", key),
                    }
                } else {
                    CommandResult {
                        success: false,
                        message: format!("Roku returned status: {}", response.status()),
                    }
                }
            }
            Err(e) => CommandResult {
                success: false,
                message: format!("Failed to send command: {}", e),
            },
        }
    }

    /// Launch an app on Roku
    pub fn launch_app(ip: &str, app_id: &str) -> CommandResult {
        let url = format!("http://{}:{}/launch/{}", ip, Self::PORT, app_id);

        let client = match reqwest::blocking::Client::builder()
            .timeout(Self::TIMEOUT)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                return CommandResult {
                    success: false,
                    message: format!("Failed to create HTTP client: {}", e),
                };
            }
        };

        match client.post(&url).send() {
            Ok(response) => {
                if response.status().is_success() {
                    CommandResult {
                        success: true,
                        message: "App launched".to_string(),
                    }
                } else {
                    CommandResult {
                        success: false,
                        message: format!("Roku returned status: {}", response.status()),
                    }
                }
            }
            Err(e) => CommandResult {
                success: false,
                message: format!("Failed to launch app: {}", e),
            },
        }
    }

    /// Get all available Roku commands
    pub fn get_commands() -> Vec<CommandInfo> {
        vec![
            // Navigation
            CommandInfo {
                id: "Up".into(),
                name: "Up".into(),
                icon: "⬆️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Down".into(),
                name: "Down".into(),
                icon: "⬇️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Left".into(),
                name: "Left".into(),
                icon: "⬅️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Right".into(),
                name: "Right".into(),
                icon: "➡️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Select".into(),
                name: "OK".into(),
                icon: "⏺️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Back".into(),
                name: "Back".into(),
                icon: "↩️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Home".into(),
                name: "Home".into(),
                icon: "🏠".into(),
                category: "Navigation".into(),
            },
            // Playback
            CommandInfo {
                id: "Play".into(),
                name: "Play/Pause".into(),
                icon: "⏯️".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "Rev".into(),
                name: "Rewind".into(),
                icon: "⏪".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "Fwd".into(),
                name: "Fast Forward".into(),
                icon: "⏩".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "InstantReplay".into(),
                name: "Replay".into(),
                icon: "🔄".into(),
                category: "Playback".into(),
            },
            // Volume
            CommandInfo {
                id: "VolumeUp".into(),
                name: "Volume Up".into(),
                icon: "🔊".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "VolumeDown".into(),
                name: "Volume Down".into(),
                icon: "🔉".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "VolumeMute".into(),
                name: "Mute".into(),
                icon: "🔇".into(),
                category: "Volume".into(),
            },
            // Power
            CommandInfo {
                id: "PowerOff".into(),
                name: "Power Off".into(),
                icon: "⏻".into(),
                category: "Power".into(),
            },
            // Info
            CommandInfo {
                id: "Info".into(),
                name: "Info".into(),
                icon: "ℹ️".into(),
                category: "Other".into(),
            },
        ]
    }

    /// Get capabilities for a Roku device
    pub fn get_capabilities(ip: &str) -> DeviceCapabilities {
        let device_info = Self::get_device_info(ip);
        let apps = Self::get_apps(ip);
        let commands = Self::get_commands();

        DeviceCapabilities {
            device_type: "roku".to_string(),
            can_control: true,
            commands,
            apps,
            device_info,
            needs_pairing: false, // Roku doesn't require pairing
            is_paired: true,
        }
    }

    fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
        let open_tag = format!("<{}>", tag);
        let close_tag = format!("</{}>", tag);

        let start = xml.find(&open_tag)? + open_tag.len();
        let end = xml[start..].find(&close_tag)? + start;

        let value = xml[start..end].trim().to_string();
        if value.is_empty() { None } else { Some(value) }
    }
}

/// Samsung Smart TV WebSocket API implementation
pub struct SamsungController;

impl SamsungController {
    const WS_PORT: u16 = 8001;
    #[allow(dead_code)]
    const WSS_PORT: u16 = 8002; // For future TLS support
    const APP_NAME: &'static str = "RustNetworkDiscovery";
    const TIMEOUT: Duration = Duration::from_secs(3);

    /// Check if a device is a Samsung TV by attempting to connect to its API
    #[allow(dead_code)]
    pub fn is_samsung(ip: &str) -> bool {
        Self::is_samsung_with_hostname(ip, None)
    }

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
                icon: "⬆️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_DOWN".into(),
                name: "Down".into(),
                icon: "⬇️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_LEFT".into(),
                name: "Left".into(),
                icon: "⬅️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_RIGHT".into(),
                name: "Right".into(),
                icon: "➡️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_ENTER".into(),
                name: "OK".into(),
                icon: "⏺️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_RETURN".into(),
                name: "Back".into(),
                icon: "↩️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_HOME".into(),
                name: "Home".into(),
                icon: "🏠".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "KEY_EXIT".into(),
                name: "Exit".into(),
                icon: "✕".into(),
                category: "Navigation".into(),
            },
            // Playback
            CommandInfo {
                id: "KEY_PLAY".into(),
                name: "Play".into(),
                icon: "▶️".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "KEY_PAUSE".into(),
                name: "Pause".into(),
                icon: "⏸️".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "KEY_STOP".into(),
                name: "Stop".into(),
                icon: "⏹️".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "KEY_REWIND".into(),
                name: "Rewind".into(),
                icon: "⏪".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "KEY_FF".into(),
                name: "Fast Forward".into(),
                icon: "⏩".into(),
                category: "Playback".into(),
            },
            // Volume & Channel
            CommandInfo {
                id: "KEY_VOLUP".into(),
                name: "Volume Up".into(),
                icon: "🔊".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "KEY_VOLDOWN".into(),
                name: "Volume Down".into(),
                icon: "🔉".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "KEY_MUTE".into(),
                name: "Mute".into(),
                icon: "🔇".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "KEY_CHUP".into(),
                name: "Channel Up".into(),
                icon: "📺+".into(),
                category: "Channel".into(),
            },
            CommandInfo {
                id: "KEY_CHDOWN".into(),
                name: "Channel Down".into(),
                icon: "📺-".into(),
                category: "Channel".into(),
            },
            // Power
            CommandInfo {
                id: "KEY_POWER".into(),
                name: "Power".into(),
                icon: "⏻".into(),
                category: "Power".into(),
            },
            // Input & Menu
            CommandInfo {
                id: "KEY_SOURCE".into(),
                name: "Source".into(),
                icon: "🔌".into(),
                category: "Other".into(),
            },
            CommandInfo {
                id: "KEY_MENU".into(),
                name: "Menu".into(),
                icon: "☰".into(),
                category: "Other".into(),
            },
            CommandInfo {
                id: "KEY_INFO".into(),
                name: "Info".into(),
                icon: "ℹ️".into(),
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

/// Main device controller that routes to specific implementations
pub struct DeviceController;

impl DeviceController {
    /// Detect what type of controllable device this is and return capabilities
    pub fn get_capabilities(
        ip: &str,
        device_type: Option<&str>,
        hostname: Option<&str>,
    ) -> DeviceCapabilities {
        // Quick check: if hostname contains "samsung", skip other checks
        if let Some(name) = hostname
            && name.to_lowercase().contains("samsung")
        {
            return SamsungController::get_capabilities(ip);
        }

        // For TV types, try both Roku and Samsung
        if device_type == Some("tv") || device_type == Some("streaming") {
            if RokuController::is_roku(ip) {
                return RokuController::get_capabilities(ip);
            }
            if SamsungController::is_samsung_with_hostname(ip, hostname) {
                return SamsungController::get_capabilities(ip);
            }
        }

        // Also try detection regardless of type (some might be misclassified)
        if RokuController::is_roku(ip) {
            return RokuController::get_capabilities(ip);
        }

        if SamsungController::is_samsung_with_hostname(ip, hostname) {
            return SamsungController::get_capabilities(ip);
        }

        // No controllable device found
        DeviceCapabilities {
            device_type: device_type.unwrap_or("unknown").to_string(),
            can_control: false,
            commands: Vec::new(),
            apps: Vec::new(),
            device_info: None,
            needs_pairing: false,
            is_paired: false,
        }
    }

    /// Send a command to a device
    pub fn send_command(ip: &str, command: &str, device_type: &str) -> CommandResult {
        match device_type {
            "roku" => RokuController::send_keypress(ip, command),
            "samsung" => SamsungController::send_key(ip, command),
            _ => CommandResult {
                success: false,
                message: format!("Unknown device type: {}", device_type),
            },
        }
    }

    /// Launch an app on a device
    pub fn launch_app(ip: &str, app_id: &str, device_type: &str) -> CommandResult {
        match device_type {
            "roku" => RokuController::launch_app(ip, app_id),
            "samsung" => CommandResult {
                success: false,
                message: "App launching not yet supported for Samsung TVs".to_string(),
            },
            _ => CommandResult {
                success: false,
                message: format!("App launching not supported for: {}", device_type),
            },
        }
    }

    /// Pair with a device that requires pairing (e.g., Samsung TV)
    pub fn pair(ip: &str, device_type: &str) -> CommandResult {
        match device_type {
            "samsung" => SamsungController::pair(ip),
            "roku" => CommandResult {
                success: true,
                message: "Roku devices don't require pairing".to_string(),
            },
            _ => CommandResult {
                success: false,
                message: format!("Pairing not supported for: {}", device_type),
            },
        }
    }
}
