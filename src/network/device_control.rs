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

/// LG ThinQ Appliance Controller (cloud-based API)
/// Uses the official LG ThinQ Connect API (opened December 2024)
/// Supports dishwashers, washing machines, dryers, refrigerators, etc.
pub struct LgThinQController;

/// ThinQ device information from cloud
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThinQDevice {
    pub device_id: String,
    pub device_type: String,
    pub device_alias: String,
    pub model_name: Option<String>,
    pub online: bool,
}

/// ThinQ device state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThinQDeviceState {
    pub device_id: String,
    pub state: serde_json::Value,
}

impl LgThinQController {
    // Official LG ThinQ API key (public, from official SDK)
    const API_KEY: &'static str = "v6GFvkweNo7DK7yD3ylIZ9w52aKBU0eJ7wLXkSR3";
    const TIMEOUT: Duration = Duration::from_secs(10);

    /// Get region code from country code
    fn get_region(country_code: &str) -> &'static str {
        match country_code.to_uppercase().as_str() {
            // North America
            "US" | "CA" | "MX" => "us",
            // Europe
            "GB" | "DE" | "FR" | "IT" | "ES" | "NL" | "BE" | "AT" | "CH" | "PL" | "SE" | "NO"
            | "DK" | "FI" | "PT" | "IE" | "CZ" | "HU" | "RO" | "BG" | "SK" | "HR" | "SI" | "EE"
            | "LV" | "LT" | "GR" | "CY" | "MT" | "LU" => "eu",
            // Korea
            "KR" => "kr",
            // Asia Pacific
            "AU" | "NZ" | "SG" | "MY" | "TH" | "PH" | "ID" | "VN" | "IN" | "JP" | "TW" | "HK" => {
                "ap"
            }
            // Default to US
            _ => "us",
        }
    }

    /// Build API base URL for a country
    fn get_api_url(country_code: &str) -> String {
        let region = Self::get_region(country_code);
        format!("https://api-{}.lgthinq.com", region)
    }

    /// Check if a device is an LG ThinQ appliance based on hostname
    pub fn is_thinq_appliance(hostname: Option<&str>) -> bool {
        if let Some(name) = hostname {
            let lower = name.to_lowercase();
            // LG ThinQ appliances have specific hostname patterns
            lower.starts_with("lma")
                || lower.starts_with("lmw")
                || lower.starts_with("wm")
                || lower.starts_with("wf")
                || lower.starts_with("ref")
                || (lower.starts_with("ac") && lower.contains("lg"))
        } else {
            false
        }
    }

    /// Detect appliance type from hostname
    pub fn detect_appliance_type(hostname: &str) -> &'static str {
        let lower = hostname.to_lowercase();
        if lower.starts_with("lma") || lower.contains("dish") {
            "Dishwasher"
        } else if lower.starts_with("lmw") || lower.starts_with("wm") || lower.contains("wash") {
            "Washing Machine"
        } else if lower.starts_with("wf") || lower.contains("dry") {
            "Dryer"
        } else if lower.starts_with("ref") || lower.contains("fridge") {
            "Refrigerator"
        } else if lower.starts_with("ac") {
            "Air Conditioner"
        } else {
            "Smart Appliance"
        }
    }

    /// Get stored ThinQ credentials
    pub fn get_credentials() -> Option<(String, String, String)> {
        use crate::db::new_connection;
        let conn = new_connection();

        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS lg_thinq_auth (
                id INTEGER PRIMARY KEY,
                pat_token TEXT NOT NULL,
                country_code TEXT NOT NULL,
                client_id TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        );

        conn.query_row(
            "SELECT pat_token, country_code, client_id FROM lg_thinq_auth WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .ok()
    }

    /// Check if we have stored credentials
    pub fn has_credentials() -> bool {
        Self::get_credentials().is_some()
    }

    /// Store ThinQ credentials (PAT token)
    pub fn store_credentials(pat_token: &str, country_code: &str, client_id: &str) -> bool {
        use crate::db::new_connection;
        let conn = new_connection();

        if let Err(e) = conn.execute(
            "CREATE TABLE IF NOT EXISTS lg_thinq_auth (
                id INTEGER PRIMARY KEY,
                pat_token TEXT NOT NULL,
                country_code TEXT NOT NULL,
                client_id TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        ) {
            eprintln!("Failed to create lg_thinq_auth table: {}", e);
            return false;
        }

        // Delete existing and insert new
        let _ = conn.execute("DELETE FROM lg_thinq_auth", []);

        match conn.execute(
            "INSERT INTO lg_thinq_auth (id, pat_token, country_code, client_id) VALUES (1, ?, ?, ?)",
            [pat_token, country_code, client_id],
        ) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("Failed to store ThinQ credentials: {}", e);
                false
            }
        }
    }

    /// Clear stored credentials
    pub fn clear_credentials() -> bool {
        use crate::db::new_connection;
        let conn = new_connection();
        conn.execute("DELETE FROM lg_thinq_auth WHERE id = 1", [])
            .is_ok()
    }

    /// Build HTTP client with proper headers
    fn build_client() -> Option<reqwest::blocking::Client> {
        reqwest::blocking::Client::builder()
            .timeout(Self::TIMEOUT)
            .build()
            .ok()
    }

    /// Make an authenticated API request
    fn api_request(
        method: &str,
        endpoint: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let (pat_token, country_code, client_id) =
            Self::get_credentials().ok_or("No ThinQ credentials configured")?;

        let client = Self::build_client().ok_or("Failed to create HTTP client")?;
        let url = format!("{}{}", Self::get_api_url(&country_code), endpoint);

        let message_id = uuid::Uuid::new_v4().to_string();

        let request = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url),
            "DELETE" => client.delete(&url),
            _ => return Err(format!("Unsupported method: {}", method)),
        }
        .header("Authorization", format!("Bearer {}", pat_token))
        .header("x-country", &country_code)
        .header("x-message-id", &message_id)
        .header("x-client-id", &client_id)
        .header("x-api-key", Self::API_KEY)
        .header("Content-Type", "application/json");

        let request = if let Some(json_body) = body {
            request.json(&json_body)
        } else {
            request
        };

        let response = request
            .send()
            .map_err(|e| format!("Request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("API error: {}", response.status()));
        }

        let json: serde_json::Value = response
            .json()
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        // Extract the response field
        if let Some(resp) = json.get("response") {
            Ok(resp.clone())
        } else {
            Ok(json)
        }
    }

    /// List all devices from ThinQ cloud
    pub fn list_devices() -> Result<Vec<ThinQDevice>, String> {
        let response = Self::api_request("GET", "/devices", None)?;

        let devices: Vec<ThinQDevice> = response
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|d| {
                Some(ThinQDevice {
                    device_id: d.get("deviceId")?.as_str()?.to_string(),
                    device_type: d.get("deviceType")?.as_str()?.to_string(),
                    device_alias: d
                        .get("alias")
                        .and_then(|a| a.as_str())
                        .unwrap_or("Unknown")
                        .to_string(),
                    model_name: d
                        .get("modelName")
                        .and_then(|m| m.as_str())
                        .map(String::from),
                    online: d.get("online").and_then(|o| o.as_bool()).unwrap_or(false),
                })
            })
            .collect();

        Ok(devices)
    }

    /// Get device state from ThinQ cloud
    pub fn get_device_state(device_id: &str) -> Result<ThinQDeviceState, String> {
        let endpoint = format!("/devices/{}/state", device_id);
        let response = Self::api_request("GET", &endpoint, None)?;

        Ok(ThinQDeviceState {
            device_id: device_id.to_string(),
            state: response,
        })
    }

    /// Send control command to device
    pub fn control_device(
        device_id: &str,
        command: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let endpoint = format!("/devices/{}/control", device_id);
        Self::api_request("POST", &endpoint, Some(command))
    }

    /// Get capabilities for an LG ThinQ appliance
    pub fn get_capabilities(hostname: &str) -> DeviceCapabilities {
        let appliance_type = Self::detect_appliance_type(hostname);
        let has_creds = Self::has_credentials();

        // Try to get device info from cloud if authenticated
        let (device_info, cloud_device_id) = if has_creds {
            // Try to find this device in the cloud
            if let Ok(devices) = Self::list_devices() {
                // Try to match by hostname pattern in alias
                let hostname_lower = hostname.to_lowercase();
                let matched = devices.iter().find(|d| {
                    d.device_alias.to_lowercase().contains(&hostname_lower)
                        || hostname_lower.contains(&d.device_alias.to_lowercase())
                });
                if let Some(device) = matched {
                    (
                        Some(DeviceInfo {
                            model: device.model_name.clone(),
                            name: Some(device.device_alias.clone()),
                            software_version: None,
                        }),
                        Some(device.device_id.clone()),
                    )
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Build commands based on appliance type
        let commands = match appliance_type {
            "Dishwasher" => vec![
                CommandInfo {
                    id: "status".into(),
                    name: "Get Status".into(),
                    icon: "📊".into(),
                    category: "Status".into(),
                },
                CommandInfo {
                    id: "start".into(),
                    name: "Start Cycle".into(),
                    icon: "▶️".into(),
                    category: "Control".into(),
                },
                CommandInfo {
                    id: "stop".into(),
                    name: "Stop".into(),
                    icon: "⏹️".into(),
                    category: "Control".into(),
                },
            ],
            "Washing Machine" | "Dryer" => vec![
                CommandInfo {
                    id: "status".into(),
                    name: "Get Status".into(),
                    icon: "📊".into(),
                    category: "Status".into(),
                },
                CommandInfo {
                    id: "start".into(),
                    name: "Start".into(),
                    icon: "▶️".into(),
                    category: "Control".into(),
                },
                CommandInfo {
                    id: "pause".into(),
                    name: "Pause".into(),
                    icon: "⏸️".into(),
                    category: "Control".into(),
                },
                CommandInfo {
                    id: "stop".into(),
                    name: "Stop".into(),
                    icon: "⏹️".into(),
                    category: "Control".into(),
                },
            ],
            "Refrigerator" => vec![
                CommandInfo {
                    id: "status".into(),
                    name: "Get Status".into(),
                    icon: "📊".into(),
                    category: "Status".into(),
                },
                CommandInfo {
                    id: "express_freeze".into(),
                    name: "Express Freeze".into(),
                    icon: "❄️".into(),
                    category: "Mode".into(),
                },
                CommandInfo {
                    id: "eco_mode".into(),
                    name: "Eco Mode".into(),
                    icon: "🌱".into(),
                    category: "Mode".into(),
                },
            ],
            "Air Conditioner" => vec![
                CommandInfo {
                    id: "power_on".into(),
                    name: "Power On".into(),
                    icon: "⏻".into(),
                    category: "Power".into(),
                },
                CommandInfo {
                    id: "power_off".into(),
                    name: "Power Off".into(),
                    icon: "⭘".into(),
                    category: "Power".into(),
                },
                CommandInfo {
                    id: "status".into(),
                    name: "Get Status".into(),
                    icon: "📊".into(),
                    category: "Status".into(),
                },
            ],
            _ => vec![CommandInfo {
                id: "status".into(),
                name: "Get Status".into(),
                icon: "📊".into(),
                category: "Status".into(),
            }],
        };

        DeviceCapabilities {
            device_type: format!("lg_thinq:{}", cloud_device_id.unwrap_or_default()),
            can_control: has_creds,
            commands,
            apps: Vec::new(),
            device_info: device_info.or(Some(DeviceInfo {
                model: Some(appliance_type.to_string()),
                name: Some(format!("LG {}", appliance_type)),
                software_version: None,
            })),
            needs_pairing: !has_creds,
            is_paired: has_creds,
        }
    }

    /// Setup ThinQ with PAT token
    pub fn pair(pat_token: &str, country_code: &str) -> CommandResult {
        // Generate a unique client ID
        let client_id = format!("thinq-netdiscovery-{}", uuid::Uuid::new_v4());

        // Store credentials
        if !Self::store_credentials(pat_token, country_code, &client_id) {
            return CommandResult {
                success: false,
                message: "Failed to store credentials. Check terminal for details.".to_string(),
            };
        }

        // Test the connection by listing devices
        match Self::list_devices() {
            Ok(devices) => CommandResult {
                success: true,
                message: format!(
                    "Connected to LG ThinQ! Found {} device(s): {}",
                    devices.len(),
                    devices
                        .iter()
                        .map(|d| format!("{} ({})", d.device_alias, d.device_type))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            },
            Err(e) => {
                // Clear invalid credentials
                Self::clear_credentials();
                CommandResult {
                    success: false,
                    message: format!("Failed to connect: {}. Please check your PAT token.", e),
                }
            }
        }
    }

    /// Send command to ThinQ appliance
    pub fn send_command(device_type_with_id: &str, command: &str) -> CommandResult {
        if !Self::has_credentials() {
            return CommandResult {
                success: false,
                message: "LG ThinQ not configured. Please set up your PAT token first.".to_string(),
            };
        }

        // Extract device_id from device_type (format: "lg_thinq:device_id")
        let device_id = device_type_with_id
            .strip_prefix("lg_thinq:")
            .unwrap_or(device_type_with_id);

        if device_id.is_empty() {
            return CommandResult {
                success: false,
                message: "Device not linked to ThinQ cloud. Try refreshing the page.".to_string(),
            };
        }

        // Handle status command specially
        if command == "status" {
            return match Self::get_device_state(device_id) {
                Ok(state) => CommandResult {
                    success: true,
                    message: format!(
                        "Device state: {}",
                        serde_json::to_string_pretty(&state.state).unwrap_or_default()
                    ),
                },
                Err(e) => CommandResult {
                    success: false,
                    message: format!("Failed to get status: {}", e),
                },
            };
        }

        // Build command payload based on command type
        let cmd_payload = match command {
            "start" => serde_json::json!({
                "operation": {
                    "washerOperationMode": "START"
                }
            }),
            "stop" => serde_json::json!({
                "operation": {
                    "washerOperationMode": "STOP"
                }
            }),
            "pause" => serde_json::json!({
                "operation": {
                    "washerOperationMode": "PAUSE"
                }
            }),
            "power_on" => serde_json::json!({
                "operation": {
                    "airConOperationMode": "POWER_ON"
                }
            }),
            "power_off" => serde_json::json!({
                "operation": {
                    "airConOperationMode": "POWER_OFF"
                }
            }),
            "express_freeze" => serde_json::json!({
                "refrigeration": {
                    "expressFreeze": true
                }
            }),
            "eco_mode" => serde_json::json!({
                "refrigeration": {
                    "ecoFriendlyMode": true
                }
            }),
            _ => {
                return CommandResult {
                    success: false,
                    message: format!("Unknown command: {}", command),
                };
            }
        };

        match Self::control_device(device_id, cmd_payload) {
            Ok(_) => CommandResult {
                success: true,
                message: format!("Command '{}' sent successfully", command),
            },
            Err(e) => CommandResult {
                success: false,
                message: format!("Command failed: {}", e),
            },
        }
    }
}

/// LG webOS TV WebSocket API implementation
pub struct LgController;

impl LgController {
    const WS_PORT: u16 = 3000;
    #[allow(dead_code)]
    const WSS_PORT: u16 = 3001;
    const TIMEOUT: Duration = Duration::from_secs(3);

    /// Check if a device is an LG webOS TV
    pub fn is_lg_tv(ip: &str, hostname: Option<&str>) -> bool {
        // Check hostname first - LG ThinQ appliances have hostnames like lma*, lmw*, wm*
        if let Some(name) = hostname {
            let lower = name.to_lowercase();
            // LG TVs often have "lg" or "webos" in hostname
            if lower.contains("lgtv") || lower.contains("webos") || lower.contains("lg-tv") {
                return true;
            }
            // Skip LG appliances (dishwashers, washers, etc.)
            if lower.starts_with("lma")
                || lower.starts_with("lmw")
                || lower.starts_with("wm")
                || lower.starts_with("wf")
            {
                return false;
            }
        }

        // Try to connect to the LG TV WebSocket port
        if let Ok(addr) = format!("{}:{}", ip, Self::WS_PORT).parse()
            && TcpStream::connect_timeout(&addr, Self::TIMEOUT).is_ok()
        {
            return true;
        }

        false
    }

    /// Get stored client key for an LG TV
    pub fn get_client_key(ip: &str) -> Option<String> {
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

    /// Store client key for an LG TV
    pub fn store_client_key(ip: &str, client_key: &str) -> bool {
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

    /// Build the handshake/registration message for LG TV
    fn build_handshake(client_key: Option<&str>) -> String {
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

        // Add client key if we have one
        if let Some(key) = client_key {
            payload["payload"]["client-key"] = serde_json::Value::String(key.to_string());
        }

        payload.to_string()
    }

    /// Initiate pairing with LG TV
    pub fn pair(ip: &str) -> CommandResult {
        let url = format!("ws://{}:{}", ip, Self::WS_PORT);
        let client_key = Self::get_client_key(ip);

        match connect(&url) {
            Ok((mut socket, _)) => {
                // Send handshake
                let handshake = Self::build_handshake(client_key.as_deref());
                if let Err(e) = socket.send(Message::Text(handshake)) {
                    return CommandResult {
                        success: false,
                        message: format!("Failed to send handshake: {}", e),
                    };
                }

                // Wait for response with client key
                let start = std::time::Instant::now();
                let pair_timeout = Duration::from_secs(30);

                while start.elapsed() < pair_timeout {
                    match socket.read() {
                        Ok(msg) => {
                            if let Message::Text(text) = msg
                                && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
                            {
                                // Check for registration response with client key
                                if let Some(payload) = json.get("payload")
                                    && let Some(key) =
                                        payload.get("client-key").and_then(|k| k.as_str())
                                {
                                    Self::store_client_key(ip, key);
                                    let _ = socket.close(None);
                                    return CommandResult {
                                        success: true,
                                        message:
                                            "Paired successfully! You can now control this TV."
                                                .to_string(),
                                    };
                                }

                                // Check for pairing prompt type
                                if let Some(msg_type) = json.get("type").and_then(|t| t.as_str())
                                    && msg_type == "registered"
                                {
                                    // Already registered or pairing approved
                                    if let Some(payload) = json.get("payload")
                                        && let Some(key) =
                                            payload.get("client-key").and_then(|k| k.as_str())
                                    {
                                        Self::store_client_key(ip, key);
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

    /// Send a command to LG TV
    pub fn send_command(ip: &str, uri: &str) -> CommandResult {
        let client_key = match Self::get_client_key(ip) {
            Some(k) => k,
            None => {
                return CommandResult {
                    success: false,
                    message: "Not paired. Please pair with the TV first.".to_string(),
                };
            }
        };

        let url = format!("ws://{}:{}", ip, Self::WS_PORT);

        match connect(&url) {
            Ok((mut socket, _)) => {
                // Send handshake first
                let handshake = Self::build_handshake(Some(&client_key));
                if let Err(e) = socket.send(Message::Text(handshake)) {
                    return CommandResult {
                        success: false,
                        message: format!("Failed to send handshake: {}", e),
                    };
                }

                // Wait for registration response
                let mut registered = false;
                for _ in 0..10 {
                    match socket.read() {
                        Ok(Message::Text(text)) => {
                            if text.contains("registered") {
                                registered = true;
                                break;
                            }
                        }
                        _ => {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                }

                if !registered {
                    let _ = socket.close(None);
                    return CommandResult {
                        success: false,
                        message: "Failed to register with TV. Try pairing again.".to_string(),
                    };
                }

                // Send the actual command
                let cmd = serde_json::json!({
                    "type": "request",
                    "id": "command_1",
                    "uri": uri
                });

                match socket.send(Message::Text(cmd.to_string())) {
                    Ok(_) => {
                        // Read response
                        let _ = socket.read();
                        let _ = socket.close(None);
                        CommandResult {
                            success: true,
                            message: "Command sent to LG TV".to_string(),
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
                message: format!("Failed to connect: {}", e),
            },
        }
    }

    /// Get device info from LG TV
    pub fn get_device_info(ip: &str) -> Option<DeviceInfo> {
        let client_key = Self::get_client_key(ip)?;
        let url = format!("ws://{}:{}", ip, Self::WS_PORT);

        let (mut socket, _) = connect(&url).ok()?;

        // Send handshake
        let handshake = Self::build_handshake(Some(&client_key));
        socket.send(Message::Text(handshake)).ok()?;

        // Wait for registration
        for _ in 0..10 {
            if let Ok(Message::Text(text)) = socket.read()
                && text.contains("registered")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        // Request system info
        let cmd = serde_json::json!({
            "type": "request",
            "id": "info_1",
            "uri": "ssap://system/getSystemInfo"
        });
        socket.send(Message::Text(cmd.to_string())).ok()?;

        // Read response
        let mut model = None;
        let mut software_version = None;

        for _ in 0..5 {
            if let Ok(Message::Text(text)) = socket.read()
                && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
                && let Some(payload) = json.get("payload")
            {
                model = payload
                    .get("modelName")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                software_version = payload
                    .get("sdkVersion")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if model.is_some() {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let _ = socket.close(None);

        Some(DeviceInfo {
            model,
            name: Some("LG TV".to_string()),
            software_version,
        })
    }

    /// Get installed apps from LG TV
    pub fn get_apps(ip: &str) -> Vec<AppInfo> {
        let client_key = match Self::get_client_key(ip) {
            Some(k) => k,
            None => return Vec::new(),
        };

        let url = format!("ws://{}:{}", ip, Self::WS_PORT);

        let (mut socket, _) = match connect(&url) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        // Send handshake
        let handshake = Self::build_handshake(Some(&client_key));
        if socket.send(Message::Text(handshake)).is_err() {
            return Vec::new();
        }

        // Wait for registration
        for _ in 0..10 {
            if let Ok(Message::Text(text)) = socket.read()
                && text.contains("registered")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        // Request app list
        let cmd = serde_json::json!({
            "type": "request",
            "id": "apps_1",
            "uri": "ssap://com.webos.applicationManager/listLaunchPoints"
        });

        if socket.send(Message::Text(cmd.to_string())).is_err() {
            return Vec::new();
        }

        // Read response
        let mut apps = Vec::new();
        for _ in 0..10 {
            if let Ok(Message::Text(text)) = socket.read()
                && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
                && let Some(payload) = json.get("payload")
                && let Some(launch_points) = payload.get("launchPoints")
                && let Some(arr) = launch_points.as_array()
            {
                for app in arr {
                    if let (Some(id), Some(title)) = (
                        app.get("id").and_then(|v| v.as_str()),
                        app.get("title").and_then(|v| v.as_str()),
                    ) {
                        let icon_url = app
                            .get("icon")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        apps.push(AppInfo {
                            id: id.to_string(),
                            name: title.to_string(),
                            icon_url,
                        });
                    }
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let _ = socket.close(None);

        apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        apps
    }

    /// Launch an app on LG TV
    pub fn launch_app(ip: &str, app_id: &str) -> CommandResult {
        let client_key = match Self::get_client_key(ip) {
            Some(k) => k,
            None => {
                return CommandResult {
                    success: false,
                    message: "Not paired. Please pair with the TV first.".to_string(),
                };
            }
        };

        let url = format!("ws://{}:{}", ip, Self::WS_PORT);

        match connect(&url) {
            Ok((mut socket, _)) => {
                // Send handshake
                let handshake = Self::build_handshake(Some(&client_key));
                if socket.send(Message::Text(handshake)).is_err() {
                    return CommandResult {
                        success: false,
                        message: "Failed to send handshake".to_string(),
                    };
                }

                // Wait for registration
                for _ in 0..10 {
                    if let Ok(Message::Text(text)) = socket.read()
                        && text.contains("registered")
                    {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }

                // Launch app
                let cmd = serde_json::json!({
                    "type": "request",
                    "id": "launch_1",
                    "uri": "ssap://system.launcher/launch",
                    "payload": {
                        "id": app_id
                    }
                });

                match socket.send(Message::Text(cmd.to_string())) {
                    Ok(_) => {
                        let _ = socket.read();
                        let _ = socket.close(None);
                        CommandResult {
                            success: true,
                            message: "App launched".to_string(),
                        }
                    }
                    Err(e) => {
                        let _ = socket.close(None);
                        CommandResult {
                            success: false,
                            message: format!("Failed to launch app: {}", e),
                        }
                    }
                }
            }
            Err(e) => CommandResult {
                success: false,
                message: format!("Failed to connect: {}", e),
            },
        }
    }

    /// Get all available LG TV commands
    pub fn get_commands() -> Vec<CommandInfo> {
        vec![
            // Navigation
            CommandInfo {
                id: "ssap://com.webos.service.ime/sendEnterKey".into(),
                name: "OK".into(),
                icon: "⏺️".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "ssap://com.webos.service.tv.display/set3DOn".into(),
                name: "3D On".into(),
                icon: "👓".into(),
                category: "Display".into(),
            },
            CommandInfo {
                id: "ssap://com.webos.service.tv.display/set3DOff".into(),
                name: "3D Off".into(),
                icon: "📺".into(),
                category: "Display".into(),
            },
            // Volume
            CommandInfo {
                id: "ssap://audio/volumeUp".into(),
                name: "Volume Up".into(),
                icon: "🔊".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "ssap://audio/volumeDown".into(),
                name: "Volume Down".into(),
                icon: "🔉".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "ssap://audio/setMute".into(),
                name: "Mute".into(),
                icon: "🔇".into(),
                category: "Volume".into(),
            },
            // Channel
            CommandInfo {
                id: "ssap://tv/channelUp".into(),
                name: "Channel Up".into(),
                icon: "📺+".into(),
                category: "Channel".into(),
            },
            CommandInfo {
                id: "ssap://tv/channelDown".into(),
                name: "Channel Down".into(),
                icon: "📺-".into(),
                category: "Channel".into(),
            },
            // Playback
            CommandInfo {
                id: "ssap://media.controls/play".into(),
                name: "Play".into(),
                icon: "▶️".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "ssap://media.controls/pause".into(),
                name: "Pause".into(),
                icon: "⏸️".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "ssap://media.controls/stop".into(),
                name: "Stop".into(),
                icon: "⏹️".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "ssap://media.controls/rewind".into(),
                name: "Rewind".into(),
                icon: "⏪".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "ssap://media.controls/fastForward".into(),
                name: "Fast Forward".into(),
                icon: "⏩".into(),
                category: "Playback".into(),
            },
            // Power
            CommandInfo {
                id: "ssap://system/turnOff".into(),
                name: "Power Off".into(),
                icon: "⏻".into(),
                category: "Power".into(),
            },
            // Input
            CommandInfo {
                id: "ssap://tv/switchInput".into(),
                name: "Switch Input".into(),
                icon: "🔌".into(),
                category: "Other".into(),
            },
            // Screen
            CommandInfo {
                id: "ssap://com.webos.service.capture/executeRecordScreen".into(),
                name: "Screen Capture".into(),
                icon: "📷".into(),
                category: "Other".into(),
            },
        ]
    }

    /// Get capabilities for an LG TV
    pub fn get_capabilities(ip: &str) -> DeviceCapabilities {
        let has_key = Self::get_client_key(ip).is_some();
        let device_info = if has_key {
            Self::get_device_info(ip)
        } else {
            None
        };
        let apps = if has_key {
            Self::get_apps(ip)
        } else {
            Vec::new()
        };
        let commands = Self::get_commands();

        DeviceCapabilities {
            device_type: "lg".to_string(),
            can_control: true,
            commands,
            apps,
            device_info,
            needs_pairing: !has_key,
            is_paired: has_key,
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
        // Check for LG ThinQ appliances first (dishwashers, washers, etc.)
        if LgThinQController::is_thinq_appliance(hostname) {
            return LgThinQController::get_capabilities(hostname.unwrap_or(""));
        }

        // Quick check: if hostname contains "samsung", skip other checks
        if let Some(name) = hostname
            && name.to_lowercase().contains("samsung")
        {
            return SamsungController::get_capabilities(ip);
        }

        // Check for LG TV (webOS)
        if let Some(name) = hostname {
            let lower = name.to_lowercase();
            if lower.contains("lgtv") || lower.contains("webos") || lower.contains("lg-tv") {
                return LgController::get_capabilities(ip);
            }
        }

        // For TV types, try Roku, Samsung, and LG
        if device_type == Some("tv") || device_type == Some("streaming") {
            if RokuController::is_roku(ip) {
                return RokuController::get_capabilities(ip);
            }
            if SamsungController::is_samsung_with_hostname(ip, hostname) {
                return SamsungController::get_capabilities(ip);
            }
            if LgController::is_lg_tv(ip, hostname) {
                return LgController::get_capabilities(ip);
            }
        }

        // Also try detection regardless of type (some might be misclassified)
        if RokuController::is_roku(ip) {
            return RokuController::get_capabilities(ip);
        }

        if SamsungController::is_samsung_with_hostname(ip, hostname) {
            return SamsungController::get_capabilities(ip);
        }

        if LgController::is_lg_tv(ip, hostname) {
            return LgController::get_capabilities(ip);
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
        // Handle lg_thinq with device_id embedded (format: "lg_thinq:device_id")
        if device_type.starts_with("lg_thinq") {
            return LgThinQController::send_command(device_type, command);
        }

        match device_type {
            "roku" => RokuController::send_keypress(ip, command),
            "samsung" => SamsungController::send_key(ip, command),
            "lg" => LgController::send_command(ip, command),
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
            "lg" => LgController::launch_app(ip, app_id),
            "samsung" => CommandResult {
                success: false,
                message: "App launching not yet supported for Samsung TVs".to_string(),
            },
            "lg_thinq" => CommandResult {
                success: false,
                message: "App launching not applicable for ThinQ appliances".to_string(),
            },
            _ => CommandResult {
                success: false,
                message: format!("App launching not supported for: {}", device_type),
            },
        }
    }

    /// Pair with a device that requires pairing (e.g., Samsung TV, LG TV)
    pub fn pair(ip: &str, device_type: &str) -> CommandResult {
        match device_type {
            "samsung" => SamsungController::pair(ip),
            "lg" => LgController::pair(ip),
            "lg_thinq" => CommandResult {
                success: false,
                message: "LG ThinQ requires PAT token setup. Use the ThinQ Setup button in the Control tab.".to_string(),
            },
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

    /// Setup LG ThinQ with PAT token
    pub fn setup_thinq(pat_token: &str, country_code: &str) -> CommandResult {
        LgThinQController::pair(pat_token, country_code)
    }

    /// List ThinQ devices
    pub fn list_thinq_devices() -> Result<Vec<ThinQDevice>, String> {
        LgThinQController::list_devices()
    }

    /// Check if ThinQ is configured
    pub fn is_thinq_configured() -> bool {
        LgThinQController::has_credentials()
    }

    /// Disconnect ThinQ by clearing stored credentials
    pub fn disconnect_thinq() -> bool {
        LgThinQController::clear_credentials()
    }
}
