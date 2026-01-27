use super::types::{AppInfo, CommandInfo, CommandResult, DeviceCapabilities, DeviceInfo};
use std::net::TcpStream;
use std::time::Duration;
use tungstenite::{Message, connect};

/// LG webOS TV WebSocket API implementation
pub struct LgController;

impl LgController {
    const WS_PORT: u16 = 3000;
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
                icon: "\u{23fa}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "ssap://com.webos.service.tv.display/set3DOn".into(),
                name: "3D On".into(),
                icon: "\u{1f453}".into(),
                category: "Display".into(),
            },
            CommandInfo {
                id: "ssap://com.webos.service.tv.display/set3DOff".into(),
                name: "3D Off".into(),
                icon: "\u{1f4fa}".into(),
                category: "Display".into(),
            },
            // Volume
            CommandInfo {
                id: "ssap://audio/volumeUp".into(),
                name: "Volume Up".into(),
                icon: "\u{1f50a}".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "ssap://audio/volumeDown".into(),
                name: "Volume Down".into(),
                icon: "\u{1f509}".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "ssap://audio/setMute".into(),
                name: "Mute".into(),
                icon: "\u{1f507}".into(),
                category: "Volume".into(),
            },
            // Channel
            CommandInfo {
                id: "ssap://tv/channelUp".into(),
                name: "Channel Up".into(),
                icon: "\u{1f4fa}+".into(),
                category: "Channel".into(),
            },
            CommandInfo {
                id: "ssap://tv/channelDown".into(),
                name: "Channel Down".into(),
                icon: "\u{1f4fa}-".into(),
                category: "Channel".into(),
            },
            // Playback
            CommandInfo {
                id: "ssap://media.controls/play".into(),
                name: "Play".into(),
                icon: "\u{25b6}\u{fe0f}".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "ssap://media.controls/pause".into(),
                name: "Pause".into(),
                icon: "\u{23f8}\u{fe0f}".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "ssap://media.controls/stop".into(),
                name: "Stop".into(),
                icon: "\u{23f9}\u{fe0f}".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "ssap://media.controls/rewind".into(),
                name: "Rewind".into(),
                icon: "\u{23ea}".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "ssap://media.controls/fastForward".into(),
                name: "Fast Forward".into(),
                icon: "\u{23e9}".into(),
                category: "Playback".into(),
            },
            // Power
            CommandInfo {
                id: "ssap://system/turnOff".into(),
                name: "Power Off".into(),
                icon: "\u{23fb}".into(),
                category: "Power".into(),
            },
            // Input
            CommandInfo {
                id: "ssap://tv/switchInput".into(),
                name: "Switch Input".into(),
                icon: "\u{1f50c}".into(),
                category: "Other".into(),
            },
            // Screen
            CommandInfo {
                id: "ssap://com.webos.service.capture/executeRecordScreen".into(),
                name: "Screen Capture".into(),
                icon: "\u{1f4f7}".into(),
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
