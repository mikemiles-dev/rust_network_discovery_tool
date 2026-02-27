//! LG webOS TV controller. Communicates via WebSocket on port 3000 for TV power,
//! volume, input control, and capability detection.

use super::lg_commands;
use super::lg_pairing;
use super::types::{AppInfo, CommandResult, DeviceCapabilities, DeviceInfo};
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
        if let Some(name) = hostname {
            let lower = name.to_lowercase();
            if lower.contains("lgtv") || lower.contains("webos") || lower.contains("lg-tv") {
                return true;
            }
            if lower.starts_with("lma")
                || lower.starts_with("lmw")
                || lower.starts_with("wm")
                || lower.starts_with("wf")
            {
                return false;
            }
        }

        if let Ok(addr) = format!("{}:{}", ip, Self::WS_PORT).parse()
            && TcpStream::connect_timeout(&addr, Self::TIMEOUT).is_ok()
        {
            return true;
        }

        false
    }

    /// Initiate pairing with LG TV
    pub fn pair(ip: &str) -> CommandResult {
        lg_pairing::pair(ip)
    }

    /// Send a command to LG TV
    pub fn send_command(ip: &str, uri: &str) -> CommandResult {
        let client_key = match lg_pairing::get_client_key(ip) {
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
                let handshake = lg_pairing::build_handshake(Some(&client_key));
                if let Err(e) = socket.send(Message::Text(handshake)) {
                    return CommandResult {
                        success: false,
                        message: format!("Failed to send handshake: {}", e),
                    };
                }

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

                let cmd = serde_json::json!({
                    "type": "request",
                    "id": "command_1",
                    "uri": uri
                });

                match socket.send(Message::Text(cmd.to_string())) {
                    Ok(_) => {
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
        let client_key = lg_pairing::get_client_key(ip)?;
        let url = format!("ws://{}:{}", ip, Self::WS_PORT);

        let (mut socket, _) = connect(&url).ok()?;

        let handshake = lg_pairing::build_handshake(Some(&client_key));
        socket.send(Message::Text(handshake)).ok()?;

        for _ in 0..10 {
            if let Ok(Message::Text(text)) = socket.read()
                && text.contains("registered")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let cmd = serde_json::json!({
            "type": "request",
            "id": "info_1",
            "uri": "ssap://system/getSystemInfo"
        });
        socket.send(Message::Text(cmd.to_string())).ok()?;

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
        let client_key = match lg_pairing::get_client_key(ip) {
            Some(k) => k,
            None => return Vec::new(),
        };

        let url = format!("ws://{}:{}", ip, Self::WS_PORT);

        let (mut socket, _) = match connect(&url) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let handshake = lg_pairing::build_handshake(Some(&client_key));
        if socket.send(Message::Text(handshake)).is_err() {
            return Vec::new();
        }

        for _ in 0..10 {
            if let Ok(Message::Text(text)) = socket.read()
                && text.contains("registered")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let cmd = serde_json::json!({
            "type": "request",
            "id": "apps_1",
            "uri": "ssap://com.webos.applicationManager/listLaunchPoints"
        });

        if socket.send(Message::Text(cmd.to_string())).is_err() {
            return Vec::new();
        }

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
        let client_key = match lg_pairing::get_client_key(ip) {
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
                let handshake = lg_pairing::build_handshake(Some(&client_key));
                if socket.send(Message::Text(handshake)).is_err() {
                    return CommandResult {
                        success: false,
                        message: "Failed to send handshake".to_string(),
                    };
                }

                for _ in 0..10 {
                    if let Ok(Message::Text(text)) = socket.read()
                        && text.contains("registered")
                    {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }

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

    /// Get capabilities for an LG TV
    pub fn get_capabilities(ip: &str) -> DeviceCapabilities {
        lg_commands::get_capabilities(ip)
    }
}
