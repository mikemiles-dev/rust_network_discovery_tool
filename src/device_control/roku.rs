//! Roku ECP controller. Implements the External Control Protocol on port 8060
//! for device info retrieval, app listing, and remote command execution.

use super::types::{AppInfo, CommandInfo, CommandResult, DeviceCapabilities, DeviceInfo};
use std::time::Duration;

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
                icon: "\u{2b06}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Down".into(),
                name: "Down".into(),
                icon: "\u{2b07}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Left".into(),
                name: "Left".into(),
                icon: "\u{2b05}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Right".into(),
                name: "Right".into(),
                icon: "\u{27a1}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Select".into(),
                name: "OK".into(),
                icon: "\u{23fa}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Back".into(),
                name: "Back".into(),
                icon: "\u{21a9}\u{fe0f}".into(),
                category: "Navigation".into(),
            },
            CommandInfo {
                id: "Home".into(),
                name: "Home".into(),
                icon: "\u{1f3e0}".into(),
                category: "Navigation".into(),
            },
            // Playback
            CommandInfo {
                id: "Play".into(),
                name: "Play/Pause".into(),
                icon: "\u{23ef}\u{fe0f}".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "Rev".into(),
                name: "Rewind".into(),
                icon: "\u{23ea}".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "Fwd".into(),
                name: "Fast Forward".into(),
                icon: "\u{23e9}".into(),
                category: "Playback".into(),
            },
            CommandInfo {
                id: "InstantReplay".into(),
                name: "Replay".into(),
                icon: "\u{1f504}".into(),
                category: "Playback".into(),
            },
            // Volume
            CommandInfo {
                id: "VolumeUp".into(),
                name: "Volume Up".into(),
                icon: "\u{1f50a}".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "VolumeDown".into(),
                name: "Volume Down".into(),
                icon: "\u{1f509}".into(),
                category: "Volume".into(),
            },
            CommandInfo {
                id: "VolumeMute".into(),
                name: "Mute".into(),
                icon: "\u{1f507}".into(),
                category: "Volume".into(),
            },
            // Power
            CommandInfo {
                id: "PowerOff".into(),
                name: "Power Off".into(),
                icon: "\u{23fb}".into(),
                category: "Power".into(),
            },
            // Info
            CommandInfo {
                id: "Info".into(),
                name: "Info".into(),
                icon: "\u{2139}\u{fe0f}".into(),
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
