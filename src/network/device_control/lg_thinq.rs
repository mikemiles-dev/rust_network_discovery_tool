//! LG ThinQ cloud controller. Interfaces with the LG Connect API for monitoring
//! and controlling appliances (dishwashers, washers, dryers, refrigerators).

use super::types::{CommandInfo, CommandResult, DeviceCapabilities, DeviceInfo};
use serde::{Deserialize, Serialize};
use std::time::Duration;

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

    /// Build API base URL for PAT authentication
    /// PAT tokens use the connect-pat endpoint regardless of region
    /// Get the API URL based on country code
    /// The actual API uses regional endpoints, not the PAT portal
    fn get_api_url(_country_code: &str) -> String {
        // LG ThinQ Connect uses a single global API endpoint
        // Country-specific routing is handled via headers, not URL
        // Reference: Home Assistant LG ThinQ integration
        "https://api-aic.lgthinq.com".to_string()
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

        let status = response.status();
        let response_text = response
            .text()
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if !status.is_success() {
            return Err(format!(
                "API error {}: {}",
                status,
                if response_text.len() > 200 {
                    &response_text[..200]
                } else {
                    &response_text
                }
            ));
        }

        if response_text.is_empty() {
            return Err("API returned empty response".to_string());
        }

        let json: serde_json::Value = serde_json::from_str(&response_text).map_err(|e| {
            format!(
                "Failed to parse JSON: {}. Response: {}",
                e,
                &response_text[..response_text.len().min(200)]
            )
        })?;

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
                    icon: "\u{1f4ca}".into(),
                    category: "Status".into(),
                },
                CommandInfo {
                    id: "start".into(),
                    name: "Start Cycle".into(),
                    icon: "\u{25b6}\u{fe0f}".into(),
                    category: "Control".into(),
                },
                CommandInfo {
                    id: "stop".into(),
                    name: "Stop".into(),
                    icon: "\u{23f9}\u{fe0f}".into(),
                    category: "Control".into(),
                },
            ],
            "Washing Machine" | "Dryer" => vec![
                CommandInfo {
                    id: "status".into(),
                    name: "Get Status".into(),
                    icon: "\u{1f4ca}".into(),
                    category: "Status".into(),
                },
                CommandInfo {
                    id: "start".into(),
                    name: "Start".into(),
                    icon: "\u{25b6}\u{fe0f}".into(),
                    category: "Control".into(),
                },
                CommandInfo {
                    id: "pause".into(),
                    name: "Pause".into(),
                    icon: "\u{23f8}\u{fe0f}".into(),
                    category: "Control".into(),
                },
                CommandInfo {
                    id: "stop".into(),
                    name: "Stop".into(),
                    icon: "\u{23f9}\u{fe0f}".into(),
                    category: "Control".into(),
                },
            ],
            "Refrigerator" => vec![
                CommandInfo {
                    id: "status".into(),
                    name: "Get Status".into(),
                    icon: "\u{1f4ca}".into(),
                    category: "Status".into(),
                },
                CommandInfo {
                    id: "express_freeze".into(),
                    name: "Express Freeze".into(),
                    icon: "\u{2744}\u{fe0f}".into(),
                    category: "Mode".into(),
                },
                CommandInfo {
                    id: "eco_mode".into(),
                    name: "Eco Mode".into(),
                    icon: "\u{1f331}".into(),
                    category: "Mode".into(),
                },
            ],
            "Air Conditioner" => vec![
                CommandInfo {
                    id: "power_on".into(),
                    name: "Power On".into(),
                    icon: "\u{23fb}".into(),
                    category: "Power".into(),
                },
                CommandInfo {
                    id: "power_off".into(),
                    name: "Power Off".into(),
                    icon: "\u{2b58}".into(),
                    category: "Power".into(),
                },
                CommandInfo {
                    id: "status".into(),
                    name: "Get Status".into(),
                    icon: "\u{1f4ca}".into(),
                    category: "Status".into(),
                },
            ],
            _ => vec![CommandInfo {
                id: "status".into(),
                name: "Get Status".into(),
                icon: "\u{1f4ca}".into(),
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
