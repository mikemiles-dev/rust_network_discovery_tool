//! Shared types for device control. Defines capabilities, commands, app info,
//! device info, and control result structures used across all device controllers.

use serde::{Deserialize, Serialize};

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
