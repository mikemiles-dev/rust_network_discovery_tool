use super::lg::LgController;
use super::lg_thinq::{LgThinQController, ThinQDevice};
use super::roku::RokuController;
use super::samsung::SamsungController;
use super::types::{CommandResult, DeviceCapabilities};

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
