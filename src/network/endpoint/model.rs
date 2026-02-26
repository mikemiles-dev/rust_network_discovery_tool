//! Device model identification. Normalizes raw model numbers to friendly display names
//! and infers models from hostnames, MAC addresses, and vendor context.

use super::classify::{is_roku_serial_number, is_roku_tv_model};
use super::model_data::*;
use super::patterns::{
    HOSTNAME_MODEL_RULES, LG_TV_SERIES, MAC_VENDOR_MODEL_RULES, SAMSUNG_TV_SERIES, SONY_TV_SERIES,
    VENDOR_TYPE_MODEL_RULES,
};
use super::types::{Characterized, pick_best};
use super::vendor::get_mac_vendor;

/// Normalize a TV/device model number to a friendly name
/// e.g., "QN43LS03TAFXZA" -> "Samsung The Frame"
/// e.g., "OLED55C3PUA" -> "LG OLED C3"
/// e.g., "HW-MS750" -> "Samsung Soundbar"
pub fn normalize_model_name(model: &str, vendor: Option<&str>) -> Option<String> {
    let model_upper = model.to_uppercase();
    let model_lower = model.to_lowercase();

    // Check for soundbar models first
    for &(prefix, skip) in SAMSUNG_SOUNDBAR_PREFIXES {
        if model_lower.starts_with(prefix) {
            let series = &model_upper[skip..];
            return Some(format!("Samsung Soundbar {}", series));
        }
    }
    if model_lower.starts_with(SAMSUNG_WAM_PREFIX) {
        return Some(format!(
            "Samsung Wireless Speaker {}",
            &model_upper[SAMSUNG_WAM_PREFIX.len()..]
        ));
    }
    // LG soundbar models
    if LG_SOUNDBAR_PREFIXES
        .iter()
        .any(|p| model_lower.starts_with(p))
        && model_lower
            .chars()
            .nth(2)
            .is_some_and(|c| c.is_ascii_digit())
    {
        return Some(format!("LG Soundbar {}", model_upper));
    }
    if model_lower.starts_with(LG_SOUNDBAR_SPECIAL_PREFIX) {
        return Some(format!("LG Soundbar {}", model_upper));
    }
    // JBL soundbar
    if JBL_SOUNDBAR_PREFIXES
        .iter()
        .any(|p| model_lower.starts_with(p))
    {
        return Some(format!("JBL {}", model_upper));
    }

    // AV Receivers
    for &(prefix, label, skip) in AV_RECEIVER_RULES {
        if model_lower.starts_with(prefix) {
            return if skip > 0 {
                Some(format!("{}{}", label, &model_upper[skip..]))
            } else {
                Some(format!("{}{}", label, model_upper))
            };
        }
    }
    // Marantz SR/NR series (SR5015, NR1711, etc.)
    for prefix in MARANTZ_PREFIXES {
        if model_lower.starts_with(prefix)
            && model_lower
                .chars()
                .nth(2)
                .is_some_and(|c| c.is_ascii_digit())
        {
            return Some(format!("Marantz {}", model_upper));
        }
    }

    // Determine vendor from model prefix or provided vendor
    let is_samsung = SAMSUNG_TV_MODEL_PREFIXES
        .iter()
        .any(|p| model_upper.starts_with(p))
        || vendor.is_some_and(|v| v.to_lowercase().contains("samsung"));
    let is_lg = LG_TV_MODEL_KEYWORDS
        .iter()
        .any(|k| model_upper.contains(k))
        || vendor.is_some_and(|v| v.to_lowercase().contains("lg"));
    let is_sony = SONY_TV_MODEL_PREFIXES
        .iter()
        .any(|p| model_upper.starts_with(p))
        || vendor.is_some_and(|v| v.to_lowercase().contains("sony"));

    // Samsung TV models
    if is_samsung {
        // Skip screen size digits to find series identifier
        // Format: [QN|UN][Size][Series][Variant]
        let has_panel_prefix = SAMSUNG_TV_MODEL_PREFIXES
            .iter()
            .any(|p| model_upper.starts_with(p));
        let series_part = if has_panel_prefix {
            // Skip panel type (2 chars) and size (2-3 digits)
            let after_panel = &model_lower[2..];
            after_panel.trim_start_matches(|c: char| c.is_ascii_digit())
        } else {
            &model_lower[..]
        };

        for (pattern, name) in SAMSUNG_TV_SERIES {
            if series_part.starts_with(pattern) {
                return Some(format!("Samsung {}", name));
            }
        }
    }

    // LG TV models
    if is_lg {
        for (pattern, name) in LG_TV_SERIES {
            if model_lower.contains(pattern) {
                return Some(format!("LG {}", name));
            }
        }
    }

    // Sony TV models
    if is_sony {
        // Skip prefix like XR or KD and size
        let series_part = model_lower
            .trim_start_matches("xr")
            .trim_start_matches("kd")
            .trim_start_matches(|c: char| c.is_ascii_digit() || c == '-');

        for (pattern, name) in SONY_TV_SERIES {
            if series_part.starts_with(pattern) {
                return Some(format!("Sony {}", name));
            }
        }
    }

    // Roku TV platform identifiers (TCL, Hisense TVs running Roku OS)
    // Models like 7105X, 7000X, 6500X are typically TCL Roku TVs
    // Vendor is set separately to TCL, so just return "Roku TV" as model
    if is_roku_tv_model(&model_upper) {
        return Some("Roku TV".to_string());
    }

    None
}

/// Characterize model from all available sources, returning the best match with source info.
/// Priority: custom_model (UserSet) > DeviceReported(SSDP, SNMP) > hostname (PatternMatched) > MAC/vendor inference (NetworkInferred)
pub fn characterize_model(
    custom_model: Option<&str>,
    ssdp_model: Option<&str>,
    snmp_model: Option<&str>,
    hostname: Option<&str>,
    macs: &[String],
    vendor: Option<&str>,
    device_type: Option<&str>,
) -> Option<Characterized<String>> {
    // User-set model has highest priority
    let user = custom_model
        .filter(|m| !m.is_empty())
        .map(|m| Characterized::user_set(m.to_string()));

    // SSDP model - normalize it for better display
    let ssdp = ssdp_model
        .filter(|m| !m.is_empty())
        .and_then(|m| normalize_model_name(m, vendor).or_else(|| Some(m.to_string())))
        .map(Characterized::device_reported);

    // SNMP model - device self-reports via sysDescr
    let from_snmp = snmp_model
        .filter(|m| !m.is_empty())
        .map(|m| Characterized::device_reported(m.to_string()));

    // Hostname-based model detection
    let from_hostname = hostname
        .filter(|h| !h.is_empty())
        .and_then(get_model_from_hostname)
        .map(Characterized::pattern_matched);

    // MAC-based model detection
    let from_mac = macs
        .iter()
        .find_map(|mac| get_model_from_mac(mac))
        .map(Characterized::network_inferred);

    // Vendor + device type inference (lowest priority pattern match)
    let from_vendor_type = vendor
        .filter(|v| !v.is_empty())
        .and_then(|v| {
            device_type
                .filter(|t| !t.is_empty())
                .and_then(|t| get_model_from_vendor_and_type(v, t))
        })
        .map(Characterized::pattern_matched);

    // Pick the best one (highest priority source)
    pick_best(&[
        user,
        ssdp,
        from_snmp,
        from_hostname,
        from_mac,
        from_vendor_type,
    ])
}

/// Extract model name from hostname patterns
pub fn get_model_from_hostname(hostname: &str) -> Option<String> {
    let lower = hostname.to_lowercase();

    // Simple rules from generated TOML data (fast path)
    for &(match_type, pattern, model) in HOSTNAME_MODEL_RULES {
        let matched = match match_type {
            "c" => lower.contains(pattern),
            "s" => lower.starts_with(pattern),
            _ => false,
        };
        if matched {
            return Some(model.to_string());
        }
    }

    // Roku devices: Roku-Ultra-XXXXX, Roku-Express-XXXXX, etc.
    if lower.starts_with("roku-") || lower.starts_with("roku_") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        if parts.len() >= 2 {
            // Model is typically the second part
            let model = parts[1];
            if !model.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(model.to_string());
            }
        }
    }

    // Roku serial number as hostname (e.g., YN00NJ468680) - typically TCL Roku TVs
    if is_roku_serial_number(&hostname.to_uppercase()) {
        return Some("Roku TV".to_string());
    }

    // PlayStation: PS4-XXXXX, PS5-XXXXX
    if lower.starts_with("ps4") {
        return Some("PlayStation 4".to_string());
    }
    if lower.starts_with("ps5") {
        return Some("PlayStation 5".to_string());
    }

    // Xbox: Xbox-One-XXXXX, Xbox-Series-X-XXXXX
    if lower.starts_with("xbox") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        if parts.len() >= 2 {
            // Combine model parts (e.g., "Series-X" -> "Series X")
            let model_parts: Vec<&str> = parts[1..]
                .iter()
                .take_while(|p| !p.chars().all(|c| c.is_ascii_hexdigit()))
                .copied()
                .collect();
            if !model_parts.is_empty() {
                return Some(format!("Xbox {}", model_parts.join(" ")));
            }
        }
        return Some("Xbox".to_string());
    }

    // iPhone: iPhone-14-Pro, iPhone15Pro, etc.
    if lower.contains("iphone") {
        // Try to extract version number
        let after_iphone = lower.split("iphone").nth(1).unwrap_or("");
        let model_str: String = after_iphone
            .chars()
            .skip_while(|c| *c == '-' || *c == '_')
            .take_while(|c| c.is_ascii_digit() || *c == '-' || *c == '_' || c.is_ascii_alphabetic())
            .collect();
        if !model_str.is_empty() {
            let cleaned: String = model_str
                .replace(['-', '_'], " ")
                .split_whitespace()
                .take_while(|p| !p.chars().all(|c| c.is_ascii_hexdigit() || c == 's'))
                .collect::<Vec<_>>()
                .join(" ");
            if !cleaned.is_empty() {
                return Some(format!("iPhone {}", cleaned));
            }
        }
        return Some("iPhone".to_string());
    }

    // iPad: iPad-Pro, iPad-Air, etc.
    if lower.contains("ipad") {
        let after_ipad = lower.split("ipad").nth(1).unwrap_or("");
        let model_str: String = after_ipad
            .chars()
            .skip_while(|c| *c == '-' || *c == '_')
            .take_while(|c| c.is_ascii_alphabetic() || *c == '-' || *c == '_')
            .collect();
        if !model_str.is_empty() && !model_str.chars().all(|c| c.is_ascii_hexdigit()) {
            let cleaned = model_str.replace(['-', '_'], " ");
            return Some(format!("iPad {}", cleaned.trim()));
        }
        return Some("iPad".to_string());
    }

    // MacBook: MacBook-Pro, MacBook-Air, etc.
    if lower.contains("macbook") {
        if lower.contains("pro") {
            return Some("MacBook Pro".to_string());
        }
        if lower.contains("air") {
            return Some("MacBook Air".to_string());
        }
        return Some("MacBook".to_string());
    }

    // Samsung devices - comprehensive model detection
    if lower.contains("samsung") || lower.starts_with("galaxy") || lower.contains("sm-") {
        let parts: Vec<&str> = hostname.split(['-', '_', ' ', '.']).collect();

        // Samsung TVs: QN65Q80B, UN55NU8000, UA55AU8000
        for part in &parts {
            let upper = part.to_uppercase();
            if (upper.starts_with("QN") || upper.starts_with("UN") || upper.starts_with("UA"))
                && upper.len() >= 6
            {
                return Some(format!("Samsung TV {}", upper));
            }
        }

        // Galaxy phones by model number (SM-XXXX)
        for part in &parts {
            let upper = part.to_uppercase();
            if upper.starts_with("SM-") {
                // S series: SM-S9xx, SM-S8xx -> "Galaxy S" + chars 4..6
                for &(prefix, label) in GALAXY_SM_PREFIX_RULES {
                    if upper.starts_with(prefix) {
                        return Some(format!("{}{}", label, &upper[4..6]));
                    }
                }
                // Older G-series: SM-G9xx -> specific Galaxy S model
                for &(prefix, name) in GALAXY_SM_G_SERIES {
                    if upper.starts_with(prefix) {
                        return Some(name.to_string());
                    }
                }
                // A series: SM-A5xx, SM-A7xx
                if upper.starts_with(GALAXY_SM_A_PREFIX) {
                    let model_num = &upper[4..6];
                    return Some(format!("Galaxy A{}", model_num));
                }
                // Z Fold: SM-F9xx
                if upper.starts_with(GALAXY_SM_FOLD_PREFIX) {
                    return Some("Galaxy Z Fold".to_string());
                }
                // Z Flip: SM-F7xx
                if upper.starts_with(GALAXY_SM_FLIP_PREFIX) {
                    return Some("Galaxy Z Flip".to_string());
                }
                // Note series: SM-N9xx
                if upper.starts_with(GALAXY_SM_NOTE_PREFIX) {
                    return Some("Galaxy Note".to_string());
                }
                // Tab series: SM-T, SM-X
                if GALAXY_SM_TAB_PREFIXES.iter().any(|p| upper.starts_with(p)) {
                    return Some("Galaxy Tab".to_string());
                }
                return Some(format!("Galaxy ({})", upper));
            }
        }

        // Galaxy phones by name pattern
        if lower.contains("galaxy") {
            // S series
            for &(pattern, name) in GALAXY_S_HOSTNAME_PATTERNS {
                if lower.contains(pattern) {
                    return Some(name.to_string());
                }
            }
            // A series
            for &(pattern, name) in GALAXY_A_HOSTNAME_PATTERNS {
                if lower.contains(pattern) {
                    return Some(name.to_string());
                }
            }
            // Z series
            if GALAXY_Z_FOLD_PATTERNS.iter().any(|p| lower.contains(p)) {
                return Some("Galaxy Z Fold".to_string());
            }
            if GALAXY_Z_FLIP_PATTERNS.iter().any(|p| lower.contains(p)) {
                return Some("Galaxy Z Flip".to_string());
            }
            // Note
            if lower.contains("note") {
                return Some("Galaxy Note".to_string());
            }
            // Tab
            if lower.contains("tab") {
                for &(pattern, name) in GALAXY_TAB_HOSTNAME_PATTERNS {
                    if lower.contains(pattern) {
                        return Some(name.to_string());
                    }
                }
                return Some("Galaxy Tab".to_string());
            }
            // Watch
            if lower.contains("watch") {
                for &(pattern, name) in GALAXY_WATCH_HOSTNAME_PATTERNS {
                    if lower.contains(pattern) {
                        return Some(name.to_string());
                    }
                }
                return Some("Galaxy Watch".to_string());
            }
            // Buds
            if lower.contains("buds") {
                for &(pattern, name) in GALAXY_BUDS_HOSTNAME_PATTERNS {
                    if lower.contains(pattern) {
                        return Some(name.to_string());
                    }
                }
                return Some("Galaxy Buds".to_string());
            }
            return Some("Galaxy".to_string());
        }

        // Samsung soundbars: HW-Q990C, HW-S800B
        for part in &parts {
            let upper = part.to_uppercase();
            if upper.starts_with("HW-") || upper.starts_with("HW") && upper.len() >= 6 {
                return Some(format!("Soundbar {}", upper));
            }
        }

        // SmartThings
        if lower.contains("smartthings") {
            for &(pattern, name) in SMARTTHINGS_VARIANTS {
                if lower.contains(pattern) {
                    return Some(name.to_string());
                }
            }
            return Some("SmartThings".to_string());
        }

        // Samsung appliances
        for &(contains_patterns, prefix_patterns, name) in SAMSUNG_APPLIANCE_RULES {
            if contains_patterns.iter().any(|p| lower.contains(p))
                || prefix_patterns.iter().any(|p| lower.starts_with(p))
            {
                return Some(name.to_string());
            }
        }
    }

    // Huawei devices - phones, tablets, routers
    if lower.contains("huawei") || lower.starts_with("honor") || lower.contains("harmonyos") {
        let parts: Vec<&str> = hostname.split(['-', '_', ' ', '.']).collect();

        // Huawei phones: P40, P30, Mate 40, Mate 30, Nova, etc.
        for part in &parts {
            let upper = part.to_uppercase();
            // P series: P40, P30, P20
            if upper.starts_with("P")
                && upper.len() >= 2
                && upper.chars().skip(1).all(|c| c.is_ascii_digit())
            {
                return Some(format!("Huawei {}", upper));
            }
            // Mate/Nova series
            for prefix in HUAWEI_PHONE_PREFIXES {
                if upper.starts_with(prefix) {
                    return Some(format!("Huawei {}", upper));
                }
            }
        }

        // Honor devices
        if lower.contains("honor") {
            for part in &parts {
                let upper = part.to_uppercase();
                // Honor number series: Honor 50, Honor 70, etc.
                if upper.chars().all(|c| c.is_ascii_digit()) && !upper.is_empty() {
                    return Some(format!("Honor {}", upper));
                }
                // Honor X series
                if upper.starts_with("X") && upper.len() >= 2 {
                    return Some(format!("Honor {}", upper));
                }
            }
            return Some("Honor Phone".to_string());
        }

        // MatePad tablets
        if lower.contains("matepad") {
            return Some("MatePad".to_string());
        }

        // HarmonyOS devices
        if lower.contains("harmonyos") {
            return Some("Huawei HarmonyOS Device".to_string());
        }

        return Some("Huawei Device".to_string());
    }

    // LG TVs: often have model numbers like OLED55C1, 65UP8000
    if lower.starts_with("lg") || lower.contains("[lg]") {
        let parts: Vec<&str> = hostname.split(['-', '_', ' ']).collect();
        for part in parts {
            let upper = part.to_uppercase();
            if upper.starts_with("OLED") || upper.starts_with("NANO") {
                return Some(upper);
            }
            // Model like 65UP8000
            if upper.len() >= 6
                && upper.chars().take(2).all(|c| c.is_ascii_digit())
                && upper
                    .chars()
                    .skip(2)
                    .take(2)
                    .all(|c| c.is_ascii_uppercase())
            {
                return Some(upper);
            }
        }
    }

    // LG ThinQ dishwashers: LDP/LDF prefixes
    if LG_DISHWASHER_PREFIXES
        .iter()
        .any(|p| lower.starts_with(p))
    {
        return Some("Dishwasher".to_string());
    }
    if lower.starts_with(LG_WASHER_PREFIX)
        && lower
            .chars()
            .nth(2)
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
    {
        return Some("Washing Machine".to_string());
    }
    if LG_DRYER_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return Some("Dryer".to_string());
    }
    if LG_FRIDGE_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return Some("Refrigerator".to_string());
    }

    // Google/Nest devices
    if lower.contains("chromecast") {
        for &(pattern, name) in CHROMECAST_VARIANTS {
            if lower.contains(pattern) {
                return Some(name.to_string());
            }
        }
        return Some("Chromecast".to_string());
    }
    if lower.contains("nest-hub") || lower.contains("nesthub") {
        for &(pattern, name) in NEST_HUB_VARIANTS {
            if lower.contains(pattern) {
                return Some(name.to_string());
            }
        }
        return Some("Nest Hub".to_string());
    }
    if NEST_MINI_PATTERNS.iter().any(|p| lower.contains(p)) {
        return Some("Nest Mini".to_string());
    }
    if lower.contains("google-home") {
        return Some("Google Home".to_string());
    }

    // Amazon Echo devices
    if lower.contains("echo") {
        for &(pattern, name) in ECHO_VARIANTS {
            if lower.contains(pattern) {
                return Some(name.to_string());
            }
        }
        return Some("Echo".to_string());
    }

    // Sonos speakers
    if lower.contains("sonos") {
        for &(pattern, name) in SONOS_VARIANTS {
            if lower.contains(pattern) {
                return Some(name.to_string());
            }
        }
    }

    // Ring doorbells/cameras
    if lower.contains("ring") {
        for &(pattern, name) in RING_VARIANTS {
            if lower.contains(pattern) {
                return Some(name.to_string());
            }
        }
    }

    // HP Printers - try to extract model
    if lower.starts_with("hp") || lower.starts_with("npi") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in parts {
            let upper = part.to_uppercase();
            if HP_PRINTER_KEYWORDS.iter().any(|k| upper.contains(k)) {
                return Some(upper);
            }
        }
    }

    // Amazon Fire TV and Kindle
    if lower.contains("fire") {
        if lower.contains("tv") || lower.contains("stick") {
            for &(pattern, name) in FIRE_TV_VARIANTS {
                if lower.contains(pattern) {
                    return Some(name.to_string());
                }
            }
            return Some("Fire TV Stick".to_string());
        }
        if lower.contains("kindle") || lower.contains("hd") {
            return Some("Fire Tablet".to_string());
        }
    }
    if lower.contains("kindle") {
        for &(pattern, name) in KINDLE_VARIANTS {
            if lower.contains(pattern) {
                return Some(name.to_string());
            }
        }
        return Some("Kindle".to_string());
    }

    // TP-Link/Tapo devices
    if lower.contains("tapo") {
        if TAPO_CAMERA_KEYWORDS.iter().any(|k| lower.contains(k)) {
            let parts: Vec<&str> = lower.split(['-', '_']).collect();
            for part in &parts {
                if TAPO_CAMERA_PREFIXES.iter().any(|p| part.starts_with(p)) {
                    return Some(format!("Tapo {}", part.to_uppercase()));
                }
            }
            return Some("Tapo Camera".to_string());
        }
        if TAPO_PLUG_KEYWORDS.iter().any(|k| lower.contains(k)) {
            return Some("Tapo Smart Plug".to_string());
        }
        if TAPO_BULB_KEYWORDS.iter().any(|k| lower.contains(k)) {
            return Some("Tapo Smart Bulb".to_string());
        }
        return Some("Tapo Device".to_string());
    }
    if KASA_PLUG_KEYWORDS.iter().any(|k| lower.contains(k)) {
        return Some("Kasa Smart Plug".to_string());
    }
    if lower.contains("deco") {
        return Some("TP-Link Deco".to_string());
    }
    if lower.contains("archer") {
        return Some("TP-Link Archer".to_string());
    }

    // Wyze devices
    if lower.contains("wyze") {
        if lower.contains("cam") {
            for &(pattern, name) in WYZE_CAM_VARIANTS {
                if lower.contains(pattern) {
                    return Some(name.to_string());
                }
            }
            return Some("Wyze Cam".to_string());
        }
        for &(pattern, name) in WYZE_DEVICE_VARIANTS {
            if lower.contains(pattern) {
                return Some(name.to_string());
            }
        }
    }

    // iRobot Roomba
    if lower.contains("roomba") || lower.contains("irobot") {
        // Try to extract model number (e.g., Roomba-i7, Roomba-s9)
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in &parts {
            let p = part.to_lowercase();
            if ROOMBA_MODEL_PREFIXES
                .iter()
                .any(|&c| p.starts_with(c))
                && p.len() >= 2
                && p.chars()
                    .nth(1)
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
            {
                return Some(format!("Roomba {}", part.to_uppercase()));
            }
            // Numeric models like 675, 960
            if p.chars().all(|c| c.is_ascii_digit()) && p.len() == 3 {
                return Some(format!("Roomba {}", part));
            }
        }
        return Some("Roomba".to_string());
    }

    // Philips Hue
    if lower.contains("hue") || lower.contains("philips") {
        for &(pattern, name) in HUE_VARIANTS {
            if lower.contains(pattern) {
                return Some(name.to_string());
            }
        }
    }

    // Ecobee thermostats
    if lower.contains("ecobee") {
        for &(pattern, name) in ECOBEE_VARIANTS {
            if lower.contains(pattern) {
                return Some(name.to_string());
            }
        }
        return Some("Ecobee Thermostat".to_string());
    }

    // Canon printers
    if lower.contains("canon") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in &parts {
            let upper = part.to_uppercase();
            if CANON_PRINTER_PREFIXES
                .iter()
                .any(|p| upper.starts_with(p))
            {
                return Some(upper);
            }
        }
    }

    // Epson printers
    if lower.contains("epson") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in &parts {
            let upper = part.to_uppercase();
            if EPSON_PRINTER_PREFIXES
                .iter()
                .any(|p| upper.starts_with(p))
                || EPSON_PRINTER_KEYWORDS.iter().any(|k| upper.contains(k))
            {
                return Some(upper);
            }
        }
    }

    // Brother printers
    if lower.contains("brother") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in &parts {
            let upper = part.to_uppercase();
            if BROTHER_PRINTER_PREFIXES
                .iter()
                .any(|p| upper.starts_with(p))
            {
                return Some(upper);
            }
        }
    }

    // Nintendo Switch
    if lower.contains("switch") && (lower.contains("nintendo") || lower.starts_with("switch")) {
        if lower.contains("lite") {
            return Some("Switch Lite".to_string());
        }
        if lower.contains("oled") {
            return Some("Switch OLED".to_string());
        }
        return Some("Nintendo Switch".to_string());
    }
    if lower.starts_with("nintendo") || lower.contains("nx-") {
        return Some("Nintendo Switch".to_string());
    }

    // eero mesh routers
    if lower.contains("eero") {
        if lower.contains("pro") {
            return Some("eero Pro".to_string());
        }
        if lower.contains("beacon") {
            return Some("eero Beacon".to_string());
        }
        return Some("eero".to_string());
    }

    // Apple Watch
    if lower.contains("apple-watch") || lower.contains("applewatch") {
        for &(pattern, name) in APPLE_WATCH_VARIANTS {
            if lower.contains(pattern) {
                return Some(name.to_string());
            }
        }
        // Try to extract series number
        for i in 1..=APPLE_WATCH_MAX_SERIES {
            if lower.contains(&format!("series{}", i)) || lower.contains(&format!("series-{}", i)) {
                return Some(format!("Apple Watch Series {}", i));
            }
        }
        return Some("Apple Watch".to_string());
    }

    // HomePod
    if lower.contains("homepod") {
        if lower.contains("mini") {
            return Some("HomePod mini".to_string());
        }
        return Some("HomePod".to_string());
    }

    // Apple TV
    if lower.contains("apple-tv") || lower.contains("appletv") {
        if lower.contains("4k") {
            return Some("Apple TV 4K".to_string());
        }
        return Some("Apple TV".to_string());
    }

    // Belkin/Wemo smart devices
    if lower.contains("wemo") {
        for &(pattern, name) in WEMO_VARIANTS {
            if lower.contains(pattern) {
                return Some(name.to_string());
            }
        }
    }

    // Tuya/Smart Life generic devices
    if lower.contains("tuya") || lower.contains("smartlife") || lower.contains("smart-life") {
        if lower.contains("plug") {
            return Some("Smart Plug".to_string());
        }
        if lower.contains("bulb") || lower.contains("light") {
            return Some("Smart Bulb".to_string());
        }
        if lower.contains("cam") {
            return Some("Smart Camera".to_string());
        }
    }

    None
}

/// Infer model from MAC vendor with additional context about discovery
/// This allows more specific model identification based on what protocols found (or didn't find) the device
pub fn infer_model_with_context(
    mac: &str,
    has_ssdp: bool,
    has_mdns: bool,
    has_open_ports: bool,
    open_ports: &[u16],
) -> Option<String> {
    let vendor = get_mac_vendor(mac)?;

    match vendor {
        "Amazon" => {
            // Fire TV: typically has ADB port 5555 when developer mode enabled, or port 8008/8443
            if AMAZON_FIRE_TV_PORTS
                .iter()
                .any(|p| open_ports.contains(p))
            {
                return Some("Amazon Fire TV".to_string());
            }
            // Ring devices: usually have SSDP or mDNS
            if has_ssdp || has_mdns {
                // Could be Ring, Fire TV, or other
                return Some("Amazon Device".to_string());
            }
            // Amazon MAC + no SSDP + no mDNS + no open ports = likely Echo
            // Echo devices communicate only with Amazon cloud, no local services
            if !has_ssdp && !has_mdns && !has_open_ports {
                return Some("Amazon Echo".to_string());
            }
            Some("Amazon Device".to_string())
        }
        "Ring" => Some("Ring Device".to_string()),
        "Google" | "Nest" => {
            // Chromecast has port 8008/8443
            if GOOGLE_CHROMECAST_PORTS
                .iter()
                .any(|p| open_ports.contains(p))
            {
                return Some("Chromecast".to_string());
            }
            // Google Home/Nest speakers respond to mDNS _googlecast
            if has_mdns {
                return Some("Google/Nest Speaker".to_string());
            }
            Some("Google Device".to_string())
        }
        _ => None,
    }
}

/// Infer model from MAC vendor when hostname detection fails
pub fn get_model_from_mac(mac: &str) -> Option<String> {
    // Check specific MAC prefixes first (for vendors mapped to parent company)
    let mac_lower = mac.to_lowercase().replace(['-', '.'], ":");
    let prefix = if mac_lower.len() >= 8 {
        &mac_lower[..8]
    } else {
        ""
    };

    // SmartThings sensors (Wisol and Samjin make sensors for Samsung)
    if SMARTTHINGS_SENSOR_MAC_PREFIXES.contains(&prefix) {
        return Some("SmartThings Sensor".to_string());
    }

    let vendor = get_mac_vendor(mac)?;

    for &(v, model) in MAC_VENDOR_MODEL_RULES {
        if v == vendor {
            return Some(model.to_string());
        }
    }

    None
}

/// Get a more specific model using both vendor and device classification
/// Called after device type classification is complete for better accuracy
pub fn get_model_from_vendor_and_type(vendor: &str, device_type: &str) -> Option<String> {
    let mut wildcard: Option<(&str, bool)> = None;
    for &(v, dt, label, literal) in VENDOR_TYPE_MODEL_RULES {
        if v != vendor {
            continue;
        }
        if dt == device_type {
            return Some(if literal {
                label.to_string()
            } else {
                format!("{} {}", vendor, label)
            });
        }
        if dt.is_empty() {
            wildcard = Some((label, literal));
        }
    }
    wildcard.map(|(label, literal)| {
        if literal {
            label.to_string()
        } else {
            format!("{} {}", vendor, label)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_model_name() {
        // Samsung The Frame
        assert_eq!(
            normalize_model_name("QN43LS03TAFXZA", None),
            Some("Samsung The Frame".to_string())
        );
        assert_eq!(
            normalize_model_name("QN65LS03BAFXZA", None),
            Some("Samsung The Frame".to_string())
        );

        // Samsung The Serif
        assert_eq!(
            normalize_model_name("QN55LS01TAFXZA", None),
            Some("Samsung The Serif".to_string())
        );

        // Samsung QLED (numbered series)
        assert_eq!(
            normalize_model_name("QN65Q80CAFXZA", None),
            Some("Samsung QLED Q8".to_string())
        );
        assert_eq!(
            normalize_model_name("QN55Q60BAFXZA", None),
            Some("Samsung QLED Q6".to_string())
        );

        // Samsung Neo QLED
        assert_eq!(
            normalize_model_name("QN85QN90BAFXZA", None),
            Some("Samsung Neo QLED QN9".to_string())
        );

        // Samsung OLED
        assert_eq!(
            normalize_model_name("QN65S95BAFXZA", None),
            Some("Samsung OLED S95".to_string())
        );

        // Samsung Crystal UHD
        assert_eq!(
            normalize_model_name("UN55TU8000FXZA", None),
            Some("Samsung Crystal UHD TU8".to_string())
        );

        // LG OLED (with vendor hint)
        assert_eq!(
            normalize_model_name("OLED55C3PUA", Some("LG")),
            Some("LG OLED".to_string())
        );
        assert_eq!(
            normalize_model_name("55C2PUA", Some("LG")),
            Some("LG OLED C2".to_string())
        );

        // Sony Bravia (with vendor hint)
        assert_eq!(
            normalize_model_name("XR55A90J", Some("Sony")),
            Some("Sony Bravia XR A90".to_string())
        );

        // Soundbar models should normalize to friendly names
        assert_eq!(
            normalize_model_name("HW-MS750", None),
            Some("Samsung Soundbar MS750".to_string())
        );
        assert_eq!(
            normalize_model_name("HW-Q990B", None),
            Some("Samsung Soundbar Q990B".to_string())
        );
        assert_eq!(
            normalize_model_name("SPK-WAM750", None),
            Some("Samsung Soundbar WAM750".to_string())
        );
        assert_eq!(
            normalize_model_name("SL8YG", None),
            Some("LG Soundbar SL8YG".to_string())
        );

        // Unknown model should return None
        assert_eq!(normalize_model_name("XYZ123ABC", None), None);
    }

    #[test]
    fn test_roku_tv_model_hostname_detection() {
        assert_eq!(
            get_model_from_hostname("YN00NJ468680"),
            Some("Roku TV".to_string())
        );
        assert_eq!(
            get_model_from_hostname("yn00nj468680"),
            Some("Roku TV".to_string())
        );
    }
}
