//! Hostname-based device model identification. Extracts model names from
//! device hostnames using brand-specific naming patterns and conventions.

use super::classify::is_roku_serial_number;
use super::model_data::*;
use super::patterns::HOSTNAME_MODEL_RULES;

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
