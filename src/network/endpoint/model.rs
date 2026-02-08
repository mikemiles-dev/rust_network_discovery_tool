//! Device model identification. Normalizes raw model numbers to friendly display names
//! and infers models from hostnames, MAC addresses, and vendor context.

use super::detection::{is_roku_serial_number, is_roku_tv_model};
use super::patterns::{LG_TV_SERIES, SAMSUNG_TV_SERIES, SONY_TV_SERIES};
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
    if model_lower.starts_with("hw-") || model_lower.starts_with("spk-") {
        // Samsung soundbar - extract series
        // HW-MS750 -> Soundbar MS750
        // HW-Q990B -> Soundbar Q990B
        let series = if model_lower.starts_with("hw-") {
            &model_upper[3..]
        } else {
            &model_upper[4..]
        };
        return Some(format!("Samsung Soundbar {}", series));
    }
    if model_lower.starts_with("wam") {
        // Samsung Wireless Audio Multiroom
        return Some(format!("Samsung Wireless Speaker {}", &model_upper[3..]));
    }
    // LG soundbar models
    if (model_lower.starts_with("sl")
        || model_lower.starts_with("sn")
        || model_lower.starts_with("sp"))
        && model_lower
            .chars()
            .nth(2)
            .is_some_and(|c| c.is_ascii_digit())
    {
        return Some(format!("LG Soundbar {}", model_upper));
    }
    if model_lower.starts_with("sc9") {
        return Some(format!("LG Soundbar {}", model_upper));
    }
    // JBL soundbar
    if model_lower.starts_with("bar-") || model_lower.starts_with("bar ") {
        return Some(format!("JBL {}", model_upper));
    }

    // AV Receivers
    // Denon AVR series (AVR-S940H, AVR-X3700H, etc.)
    if model_lower.starts_with("avr-") {
        let series = &model_upper[4..];
        return Some(format!("Denon AVR {}", series));
    }
    // Yamaha RX-V series (RX-V479, RX-V685, etc.)
    if model_lower.starts_with("rx-v") {
        let series = &model_upper[4..];
        return Some(format!("Yamaha RX-V{}", series));
    }
    // Yamaha RX-A Aventage series
    if model_lower.starts_with("rx-a") {
        let series = &model_upper[4..];
        return Some(format!("Yamaha Aventage RX-A{}", series));
    }
    // Marantz SR series (SR5015, SR6015, etc.)
    if model_lower.starts_with("sr")
        && model_lower
            .chars()
            .nth(2)
            .is_some_and(|c| c.is_ascii_digit())
    {
        return Some(format!("Marantz {}", model_upper));
    }
    // Marantz NR series (NR1711, etc.)
    if model_lower.starts_with("nr")
        && model_lower
            .chars()
            .nth(2)
            .is_some_and(|c| c.is_ascii_digit())
    {
        return Some(format!("Marantz {}", model_upper));
    }
    // Onkyo TX-NR series
    if model_lower.starts_with("tx-nr") || model_lower.starts_with("tx-rz") {
        return Some(format!("Onkyo {}", model_upper));
    }
    // Pioneer VSX series
    if model_lower.starts_with("vsx-") {
        return Some(format!("Pioneer {}", model_upper));
    }

    // Determine vendor from model prefix or provided vendor
    let is_samsung = model_upper.starts_with("QN")
        || model_upper.starts_with("UN")
        || vendor.is_some_and(|v| v.to_lowercase().contains("samsung"));
    let is_lg = model_upper.starts_with("OLED")
        || model_upper.contains("NANO")
        || model_upper.contains("QNED")
        || vendor.is_some_and(|v| v.to_lowercase().contains("lg"));
    let is_sony = model_upper.starts_with("XR")
        || model_upper.starts_with("KD")
        || vendor.is_some_and(|v| v.to_lowercase().contains("sony"));

    // Samsung TV models
    if is_samsung {
        // Skip screen size digits to find series identifier
        // Format: [QN|UN][Size][Series][Variant]
        let series_part = if model_upper.starts_with("QN") || model_upper.starts_with("UN") {
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
    pick_best(&[user, ssdp, from_snmp, from_hostname, from_mac, from_vendor_type])
}

/// Extract model name from hostname patterns
pub fn get_model_from_hostname(hostname: &str) -> Option<String> {
    let lower = hostname.to_lowercase();

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
                // S series: SM-S9xx, SM-G9xx
                if upper.starts_with("SM-S9") || upper.starts_with("SM-S8") {
                    return Some(format!("Galaxy S{}", &upper[4..6]));
                }
                if upper.starts_with("SM-G99") {
                    return Some("Galaxy S21".to_string());
                }
                if upper.starts_with("SM-G98") {
                    return Some("Galaxy S20".to_string());
                }
                if upper.starts_with("SM-G97") {
                    return Some("Galaxy S10".to_string());
                }
                if upper.starts_with("SM-G96") {
                    return Some("Galaxy S9".to_string());
                }
                if upper.starts_with("SM-G95") {
                    return Some("Galaxy S8".to_string());
                }
                // A series: SM-A5xx, SM-A7xx
                if upper.starts_with("SM-A") {
                    let model_num = &upper[4..6];
                    return Some(format!("Galaxy A{}", model_num));
                }
                // Z Fold: SM-F9xx
                if upper.starts_with("SM-F9") {
                    return Some("Galaxy Z Fold".to_string());
                }
                // Z Flip: SM-F7xx
                if upper.starts_with("SM-F7") {
                    return Some("Galaxy Z Flip".to_string());
                }
                // Note series: SM-N9xx
                if upper.starts_with("SM-N9") {
                    return Some("Galaxy Note".to_string());
                }
                // Tab series: SM-T, SM-X
                if upper.starts_with("SM-T") || upper.starts_with("SM-X") {
                    return Some("Galaxy Tab".to_string());
                }
                return Some(format!("Galaxy ({})", upper));
            }
        }

        // Galaxy phones by name pattern
        if lower.contains("galaxy") {
            // S series
            if lower.contains("s24") {
                return Some("Galaxy S24".to_string());
            }
            if lower.contains("s23") {
                return Some("Galaxy S23".to_string());
            }
            if lower.contains("s22") {
                return Some("Galaxy S22".to_string());
            }
            if lower.contains("s21") {
                return Some("Galaxy S21".to_string());
            }
            if lower.contains("s20") {
                return Some("Galaxy S20".to_string());
            }
            if lower.contains("s10") {
                return Some("Galaxy S10".to_string());
            }
            // A series
            if lower.contains("a54") {
                return Some("Galaxy A54".to_string());
            }
            if lower.contains("a53") {
                return Some("Galaxy A53".to_string());
            }
            if lower.contains("a52") {
                return Some("Galaxy A52".to_string());
            }
            if lower.contains("a34") {
                return Some("Galaxy A34".to_string());
            }
            if lower.contains("a14") {
                return Some("Galaxy A14".to_string());
            }
            // Z series
            if lower.contains("z-fold") || lower.contains("zfold") || lower.contains("fold") {
                return Some("Galaxy Z Fold".to_string());
            }
            if lower.contains("z-flip") || lower.contains("zflip") || lower.contains("flip") {
                return Some("Galaxy Z Flip".to_string());
            }
            // Note
            if lower.contains("note") {
                return Some("Galaxy Note".to_string());
            }
            // Tab
            if lower.contains("tab") {
                if lower.contains("s9") {
                    return Some("Galaxy Tab S9".to_string());
                }
                if lower.contains("s8") {
                    return Some("Galaxy Tab S8".to_string());
                }
                if lower.contains("s7") {
                    return Some("Galaxy Tab S7".to_string());
                }
                if lower.contains("s6") {
                    return Some("Galaxy Tab S6".to_string());
                }
                return Some("Galaxy Tab".to_string());
            }
            // Watch
            if lower.contains("watch") {
                if lower.contains("ultra") {
                    return Some("Galaxy Watch Ultra".to_string());
                }
                if lower.contains("6") {
                    return Some("Galaxy Watch 6".to_string());
                }
                if lower.contains("5") {
                    return Some("Galaxy Watch 5".to_string());
                }
                if lower.contains("4") {
                    return Some("Galaxy Watch 4".to_string());
                }
                return Some("Galaxy Watch".to_string());
            }
            // Buds
            if lower.contains("buds") {
                if lower.contains("pro") {
                    return Some("Galaxy Buds Pro".to_string());
                }
                if lower.contains("live") {
                    return Some("Galaxy Buds Live".to_string());
                }
                if lower.contains("fe") {
                    return Some("Galaxy Buds FE".to_string());
                }
                if lower.contains("2") {
                    return Some("Galaxy Buds 2".to_string());
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
            if lower.contains("hub") {
                return Some("SmartThings Hub".to_string());
            }
            if lower.contains("station") {
                return Some("SmartThings Station".to_string());
            }
            return Some("SmartThings".to_string());
        }

        // Samsung appliances
        if lower.contains("fridge") || lower.contains("refrigerator") || lower.starts_with("rf") {
            return Some("Samsung Refrigerator".to_string());
        }
        if lower.contains("washer") || lower.starts_with("wf") || lower.starts_with("ww") {
            return Some("Samsung Washer".to_string());
        }
        if lower.contains("dryer") || lower.starts_with("dv") {
            return Some("Samsung Dryer".to_string());
        }
        if lower.contains("dishwasher") || lower.starts_with("dw") {
            return Some("Samsung Dishwasher".to_string());
        }
        if lower.contains("oven") || lower.contains("range") {
            return Some("Samsung Oven".to_string());
        }
        if lower.contains("vacuum") || lower.contains("jet") {
            return Some("Samsung Jet".to_string());
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
            // Mate series: MATE40, MATE30
            if upper.starts_with("MATE") && upper.len() >= 5 {
                return Some(format!("Huawei {}", upper));
            }
            // Nova series
            if upper.starts_with("NOVA") {
                return Some(format!("Huawei {}", upper));
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

    // LG ThinQ appliances: LMA749755 (dishwasher), WM3600HWA (washer), etc.
    if lower.starts_with("lma") || lower.starts_with("ldp") || lower.starts_with("ldf") {
        return Some("Dishwasher".to_string());
    }
    if lower.starts_with("wm")
        && lower
            .chars()
            .nth(2)
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
    {
        return Some("Washing Machine".to_string());
    }
    if lower.starts_with("dlex") || lower.starts_with("dle") || lower.starts_with("dlg") {
        return Some("Dryer".to_string());
    }
    if lower.starts_with("lrm") || lower.starts_with("lrf") || lower.starts_with("lrs") {
        return Some("Refrigerator".to_string());
    }

    // Google/Nest devices
    if lower.contains("chromecast") {
        if lower.contains("ultra") {
            return Some("Chromecast Ultra".to_string());
        }
        if lower.contains("4k") || lower.contains("google-tv") {
            return Some("Chromecast with Google TV".to_string());
        }
        return Some("Chromecast".to_string());
    }
    if lower.contains("nest-hub") || lower.contains("nesthub") {
        if lower.contains("max") {
            return Some("Nest Hub Max".to_string());
        }
        return Some("Nest Hub".to_string());
    }
    if lower.contains("nest-mini") || lower.contains("google-home-mini") {
        return Some("Nest Mini".to_string());
    }
    if lower.contains("google-home") {
        return Some("Google Home".to_string());
    }

    // Amazon Echo devices
    if lower.contains("echo") {
        if lower.contains("dot") {
            return Some("Echo Dot".to_string());
        }
        if lower.contains("show") {
            return Some("Echo Show".to_string());
        }
        if lower.contains("studio") {
            return Some("Echo Studio".to_string());
        }
        if lower.contains("plus") {
            return Some("Echo Plus".to_string());
        }
        return Some("Echo".to_string());
    }

    // Sonos speakers
    if lower.contains("sonos") {
        if lower.contains("one") {
            return Some("Sonos One".to_string());
        }
        if lower.contains("beam") {
            return Some("Sonos Beam".to_string());
        }
        if lower.contains("arc") {
            return Some("Sonos Arc".to_string());
        }
        if lower.contains("move") {
            return Some("Sonos Move".to_string());
        }
        if lower.contains("roam") {
            return Some("Sonos Roam".to_string());
        }
        if lower.contains("sub") {
            return Some("Sonos Sub".to_string());
        }
        if lower.contains("play:1") || lower.contains("play1") {
            return Some("Sonos Play:1".to_string());
        }
        if lower.contains("play:3") || lower.contains("play3") {
            return Some("Sonos Play:3".to_string());
        }
        if lower.contains("play:5") || lower.contains("play5") {
            return Some("Sonos Play:5".to_string());
        }
    }

    // Ring doorbells/cameras
    if lower.contains("ring") {
        if lower.contains("doorbell") {
            return Some("Ring Doorbell".to_string());
        }
        if lower.contains("cam") || lower.contains("camera") {
            return Some("Ring Camera".to_string());
        }
        if lower.contains("stick") {
            return Some("Ring Stick Up Cam".to_string());
        }
    }

    // HP Printers - try to extract model
    if lower.starts_with("hp") || lower.starts_with("npi") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in parts {
            // HP model patterns like LaserJet, OfficeJet, DeskJet, ENVY
            let upper = part.to_uppercase();
            if upper.contains("LASERJET")
                || upper.contains("OFFICEJET")
                || upper.contains("DESKJET")
                || upper.contains("ENVY")
                || upper.contains("PHOTOSMART")
            {
                return Some(upper);
            }
        }
    }

    // Amazon Fire TV and Kindle
    if lower.contains("fire") {
        if lower.contains("tv") || lower.contains("stick") {
            if lower.contains("4k") {
                return Some("Fire TV Stick 4K".to_string());
            }
            if lower.contains("max") {
                return Some("Fire TV Stick 4K Max".to_string());
            }
            if lower.contains("lite") {
                return Some("Fire TV Stick Lite".to_string());
            }
            if lower.contains("cube") {
                return Some("Fire TV Cube".to_string());
            }
            return Some("Fire TV Stick".to_string());
        }
        if lower.contains("kindle") || lower.contains("hd") {
            return Some("Fire Tablet".to_string());
        }
    }
    if lower.contains("kindle") {
        if lower.contains("paperwhite") {
            return Some("Kindle Paperwhite".to_string());
        }
        if lower.contains("oasis") {
            return Some("Kindle Oasis".to_string());
        }
        return Some("Kindle".to_string());
    }

    // TP-Link/Tapo devices
    if lower.contains("tapo") {
        if lower.contains("c200") || lower.contains("c210") || lower.contains("c220") {
            let parts: Vec<&str> = lower.split(['-', '_']).collect();
            for part in &parts {
                if part.starts_with("c2") || part.starts_with("c3") || part.starts_with("c4") {
                    return Some(format!("Tapo {}", part.to_uppercase()));
                }
            }
            return Some("Tapo Camera".to_string());
        }
        if lower.contains("p100") || lower.contains("p110") || lower.contains("p105") {
            return Some("Tapo Smart Plug".to_string());
        }
        if lower.contains("l530") || lower.contains("l510") || lower.contains("l900") {
            return Some("Tapo Smart Bulb".to_string());
        }
        return Some("Tapo Device".to_string());
    }
    if lower.contains("kasa")
        || lower.contains("hs100")
        || lower.contains("hs110")
        || lower.contains("hs200")
    {
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
            if lower.contains("v3") {
                return Some("Wyze Cam v3".to_string());
            }
            if lower.contains("pan") {
                return Some("Wyze Cam Pan".to_string());
            }
            if lower.contains("outdoor") {
                return Some("Wyze Cam Outdoor".to_string());
            }
            return Some("Wyze Cam".to_string());
        }
        if lower.contains("plug") {
            return Some("Wyze Plug".to_string());
        }
        if lower.contains("bulb") {
            return Some("Wyze Bulb".to_string());
        }
        if lower.contains("lock") {
            return Some("Wyze Lock".to_string());
        }
        if lower.contains("vacuum") {
            return Some("Wyze Robot Vacuum".to_string());
        }
    }

    // iRobot Roomba
    if lower.contains("roomba") || lower.contains("irobot") {
        // Try to extract model number (e.g., Roomba-i7, Roomba-s9)
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in &parts {
            let p = part.to_lowercase();
            if (p.starts_with('i')
                || p.starts_with('s')
                || p.starts_with('j')
                || p.starts_with('e'))
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
        if lower.contains("bridge") {
            return Some("Hue Bridge".to_string());
        }
        if lower.contains("bulb") || lower.contains("lamp") || lower.contains("light") {
            return Some("Hue Light".to_string());
        }
        if lower.contains("play") {
            return Some("Hue Play".to_string());
        }
        if lower.contains("strip") || lower.contains("lightstrip") {
            return Some("Hue Lightstrip".to_string());
        }
        if lower.contains("bloom") {
            return Some("Hue Bloom".to_string());
        }
        if lower.contains("go") {
            return Some("Hue Go".to_string());
        }
    }

    // Hatch Rest+ baby sound machine
    if lower.starts_with("restplus") {
        return Some("Hatch Rest+".to_string());
    }

    // Ecobee thermostats
    if lower.contains("ecobee") {
        if lower.contains("lite") {
            return Some("Ecobee Lite".to_string());
        }
        if lower.contains("smart") || lower.contains("premium") {
            return Some("Ecobee Smart Thermostat".to_string());
        }
        if lower.contains("sensor") {
            return Some("Ecobee Sensor".to_string());
        }
        return Some("Ecobee Thermostat".to_string());
    }

    // Canon printers
    if lower.contains("canon") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in &parts {
            let upper = part.to_uppercase();
            if upper.starts_with("MX")
                || upper.starts_with("MG")
                || upper.starts_with("TS")
                || upper.starts_with("TR")
                || upper.starts_with("PIXMA")
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
            if upper.starts_with("ET")
                || upper.starts_with("WF")
                || upper.starts_with("XP")
                || upper.starts_with("L")
                || upper.contains("ECOTANK")
                || upper.contains("WORKFORCE")
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
            if upper.starts_with("HL") || upper.starts_with("MFC") || upper.starts_with("DCP") {
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
        if lower.contains("ultra") {
            return Some("Apple Watch Ultra".to_string());
        }
        if lower.contains("se") {
            return Some("Apple Watch SE".to_string());
        }
        // Try to extract series number
        for i in 1..=10 {
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
        if lower.contains("mini") {
            return Some("Wemo Mini".to_string());
        }
        if lower.contains("insight") {
            return Some("Wemo Insight".to_string());
        }
        if lower.contains("switch") || lower.contains("plug") {
            return Some("Wemo Smart Plug".to_string());
        }
        if lower.contains("dimmer") {
            return Some("Wemo Dimmer".to_string());
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
            if open_ports.contains(&5555) {
                return Some("Amazon Fire TV".to_string());
            }
            if open_ports.contains(&8008) || open_ports.contains(&8443) {
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
            if open_ports.contains(&8008) || open_ports.contains(&8443) {
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
    if prefix == "70:2c:1f" || prefix == "28:6d:97" {
        return Some("SmartThings Sensor".to_string());
    }

    let vendor = get_mac_vendor(mac)?;

    match vendor {
        "Nintendo" => Some("Nintendo Switch".to_string()),
        "Sony" => Some("PlayStation".to_string()),
        "Samsung" => Some("Samsung Device".to_string()),
        "LG" => Some("LG Device".to_string()),
        "Apple" => Some("Apple Device".to_string()),
        "Google" => Some("Google Device".to_string()),
        "Amazon" => Some("Amazon Device".to_string()),
        "Microsoft" => Some("Xbox".to_string()),
        "HP" => Some("HP Device".to_string()),
        "iRobot" => Some("Roomba".to_string()),
        "Ecobee" => Some("Ecobee Thermostat".to_string()),
        "Ring" => Some("Ring Device".to_string()),
        "Sonos" => Some("Sonos Speaker".to_string()),
        "Roku" => Some("Roku".to_string()),
        "Philips Hue" => Some("Hue Device".to_string()),
        "Wyze" => Some("Wyze Device".to_string()),
        "eero" => Some("eero Router".to_string()),
        "Nest" => Some("Nest Device".to_string()),
        "TP-Link" => Some("TP-Link Device".to_string()),
        "Ubiquiti" => Some("Ubiquiti Device".to_string()),
        "Vizio" => Some("Vizio TV".to_string()),
        "TCL" => Some("Roku TV".to_string()),
        "Hisense" => Some("Hisense TV".to_string()),
        "Texas Instruments" => Some("TI IoT Device".to_string()),
        "Samjin" => Some("SmartThings Sensor".to_string()),
        "Wisol" => Some("SmartThings Sensor".to_string()),
        "Synology" => Some("Synology NAS".to_string()),
        "ASUS" => Some("ASUS Device".to_string()),
        "Logitech" => Some("Logitech Device".to_string()),
        "LiteON" => Some("LiteON Device".to_string()),
        "FN-Link" => Some("Smart TV".to_string()),
        _ => None,
    }
}

/// (vendor, device_type_or_empty_for_wildcard, label, is_literal)
/// When is_literal is true, return label as-is instead of "{vendor} {label}"
const VENDOR_TYPE_MODELS: &[(&str, &str, &str, bool)] = &[
    // Samsung
    ("Samsung", "tv", "Smart TV", false),
    ("Samsung", "phone", "Galaxy", false),
    ("Samsung", "computer", "Computer", false),
    ("Samsung", "appliance", "Appliance", false),
    ("Samsung", "soundbar", "Soundbar", false),
    ("Samsung", "", "Device", false),
    // LG
    ("LG", "tv", "Smart TV", false),
    ("LG", "phone", "Phone", false),
    ("LG", "computer", "Computer", false),
    ("LG", "appliance", "ThinQ Appliance", false),
    ("LG", "soundbar", "Soundbar", false),
    ("LG", "", "Device", false),
    // Sony
    ("Sony", "tv", "Bravia TV", false),
    ("Sony", "gaming", "PlayStation", true),
    ("Sony", "computer", "VAIO", false),
    ("Sony", "soundbar", "Soundbar", false),
    ("Sony", "", "Device", false),
    // Apple
    ("Apple", "phone", "iPhone", true),
    ("Apple", "tv", "Apple TV", true),
    ("Apple", "computer", "Mac", true),
    ("Apple", "local", "Mac", true),
    ("Apple", "", "Apple Device", true),
    // Microsoft
    ("Microsoft", "gaming", "Xbox", true),
    ("Microsoft", "computer", "Surface", true),
    ("Microsoft", "", "Device", false),
    // Nintendo
    ("Nintendo", "gaming", "Switch", false),
    ("Nintendo", "", "Device", false),
    // Google
    ("Google", "tv", "Chromecast", true),
    ("Google", "phone", "Pixel", false),
    ("Google", "", "Device", false),
    // Huawei
    ("Huawei", "phone", "Phone", false),
    ("Huawei", "gateway", "Router", false),
    ("Huawei", "tv", "Smart Screen", false),
    ("Huawei", "", "Device", false),
    // Amazon
    ("Amazon", "tv", "Fire TV", true),
    ("Amazon", "", "Device", false),
    // HP
    ("HP", "printer", "Printer", false),
    ("HP", "computer", "Computer", false),
    ("HP", "local", "Computer", false),
    ("HP", "", "Device", false),
    // Belkin/WeMo
    ("Belkin", "appliance", "WeMo Smart Plug", true),
    ("Belkin", "gateway", "Router", false),
    ("Belkin", "", "WeMo Device", true),
    // Wisol IoT devices
    ("Wisol", "appliance", "Sensor", false),
    ("Wisol", "", "IoT Device", false),
    // USI (contract manufacturer)
    ("USI", "phone", "Mobile Device", false),
    ("USI", "appliance", "IoT Device", false),
    ("USI", "", "Device", false),
    // TCL TVs (often running Roku OS)
    ("TCL", "tv", "Roku TV", true),
    ("TCL", "", "Device", false),
    // Hisense
    ("Hisense", "tv", "Smart TV", false),
    ("Hisense", "", "Device", false),
    // Vizio
    ("Vizio", "tv", "Smart TV", false),
    ("Vizio", "soundbar", "Soundbar", false),
    ("Vizio", "", "Device", false),
    // Roku
    ("Roku", "tv", "TV", false),
    ("Roku", "", "Roku", true),
    // Single-wildcard vendors
    ("Sonos", "", "Speaker", false),
    ("iRobot", "", "Roomba", true),
    ("Ecobee", "", "Thermostat", false),
    ("Ring", "", "Device", false),
    ("Philips Hue", "", "Hue Device", true),
    ("Wyze", "", "Device", false),
    ("eero", "gateway", "Router", false),
    ("eero", "", "eero", true),
    ("Nest", "", "Device", false),
    ("TP-Link", "appliance", "Kasa Smart Plug", true),
    ("TP-Link", "gateway", "Router", false),
    ("TP-Link", "", "Device", false),
    ("Tuya", "", "Smart Device", false),
    ("Dyson", "", "Air Purifier", false),
    // Networking equipment
    ("Commscope", "gateway", "ARRIS Modem/Router", true),
    ("Commscope", "", "ARRIS Device", true),
    ("ARRIS", "gateway", "Modem/Router", false),
    ("ARRIS", "", "Device", false),
    ("Netgear", "gateway", "Router", false),
    ("Netgear", "", "Device", false),
    ("Linksys", "gateway", "Router", false),
    ("Linksys", "", "Device", false),
    ("Ubiquiti", "gateway", "UniFi Gateway", true),
    ("Ubiquiti", "", "UniFi Device", true),
    ("MikroTik", "gateway", "Router", false),
    ("MikroTik", "", "Device", false),
    ("Cisco", "gateway", "Router", false),
    ("Cisco", "", "Device", false),
    // AV equipment
    ("Denon", "soundbar", "AV Receiver", false),
    ("Denon", "", "AV Receiver", false),
    ("Yamaha", "soundbar", "AV Receiver", false),
    ("Yamaha", "", "Audio Device", false),
    ("Logitech", "appliance", "Harmony Hub", true),
    ("Logitech", "", "Device", false),
    // Printers
    ("Brother", "printer", "Printer", false),
    ("Brother", "", "Device", false),
    // IoT module vendors
    ("Espressif", "appliance", "ESP Smart Device", true),
    ("Espressif", "", "ESP Device", true),
    // Robot vacuums
    ("Roborock", "", "Vacuum", false),
    // Security devices
    ("SimpliSafe", "", "Security", false),
    ("Dahua", "", "Camera", false),
    // Smart home appliances
    ("Bosch", "appliance", "Appliance", false),
    ("Bosch", "", "Device", false),
    ("Seeed", "", "IoT Device", false),
    ("Texas Instruments", "", "IoT Device", true),
    // Virtualization
    ("Proxmox", "virtualization", "Server", false),
    ("Proxmox", "", "VM", false),
    // Computers
    ("ASRock", "", "PC", false),
    ("ASUS", "gateway", "Router", false),
    ("ASUS", "computer", "Computer", false),
    ("ASUS", "local", "Computer", false),
    ("ASUS", "", "Device", false),
    ("LiteON", "computer", "Network Card", false),
    ("LiteON", "", "Device", false),
    // NAS devices
    ("Synology", "", "NAS", false),
    // WiFi module vendors
    ("FN-Link", "tv", "Smart TV", true),
    ("FN-Link", "", "WiFi Device", false),
];

/// Get a more specific model using both vendor and device classification
/// Called after device type classification is complete for better accuracy
pub fn get_model_from_vendor_and_type(vendor: &str, device_type: &str) -> Option<String> {
    let mut wildcard: Option<(&str, bool)> = None;
    for &(v, dt, label, literal) in VENDOR_TYPE_MODELS {
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
