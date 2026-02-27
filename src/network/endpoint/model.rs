//! Device model identification. Normalizes raw model numbers to friendly display names
//! and infers models from hostnames, MAC addresses, and vendor context.

use super::classify::is_roku_tv_model;
use super::hostname_model::get_model_from_hostname;
use super::model_data::*;
use super::patterns::{
    LG_TV_SERIES, MAC_VENDOR_MODEL_RULES, SAMSUNG_TV_SERIES, SONY_TV_SERIES,
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
    let is_lg = LG_TV_MODEL_KEYWORDS.iter().any(|k| model_upper.contains(k))
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
            if AMAZON_FIRE_TV_PORTS.iter().any(|p| open_ports.contains(p)) {
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
