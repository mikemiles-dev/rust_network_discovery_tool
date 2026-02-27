//! SNMP and SSDP model parsing and consistency logic.

use rusqlite::{Connection, params};

use crate::network::endpoint::get_mac_vendor;

/// Parse SNMP sysDescr to extract vendor and model information
/// Returns (vendor, model) as Option strings
pub fn parse_snmp_sys_descr(sys_descr: &str) -> (Option<String>, Option<String>) {
    let descr_lower = sys_descr.to_lowercase();

    // Common vendor patterns in sysDescr
    let vendor_patterns: &[(&str, &str)] = &[
        ("hewlett-packard", "HP"),
        ("hp ", "HP"),
        ("cisco", "Cisco"),
        ("synology", "Synology"),
        ("qnap", "QNAP"),
        ("netgear", "NETGEAR"),
        ("linksys", "Linksys"),
        ("ubiquiti", "Ubiquiti"),
        ("unifi", "Ubiquiti"),
        ("mikrotik", "MikroTik"),
        ("tp-link", "TP-Link"),
        ("asus", "ASUS"),
        ("d-link", "D-Link"),
        ("buffalo", "Buffalo"),
        ("brother", "Brother"),
        ("canon", "Canon"),
        ("epson", "Epson"),
        ("xerox", "Xerox"),
        ("ricoh", "Ricoh"),
        ("dell", "Dell"),
        ("lenovo", "Lenovo"),
        ("apple", "Apple"),
        ("asustor", "ASUSTOR"),
        ("drobo", "Drobo"),
        ("western digital", "Western Digital"),
        ("seagate", "Seagate"),
        ("aruba", "Aruba"),
        ("juniper", "Juniper"),
        ("fortinet", "Fortinet"),
        ("paloalto", "Palo Alto"),
        ("sonicwall", "SonicWall"),
    ];

    let mut vendor: Option<String> = None;
    for (pattern, name) in vendor_patterns {
        // "hp " needs word boundary check to avoid matching "chapter", "graph ", etc.
        if *pattern == "hp " {
            if descr_lower.starts_with("hp ")
                || descr_lower.contains(" hp ")
                || descr_lower.contains("\nhp ")
            {
                vendor = Some(name.to_string());
                break;
            }
        } else if descr_lower.contains(pattern) {
            vendor = Some(name.to_string());
            break;
        }
    }

    // Try to extract model - look for common patterns
    let mut model: Option<String> = None;

    // HP printer pattern: "PID:HP Color LaserJet..." - common in HP printer SNMP
    if let Some(idx) = descr_lower.find("pid:hp") {
        let after_pid = &sys_descr[idx + 4..]; // Skip "PID:"
        // Take the HP model name - everything after "HP " until end or comma
        let trimmed = after_pid.trim();
        // HP models typically end at the end of string or before a comma
        let model_str = if let Some(end) = trimmed.find(',') {
            trimmed[..end].trim()
        } else {
            trimmed
        };
        if model_str.len() > 2 {
            model = Some(model_str.to_string());
            // Also set vendor to HP if not already set
            if vendor.is_none() {
                vendor = Some("HP".to_string());
            }
        }
    }

    // Pattern: "Model: XYZ" or "Model XYZ"
    if model.is_none()
        && let Some(idx) = descr_lower.find("model")
    {
        let after_model = &sys_descr[idx + 5..];
        let trimmed = after_model.trim_start_matches([':', ' ']);
        if let Some(end) = trimmed.find([',', ';', '\n', '\r']) {
            let m = trimmed[..end].trim();
            if !m.is_empty() {
                model = Some(m.to_string());
            }
        } else if !trimmed.is_empty() {
            // Take first word/phrase
            let m = trimmed
                .split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ");
            if !m.is_empty() {
                model = Some(m);
            }
        }
    }

    // For HP printers, look for "HP XXXX" pattern
    if model.is_none()
        && vendor.as_deref() == Some("HP")
        && let Some(idx) = descr_lower.find("hp ")
    {
        let after_hp = &sys_descr[idx + 3..];
        // Take first word(s) that look like a model
        let parts: Vec<&str> = after_hp.split_whitespace().take(3).collect();
        if !parts.is_empty() {
            let m = parts.join(" ");
            if m.len() > 2 {
                model = Some(m);
            }
        }
    }

    // For Synology NAS, extract model from pattern like "DS920+"
    if model.is_none() && vendor.as_deref() == Some("Synology") {
        // Look for DS/RS followed by numbers
        for word in sys_descr.split_whitespace() {
            let w = word.to_uppercase();
            if (w.starts_with("DS") || w.starts_with("RS")) && w.len() > 2 {
                let rest = &w[2..];
                if rest
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
                {
                    model = Some(word.to_string());
                    break;
                }
            }
        }
    }

    (vendor, model)
}

/// Check if SSDP model is consistent with endpoint's MAC vendor.
/// Prevents saving mismatched SSDP data when IP addresses get reassigned.
pub(super) fn is_ssdp_model_consistent_with_endpoint(
    conn: &Connection,
    endpoint_id: i64,
    ssdp_model: &str,
) -> bool {
    // Get MAC addresses for this endpoint
    let macs: Vec<String> = conn
        .prepare("SELECT DISTINCT mac FROM endpoint_attributes WHERE endpoint_id = ?1 AND mac IS NOT NULL AND mac != ''")
        .and_then(|mut stmt| {
            stmt.query_map(params![endpoint_id], |row| row.get(0))
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();

    if macs.is_empty() {
        return true; // No MAC to validate against, allow it
    }

    let model_lower = ssdp_model.to_lowercase();

    // Extract brand names from the SSDP model
    // Common streaming device brands that we want to match
    let ssdp_brands: Vec<&str> = [
        "roku",
        "onn",
        "tcl",
        "hisense",
        "samsung",
        "lg",
        "sony",
        "vizio",
        "apple",
        "amazon",
        "fire",
        "chromecast",
        "google",
        "nvidia",
        "xbox",
        "playstation",
        "hp",
        "epson",
        "canon",
        "brother",
    ]
    .iter()
    .filter(|brand| model_lower.contains(*brand))
    .copied()
    .collect();

    // If no recognizable brand in SSDP model, allow it
    if ssdp_brands.is_empty() {
        return true;
    }

    // Check each MAC's vendor against the SSDP brands
    for mac in &macs {
        if let Some(mac_vendor) = get_mac_vendor(mac) {
            let vendor_lower = mac_vendor.to_lowercase();

            // If MAC vendor matches any SSDP brand, it's consistent
            for brand in &ssdp_brands {
                if vendor_lower.contains(brand) || brand.contains(vendor_lower.as_str()) {
                    return true;
                }
            }

            // Special case: TCL/Hisense/Philips can run Roku OS
            // If MAC is TCL/Hisense/Philips and SSDP says Roku, that's OK
            if (vendor_lower.contains("tcl")
                || vendor_lower.contains("hisense")
                || vendor_lower.contains("philips"))
                && ssdp_brands.contains(&"roku")
            {
                return true;
            }

            // Special case: Earda is OEM for TCL Roku TVs
            if vendor_lower.contains("earda")
                && (ssdp_brands.contains(&"tcl") || ssdp_brands.contains(&"roku"))
            {
                return true;
            }

            // If we have a known vendor and SSDP brand doesn't match, reject
            // This prevents "onn." SSDP data from being saved to a TCL device
            if !vendor_lower.is_empty() && !ssdp_brands.is_empty() {
                // Check for conflicting brands (onn vs tcl, samsung vs lg, etc.)
                let conflicting_pairs = [
                    ("onn", "tcl"),
                    ("onn", "hisense"),
                    ("onn", "samsung"),
                    ("onn", "lg"),
                    ("onn", "sony"),
                    ("samsung", "lg"),
                    ("samsung", "sony"),
                    ("samsung", "tcl"),
                    ("lg", "sony"),
                    ("lg", "tcl"),
                    ("lg", "samsung"),
                    ("hp", "epson"),
                    ("hp", "canon"),
                    ("hp", "brother"),
                    ("epson", "canon"),
                    ("epson", "brother"),
                    ("canon", "brother"),
                ];

                for (brand_a, brand_b) in conflicting_pairs {
                    // If vendor is brand_a and ssdp is brand_b (or vice versa), it's a conflict
                    if (vendor_lower.contains(brand_a) && ssdp_brands.contains(&brand_b))
                        || (vendor_lower.contains(brand_b) && ssdp_brands.contains(&brand_a))
                    {
                        return false;
                    }
                }
            }
        }
    }

    true // Default to allowing if no clear conflict
}

/// Check if new_model is more specific than current_model.
/// Used to allow updating stored SSDP data when better info is discovered.
pub(super) fn is_more_specific_model(new_model: &str, current_model: &str) -> bool {
    let new_lower = new_model.to_lowercase();
    let current_lower = current_model.to_lowercase();

    // If they're the same, no need to update
    if new_lower == current_lower {
        return false;
    }

    // New model is longer and contains the current model - likely more specific
    // e.g., "Samsung The Frame 65" is more specific than "Samsung"
    if new_model.len() > current_model.len() && new_lower.contains(&current_lower) {
        return true;
    }

    // Current model is very generic (just a brand name)
    let generic_names = [
        "samsung", "lg", "sony", "tcl", "hisense", "vizio", "roku", "apple", "google", "amazon",
    ];
    let current_is_generic = generic_names.iter().any(|g| current_lower == *g);
    if current_is_generic && new_model.len() > current_model.len() {
        return true;
    }

    // New model contains specific product identifiers that current lacks
    let specific_indicators = [
        "the frame",
        "the serif",
        "the sero",
        "qled",
        "oled",
        "neo qled",
        "nanocell",
        "bravia",
        "roku ultra",
        "roku express",
        "chromecast",
        "fire tv",
        "echo",
        "homepod",
    ];
    let new_has_specific = specific_indicators.iter().any(|s| new_lower.contains(s));
    let current_has_specific = specific_indicators
        .iter()
        .any(|s| current_lower.contains(s));
    if new_has_specific && !current_has_specific {
        return true;
    }

    false
}
