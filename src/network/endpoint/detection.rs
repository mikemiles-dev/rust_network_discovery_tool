//! Hostname-based device detection. Pattern matching functions to classify devices
//! as printers, TVs, gaming consoles, phones, soundbars, appliances, or VMs from their hostnames.

use super::patterns::{
    APPLIANCE_PATTERNS, GAMING_PATTERNS, PHONE_CONDITIONAL, PHONE_PATTERNS, PHONE_PREFIXES,
    PRINTER_PATTERNS, PRINTER_PREFIXES, SOUNDBAR_MODEL_PREFIXES, SOUNDBAR_PATTERNS, TV_PATTERNS,
    TV_PREFIXES, VM_PATTERNS,
};

/// Check if hostname matches any pattern in list
pub(crate) fn matches_pattern(hostname: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| hostname.contains(p))
}

/// Check if hostname starts with any prefix in list
pub(crate) fn matches_prefix(hostname: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| hostname.starts_with(p))
}

/// Check if hostname matches pattern but not exclusion
pub(crate) fn matches_conditional(hostname: &str, conditionals: &[(&str, &str)]) -> bool {
    conditionals
        .iter()
        .any(|(pattern, exclude)| hostname.contains(pattern) && !hostname.contains(exclude))
}

/// Check if hostname indicates a printer
pub(crate) fn is_printer_hostname(hostname: &str) -> bool {
    matches_pattern(hostname, PRINTER_PATTERNS) || matches_prefix(hostname, PRINTER_PREFIXES)
}

/// Check if hostname indicates a TV/streaming device
pub(crate) fn is_tv_hostname(hostname: &str) -> bool {
    if matches_pattern(hostname, TV_PATTERNS) || matches_prefix(hostname, TV_PREFIXES) {
        return true;
    }
    // Roku serial number as hostname (e.g., YN00NJ468680)
    let hostname_upper = hostname.to_uppercase();
    is_roku_serial_number(&hostname_upper)
}

/// Check if hostname indicates a gaming console
pub(crate) fn is_gaming_hostname(hostname: &str) -> bool {
    matches_pattern(hostname, GAMING_PATTERNS)
}

/// Check if hostname indicates a phone/tablet
pub(crate) fn is_phone_hostname(hostname: &str) -> bool {
    if matches_pattern(hostname, PHONE_PATTERNS) || matches_prefix(hostname, PHONE_PREFIXES) {
        return true;
    }
    if matches_conditional(hostname, PHONE_CONDITIONAL) {
        return true;
    }
    // Special case: android but not androidtv
    if hostname.contains("android") && !hostname.contains("androidtv") && !hostname.contains("tv") {
        return true;
    }
    // Special case: asus phone
    if hostname.contains("asus") && (hostname.contains("phone") || hostname.contains("zenfone")) {
        return true;
    }
    false
}

/// Check if hostname indicates a VM/container
pub(crate) fn is_vm_hostname(hostname: &str) -> bool {
    matches_pattern(hostname, VM_PATTERNS)
        || hostname.starts_with("vm-")
        || hostname.ends_with("-vm")
}

/// Check if hostname indicates a soundbar
pub(crate) fn is_soundbar_hostname(hostname: &str) -> bool {
    if matches_pattern(hostname, SOUNDBAR_PATTERNS) {
        return true;
    }
    // Sonos Arc special case
    if hostname.contains("arc") && (hostname.contains("sonos") || hostname.contains("sound")) {
        return true;
    }
    // Brand + sound combinations
    let sound_brands = ["yamaha", "samsung", "lg", "vizio"];
    if sound_brands.iter().any(|b| hostname.contains(b)) && hostname.contains("sound") {
        return true;
    }
    // JBL bar
    if hostname.contains("jbl") && hostname.contains("bar") {
        return true;
    }
    false
}

/// Check if SSDP/UPnP model indicates a soundbar
pub(crate) fn is_soundbar_model(model: &str) -> bool {
    let model_lower = model.to_lowercase();
    SOUNDBAR_MODEL_PREFIXES
        .iter()
        .any(|prefix| model_lower.starts_with(prefix))
}

/// Check if a model name indicates a TV
pub(crate) fn is_tv_model(model: &str) -> bool {
    let model_lower = model.to_lowercase();
    let model_upper = model.to_uppercase();

    // Check for known TV model patterns
    // Samsung TV model patterns
    if model_upper.starts_with("QN")
        || model_upper.starts_with("UN")
        || model_upper.starts_with("UA")
    {
        // QN = QLED, UN/UA = LED TVs
        // e.g., QN43LS03TAFXZA (The Frame), UN55TU8000FXZA
        return true;
    }

    // Samsung Frame TVs (LS series)
    if model_upper.contains("LS03") || model_upper.contains("LS01") {
        return true;
    }

    // LG TV model patterns
    if model_upper.starts_with("OLED") || model_upper.starts_with("NANO") {
        return true;
    }

    // Sony Bravia
    if model_lower.contains("bravia")
        || model_upper.starts_with("XR")
        || model_upper.starts_with("KD-")
    {
        return true;
    }

    // Vizio
    if model_lower.contains("vizio") {
        return true;
    }

    // Roku TV platform identifiers (TCL, Hisense, etc. running Roku OS)
    // Format: 4 digits followed by optional X (e.g., 7105X, 7000X, 6500X, 3800X)
    // 7XXX series = TCL TVs, 6XXX = mid-range, 3XXX = budget models
    if is_roku_tv_model(&model_upper) {
        return true;
    }

    // Check for generic TV indicators in model name
    if model_lower.contains("the frame") || model_lower.contains("samsung tv") {
        return true;
    }

    false
}

/// Check if a string is a Roku serial number
/// Roku serial numbers follow the pattern: 2 letters + 2 digits + 2 letters + N digits
/// - 12 chars total: 2 letters + 2 digits + 2 letters + 6 digits (e.g., YN00NJ468680)
/// - 10 chars total: 2 letters + 2 digits + 2 letters + 4 digits (e.g., BR23AM1691)
pub(crate) fn is_roku_serial_number(s: &str) -> bool {
    // Must be 10 or 12 characters
    if s.len() != 10 && s.len() != 12 {
        return false;
    }
    let chars: Vec<char> = s.chars().collect();
    // First 2 chars: letters
    chars[0].is_ascii_alphabetic()
        && chars[1].is_ascii_alphabetic()
        // Next 2 chars: digits
        && chars[2].is_ascii_digit()
        && chars[3].is_ascii_digit()
        // Next 2 chars: letters
        && chars[4].is_ascii_alphabetic()
        && chars[5].is_ascii_alphabetic()
        // Remaining chars (4 or 6): all digits
        && chars[6..].iter().all(|c| c.is_ascii_digit())
}

/// Check if model is a Roku TV platform identifier
/// Roku TV models follow patterns like 7105X, 7000X, 6500X, 3800X
pub(crate) fn is_roku_tv_model(model: &str) -> bool {
    let model_upper = model.to_uppercase();
    // Pattern: 4 digits, optionally followed by X
    if model_upper.len() >= 4 && model_upper.len() <= 5 {
        let chars: Vec<char> = model_upper.chars().collect();
        // First 4 chars must be digits
        if chars[0..4].iter().all(|c| c.is_ascii_digit()) {
            // 5th char (if present) must be X
            if chars.len() == 4 || chars[4] == 'X' {
                // Roku TV models typically start with 3, 4, 5, 6, or 7
                let first_digit = chars[0];
                return matches!(first_digit, '3' | '4' | '5' | '6' | '7' | '8' | '9');
            }
        }
    }

    // Roku serial number format used as hostname (e.g., YN00NJ468680)
    // Pattern: 2 letters + 2 digits + 2 letters + 6 digits (12 chars total)
    if is_roku_serial_number(&model_upper) {
        return true;
    }
    false
}

/// Check if hostname indicates an appliance
pub(crate) fn is_appliance_hostname(hostname: &str) -> bool {
    if matches_pattern(hostname, APPLIANCE_PATTERNS) {
        return true;
    }
    // Whirlpool (but not router)
    if hostname.contains("whirlpool") && !hostname.contains("router") {
        return true;
    }
    // GE appliance
    if hostname.contains("ge-") && hostname.contains("appliance") {
        return true;
    }
    // Bosch washer/dishwasher
    if hostname.contains("bosch") && (hostname.contains("wash") || hostname.contains("dish")) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_printer() {
        // Hostname patterns
        assert_eq!(is_printer_hostname("hp-laserjet-pro"), true);
        assert_eq!(is_printer_hostname("canon-mx920"), true);
        assert_eq!(is_printer_hostname("epson-wf-7720"), true);
        assert_eq!(is_printer_hostname("brother-mfc-9340cdw"), true);
        assert_eq!(is_printer_hostname("npi123456"), true);
        assert_eq!(is_printer_hostname("brn001122334455"), true);

        // Non-printers
        assert_eq!(is_printer_hostname("my-laptop"), false);
        assert_eq!(is_printer_hostname("iphone"), false);
    }

    #[test]
    fn test_classify_tv() {
        // Hostname patterns
        assert_eq!(is_tv_hostname("samsung-tv"), true);
        assert_eq!(is_tv_hostname("roku-ultra"), true);
        assert_eq!(is_tv_hostname("chromecast-living-room"), true);
        assert_eq!(is_tv_hostname("appletv"), true);
        assert_eq!(is_tv_hostname("firetv-stick"), true);
        assert_eq!(is_tv_hostname("the-frame"), true);

        // Roku serial number hostnames (e.g., YN00NJ468680)
        assert_eq!(is_tv_hostname("YN00NJ468680"), true);
        assert_eq!(is_tv_hostname("yn00nj468680"), true); // lowercase
        assert_eq!(is_tv_hostname("YK00KM123456"), true);

        // Non-TVs (lg-* removed - too generic, matches soundbars)
        assert_eq!(is_tv_hostname("lg-oled55"), false); // Use SSDP model instead
        assert_eq!(is_tv_hostname("my-laptop"), false);
        assert_eq!(is_tv_hostname("printer"), false);
    }

    #[test]
    fn test_roku_serial_number_detection() {
        // Valid Roku serial numbers: 2 letters + 2 digits + 2 letters + 6 digits (12 chars)
        assert_eq!(is_roku_serial_number("YN00NJ468680"), true);
        assert_eq!(is_roku_serial_number("YK00KM123456"), true);
        assert_eq!(is_roku_serial_number("AB12CD345678"), true);

        // Valid Roku serial numbers: 2 letters + 2 digits + 2 letters + 4 digits (10 chars)
        assert_eq!(is_roku_serial_number("BR23AM1691"), true);
        assert_eq!(is_roku_serial_number("AB12CD3456"), true);
        assert_eq!(is_roku_serial_number("XY99ZZ0000"), true);

        // Invalid patterns
        assert_eq!(is_roku_serial_number("YN00NJ46868"), false); // 11 chars - invalid length
        assert_eq!(is_roku_serial_number("YN00NJ4686801"), false); // Too long (13 chars)
        assert_eq!(is_roku_serial_number("1N00NJ468680"), false); // First char not letter
        assert_eq!(is_roku_serial_number("YNA0NJ468680"), false); // Third char not digit
        assert_eq!(is_roku_serial_number("YN0ANJ468680"), false); // Fourth char not digit
        assert_eq!(is_roku_serial_number("YN001J468680"), false); // Fifth char not letter
        assert_eq!(is_roku_serial_number("YN00N1468680"), false); // Sixth char not letter
        assert_eq!(is_roku_serial_number("YN00NJA68680"), false); // Seventh char not digit
        assert_eq!(is_roku_serial_number("samsung-tv"), false); // Wrong format
        assert_eq!(is_roku_serial_number("7105X"), false); // Roku model, not serial
        assert_eq!(is_roku_serial_number("BR23AM169"), false); // 9 chars - too short
    }

    #[test]
    fn test_roku_tv_model_detection() {
        // Roku TV platform identifiers (TCL, Hisense TVs running Roku OS)
        assert_eq!(is_roku_tv_model("7105X"), true);
        assert_eq!(is_roku_tv_model("7000X"), true);
        assert_eq!(is_roku_tv_model("6500X"), true);
        assert_eq!(is_roku_tv_model("3800X"), true);
        assert_eq!(is_roku_tv_model("4200"), true); // Without X suffix
        assert_eq!(is_roku_tv_model("8500X"), true);

        // Should be recognized as TV
        assert_eq!(is_tv_model("7105X"), true);
        assert_eq!(is_tv_model("7000X"), true);

        // Non-Roku TV models
        assert_eq!(is_roku_tv_model("HW-MS750"), false); // Samsung soundbar
        assert_eq!(is_roku_tv_model("OLED55C3"), false); // LG TV (different format)
        assert_eq!(is_roku_tv_model("12345X"), false); // Too many digits
        assert_eq!(is_roku_tv_model("710X"), false); // Only 3 digits
        assert_eq!(is_roku_tv_model("7105Y"), false); // Wrong suffix

        // Roku serial numbers should also be detected as Roku TV models
        assert_eq!(is_roku_tv_model("YN00NJ468680"), true);
        assert_eq!(is_roku_tv_model("yn00nj468680"), true); // lowercase
    }

    #[test]
    fn test_classify_gaming() {
        assert_eq!(is_gaming_hostname("xbox-series-x"), true);
        assert_eq!(is_gaming_hostname("playstation-5"), true);
        assert_eq!(is_gaming_hostname("nintendo-switch"), true);
        assert_eq!(is_gaming_hostname("steamdeck"), true);

        assert_eq!(is_gaming_hostname("my-pc"), false);
    }

    #[test]
    fn test_classify_phone() {
        assert_eq!(is_phone_hostname("iphone-14-pro"), true);
        assert_eq!(is_phone_hostname("ipad-mini"), true);
        assert_eq!(is_phone_hostname("galaxy-s23"), true);
        assert_eq!(is_phone_hostname("pixel-7"), true);
        assert_eq!(is_phone_hostname("sm-g991u"), true);
        assert_eq!(is_phone_hostname("oneplus-11"), true);
        assert_eq!(is_phone_hostname("moto-g-power"), true);

        // Should NOT match TV variants
        assert_eq!(is_phone_hostname("galaxy-tv"), false);
        assert_eq!(is_phone_hostname("androidtv"), false);
    }

    #[test]
    fn test_classify_vm() {
        assert_eq!(is_vm_hostname("vmware-esxi-01"), true);
        assert_eq!(is_vm_hostname("proxmox-server"), true);
        assert_eq!(is_vm_hostname("docker-host"), true);
        assert_eq!(is_vm_hostname("kubernetes-node-1"), true);
        assert_eq!(is_vm_hostname("vm-ubuntu-22"), true);
        assert_eq!(is_vm_hostname("webserver-vm"), true);

        assert_eq!(is_vm_hostname("my-laptop"), false);
    }

    #[test]
    fn test_classify_soundbar() {
        assert_eq!(is_soundbar_hostname("sonos-beam"), true);
        assert_eq!(is_soundbar_hostname("bose-soundbar-700"), true);
        assert_eq!(is_soundbar_hostname("samsung-sound-plus"), true);
        assert_eq!(is_soundbar_hostname("jbl-bar-5.1"), true);

        assert_eq!(is_soundbar_hostname("samsung-tv"), false);
    }

    #[test]
    fn test_is_tv_model() {
        // Samsung QLED TVs
        assert!(is_tv_model("QN43LS03TAFXZA")); // The Frame
        assert!(is_tv_model("QN65Q80AAFXZA")); // QLED Q80A
        assert!(is_tv_model("QN55QN90AAFXZA")); // Neo QLED

        // Samsung LED TVs
        assert!(is_tv_model("UN55TU8000FXZA"));
        assert!(is_tv_model("UA43AU7000KXXS"));

        // Samsung The Frame specific
        assert!(is_tv_model("LS03T"));
        assert!(is_tv_model("QN43LS01TAFXZA")); // The Serif

        // LG OLED TVs
        assert!(is_tv_model("OLED55C3PUA"));
        assert!(is_tv_model("OLED65G3PUA"));

        // LG NanoCell TVs
        assert!(is_tv_model("NANO75UPA"));

        // Sony Bravia
        assert!(is_tv_model("XR-55A80J"));
        assert!(is_tv_model("KD-55X80K"));
        assert!(is_tv_model("Sony Bravia"));

        // Vizio
        assert!(is_tv_model("Vizio M-Series"));

        // Generic patterns
        assert!(is_tv_model("Samsung The Frame"));
        assert!(is_tv_model("Samsung TV"));

        // Should NOT match
        assert!(!is_tv_model("HW-MS750")); // Soundbar
        assert!(!is_tv_model("Galaxy S23")); // Phone
        assert!(!is_tv_model("MacBook Pro")); // Computer
        assert!(!is_tv_model("random-device"));
    }

    #[test]
    fn test_classify_appliance() {
        assert_eq!(is_appliance_hostname("lg-dishwasher"), true);
        assert_eq!(is_appliance_hostname("samsung-washer"), true);
        assert_eq!(is_appliance_hostname("whirlpool-dryer"), true);
        assert_eq!(is_appliance_hostname("bosch-dishwasher-500"), true);

        assert_eq!(is_appliance_hostname("my-laptop"), false);
    }
}
