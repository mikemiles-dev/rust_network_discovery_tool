//! Hostname-based device classification. Identifies device types (printers, TVs,
//! gaming consoles, phones, soundbars, appliances, VMs) by matching hostname
//! strings against known patterns, prefixes, and conditional rules.

use super::classify::{
    is_roku_serial_number, matches_conditional, matches_pattern, matches_prefix,
};
use super::patterns::{
    APPLIANCE_PATTERNS, GAMING_PATTERNS, PHONE_CONDITIONAL, PHONE_PATTERNS, PHONE_PREFIXES,
    PRINTER_PATTERNS, PRINTER_PREFIXES, SOUNDBAR_PATTERNS, TV_PATTERNS, TV_PREFIXES, VM_PATTERNS,
};

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
    fn test_classify_appliance() {
        assert_eq!(is_appliance_hostname("lg-dishwasher"), true);
        assert_eq!(is_appliance_hostname("samsung-washer"), true);
        assert_eq!(is_appliance_hostname("whirlpool-dryer"), true);
        assert_eq!(is_appliance_hostname("bosch-dishwasher-500"), true);

        assert_eq!(is_appliance_hostname("my-laptop"), false);
    }
}
