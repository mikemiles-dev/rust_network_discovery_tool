//! Device classification patterns and constants. Defines hostname patterns, vendor lists,
//! TV series data, mDNS service identifiers, and classification constants for device type detection.

// Classification type constants
pub(crate) const CLASSIFICATION_GATEWAY: &str = "gateway";
pub(crate) const CLASSIFICATION_INTERNET: &str = "internet";
pub(crate) const CLASSIFICATION_PRINTER: &str = "printer";
pub(crate) const CLASSIFICATION_TV: &str = "tv";
pub(crate) const CLASSIFICATION_GAMING: &str = "gaming";
pub(crate) const CLASSIFICATION_VIRTUALIZATION: &str = "virtualization";
pub(crate) const CLASSIFICATION_SOUNDBAR: &str = "soundbar";
pub(crate) const CLASSIFICATION_APPLIANCE: &str = "appliance";
pub(crate) const CLASSIFICATION_PHONE: &str = "phone";
pub(crate) const CLASSIFICATION_COMPUTER: &str = "computer";

// All pattern/prefix/vendor/service/TV-series/rule arrays are generated from TOML.
// To regenerate: cd tools/device-rules-generator && cargo run --release
include!("device_rules_data.rs");
