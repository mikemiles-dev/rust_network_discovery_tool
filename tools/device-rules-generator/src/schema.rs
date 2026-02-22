use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
pub struct DeviceRules {
    /// Hostname classification patterns (contains match)
    /// Map: classification -> list of patterns
    pub patterns: BTreeMap<String, Vec<String>>,

    /// Hostname classification prefixes (starts_with match)
    /// Map: classification -> list of prefixes
    pub prefixes: BTreeMap<String, Vec<String>>,

    /// Conditional patterns (contains X but not Y)
    #[serde(default)]
    pub conditionals: Vec<Conditional>,

    /// MAC vendor -> device type
    pub vendor_classes: BTreeMap<String, Vec<String>>,

    /// mDNS service -> device type
    pub services: BTreeMap<String, Vec<String>>,

    /// Standalone lists
    pub standalone: StandaloneLists,

    /// TV series lookup tables
    #[serde(default)]
    pub tv_series: Vec<TvSeries>,

    /// Hostname -> vendor rules
    #[serde(default)]
    pub hostname_vendors: Vec<HostnameVendor>,

    /// Hostname -> model rules
    #[serde(default)]
    pub hostname_models: Vec<HostnameModel>,

    /// Vendor + device_type -> model fallback
    #[serde(default)]
    pub vendor_type_models: Vec<VendorTypeModel>,

    /// MAC vendor -> default model fallback
    #[serde(default)]
    pub mac_vendor_models: Vec<MacVendorModel>,
}

#[derive(Deserialize)]
pub struct StandaloneLists {
    pub mac_desktop_services: Vec<String>,
    pub soundbar_model_prefixes: Vec<String>,
    pub lg_appliance_prefixes: Vec<String>,
}

#[derive(Deserialize)]
pub struct Conditional {
    pub pattern: String,
    pub exclude: String,
    pub classification: String,
}

#[derive(Deserialize)]
pub struct TvSeries {
    pub vendor: String,
    pub entries: Vec<TvSeriesEntry>,
}

#[derive(Deserialize)]
pub struct TvSeriesEntry {
    pub pattern: String,
    pub name: String,
}

#[derive(Deserialize)]
pub struct HostnameVendor {
    pub match_type: String,
    pub patterns: Vec<String>,
    pub vendor: String,
}

#[derive(Deserialize)]
pub struct HostnameModel {
    pub match_type: String,
    pub pattern: String,
    pub model: String,
}

#[derive(Deserialize)]
pub struct VendorTypeModel {
    pub vendor: String,
    pub device_type: String,
    pub label: String,
    pub literal: bool,
}

#[derive(Deserialize)]
pub struct MacVendorModel {
    pub vendor: String,
    pub model: String,
}
