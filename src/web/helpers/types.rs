//! Shared struct and type definitions used as return types by the web helper queries.

use serde::{Deserialize, Serialize};

/// Combined endpoint stats (bytes, last_seen, online) from single query
#[derive(Clone)]
pub(crate) struct EndpointStats {
    pub(crate) bytes: i64,
    pub(crate) last_seen: String,
    pub(crate) online: bool,
}

#[derive(serde::Serialize)]
pub(crate) struct EndpointDetailsResponse {
    pub(crate) endpoint_name: String,
    pub(crate) device_type: String,
    pub(crate) is_manual_override: bool,
    pub(crate) device_vendor: String,
    pub(crate) device_model: String,
    pub(crate) ips: Vec<String>,
    pub(crate) macs: Vec<String>,
    pub(crate) hostnames: Vec<String>,
    pub(crate) ports: Vec<String>,
    pub(crate) protocols: Vec<String>,
    pub(crate) bytes_in: i64,
    pub(crate) bytes_out: i64,
}

#[derive(serde::Deserialize)]
pub(crate) struct NodeQuery {
    pub(crate) node: Option<String>,
    pub(crate) ip: Option<String>,
    pub(crate) mac: Option<String>,
    pub(crate) scan_interval: Option<u64>,
}

#[derive(serde::Serialize)]
pub(crate) struct DnsEntryView {
    pub(crate) ip: String,
    pub(crate) hostname: String,
    pub(crate) services: String,
    pub(crate) timestamp: String,
}

#[derive(Serialize, Default)]
pub(crate) struct BytesStats {
    pub(crate) bytes_in: i64,
    pub(crate) bytes_out: i64,
}

/// Unified success/message response for API endpoints
#[derive(Serialize)]
pub(crate) struct ApiResponse {
    pub(crate) success: bool,
    pub(crate) message: String,
}

/// Request containing a single IP address
#[derive(Deserialize)]
pub(crate) struct IpRequest {
    pub(crate) ip: String,
}

/// Request containing a single endpoint name
#[derive(Deserialize)]
pub(crate) struct EndpointNameRequest {
    pub(crate) endpoint_name: String,
}

/// Vendors that manufacture WiFi/BT chipsets (not consumer-facing brands)
pub(crate) const COMPONENT_VENDORS: &[&str] = &[
    "AzureWave",
    "Broadcom",
    "Espressif",
    "Marvell",
    "MediaTek",
    "Murata",
    "Qualcomm",
    "Realtek",
    "Tuya",
    "USI",
    "Wisol",
];

/// Default scan interval in minutes (1 year)
pub(crate) const DEFAULT_SCAN_INTERVAL_MINUTES: u64 = 525600;

/// Default threshold in seconds for considering an endpoint "active"
pub(crate) const DEFAULT_ACTIVE_THRESHOLD_SECONDS: i64 = 120;

/// Model/Vendor data for an endpoint
#[derive(Default)]
pub(crate) struct EndpointModelData {
    pub(crate) custom_model: Option<String>,
    pub(crate) ssdp_model: Option<String>,
    pub(crate) ssdp_friendly_name: Option<String>,
    pub(crate) custom_vendor: Option<String>,
    pub(crate) snmp_vendor: Option<String>,
    pub(crate) snmp_model: Option<String>,
}
