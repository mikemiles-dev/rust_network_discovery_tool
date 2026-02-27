//! Endpoints table API handler: provides data for the AJAX-refreshed endpoints table.

use actix_web::{HttpResponse, Responder, get};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::db::get_setting_i64;
use crate::network::endpoint::{
    characterize_model, characterize_vendor, get_mac_vendor, get_model_from_vendor_and_type,
};

use crate::web::{
    COMPONENT_VENDORS, DEFAULT_ACTIVE_THRESHOLD_SECONDS, DEFAULT_SCAN_INTERVAL_MINUTES,
    dropdown_endpoints, get_all_endpoint_types, get_combined_endpoint_stats,
    get_endpoint_ips_and_macs, get_endpoint_ssdp_models,
};

// ============================================================================
// Global State
// ============================================================================

// Cache for endpoint table data to avoid repeated DB queries
static ENDPOINT_TABLE_CACHE: OnceLock<Mutex<EndpointTableCache>> = OnceLock::new();

struct EndpointTableCache {
    data: Option<Vec<EndpointTableRow>>,
    last_updated: std::time::Instant,
    ttl_seconds: u64,
}

impl EndpointTableCache {
    fn new() -> Self {
        Self {
            data: None,
            last_updated: std::time::Instant::now(),
            ttl_seconds: 3, // Cache for 3 seconds
        }
    }

    fn is_valid(&self) -> bool {
        self.data.is_some() && self.last_updated.elapsed().as_secs() < self.ttl_seconds
    }

    fn get(&self) -> Option<Vec<EndpointTableRow>> {
        if self.is_valid() {
            self.data.clone()
        } else {
            None
        }
    }

    fn set(&mut self, data: Vec<EndpointTableRow>) {
        self.data = Some(data);
        self.last_updated = std::time::Instant::now();
    }
}

fn get_endpoint_table_cache() -> &'static Mutex<EndpointTableCache> {
    ENDPOINT_TABLE_CACHE.get_or_init(|| Mutex::new(EndpointTableCache::new()))
}

// ============================================================================
// Endpoints Table API (for AJAX refresh without full page reload)
// ============================================================================

#[derive(Clone, Serialize)]
pub struct EndpointTableRow {
    name: String,
    vendor: Option<String>,
    model: Option<String>,
    device_type: Option<String>,
    bytes: i64,
    last_seen: String,
    online: bool,
}

#[derive(Serialize)]
pub struct EndpointsTableResponse {
    endpoints: Vec<EndpointTableRow>,
}

/// Get endpoint table data for AJAX refresh (doesn't reload full page)
#[get("/api/endpoints/table")]
pub async fn get_endpoints_table() -> impl Responder {
    // Check cache first (3-second TTL)
    {
        let cache = get_endpoint_table_cache();
        if let Ok(cache_guard) = cache.lock()
            && let Some(cached_data) = cache_guard.get()
        {
            return HttpResponse::Ok().json(EndpointsTableResponse {
                endpoints: cached_data,
            });
        }
    }

    let scan_interval: u64 = DEFAULT_SCAN_INTERVAL_MINUTES; // Same default as index route
    let active_threshold =
        get_setting_i64("active_threshold_seconds", DEFAULT_ACTIVE_THRESHOLD_SECONDS) as u64;

    // Get endpoint list
    let dropdown_future = tokio::task::spawn_blocking(move || dropdown_endpoints(scan_interval));
    let dropdown_endpoints_list = dropdown_future.await.unwrap_or_default();

    if dropdown_endpoints_list.is_empty() {
        return HttpResponse::Ok().json(EndpointsTableResponse {
            endpoints: Vec::new(),
        });
    }

    // Prepare for parallel queries
    let dropdown_for_stats = dropdown_endpoints_list.clone();
    let dropdown_for_types = dropdown_endpoints_list.clone();
    let dropdown_for_ips = dropdown_endpoints_list.clone();
    let dropdown_for_ssdp = dropdown_endpoints_list.clone();

    // OPTIMIZATION: Combined stats query (replaces 3 separate queries for bytes, last_seen, online)
    let stats_future = tokio::task::spawn_blocking(move || {
        get_combined_endpoint_stats(&dropdown_for_stats, scan_interval, active_threshold)
    });

    let all_types_future =
        tokio::task::spawn_blocking(move || get_all_endpoint_types(&dropdown_for_types));

    // Fetch vendor/model data (always fresh - removed cache that caused stale data issues)
    let ips_macs_future =
        tokio::task::spawn_blocking(move || get_endpoint_ips_and_macs(&dropdown_for_ips));
    let ssdp_models_future =
        tokio::task::spawn_blocking(move || get_endpoint_ssdp_models(&dropdown_for_ssdp));

    // Run all queries in parallel
    let (stats_result, all_types_result, ips_macs_result, ssdp_models_result) = tokio::join!(
        stats_future,
        all_types_future,
        ips_macs_future,
        ssdp_models_future
    );

    let endpoint_stats = stats_result.unwrap_or_default();
    let (dropdown_types, _manual_overrides) = all_types_result.unwrap_or_default();
    let endpoint_ips_macs = ips_macs_result.unwrap_or_default();
    let endpoint_ssdp_models = ssdp_models_result.unwrap_or_default();

    // Build vendor lookup
    let endpoint_vendors: HashMap<String, String> =
        dropdown_endpoints_list
            .iter()
            .filter_map(|endpoint| {
                let endpoint_lower = endpoint.to_lowercase();
                let (
                    _custom_model,
                    ssdp_model,
                    ssdp_friendly,
                    custom_vendor,
                    snmp_vendor,
                    _snmp_model,
                ) = endpoint_ssdp_models
                    .get(&endpoint_lower)
                    .map(|m| {
                        (
                            m.custom_model.as_deref(),
                            m.ssdp_model.as_deref(),
                            m.ssdp_friendly_name.as_deref(),
                            m.custom_vendor.as_deref(),
                            m.snmp_vendor.as_deref(),
                            m.snmp_model.as_deref(),
                        )
                    })
                    .unwrap_or((None, None, None, None, None, None));

                let macs: Vec<String> = endpoint_ips_macs
                    .get(&endpoint_lower)
                    .map(|(_, m)| m.clone())
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|mac| {
                        get_mac_vendor(mac)
                            .map(|v| !COMPONENT_VENDORS.contains(&v))
                            .unwrap_or(true)
                    })
                    .collect();

                characterize_vendor(
                    custom_vendor,
                    ssdp_friendly,
                    snmp_vendor,
                    Some(endpoint.as_str()),
                    &macs,
                    ssdp_model,
                )
                .map(|c| (endpoint_lower, c.value))
            })
            .collect();

    // Build model lookup (first pass without device_type)
    let mut endpoint_models: HashMap<String, String> = dropdown_endpoints_list
        .iter()
        .filter_map(|endpoint| {
            let endpoint_lower = endpoint.to_lowercase();
            let (custom_model, ssdp_model, _, _, _, snmp_model) = endpoint_ssdp_models
                .get(&endpoint_lower)
                .map(|m| {
                    (
                        m.custom_model.as_deref(),
                        m.ssdp_model.as_deref(),
                        m.ssdp_friendly_name.as_deref(),
                        m.custom_vendor.as_deref(),
                        m.snmp_vendor.as_deref(),
                        m.snmp_model.as_deref(),
                    )
                })
                .unwrap_or((None, None, None, None, None, None));

            let macs: Vec<String> = endpoint_ips_macs
                .get(&endpoint_lower)
                .map(|(_, m)| m.clone())
                .unwrap_or_default();

            let vendor = endpoint_vendors.get(&endpoint_lower).map(|v| v.as_str());

            characterize_model(
                custom_model,
                ssdp_model,
                snmp_model,
                Some(endpoint.as_str()),
                &macs,
                vendor,
                None,
            )
            .map(|c| (endpoint_lower, c.value))
        })
        .collect();

    // Second pass: enhance models using vendor + device type for endpoints without models
    for endpoint in &dropdown_endpoints_list {
        let endpoint_lower = endpoint.to_lowercase();
        if !endpoint_models.contains_key(&endpoint_lower)
            && let Some(vendor) = endpoint_vendors.get(&endpoint_lower)
            && let Some(device_type) = dropdown_types.get(&endpoint_lower)
            && let Some(model) = get_model_from_vendor_and_type(vendor, device_type)
        {
            endpoint_models.insert(endpoint_lower, model);
        }
    }

    // Build response
    let endpoints: Vec<EndpointTableRow> = dropdown_endpoints_list
        .iter()
        .map(|endpoint| {
            let endpoint_lower = endpoint.to_lowercase();
            let stats = endpoint_stats.get(&endpoint_lower);
            EndpointTableRow {
                name: endpoint.clone(),
                vendor: endpoint_vendors.get(&endpoint_lower).cloned(),
                model: endpoint_models.get(&endpoint_lower).cloned(),
                device_type: dropdown_types.get(&endpoint_lower).map(|s| s.to_string()),
                bytes: stats.map(|s| s.bytes).unwrap_or(0),
                last_seen: stats
                    .map(|s| s.last_seen.clone())
                    .unwrap_or_else(|| "-".to_string()),
                online: stats.map(|s| s.online).unwrap_or(false),
            }
        })
        .collect();

    // Update cache
    {
        let cache = get_endpoint_table_cache();
        if let Ok(mut cache_guard) = cache.lock() {
            cache_guard.set(endpoints.clone());
        }
    }

    HttpResponse::Ok().json(EndpointsTableResponse { endpoints })
}
