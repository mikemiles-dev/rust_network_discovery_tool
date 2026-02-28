//! Endpoint details API handler: fetches full device information for the details panel.

use actix_web::{HttpResponse, Responder, get};

use crate::db::get_pool;
use crate::network::communication::extract_model_from_vendor_class;
use crate::network::endpoint::{
    EndPoint, get_hostname_vendor, get_mac_vendor, get_model_from_hostname, get_model_from_mac,
    get_model_from_vendor_and_type, get_vendor_from_model, infer_model_with_context,
    normalize_model_name, strip_local_suffix,
};

use crate::web::{
    COMPONENT_VENDORS, DEFAULT_SCAN_INTERVAL_MINUTES, EndpointDetailsResponse,
    NodeQuery, get_all_ips_macs_and_hostnames_from_single_hostname, get_bytes_for_endpoint,
    get_ports_for_endpoint, get_protocols_for_endpoint, probe_and_save_hp_printer_model_blocking,
};

use super::super::devices::get_probing_endpoints;

// ============================================================================
// Endpoint Details API
// ============================================================================

#[get("/api/endpoint/{name}/details")]
pub async fn get_endpoint_details(
    path: actix_web::web::Path<String>,
    query: actix_web::web::Query<NodeQuery>,
) -> impl Responder {
    let endpoint_name = path.into_inner();
    let internal_minutes = query.scan_interval.unwrap_or(DEFAULT_SCAN_INTERVAL_MINUTES);

    // Run all blocking DB operations in a separate thread pool
    let result = tokio::task::spawn_blocking(move || {
        get_endpoint_details_blocking(endpoint_name, internal_minutes)
    })
    .await;

    match result {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to fetch endpoint details"
        })),
    }
}

/// Blocking implementation of endpoint details fetching
fn get_endpoint_details_blocking(
    endpoint_name: String,
    internal_minutes: u64,
) -> EndpointDetailsResponse {
    use dns_lookup::get_hostname;

    // Get IPs, MACs, and hostnames
    let (ips, macs, hostnames) = get_all_ips_macs_and_hostnames_from_single_hostname(
        endpoint_name.clone(),
        internal_minutes,
    );

    // Get device type for this endpoint
    let conn = get_pool().get().expect("Failed to get pooled connection");
    let manual_types = EndPoint::get_all_manual_device_types(&conn);
    let auto_types = EndPoint::get_all_auto_device_types(&conn);

    // Check for manual override first (case-insensitive)
    let manual_type = manual_types
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&endpoint_name))
        .map(|(_, v)| v.clone());

    // Check for stored auto-detected type (persists across renames)
    let stored_auto_type = auto_types
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&endpoint_name))
        .map(|(_, v)| v.clone());

    // Single consolidated query for all endpoint metadata (replaces 4 separate queries)
    let (custom_model, ssdp_model, custom_vendor, dhcp_vendor_class) = conn
        .query_row(
            "SELECT e.custom_model, e.ssdp_model, e.custom_vendor,
                    (SELECT ea.dhcp_vendor_class FROM endpoint_attributes ea
                     WHERE ea.endpoint_id = e.id
                     AND ea.dhcp_vendor_class IS NOT NULL AND ea.dhcp_vendor_class != ''
                     LIMIT 1)
             FROM endpoints e
             WHERE (LOWER(e.name) = LOWER(?1) OR LOWER(e.custom_name) = LOWER(?1))
             LIMIT 1",
            rusqlite::params![&endpoint_name],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .unwrap_or((None, None, None, None));

    // Get local hostname for comparison
    let local_hostname =
        strip_local_suffix(&get_hostname().unwrap_or_else(|_| "Unknown".to_string()));

    let (device_type, is_manual_override) = if let Some(mt) = manual_type {
        (mt, true)
    } else if let Some(at) = stored_auto_type {
        // Use stored auto-detected type (persists across renames)
        (at, false)
    } else if endpoint_name.eq_ignore_ascii_case(&local_hostname) {
        // This is the local machine
        let _ = EndPoint::set_auto_device_type(&conn, &endpoint_name, "local");
        ("local".to_string(), false)
    } else {
        // First check network-level classification (gateway, internet)
        let first_ip = ips.first().cloned();
        if let Some(network_type) =
            EndPoint::classify_endpoint(first_ip.clone(), Some(endpoint_name.clone()))
        {
            let _ = EndPoint::set_auto_device_type(&conn, &endpoint_name, network_type);
            (network_type.to_string(), false)
        } else {
            // Use EndPoint::classify_device_type for device-specific detection
            let auto_type = EndPoint::classify_device_type(
                Some(&endpoint_name),
                &ips,
                &[],
                &macs,
                ssdp_model.as_deref(),
            )
            .unwrap_or_else(|| {
                // Fallback: if on local network, classify as "local", otherwise "other"
                if let Some(ref ip_str) = first_ip {
                    if EndPoint::is_on_local_network(ip_str) {
                        "local"
                    } else {
                        "other"
                    }
                } else {
                    "other"
                }
            });
            let _ = EndPoint::set_auto_device_type(&conn, &endpoint_name, auto_type);
            (auto_type.to_string(), false)
        }
    };

    // Get device vendor from MAC or hostname
    // Prefer hostname vendor over component manufacturers (Espressif, Tuya, etc.)
    let mac_vendor = macs.iter().find_map(|mac| get_mac_vendor(mac));
    let hostname_vendor = get_hostname_vendor(&endpoint_name);

    // Try to detect vendor from model (e.g., "7105X" -> TCL)
    let model_vendor = ssdp_model
        .as_ref()
        .and_then(|m| get_vendor_from_model(m));

    // Custom vendor takes priority if set
    let device_vendor: String = if let Some(ref cv) = custom_vendor {
        if !cv.is_empty() {
            cv.clone()
        } else {
            String::new()
        }
    } else {
        match (hostname_vendor, mac_vendor, model_vendor) {
            // Hostname vendor identified (e.g., LG from "ldf7774st") - prefer it
            (Some(hv), _, _) => hv.to_string(),
            // Model vendor identified (e.g., TCL from "7105X") - use it before MAC
            (None, _, Some(mv)) => mv.to_string(),
            // MAC vendor is a component manufacturer - don't show it
            (None, Some(mv), None) if COMPONENT_VENDORS.contains(&mv) => String::new(),
            // MAC vendor is a product manufacturer - show it
            (None, Some(mv), None) => mv.to_string(),
            // No vendor identified
            (None, None, None) => String::new(),
        }
    };

    // Check if device has SSDP info (for context-aware model detection)
    // Check for non-empty string, not just Some()
    let has_ssdp = ssdp_model.as_ref().is_some_and(|m| !m.is_empty());

    // Auto-probe HP devices without a model
    // Check for None OR empty string since database might have either
    let needs_model = custom_model.as_ref().is_none_or(|m| m.is_empty())
        && ssdp_model.as_ref().is_none_or(|m| m.is_empty());

    if device_vendor == "HP"
        && needs_model
        && let Some(ip) = ips.first().cloned()
        && let Ok(endpoint_id) = conn.query_row(
            "SELECT e.id FROM endpoints e WHERE LOWER(e.name) = LOWER(?1) OR LOWER(e.custom_name) = LOWER(?1) LIMIT 1",
            rusqlite::params![&endpoint_name],
            |row| row.get::<_, i64>(0),
        )
    {
        // Check if already probing this endpoint to prevent duplicate probes
        let should_probe = {
            let mut probing = get_probing_endpoints().lock().unwrap();
            if probing.contains(&endpoint_id) {
                false
            } else {
                probing.insert(endpoint_id);
                true
            }
        };

        if should_probe {
            // Spawn a thread for the probe (we're already in a blocking context)
            std::thread::spawn(move || {
                probe_and_save_hp_printer_model_blocking(&ip, endpoint_id);
                // Remove from probing set when done
                let mut probing = get_probing_endpoints().lock().unwrap();
                probing.remove(&endpoint_id);
            });
        }
    }

    // Get device model: custom_model first, then SSDP (with normalization), hostname, MAC, DHCP vendor class, vendor+type fallback
    let device_model: String = custom_model
        .or_else(|| {
            ssdp_model.as_ref().and_then(|model| {
                // Try to normalize the SSDP model (e.g., QN43LS03TAFXZA -> Samsung The Frame)
                let vendor_ref = if device_vendor.is_empty() {
                    None
                } else {
                    Some(device_vendor.as_str())
                };
                normalize_model_name(model, vendor_ref).or_else(|| Some(model.clone()))
            })
        })
        .or_else(|| get_model_from_hostname(&endpoint_name))
        .or_else(|| {
            // Context-aware MAC detection for Amazon devices etc.
            macs.iter().find_map(|mac| {
                infer_model_with_context(mac, has_ssdp, false, false, &[])
                    .or_else(|| get_model_from_mac(mac))
            })
        })
        .or_else(|| {
            // Try DHCP vendor class (e.g., "samsung:SM-G998B")
            dhcp_vendor_class
                .as_ref()
                .and_then(|vc| extract_model_from_vendor_class(vc))
        })
        .or_else(|| {
            // Use vendor + device type for more specific model
            if !device_vendor.is_empty() {
                get_model_from_vendor_and_type(&device_vendor, &device_type)
            } else {
                None
            }
        })
        .unwrap_or_default();

    // Get protocols
    let protocols = get_protocols_for_endpoint(endpoint_name.clone(), internal_minutes);

    // Get ports
    let ports = get_ports_for_endpoint(endpoint_name.clone(), internal_minutes);

    // Get bytes stats
    let bytes_stats = get_bytes_for_endpoint(endpoint_name.clone(), internal_minutes);

    EndpointDetailsResponse {
        endpoint_name,
        device_type,
        is_manual_override,
        device_vendor,
        device_model,
        ips,
        macs,
        hostnames,
        ports,
        protocols,
        bytes_in: bytes_stats.bytes_in,
        bytes_out: bytes_stats.bytes_out,
    }
}
