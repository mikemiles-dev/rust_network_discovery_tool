//! Index page handler. Builds the full Tera template context for the main
//! dashboard view, including communications graph, endpoint details, and
//! device metadata.

use std::collections::{HashMap, HashSet};

use actix_web::web::{Data, Query};
use actix_web::{HttpResponse, Responder, get};
use dns_lookup::get_hostname;
use tera::{Context, Tera};
use tokio::task;

use crate::db::{get_pool, get_setting_i64};
use crate::network::communication::extract_model_from_vendor_class;
use crate::network::endpoint::{
    characterize_model, characterize_vendor, get_mac_vendor, get_model_from_hostname,
    get_model_from_mac, get_model_from_vendor_and_type, infer_model_with_context,
    normalize_model_name, strip_local_suffix,
};
use crate::network::protocol::ProtocolPort;

use super::graph::*;
use super::helpers::*;

// Define a handler function for the web request
#[get("/")]
pub(super) async fn index(tera: Data<Tera>, query: Query<NodeQuery>) -> impl Responder {
    let hostname = strip_local_suffix(&get_hostname().unwrap_or_else(|_| "Unknown".to_string()));
    let scan_interval = query.scan_interval.unwrap_or(525600);

    // Resolve ip=/mac= query params to an effective node name
    let effective_node: Option<String> = if query.node.is_some() {
        query.node.clone()
    } else if let Some(ref ip) = query.ip {
        let ip_clone = ip.clone();
        let resolved = task::spawn_blocking(move || {
            let conn = get_pool().get().ok()?;
            resolve_identifier_to_display_name(&conn, &ip_clone)
        })
        .await
        .ok()
        .flatten();
        Some(resolved.unwrap_or_else(|| ip.clone()))
    } else if let Some(ref mac) = query.mac {
        let mac_clone = mac.clone();
        let resolved = task::spawn_blocking(move || {
            let conn = get_pool().get().ok()?;
            resolve_identifier_to_display_name(&conn, &mac_clone)
        })
        .await
        .ok()
        .flatten();
        Some(resolved.unwrap_or_else(|| mac.clone()))
    } else {
        None
    };

    let selected_endpoint = effective_node.clone().unwrap_or_default();

    // Phase 1: Run independent queries in parallel
    let query_node_1 = effective_node.clone();
    let nodes_future = tokio::task::spawn_blocking(move || get_nodes(query_node_1, scan_interval));
    let dropdown_future = tokio::task::spawn_blocking(move || dropdown_endpoints(scan_interval));
    let interfaces_future = tokio::task::spawn_blocking(super::get_interfaces);

    let (communications_result, dropdown_result, interfaces_result) =
        tokio::join!(nodes_future, dropdown_future, interfaces_future);

    let communications = communications_result.unwrap_or_default();
    let mut dropdown_endpoints = dropdown_result.unwrap_or_default();
    let interfaces = interfaces_result.unwrap_or_default();

    let mut endpoints = get_endpoints(&communications);

    // If a specific node was selected but isn't in the endpoints list, add it
    // This handles isolated endpoints with no communications
    if let Some(ref selected_node) = effective_node
        && !endpoints.contains(selected_node)
    {
        endpoints.push(selected_node.clone());
    }
    // Also add to dropdown_endpoints so the node appears in the list
    if let Some(ref selected_node) = effective_node
        && !dropdown_endpoints.contains(selected_node)
    {
        dropdown_endpoints.push(selected_node.clone());
    }
    let supported_protocols = ProtocolPort::get_supported_protocols();

    // Phase 2: Run queries that depend on dropdown_endpoints in parallel
    let dropdown_for_ips = dropdown_endpoints.clone();
    let dropdown_for_vendor = dropdown_endpoints.clone();
    let dropdown_for_bytes = dropdown_endpoints.clone();
    let dropdown_for_seen = dropdown_endpoints.clone();
    let dropdown_for_online = dropdown_endpoints.clone();
    let dropdown_for_types = dropdown_endpoints.clone();
    let dropdown_for_ssdp = dropdown_endpoints.clone();

    let ips_macs_future =
        tokio::task::spawn_blocking(move || get_endpoint_ips_and_macs(&dropdown_for_ips));
    let vendor_classes_future =
        tokio::task::spawn_blocking(move || get_endpoint_vendor_classes(&dropdown_for_vendor));
    let bytes_future = tokio::task::spawn_blocking(move || {
        get_all_endpoints_bytes(&dropdown_for_bytes, scan_interval)
    });
    let last_seen_future = tokio::task::spawn_blocking(move || {
        get_all_endpoints_last_seen(&dropdown_for_seen, scan_interval)
    });
    let online_status_future = tokio::task::spawn_blocking(move || {
        // Get active threshold from settings (default 120 seconds = 2 minutes)
        let active_threshold = get_setting_i64("active_threshold_seconds", 120) as u64;
        get_all_endpoints_online_status(&dropdown_for_online, active_threshold)
    });
    let all_types_future =
        tokio::task::spawn_blocking(move || get_all_endpoint_types(&dropdown_for_types));
    let ssdp_models_future =
        tokio::task::spawn_blocking(move || get_endpoint_ssdp_models(&dropdown_for_ssdp));

    let (
        ips_macs_result,
        vendor_classes_result,
        bytes_result,
        last_seen_result,
        online_status_result,
        all_types_result,
        ssdp_models_result,
    ) = tokio::join!(
        ips_macs_future,
        vendor_classes_future,
        bytes_future,
        last_seen_future,
        online_status_future,
        all_types_future,
        ssdp_models_future
    );

    let endpoint_ips_macs = ips_macs_result.unwrap_or_default();
    let endpoint_dhcp_vendor_classes = vendor_classes_result.unwrap_or_default();
    let endpoint_bytes = bytes_result.unwrap_or_default();
    let endpoint_last_seen = last_seen_result.unwrap_or_default();
    let endpoint_online_status = online_status_result.unwrap_or_default();
    let (dropdown_types, manual_overrides) = all_types_result.unwrap_or_default();
    let endpoint_ssdp_models = ssdp_models_result.unwrap_or_default();

    // Build vendor lookup for all endpoints (hostname first, then MAC)
    // Hostname detection is more accurate for devices with generic WiFi chips
    // Component manufacturers that shouldn't be shown as device vendors
    let component_vendors = [
        "Espressif",
        "Tuya",
        "Realtek",
        "MediaTek",
        "Qualcomm",
        "Broadcom",
        "Marvell",
        "USI",
        "Wisol",
        "Murata",
        "AzureWave",
    ];
    // Build vendor lookup using characterize_vendor for clean priority handling
    let endpoint_vendors: HashMap<String, String> =
        dropdown_endpoints
            .iter()
            .filter_map(|endpoint| {
                let endpoint_lower = endpoint.to_lowercase();

                // Get data from various sources
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
                    // Filter out component manufacturers
                    .into_iter()
                    .filter(|mac| {
                        get_mac_vendor(mac)
                            .map(|v| !component_vendors.contains(&v))
                            .unwrap_or(true)
                    })
                    .collect();

                // Use characterize_vendor for clean priority-based selection
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

    // Extract unique vendor names for the vendor dropdown filter
    let mut unique_vendors: Vec<String> = endpoint_vendors
        .values()
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    unique_vendors.sort();

    // Build model lookup using characterize_model for clean priority handling
    let endpoint_models: HashMap<String, String> = dropdown_endpoints
        .iter()
        .filter_map(|endpoint| {
            let endpoint_lower = endpoint.to_lowercase();

            // Get data from various sources
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

            // Use characterize_model for clean priority-based selection
            // Note: device_type is None here; vendor+type inference happens in second pass below
            characterize_model(
                custom_model,
                ssdp_model,
                snmp_model,
                Some(endpoint.as_str()),
                &macs,
                vendor,
                None, // device_type added in second pass
            )
            .map(|c| (endpoint_lower, c.value))
        })
        .collect();

    let mut endpoint_types = get_endpoint_types(&communications);
    // Merge dropdown types into endpoint_types
    // Manual overrides should take priority, so use insert() for those
    for (endpoint, type_str) in dropdown_types {
        if manual_overrides.contains(&endpoint) {
            // Manual override - always use this type
            endpoint_types.insert(endpoint, type_str);
        } else {
            endpoint_types.entry(endpoint).or_insert(type_str);
        }
    }
    // Ensure all dropdown endpoints have a type (default to "other" if not classified)
    for endpoint in &dropdown_endpoints {
        endpoint_types.entry(endpoint.clone()).or_insert("other");
    }
    // Also ensure all endpoints from communications have a type
    for endpoint in &endpoints {
        endpoint_types.entry(endpoint.clone()).or_insert("other");
    }
    // Always classify local device as "local"
    endpoint_types.insert(hostname.clone(), "local");
    // Ensure the selected endpoint is always in endpoint_types (for URL navigation)
    if !selected_endpoint.is_empty() {
        endpoint_types
            .entry(selected_endpoint.clone())
            .or_insert("other");
    }

    // Second pass: enhance models using vendor + device type for endpoints without models
    let mut endpoint_models = endpoint_models;
    for (endpoint, device_type) in &endpoint_types {
        let endpoint_lower = endpoint.to_lowercase();
        // Use lowercase for case-insensitive lookups
        if !endpoint_models.contains_key(&endpoint_lower)
            && let Some(vendor) = endpoint_vendors.get(&endpoint_lower)
            && let Some(model) = get_model_from_vendor_and_type(vendor, device_type)
        {
            endpoint_models.insert(endpoint_lower, model);
        }
    }

    // Convert manual_overrides to Vec for serialization
    let manual_overrides: Vec<String> = manual_overrides.into_iter().collect();

    // Phase 3: Run selected endpoint queries in parallel
    let selected_for_ips = selected_endpoint.clone();
    let selected_for_protocols = selected_endpoint.clone();
    let selected_for_bytes = selected_endpoint.clone();

    let ips_macs_hostnames_future = tokio::task::spawn_blocking(move || {
        get_all_ips_macs_and_hostnames_from_single_hostname(selected_for_ips, scan_interval)
    });
    let protocols_future = tokio::task::spawn_blocking(move || {
        get_protocols_for_endpoint(selected_for_protocols, scan_interval)
    });
    let bytes_stats_future = tokio::task::spawn_blocking(move || {
        get_bytes_for_endpoint(selected_for_bytes, scan_interval)
    });

    // Ports query depends on whether a node is selected
    let ports_future = if effective_node.is_some() {
        // Use in-memory data, no DB query needed
        let comms = communications.clone();
        let selected = selected_endpoint.clone();
        tokio::task::spawn_blocking(move || get_ports_from_communications(&comms, &selected))
    } else {
        let selected_for_ports = selected_endpoint.clone();
        tokio::task::spawn_blocking(move || {
            get_ports_for_endpoint(selected_for_ports, scan_interval)
        })
    };

    let (ips_macs_hostnames_result, protocols_result, bytes_stats_result, ports_result) = tokio::join!(
        ips_macs_hostnames_future,
        protocols_future,
        bytes_stats_future,
        ports_future
    );

    let (ips, macs, hostnames) = ips_macs_hostnames_result.unwrap_or_default();
    let protocols = protocols_result.unwrap_or_default();
    let bytes_stats = bytes_stats_result.unwrap_or_else(|_| BytesStats::default());
    let ports = ports_result.unwrap_or_default();

    // Build MAC vendor lookup
    let mac_vendors: HashMap<String, String> = macs
        .iter()
        .filter_map(|mac| get_mac_vendor(mac).map(|vendor| (mac.clone(), vendor.to_string())))
        .collect();
    const COMPONENT_VENDORS: &[&str] = &[
        "Espressif",
        "Tuya",
        "Realtek",
        "MediaTek",
        "Qualcomm",
        "Broadcom",
        "Marvell",
        "USI",
        "Wisol",
        "Murata",
    ];

    // Get model/vendor data including custom_vendor and snmp_vendor
    let selected_lower = selected_endpoint.to_lowercase();
    let models_data = endpoint_ssdp_models.get(&selected_lower);

    let (
        detail_custom_vendor,
        detail_ssdp_friendly,
        detail_snmp_vendor,
        detail_ssdp_model,
        detail_snmp_model,
    ) = models_data
        .map(|m| {
            (
                m.custom_vendor.as_deref(),
                m.ssdp_friendly_name.as_deref(),
                m.snmp_vendor.as_deref(),
                m.ssdp_model.as_deref(),
                m.snmp_model.as_deref(),
            )
        })
        .unwrap_or((None, None, None, None, None));

    // Filter out component manufacturers from MACs for vendor detection
    let vendor_macs: Vec<String> = macs
        .iter()
        .filter(|mac| {
            get_mac_vendor(mac)
                .map(|v| !COMPONENT_VENDORS.contains(&v))
                .unwrap_or(true)
        })
        .cloned()
        .collect();

    let device_vendor: String = characterize_vendor(
        detail_custom_vendor,
        detail_ssdp_friendly,
        detail_snmp_vendor,
        Some(selected_endpoint.as_str()),
        &vendor_macs,
        detail_ssdp_model,
    )
    .map(|c| c.value)
    .unwrap_or_default();

    // Get model: custom_model first, then SSDP/SNMP (with normalization), hostname, MAC, DHCP vendor class, vendor+type fallback

    // Check custom_model first (user-set model takes priority)
    let device_model: String = models_data
        .and_then(|m| m.custom_model.clone())
        .or_else(|| {
            // Try SSDP model with normalization
            models_data
                .and_then(|m| m.ssdp_model.as_ref())
                .and_then(|model| {
                    let vendor_ref = if device_vendor.is_empty() {
                        None
                    } else {
                        Some(device_vendor.as_str())
                    };
                    normalize_model_name(model, vendor_ref).or_else(|| Some(model.to_string()))
                })
        })
        .or_else(|| {
            // Try SNMP model (device self-reported via sysDescr)
            detail_snmp_model.map(|m| m.to_string())
        })
        .or_else(|| get_model_from_hostname(&selected_endpoint))
        .or_else(|| {
            // Context-aware MAC detection for Amazon devices etc.
            let has_ssdp = models_data
                .is_some_and(|m| m.ssdp_model.is_some() || m.ssdp_friendly_name.is_some());
            macs.iter().find_map(|mac| {
                infer_model_with_context(mac, has_ssdp, false, false, &[])
                    .or_else(|| get_model_from_mac(mac))
            })
        })
        .or_else(|| {
            // Try DHCP vendor class (e.g., "samsung:SM-G998B")
            endpoint_dhcp_vendor_classes
                .get(&selected_endpoint)
                .and_then(|vc| extract_model_from_vendor_class(vc))
        })
        .or_else(|| {
            // Use vendor + device type for more specific model
            let device_type = endpoint_types
                .get(&selected_endpoint)
                .copied()
                .unwrap_or("other");
            if !device_vendor.is_empty() {
                get_model_from_vendor_and_type(&device_vendor, device_type)
            } else {
                None
            }
        })
        .unwrap_or_default();

    // Ensure the selected endpoint's vendor/model are in the lookup maps
    // This handles cases where the endpoint was added via URL but its data
    // wasn't found in batch queries (e.g., mDNS-resolved names)
    let mut endpoint_vendors = endpoint_vendors;
    if !device_vendor.is_empty() {
        endpoint_vendors
            .entry(selected_lower.clone())
            .or_insert(device_vendor.clone());
    }
    if !device_model.is_empty() {
        endpoint_models
            .entry(selected_lower)
            .or_insert(device_model.clone());
    }

    let mut context = Context::new();
    context.insert("communications", &communications);
    context.insert("endpoints", &endpoints);
    context.insert("endpoint_types", &endpoint_types);
    context.insert("interfaces", &interfaces);
    context.insert("hostname", &hostname);
    context.insert("endpoint", &selected_endpoint);
    context.insert("supported_protocols", &supported_protocols);
    context.insert("selected_node", &effective_node);
    context.insert("dropdown_endpoints", &dropdown_endpoints);
    context.insert("endpoint_ips_macs", &endpoint_ips_macs);
    context.insert("endpoint_vendors", &endpoint_vendors);
    context.insert("unique_vendors", &unique_vendors);
    context.insert("endpoint_models", &endpoint_models);
    context.insert("endpoint_bytes", &endpoint_bytes);
    context.insert("endpoint_last_seen", &endpoint_last_seen);
    context.insert("endpoint_online_status", &endpoint_online_status);
    context.insert("ips", &ips);
    context.insert("macs", &macs);
    context.insert("mac_vendors", &mac_vendors);
    context.insert("device_vendor", &device_vendor);
    context.insert("device_model", &device_model);
    context.insert("hostnames", &hostnames);
    context.insert("ports", &ports);
    context.insert("protocols", &protocols);
    context.insert("bytes_in", &bytes_stats.bytes_in);
    context.insert("bytes_out", &bytes_stats.bytes_out);
    context.insert("dns_entries", &get_dns_entries());
    context.insert("manual_overrides", &manual_overrides);

    let rendered = tera
        .render("index.html", &context)
        .expect("Failed to render template");

    HttpResponse::Ok().body(rendered)
}
