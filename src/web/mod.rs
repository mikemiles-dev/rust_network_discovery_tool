//! Web server module. Implements the Actix-web REST API and HTML UI for endpoint
//! browsing, scan control, device management, and PCAP file import.

mod api;
use api::*;

mod helpers;
pub(crate) use helpers::*;

use actix_web::{
    App, HttpServer,
    web::{Data, Query},
};
use actix_web::{HttpResponse, Responder, get};
use dns_lookup::get_hostname;
use pnet::datalink;
use rust_embed::RustEmbed;
use std::collections::{HashMap, HashSet};
use tera::{Context, Tera};
use tokio::task;

use crate::db::{
    get_setting_i64, new_connection_result,
};
use crate::network::communication::extract_model_from_vendor_class;
use crate::network::endpoint::{
    EndPoint, characterize_model, characterize_vendor, get_mac_vendor, get_model_from_hostname,
    get_model_from_mac, get_model_from_vendor_and_type, infer_model_with_context,
    normalize_model_name, strip_local_suffix,
};
use crate::network::protocol::ProtocolPort;
use crate::scanner::ScanType;

use serde::{Deserialize, Serialize};

// ============================================================================
// Type Definitions
// ============================================================================

#[derive(RustEmbed)]
#[folder = "templates/"]
struct Templates;

#[derive(RustEmbed)]
#[folder = "static/"]
struct StaticAssets;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    src_hostname: String,
    dst_hostname: String,
    sub_protocol: String,
    src_type: Option<&'static str>,
    dst_type: Option<&'static str>,
    src_port: Option<String>,
    dst_port: Option<String>,
}

// Internal struct for query results
struct CommunicationRow {
    src_hostname: String,
    dst_hostname: String,
    sub_protocol: String,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
}

fn get_interfaces() -> Vec<String> {
    let interfaces = datalink::interfaces();
    interfaces.into_iter().map(|iface| iface.name).collect()
}

/// Extract listening ports from communications data (already filtered for graph)
/// Only shows destination ports where endpoint is the destination (ports it's listening on)
/// Excludes ephemeral ports (49152-65535) which are just used for receiving responses
pub(super) fn get_ports_from_communications(
    communications: &[Node],
    selected_endpoint: &str,
) -> Vec<String> {
    let mut ports: HashSet<i64> = HashSet::new();

    for node in communications {
        // Only get destination port when endpoint is the destination (listening port)
        // Skip ephemeral ports (49152+)
        if node.dst_hostname == selected_endpoint
            && let Some(ref port_str) = node.dst_port
        {
            for p in port_str.split(',') {
                if let Ok(port) = p.trim().parse::<i64>()
                    && port < 49152
                {
                    ports.insert(port);
                }
            }
        }
    }

    let mut ports_vec: Vec<i64> = ports.into_iter().collect();
    ports_vec.sort();
    ports_vec.into_iter().map(|p| p.to_string()).collect()
}

fn get_nodes(current_node: Option<String>, internal_minutes: u64) -> Vec<Node> {
    let conn = try_db!(new_connection_result(), Vec::new());

    // If no node specified, show all communications (overall network view)
    // If node is specified, filter to only that endpoint's communications
    let endpoint_ids = match current_node {
        Some(hostname) => {
            let ids = resolve_identifier_to_endpoint_ids(&conn, &hostname);
            if ids.is_empty() {
                return Vec::new();
            }
            Some(ids)
        }
        None => None,
    };

    // Use CTE to pre-compute display names and IPs for each endpoint
    // This avoids correlated subqueries which are slow
    // Filter out endpoints that ONLY have locally administered (randomized) MACs
    // Locally administered MACs have 2nd hex digit of 2, 6, A, or E
    let endpoint_info_cte = "
        WITH endpoint_info AS (
            SELECT
                e.id,
                COALESCE(e.custom_name,
                    CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%' AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' AND NOT (LENGTH(e.name) = 36 AND e.name GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*') THEN e.name END,
                    MIN(CASE WHEN ea.hostname IS NOT NULL AND ea.hostname != '' AND NOT (LENGTH(ea.hostname) = 36 AND ea.hostname GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*') THEN ea.hostname END)) AS display_name,
                MIN(ea.ip) AS ip
            FROM endpoints e
            LEFT JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
            WHERE (
                -- Has at least one real (non-locally-administered) MAC
                EXISTS (
                    SELECT 1 FROM endpoint_attributes ea2
                    WHERE ea2.endpoint_id = e.id
                    AND ea2.mac IS NOT NULL
                    AND ea2.mac != ''
                    AND UPPER(SUBSTR(ea2.mac, 2, 1)) NOT IN ('2', '6', 'A', 'E')
                )
                OR
                -- Or has no MACs at all (allow IP-only endpoints)
                NOT EXISTS (
                    SELECT 1 FROM endpoint_attributes ea3
                    WHERE ea3.endpoint_id = e.id
                    AND ea3.mac IS NOT NULL
                    AND ea3.mac != ''
                )
            )
            GROUP BY e.id
        )";

    // Build query - either filtered by endpoint or show all
    let (query, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = match &endpoint_ids {
        Some(ids) => {
            let placeholders = build_in_placeholders(ids.len());
            let query = format!(
                "{endpoint_info_cte}
                SELECT
                    src_info.display_name AS src_hostname,
                    dst_info.display_name AS dst_hostname,
                    c.source_port as src_port,
                    c.destination_port as dst_port,
                    c.ip_header_protocol as header_protocol,
                    c.sub_protocol,
                    src_info.ip AS src_ip,
                    dst_info.ip AS dst_ip
                FROM communications AS c
                INNER JOIN endpoint_info AS src_info ON c.src_endpoint_id = src_info.id
                INNER JOIN endpoint_info AS dst_info ON c.dst_endpoint_id = dst_info.id
                WHERE (c.src_endpoint_id IN ({0}) OR c.dst_endpoint_id IN ({0}))
                AND c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
                AND src_info.display_name IS NOT NULL AND src_info.display_name != ''
                AND dst_info.display_name IS NOT NULL AND dst_info.display_name != ''",
                placeholders
            );

            let mut params = box_i64_params(ids);
            params.extend(box_i64_params(ids));
            params.push(Box::new(internal_minutes));
            (query, params)
        }
        None => {
            let query = format!(
                "{endpoint_info_cte}
                SELECT
                    src_info.display_name AS src_hostname,
                    dst_info.display_name AS dst_hostname,
                    c.source_port as src_port,
                    c.destination_port as dst_port,
                    c.ip_header_protocol as header_protocol,
                    c.sub_protocol,
                    src_info.ip AS src_ip,
                    dst_info.ip AS dst_ip
                FROM communications AS c
                INNER JOIN endpoint_info AS src_info ON c.src_endpoint_id = src_info.id
                INNER JOIN endpoint_info AS dst_info ON c.dst_endpoint_id = dst_info.id
                WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
                AND src_info.display_name IS NOT NULL AND src_info.display_name != ''
                AND dst_info.display_name IS NOT NULL AND dst_info.display_name != ''"
            );

            (query, vec![Box::new(internal_minutes)])
        }
    };

    let mut stmt = try_db!(conn.prepare(&query), Vec::new());

    let rows = try_db!(
        stmt.query_map(params_to_refs(&params).as_slice(), |row| {
            let header_protocol = row.get::<_, String>("header_protocol")?;
            let sub_protocol = row
                .get::<_, Option<String>>("sub_protocol")?
                .filter(|s| !s.is_empty())
                .unwrap_or(header_protocol);

            Ok(CommunicationRow {
                src_hostname: row.get("src_hostname")?,
                dst_hostname: row.get("dst_hostname")?,
                sub_protocol,
                src_ip: row.get::<_, Option<String>>("src_ip").ok().flatten(),
                dst_ip: row.get::<_, Option<String>>("dst_ip").ok().flatten(),
                src_port: row.get::<_, Option<u16>>("src_port").ok().flatten(),
                dst_port: row.get::<_, Option<u16>>("dst_port").ok().flatten(),
            })
        }),
        Vec::new()
    );

    // Group by source and destination, collecting all protocols and ports
    type CommKey = (String, String);
    type CommData = (
        Vec<String>,
        Option<String>,
        Option<String>,
        Vec<u16>,
        Vec<u16>,
    );
    let mut comm_map: std::collections::HashMap<CommKey, CommData> =
        std::collections::HashMap::new();

    for row in rows.flatten() {
        let key = (row.src_hostname.clone(), row.dst_hostname.clone());
        let entry = comm_map.entry(key).or_insert((
            vec![],
            row.src_ip.clone(),
            row.dst_ip.clone(),
            vec![],
            vec![],
        ));
        if !entry.0.contains(&row.sub_protocol) {
            entry.0.push(row.sub_protocol);
        }
        // Add source port if present and not already in list
        if let Some(src_port) = row.src_port
            && !entry.3.contains(&src_port)
        {
            entry.3.push(src_port);
        }
        // Add destination port if present and not already in list
        if let Some(dst_port) = row.dst_port
            && !entry.4.contains(&dst_port)
        {
            entry.4.push(dst_port);
        }
    }

    // Convert to nodes with aggregated protocols and ports
    comm_map
        .into_iter()
        .map(
            |((src, dst), (protocols, src_ip, dst_ip, src_ports, dst_ports))| {
                let src_type = EndPoint::classify_endpoint(src_ip, Some(src.clone()));
                let dst_type = EndPoint::classify_endpoint(dst_ip, Some(dst.clone()));

                // Join protocols with comma for display, but keep them separate for filtering
                let sub_protocol = protocols.join(",");

                // Join all ports with comma for filtering (convert Vec<u16> to comma-separated string)
                let src_port = if src_ports.is_empty() {
                    None
                } else {
                    Some(
                        src_ports
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                };
                let dst_port = if dst_ports.is_empty() {
                    None
                } else {
                    Some(
                        dst_ports
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                };

                // Try to resolve IP-like hostnames from mDNS cache
                let src_resolved = resolve_from_mdns_cache(&src).unwrap_or(src);
                let dst_resolved = resolve_from_mdns_cache(&dst).unwrap_or(dst);

                Node {
                    src_hostname: src_resolved,
                    dst_hostname: dst_resolved,
                    sub_protocol,
                    src_type,
                    dst_type,
                    src_port,
                    dst_port,
                }
            },
        )
        .collect()
}

fn get_endpoints(communications: &[Node]) -> Vec<String> {
    communications.iter().fold(vec![], |mut acc, comm| {
        if !acc.contains(&comm.src_hostname) {
            acc.push(comm.src_hostname.clone());
        }
        if !acc.contains(&comm.dst_hostname) {
            acc.push(comm.dst_hostname.clone());
        }
        acc
    })
}

fn get_endpoint_types(communications: &[Node]) -> std::collections::HashMap<String, &'static str> {
    let mut types = std::collections::HashMap::new();
    for comm in communications {
        if let Some(src_type) = comm.src_type {
            types.entry(comm.src_hostname.clone()).or_insert(src_type);
        }
        if let Some(dst_type) = comm.dst_type {
            types.entry(comm.dst_hostname.clone()).or_insert(dst_type);
        }
    }
    types
}

/// Check if another instance of this application is already running on any of the
/// candidate ports. Returns `Some((port, pid))` if a running instance is found.
fn detect_existing_instance(ports: &[u16]) -> Option<(u16, u32)> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .ok()?;

    for &port in ports {
        if let Ok(resp) = client
            .get(format!("http://127.0.0.1:{}/api/instance", port))
            .send()
            && let Ok(json) = resp.json::<serde_json::Value>()
            && json.get("app").and_then(|v| v.as_str()) == Some("awareness")
        {
            let pid = json.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            return Some((port, pid));
        }
    }
    None
}

pub fn start(preferred_port: u16) {
    task::spawn_blocking(move || {
        println!("Starting web server");

        // Check if another instance is already running
        let check_ports = [preferred_port, 8081, 8082, 8083, 8084];
        if let Some((port, pid)) = detect_existing_instance(&check_ports) {
            eprintln!(
                "Another instance is already running on http://127.0.0.1:{} (PID {})",
                port, pid
            );
            eprintln!("Stop the existing instance before starting a new one.");
            std::process::exit(1);
        }

        let sys = actix_rt::System::new();

        // Load templates from embedded files
        let mut tera = Tera::default();
        for file in Templates::iter() {
            let file_name = file.as_ref();
            if let Some(content) = Templates::get(file_name) {
                let template_str = std::str::from_utf8(content.data.as_ref())
                    .expect("Template file is not valid UTF-8");
                if let Err(e) = tera.add_raw_template(file_name, template_str) {
                    eprintln!("Failed to load template {}: {}", file_name, e);
                    eprintln!("Web server will not start");
                    return;
                }
            }
        }

        sys.block_on(async {
            // Try to bind to the preferred port, then fallback ports
            let fallback_ports = [preferred_port, 8081, 8082, 8083, 8084];
            let mut bound_port = None;
            let mut last_error = None;

            for port in fallback_ports {
                let tera_clone = tera.clone();
                match HttpServer::new(move || {
                    App::new()
                        .app_data(Data::new(tera_clone.clone()))
                        .service(static_files)
                        .service(index)
                        .service(set_endpoint_type)
                        .service(rename_endpoint)
                        .service(set_endpoint_model)
                        .service(set_endpoint_vendor)
                        .service(probe_endpoint)
                        .service(delete_endpoint)
                        .service(merge_endpoints)
                        .service(probe_endpoint_model)
                        .service(get_dns_entries_api)
                        .service(get_internet_destinations)
                        .service(probe_hostname)
                        .service(probe_netbios)
                        .service(ping_endpoint)
                        .service(port_scan_endpoint)
                        .service(get_endpoint_details)
                        .service(get_protocol_endpoints)
                        .service(get_all_protocols_api)
                        .service(get_device_capabilities)
                        .service(send_device_command)
                        .service(launch_device_app)
                        .service(pair_device)
                        .service(setup_thinq)
                        .service(get_thinq_status)
                        .service(list_thinq_devices)
                        .service(disconnect_thinq)
                        .service(start_scan)
                        .service(stop_scan)
                        .service(get_scan_status)
                        .service(get_scan_capabilities)
                        .service(get_scan_config)
                        .service(set_scan_config)
                        .service(get_endpoints_table)
                        .service(export_endpoints_xlsx)
                        .service(get_settings)
                        .service(update_setting)
                        .service(get_capture_status)
                        .service(toggle_capture_pause)
                        .service(set_capture_pause)
                        .service(upload_pcap)
                        .service(get_notifications)
                        .service(dismiss_notifications)
                        .service(clear_notifications)
                        .service(get_instance)
                })
                .bind(("127.0.0.1", port))
                {
                    Ok(server) => {
                        if port != preferred_port {
                            println!(
                                "Port {} was already in use, using port {} instead",
                                preferred_port, port
                            );
                        }
                        println!("Web server listening on http://127.0.0.1:{}", port);

                        // Start initial network scan on startup with ALL scan types
                        tokio::spawn(async {
                            // Small delay to let the server fully initialize
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            let manager = get_scan_manager();
                            // Use all scan types for the initial scan to get comprehensive discovery
                            let scan_types = vec![
                                ScanType::Arp,
                                ScanType::Icmp,
                                ScanType::Ndp,
                                ScanType::Ssdp,
                                ScanType::NetBios,
                                ScanType::Port,
                            ];
                            println!("Starting initial network scan (all types)...");
                            if let Err(e) = manager.start_scan(scan_types).await {
                                eprintln!("Failed to start initial scan: {}", e);
                            }
                        });

                        if let Err(e) = server.run().await {
                            eprintln!("Web server error: {}", e);
                        }
                        bound_port = Some(port);
                        break;
                    }
                    Err(e) => {
                        last_error = Some((port, e));
                    }
                }
            }

            if bound_port.is_none()
                && let Some((port, e)) = last_error
            {
                eprintln!("Failed to bind web server to any port.");
                eprintln!("Tried ports: {:?}", fallback_ports);
                eprintln!("Last error on port {}: {}", port, e);
                eprintln!();
                eprintln!("Possible solutions:");
                eprintln!("  1. Stop any other processes using these ports");
                eprintln!("  2. Set a different port using the WEB_PORT environment variable");
                eprintln!("     Example: WEB_PORT=9000 ./awareness");
            }
        })
    });
}

#[get("/static/{filename:.*}")]
async fn static_files(path: actix_web::web::Path<String>) -> impl Responder {
    let filename = path.into_inner();
    match StaticAssets::get(&filename) {
        Some(content) => {
            let mime_type = mime_guess::from_path(&filename)
                .first_or_octet_stream()
                .to_string();
            HttpResponse::Ok()
                .content_type(mime_type)
                .body(content.data.into_owned())
        }
        None => HttpResponse::NotFound().body("File not found"),
    }
}

// Define a handler function for the web request
#[get("/")]
async fn index(tera: Data<Tera>, query: Query<NodeQuery>) -> impl Responder {
    let hostname = strip_local_suffix(&get_hostname().unwrap_or_else(|_| "Unknown".to_string()));
    let scan_interval = query.scan_interval.unwrap_or(525600);

    // Resolve ip=/mac= query params to an effective node name
    let effective_node: Option<String> = if query.node.is_some() {
        query.node.clone()
    } else if let Some(ref ip) = query.ip {
        let ip_clone = ip.clone();
        let resolved = task::spawn_blocking(move || {
            let conn = new_connection_result().ok()?;
            resolve_identifier_to_display_name(&conn, &ip_clone)
        })
        .await
        .ok()
        .flatten();
        Some(resolved.unwrap_or_else(|| ip.clone()))
    } else if let Some(ref mac) = query.mac {
        let mac_clone = mac.clone();
        let resolved = task::spawn_blocking(move || {
            let conn = new_connection_result().ok()?;
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
    let interfaces_future = tokio::task::spawn_blocking(get_interfaces);

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
                    .map(|(cm, sm, sf, cv, sv, snm)| {
                        (
                            cm.as_deref(),
                            sm.as_deref(),
                            sf.as_deref(),
                            cv.as_deref(),
                            sv.as_deref(),
                            snm.as_deref(),
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
                .map(|(cm, sm, sf, cv, sv, snm)| {
                    (
                        cm.as_deref(),
                        sm.as_deref(),
                        sf.as_deref(),
                        cv.as_deref(),
                        sv.as_deref(),
                        snm.as_deref(),
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
        .map(|(_, sm, sf, cv, sv, snm)| {
            (
                cv.as_deref(),
                sf.as_deref(),
                sv.as_deref(),
                sm.as_deref(),
                snm.as_deref(),
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
        .and_then(|(custom_model_opt, _, _, _, _, _)| custom_model_opt.clone())
        .or_else(|| {
            // Try SSDP model with normalization
            models_data
                .and_then(|(_, ssdp_model_opt, _, _, _, _)| ssdp_model_opt.as_ref())
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
                .is_some_and(|(_, ssdp, friendly, _, _, _)| ssdp.is_some() || friendly.is_some());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looks_like_ip_ipv4() {
        assert!(looks_like_ip("192.168.1.1"));
        assert!(looks_like_ip("10.0.0.1"));
        assert!(looks_like_ip("255.255.255.255"));
        assert!(looks_like_ip("0.0.0.0"));
    }

    #[test]
    fn test_looks_like_ip_ipv6() {
        assert!(looks_like_ip("::1"));
        assert!(looks_like_ip("fe80::1"));
        assert!(looks_like_ip("2001:db8::1"));
        assert!(looks_like_ip("::ffff:192.168.1.1"));
    }

    #[test]
    fn test_looks_like_ip_hostnames() {
        assert!(!looks_like_ip("my-macbook.local"));
        assert!(!looks_like_ip("router"));
        assert!(!looks_like_ip("nintendo-switch"));
        assert!(!looks_like_ip("LG-Dishwasher"));
        assert!(!looks_like_ip("host.domain.com"));
    }

    #[test]
    fn test_looks_like_ip_edge_cases() {
        // Not quite an IP - wrong number of octets
        assert!(!looks_like_ip("192.168.1"));
        assert!(!looks_like_ip("192.168.1.1.1"));
        // Contains numbers but is a hostname
        assert!(!looks_like_ip("host123"));
        assert!(!looks_like_ip("192host"));
    }

    #[test]
    fn test_case_insensitive_hashmap_pattern() {
        // This tests the pattern used throughout the codebase for case-insensitive lookups
        let mut map: HashMap<String, String> = HashMap::new();

        // Insert with lowercase key
        map.insert("my-macbook.local".to_lowercase(), "value1".to_string());
        map.insert("nintendo-switch".to_lowercase(), "value2".to_string());

        // Lookup should work regardless of case
        assert_eq!(
            map.get(&"My-MacBook.local".to_lowercase()),
            Some(&"value1".to_string())
        );
        assert_eq!(
            map.get(&"MY-MACBOOK.LOCAL".to_lowercase()),
            Some(&"value1".to_string())
        );
        assert_eq!(
            map.get(&"Nintendo-Switch".to_lowercase()),
            Some(&"value2".to_string())
        );
        assert_eq!(
            map.get(&"NINTENDO-SWITCH".to_lowercase()),
            Some(&"value2".to_string())
        );
    }

    #[test]
    fn test_case_insensitive_hashset_contains() {
        // Test HashSet pattern used for endpoint lookups
        let endpoints = vec![
            "My-MacBook.local".to_string(),
            "Nintendo-Switch".to_string(),
            "LG-Dishwasher".to_string(),
        ];

        let endpoints_lower: HashSet<String> = endpoints.iter().map(|e| e.to_lowercase()).collect();

        // All case variations should be found
        assert!(endpoints_lower.contains(&"my-macbook.local".to_string()));
        assert!(endpoints_lower.contains(&"MY-MACBOOK.LOCAL".to_lowercase()));
        assert!(endpoints_lower.contains(&"nintendo-switch".to_string()));
        assert!(endpoints_lower.contains(&"NINTENDO-SWITCH".to_lowercase()));
    }

    #[test]
    fn test_build_in_placeholders() {
        assert_eq!(build_in_placeholders(0), "");
        assert_eq!(build_in_placeholders(1), "?");
        assert_eq!(build_in_placeholders(3), "?,?,?");
        assert_eq!(build_in_placeholders(5), "?,?,?,?,?");
    }

    #[test]
    fn test_display_name_sql_constant_format() {
        // Verify the DISPLAY_NAME_SQL constant has expected structure
        assert!(DISPLAY_NAME_SQL.contains("COALESCE"));
        assert!(DISPLAY_NAME_SQL.contains("e.custom_name"));
        assert!(DISPLAY_NAME_SQL.contains("e.name"));
        assert!(DISPLAY_NAME_SQL.contains("MIN(hostname)"));
        assert!(DISPLAY_NAME_SQL.contains("MIN(ip)"));
        // Verify it filters out IP-like values
        assert!(DISPLAY_NAME_SQL.contains("NOT LIKE '%:%'")); // IPv6 filter
        assert!(DISPLAY_NAME_SQL.contains("NOT GLOB")); // IPv4 filter
    }
}
