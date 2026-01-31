//! API handlers for the `/api/*` HTTP endpoints.
//! Extracted from `mod.rs` to reduce file size and improve maintainability.

use actix_multipart::Multipart;
use actix_web::web::{Json, Query};
use actix_web::{HttpResponse, Responder, get, post};
use futures_util::StreamExt;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use tokio::sync::mpsc;

use crate::db::{
    SQLWriter, get_all_settings, get_setting_i64, insert_notification,
    insert_notification_with_endpoint_id, new_connection, new_connection_result, set_setting,
};
use crate::network::communication::extract_model_from_vendor_class;
use crate::network::device_control::DeviceController;
use crate::network::endpoint::{
    EndPoint, characterize_model, characterize_vendor, get_hostname_vendor, get_mac_vendor,
    get_model_from_hostname, get_model_from_mac, get_model_from_vendor_and_type,
    get_vendor_from_model, infer_model_with_context, normalize_model_name,
    strip_local_suffix,
};
use crate::scanner::manager::{ScanConfig, ScanManager};
use crate::scanner::{ScanResult, ScanType, check_scan_privileges};

use rust_xlsxwriter::{Format, Workbook};

// Shared items from parent (mod.rs)
use super::{
    EndpointDetailsResponse, NodeQuery,
    DISPLAY_NAME_SQL, dropdown_endpoints,
    get_all_endpoint_types, get_all_endpoints_last_seen,
    get_all_endpoints_online_status, get_all_ips_macs_and_hostnames_from_single_hostname,
    get_bytes_for_endpoint, get_combined_endpoint_stats, get_dns_entries,
    get_endpoint_ips_and_macs, get_endpoint_ssdp_models,
    get_endpoints_for_protocol, get_all_protocols,
    get_ports_for_endpoint, get_protocols_for_endpoint,
    looks_like_ip,
    probe_and_save_hp_printer_model_blocking, probe_hp_printer_model_blocking,
};

// ============================================================================
// Global State
// ============================================================================

// Track endpoints currently being probed to prevent duplicate probes
static PROBING_ENDPOINTS: OnceLock<Mutex<HashSet<i64>>> = OnceLock::new();

fn get_probing_endpoints() -> &'static Mutex<HashSet<i64>> {
    PROBING_ENDPOINTS.get_or_init(|| Mutex::new(HashSet::new()))
}

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

/// Global scan manager instance
static SCAN_MANAGER: OnceLock<std::sync::Arc<ScanManager>> = OnceLock::new();

pub fn get_scan_manager() -> std::sync::Arc<ScanManager> {
    SCAN_MANAGER
        .get_or_init(|| {
            let (tx, mut rx) = mpsc::channel::<ScanResult>(1000);

            // Spawn a task to process scan results
            tokio::spawn(async move {
                while let Some(result) = rx.recv().await {
                    // Process scan result - create/update endpoint in database
                    if let Err(e) = process_scan_result(&result) {
                        eprintln!("Error processing scan result: {}", e);
                    }
                }
            });

            std::sync::Arc::new(ScanManager::new(tx))
        })
        .clone()
}

// ============================================================================
// DNS API Endpoints
// ============================================================================

#[get("/api/dns-entries")]
pub async fn get_dns_entries_api() -> impl Responder {
    HttpResponse::Ok().json(get_dns_entries())
}

#[derive(serde::Serialize)]
pub struct InternetDestinationsResponse {
    destinations: Vec<crate::network::endpoint::InternetDestination>,
}

/// Get all internet destinations
#[get("/api/internet")]
pub async fn get_internet_destinations() -> impl Responder {
    let result = tokio::task::spawn_blocking(|| {
        let conn = new_connection();
        crate::network::endpoint::EndPoint::get_internet_destinations(&conn)
    })
    .await;

    match result {
        Ok(Ok(destinations)) => {
            HttpResponse::Ok().json(InternetDestinationsResponse { destinations })
        }
        Ok(Err(e)) => {
            eprintln!("Failed to get internet destinations: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch internet destinations"
            }))
        }
        Err(e) => {
            eprintln!("Task error getting internet destinations: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal error"
            }))
        }
    }
}

// ============================================================================
// Probe API Endpoints
// ============================================================================

#[derive(serde::Deserialize)]
pub struct ProbeRequest {
    ip: String,
}

#[derive(serde::Serialize)]
pub struct ProbeResponse {
    ip: String,
    hostname: Option<String>,
    success: bool,
}

/// Probe a device for its hostname using reverse DNS/mDNS lookup
/// Also persists the hostname to the database if found
#[post("/api/probe-hostname")]
pub async fn probe_hostname(body: Json<ProbeRequest>) -> impl Responder {
    use crate::network::mdns_lookup::MDnsLookup;

    let hostname = MDnsLookup::probe_hostname(&body.ip);

    // If we found a real hostname (not just the IP back), save it to the database
    if let Some(ref h) = hostname
        && !looks_like_ip(h)
    {
        let ip_clone = body.ip.clone();
        let hostname_clone = h.clone();
        // Spawn a blocking task to update the database
        tokio::task::spawn_blocking(move || {
            if let Ok(conn) = new_connection_result() {
                // Update hostname in endpoint_attributes where ip matches
                let _ = conn.execute(
                    "UPDATE endpoint_attributes SET hostname = ?1 WHERE ip = ?2 AND (hostname IS NULL OR hostname = ?2 OR hostname LIKE '%:%' OR hostname GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*')",
                    rusqlite::params![hostname_clone, ip_clone],
                );
            }
        });
    }

    HttpResponse::Ok().json(ProbeResponse {
        ip: body.ip.clone(),
        hostname: hostname.clone(),
        success: hostname.is_some(),
    })
}

#[derive(Serialize)]
pub struct NetBiosProbeResponse {
    ip: String,
    netbios_name: Option<String>,
    group_name: Option<String>,
    mac: Option<String>,
    success: bool,
}

/// Probe a device for its NetBIOS name
#[post("/api/probe-netbios")]
pub async fn probe_netbios(body: Json<ProbeRequest>) -> impl Responder {
    use crate::scanner::netbios::NetBiosScanner;
    use std::net::Ipv4Addr;

    let ip_str = body.ip.clone();

    // Parse IP address
    let ip: Ipv4Addr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return HttpResponse::BadRequest().json(NetBiosProbeResponse {
                ip: ip_str,
                netbios_name: None,
                group_name: None,
                mac: None,
                success: false,
            });
        }
    };

    // Run the NetBIOS query in a blocking task
    let result = tokio::task::spawn_blocking(move || {
        let scanner = NetBiosScanner::new().with_timeout(2000);
        scanner.query_ip(ip)
    })
    .await;

    match result {
        Ok(Some(netbios)) => {
            // Save NetBIOS name to endpoint if found
            let netbios_name = netbios.netbios_name.clone();
            let ip_for_db = ip_str.clone();
            tokio::task::spawn_blocking(move || {
                if let Ok(conn) = new_connection_result() {
                    // Find endpoint by IP and update netbios_name
                    let _ = conn.execute(
                        "UPDATE endpoints SET netbios_name = ?1 WHERE id IN (SELECT endpoint_id FROM endpoint_attributes WHERE ip = ?2) AND (netbios_name IS NULL OR netbios_name = '')",
                        rusqlite::params![netbios_name, ip_for_db],
                    );
                    // Also update endpoint name if it's currently just an IP address
                    let _ = conn.execute(
                        "UPDATE endpoints SET name = ?1 WHERE id IN (SELECT endpoint_id FROM endpoint_attributes WHERE ip = ?2) AND (name = ?2 OR name GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*')",
                        rusqlite::params![netbios_name, ip_for_db],
                    );
                }
            });

            HttpResponse::Ok().json(NetBiosProbeResponse {
                ip: ip_str,
                netbios_name: Some(netbios.netbios_name),
                group_name: netbios.group_name,
                mac: netbios.mac,
                success: true,
            })
        }
        _ => HttpResponse::Ok().json(NetBiosProbeResponse {
            ip: ip_str,
            netbios_name: None,
            group_name: None,
            mac: None,
            success: false,
        }),
    }
}

#[derive(Deserialize)]
pub struct PingRequest {
    ip: String,
}

#[derive(Serialize)]
pub struct PingResponse {
    success: bool,
    latency_ms: Option<f64>,
    message: Option<String>,
}

/// Ping a device using ICMP echo
#[post("/api/ping")]
pub async fn ping_endpoint(body: Json<PingRequest>) -> impl Responder {
    use std::net::IpAddr;
    use std::process::Command;
    use std::time::Instant;

    let ip = body.ip.clone();

    // Validate IP address
    if ip.parse::<IpAddr>().is_err() {
        return HttpResponse::BadRequest().json(PingResponse {
            success: false,
            latency_ms: None,
            message: Some("Invalid IP address".to_string()),
        });
    }

    // Use system ping command (works without root on most systems)
    // macOS uses -t for timeout, Linux uses -W
    let start = Instant::now();
    #[cfg(target_os = "macos")]
    let output = Command::new("ping")
        .args(["-c", "1", "-t", "2", &ip])
        .output();
    #[cfg(not(target_os = "macos"))]
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "2", &ip])
        .output();

    match output {
        Ok(result) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            if result.status.success() {
                // Try to parse actual latency from ping output
                let stdout = String::from_utf8_lossy(&result.stdout);
                let latency = parse_ping_latency(&stdout).unwrap_or(elapsed);
                HttpResponse::Ok().json(PingResponse {
                    success: true,
                    latency_ms: Some(latency),
                    message: None,
                })
            } else {
                HttpResponse::Ok().json(PingResponse {
                    success: false,
                    latency_ms: None,
                    message: Some("Host unreachable".to_string()),
                })
            }
        }
        Err(e) => HttpResponse::Ok().json(PingResponse {
            success: false,
            latency_ms: None,
            message: Some(format!("Ping failed: {}", e)),
        }),
    }
}

/// Parse latency from ping output (e.g., "time=1.23 ms")
fn parse_ping_latency(output: &str) -> Option<f64> {
    for line in output.lines() {
        if let Some(time_idx) = line.find("time=") {
            let after_time = &line[time_idx + 5..];
            if let Some(latency) = after_time
                .find(" ms")
                .and_then(|idx| after_time[..idx].parse::<f64>().ok())
            {
                return Some(latency);
            }
            // Also try without space (time=1.23ms)
            if let Some(latency) = after_time
                .find("ms")
                .and_then(|idx| after_time[..idx].parse::<f64>().ok())
            {
                return Some(latency);
            }
        }
    }
    None
}

#[derive(Deserialize)]
pub struct PortScanRequest {
    ip: String,
}

#[derive(Serialize)]
pub struct OpenPort {
    port: u16,
    service: Option<String>,
}

#[derive(Serialize)]
pub struct PortScanResponse {
    success: bool,
    open_ports: Vec<OpenPort>,
    message: Option<String>,
}

/// Scan common ports on a device
#[post("/api/port-scan")]
pub async fn port_scan_endpoint(body: Json<PortScanRequest>) -> impl Responder {
    use std::net::{IpAddr, SocketAddr, TcpStream};
    use std::time::Duration;

    let ip = body.ip.clone();

    // Validate IP address
    let ip_addr: IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => {
            return HttpResponse::BadRequest().json(PortScanResponse {
                success: false,
                open_ports: vec![],
                message: Some("Invalid IP address".to_string()),
            });
        }
    };

    // Common ports to scan
    let ports_to_scan: Vec<(u16, &str)> = vec![
        (21, "FTP"),
        (22, "SSH"),
        (23, "Telnet"),
        (25, "SMTP"),
        (53, "DNS"),
        (80, "HTTP"),
        (110, "POP3"),
        (143, "IMAP"),
        (443, "HTTPS"),
        (445, "SMB"),
        (993, "IMAPS"),
        (995, "POP3S"),
        (3389, "RDP"),
        (5000, "UPnP"),
        (5900, "VNC"),
        (8080, "HTTP-Alt"),
        (8443, "HTTPS-Alt"),
        (8888, "HTTP-Alt"),
        (9000, "HTTP-Alt"),
    ];

    // Scan ports concurrently
    let ip_for_scan = ip_addr;
    let open_ports = tokio::task::spawn_blocking(move || {
        let mut open = Vec::new();
        let timeout = Duration::from_millis(500);

        for (port, service) in ports_to_scan {
            let addr = SocketAddr::new(ip_for_scan, port);
            if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                open.push(OpenPort {
                    port,
                    service: Some(service.to_string()),
                });
            }
        }
        open
    })
    .await
    .unwrap_or_default();

    HttpResponse::Ok().json(PortScanResponse {
        success: true,
        open_ports,
        message: None,
    })
}

// ============================================================================
// Endpoint Details API
// ============================================================================

#[get("/api/endpoint/{name}/details")]
pub async fn get_endpoint_details(
    path: actix_web::web::Path<String>,
    query: actix_web::web::Query<NodeQuery>,
) -> impl Responder {
    let endpoint_name = path.into_inner();
    let internal_minutes = query.scan_interval.unwrap_or(525600);

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
    let conn = new_connection();
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

    // Get SSDP model for this endpoint (for device classification)
    let ssdp_model: Option<String> = conn
        .query_row(
            &format!(
                "SELECT e.ssdp_model FROM endpoints e WHERE {} = ?1 COLLATE NOCASE AND e.ssdp_model IS NOT NULL",
                DISPLAY_NAME_SQL
            ),
            [&endpoint_name],
            |row| row.get(0),
        )
        .ok();

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

    // Component vendors - these make chips/modules used by other manufacturers
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

    // Get SSDP model early so we can use it for vendor detection
    let ssdp_model_for_vendor: Option<String> = conn
        .query_row(
            "SELECT e.ssdp_model FROM endpoints e
             WHERE (LOWER(e.name) = LOWER(?1) OR LOWER(e.custom_name) = LOWER(?1))
             AND e.ssdp_model IS NOT NULL AND e.ssdp_model != ''
             LIMIT 1",
            rusqlite::params![&endpoint_name],
            |row| row.get(0),
        )
        .ok();

    // Try to detect vendor from model (e.g., "7105X" -> TCL)
    let model_vendor = ssdp_model_for_vendor
        .as_ref()
        .and_then(|m| get_vendor_from_model(m));

    // Get DHCP vendor class for this endpoint (if available)
    let dhcp_vendor_class: Option<String> = conn
        .query_row(
            "SELECT ea.dhcp_vendor_class
         FROM endpoints e
         INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
         WHERE (LOWER(e.name) = LOWER(?1) OR LOWER(e.custom_name) = LOWER(?1))
         AND ea.dhcp_vendor_class IS NOT NULL AND ea.dhcp_vendor_class != ''
         LIMIT 1",
            rusqlite::params![&endpoint_name],
            |row| row.get(0),
        )
        .ok();

    // Get custom_model, SSDP model, and custom_vendor for this endpoint
    let (custom_model, ssdp_model, custom_vendor): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT e.custom_model, e.ssdp_model, e.custom_vendor
         FROM endpoints e
         WHERE (LOWER(e.name) = LOWER(?1) OR LOWER(e.custom_name) = LOWER(?1))
         LIMIT 1",
            rusqlite::params![&endpoint_name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or((None, None, None));

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

// ============================================================================
// Protocol API Endpoints
// ============================================================================

#[derive(Serialize)]
pub struct ProtocolEndpointsResponse {
    protocol: String,
    endpoints: Vec<String>,
}

#[derive(Deserialize)]
pub struct ProtocolQuery {
    scan_interval: Option<u64>,
    from_endpoint: Option<String>,
}

#[get("/api/protocol/{protocol}/endpoints")]
pub async fn get_protocol_endpoints(
    path: actix_web::web::Path<String>,
    query: actix_web::web::Query<ProtocolQuery>,
) -> impl Responder {
    let protocol = path.into_inner();
    let internal_minutes = query.scan_interval.unwrap_or(525600);

    let endpoints =
        get_endpoints_for_protocol(&protocol, internal_minutes, query.from_endpoint.as_deref());

    HttpResponse::Ok().json(ProtocolEndpointsResponse {
        protocol,
        endpoints,
    })
}

#[derive(Serialize)]
pub struct AllProtocolsResponse {
    protocols: Vec<String>,
}

#[get("/api/protocols")]
pub async fn get_all_protocols_api(query: actix_web::web::Query<NodeQuery>) -> impl Responder {
    let internal_minutes = query.scan_interval.unwrap_or(525600);
    let protocols = get_all_protocols(internal_minutes);
    HttpResponse::Ok().json(AllProtocolsResponse { protocols })
}

// ============================================================================
// Endpoint Management API Endpoints
// ============================================================================

#[derive(Deserialize)]
pub struct ClassifyRequest {
    endpoint_name: String,
    device_type: Option<String>,
}

#[derive(Serialize)]
pub struct ClassifyResponse {
    success: bool,
    message: String,
}

#[post("/api/endpoint/classify")]
pub async fn set_endpoint_type(body: Json<ClassifyRequest>) -> impl Responder {
    let conn = new_connection();

    // If device_type is "auto" or empty, clear the manual override
    let device_type = match &body.device_type {
        Some(t) if t == "auto" || t.is_empty() => None,
        Some(t) => Some(t.as_str()),
        None => None,
    };

    match EndPoint::set_manual_device_type(&conn, &body.endpoint_name, device_type) {
        Ok(rows_updated) => {
            if rows_updated > 0 {
                insert_notification(
                    &conn,
                    "endpoint_reclassified",
                    &format!(
                        "Endpoint '{}' type {}",
                        body.endpoint_name,
                        device_type
                            .map(|t| format!("set to '{}'", t))
                            .unwrap_or_else(|| "cleared".to_string()),
                    ),
                    None,
                    Some(&body.endpoint_name),
                );

                HttpResponse::Ok().json(ClassifyResponse {
                    success: true,
                    message: format!(
                        "Device type {} for {}",
                        device_type
                            .map(|t| format!("set to '{}'", t))
                            .unwrap_or_else(|| "cleared".to_string()),
                        body.endpoint_name
                    ),
                })
            } else {
                HttpResponse::NotFound().json(ClassifyResponse {
                    success: false,
                    message: format!("Endpoint '{}' not found", body.endpoint_name),
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(ClassifyResponse {
            success: false,
            message: format!("Database error: {}", e),
        }),
    }
}

#[derive(Deserialize)]
pub struct RenameRequest {
    endpoint_name: String,
    custom_name: Option<String>,
}

#[derive(Serialize)]
pub struct RenameResponse {
    success: bool,
    message: String,
    original_name: Option<String>,
}

#[post("/api/endpoint/rename")]
pub async fn rename_endpoint(body: Json<RenameRequest>) -> impl Responder {
    let conn = new_connection();

    // If custom_name is empty string, treat as None (clear the custom name)
    let custom_name = match &body.custom_name {
        Some(n) if n.is_empty() => None,
        Some(n) => Some(n.as_str()),
        None => None,
    };

    // When clearing the custom name, get the original name first so the UI can redirect
    let original_name = if custom_name.is_none() {
        EndPoint::get_original_name(&conn, &body.endpoint_name)
    } else {
        None
    };

    match EndPoint::set_custom_name(&conn, &body.endpoint_name, custom_name) {
        Ok(rows_updated) => {
            if rows_updated > 0 {
                insert_notification(
                    &conn,
                    "endpoint_renamed",
                    &format!(
                        "Endpoint '{}' renamed to '{}'",
                        body.endpoint_name,
                        custom_name.unwrap_or("(original)")
                    ),
                    None,
                    Some(&body.endpoint_name),
                );

                HttpResponse::Ok().json(RenameResponse {
                    success: true,
                    message: format!(
                        "Custom name {} for {}",
                        custom_name
                            .map(|n| format!("set to '{}'", n))
                            .unwrap_or_else(|| "cleared".to_string()),
                        body.endpoint_name
                    ),
                    original_name,
                })
            } else {
                HttpResponse::NotFound().json(RenameResponse {
                    success: false,
                    message: format!("Endpoint '{}' not found", body.endpoint_name),
                    original_name: None,
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(RenameResponse {
            success: false,
            message: format!("Database error: {}", e),
            original_name: None,
        }),
    }
}

#[derive(Deserialize)]
pub struct SetModelRequest {
    endpoint_name: String,
    model: Option<String>,
}

#[derive(Serialize)]
pub struct SetModelResponse {
    success: bool,
    message: String,
}

#[post("/api/endpoint/model")]
pub async fn set_endpoint_model(body: Json<SetModelRequest>) -> impl Responder {
    let conn = new_connection();

    // If model is "auto" or empty, clear the custom model
    let model = match &body.model {
        Some(m) if m == "auto" || m.is_empty() => None,
        Some(m) => Some(m.as_str()),
        None => None,
    };

    match EndPoint::set_custom_model(&conn, &body.endpoint_name, model) {
        Ok(rows_updated) => {
            if rows_updated > 0 {
                let (event, title) = if let Some(m) = model {
                    ("model_changed", format!("Model set to '{}' for {}", m, body.endpoint_name))
                } else {
                    ("model_changed", format!("Model cleared for {}", body.endpoint_name))
                };
                insert_notification(
                    &conn, event, &title, None, Some(&body.endpoint_name),
                );
                HttpResponse::Ok().json(SetModelResponse {
                    success: true,
                    message: format!(
                        "Model {} for {}",
                        model
                            .map(|m| format!("set to '{}'", m))
                            .unwrap_or_else(|| "cleared".to_string()),
                        body.endpoint_name
                    ),
                })
            } else {
                HttpResponse::NotFound().json(SetModelResponse {
                    success: false,
                    message: format!("Endpoint '{}' not found", body.endpoint_name),
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(SetModelResponse {
            success: false,
            message: format!("Database error: {}", e),
        }),
    }
}

#[derive(Deserialize)]
pub struct SetVendorRequest {
    endpoint_name: String,
    vendor: Option<String>,
}

#[derive(Serialize)]
pub struct SetVendorResponse {
    success: bool,
    message: String,
}

#[post("/api/endpoint/vendor")]
pub async fn set_endpoint_vendor(body: Json<SetVendorRequest>) -> impl Responder {
    let conn = new_connection();

    // If vendor is "auto" or empty, clear the custom vendor
    let vendor = match &body.vendor {
        Some(v) if v == "auto" || v.is_empty() => None,
        Some(v) => Some(v.as_str()),
        None => None,
    };

    match EndPoint::set_custom_vendor(&conn, &body.endpoint_name, vendor) {
        Ok(rows_updated) => {
            if rows_updated > 0 {
                let (event, title) = if let Some(v) = vendor {
                    ("vendor_changed", format!("Vendor set to '{}' for {}", v, body.endpoint_name))
                } else {
                    ("vendor_changed", format!("Vendor cleared for {}", body.endpoint_name))
                };
                insert_notification(
                    &conn, event, &title, None, Some(&body.endpoint_name),
                );
                HttpResponse::Ok().json(SetVendorResponse {
                    success: true,
                    message: format!(
                        "Vendor {} for {}",
                        vendor
                            .map(|v| format!("set to '{}'", v))
                            .unwrap_or_else(|| "cleared".to_string()),
                        body.endpoint_name
                    ),
                })
            } else {
                HttpResponse::NotFound().json(SetVendorResponse {
                    success: false,
                    message: format!("Endpoint '{}' not found", body.endpoint_name),
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(SetVendorResponse {
            success: false,
            message: format!("Database error: {}", e),
        }),
    }
}

#[derive(Deserialize)]
pub struct ProbeEndpointRequest {
    endpoint_name: String,
}

#[derive(Serialize)]
pub struct ProbeEndpointResponse {
    success: bool,
    message: String,
    snmp_info: Option<SnmpProbeInfo>,
    netbios_name: Option<String>,
}

#[derive(Serialize)]
pub struct SnmpProbeInfo {
    sys_descr: Option<String>,
    sys_name: Option<String>,
    sys_location: Option<String>,
}

/// Probe an endpoint for device information (SNMP, NetBIOS)
#[post("/api/endpoint/probe")]
pub async fn probe_endpoint(body: Json<ProbeEndpointRequest>) -> impl Responder {
    use crate::scanner::netbios::NetBiosScanner;
    use crate::scanner::snmp::SnmpScanner;

    let conn = new_connection();

    // Get IPs for this endpoint
    let ips: Vec<String> = conn
        .prepare(&format!(
            "SELECT DISTINCT ea.ip FROM endpoints e
             JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
             WHERE {} = ?1 COLLATE NOCASE
             AND ea.ip IS NOT NULL AND ea.ip != ''",
            DISPLAY_NAME_SQL
        ))
        .and_then(|mut stmt| {
            stmt.query_map([&body.endpoint_name], |row| row.get(0))
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();

    if ips.is_empty() {
        return HttpResponse::NotFound().json(ProbeEndpointResponse {
            success: false,
            message: format!("No IPs found for endpoint '{}'", body.endpoint_name),
            snmp_info: None,
            netbios_name: None,
        });
    }

    // Get endpoint ID for saving results
    let endpoint_id: Option<i64> = conn
        .query_row(
            &format!(
                "SELECT e.id FROM endpoints e WHERE {} = ?1 COLLATE NOCASE LIMIT 1",
                DISPLAY_NAME_SQL
            ),
            [&body.endpoint_name],
            |row| row.get(0),
        )
        .ok();

    let mut snmp_info = None;
    let mut netbios_name = None;

    // Probe each IP
    for ip_str in &ips {
        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
            // SNMP probe
            if snmp_info.is_none() {
                let snmp_scanner = SnmpScanner::new().with_timeout(3000);
                if let Some(result) = snmp_scanner.query_ip(ip) {
                    // Save to database
                    if let Some(eid) = endpoint_id {
                        let details = serde_json::json!({
                            "sys_descr": result.sys_descr,
                            "sys_object_id": result.sys_object_id,
                            "sys_name": result.sys_name,
                            "sys_location": result.sys_location,
                            "community": result.community,
                        });
                        let _ = insert_scan_result(
                            &conn,
                            eid,
                            "snmp",
                            None,
                            Some(&details.to_string()),
                        );

                        // Extract and save vendor/model from sysDescr
                        if let Some(ref sys_descr) = result.sys_descr {
                            let (vendor, model) = parse_snmp_sys_descr(sys_descr);
                            if let Some(v) = &vendor {
                                let rows = conn.execute(
                                    "UPDATE endpoints SET vendor = ?1 WHERE id = ?2 AND (vendor IS NULL OR vendor = '')",
                                    params![v, eid],
                                ).unwrap_or(0);
                                if rows > 0 {
                                    insert_notification_with_endpoint_id(
                                        &conn, "vendor_identified",
                                        &format!("Vendor identified: {}", v),
                                        None, None, Some(eid),
                                    );
                                }
                            }
                            if let Some(m) = &model {
                                let rows = conn.execute(
                                    "UPDATE endpoints SET ssdp_model = ?1 WHERE id = ?2 AND (ssdp_model IS NULL OR ssdp_model = '')",
                                    params![m, eid],
                                ).unwrap_or(0);
                                if rows > 0 {
                                    insert_notification_with_endpoint_id(
                                        &conn, "model_identified",
                                        &format!("Device model identified: {}", m),
                                        None, None, Some(eid),
                                    );
                                }
                            }
                        }

                        // Update endpoint name from sysName if current name is just an IP
                        if let Some(ref sys_name) = result.sys_name
                            && !sys_name.is_empty()
                        {
                            let _ = conn.execute(
                                "UPDATE endpoints SET name = ?1 WHERE id = ?2 AND (name = ?3 OR name GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*')",
                                params![sys_name, eid, ip_str],
                            );
                        }
                    }

                    snmp_info = Some(SnmpProbeInfo {
                        sys_descr: result.sys_descr,
                        sys_name: result.sys_name,
                        sys_location: result.sys_location,
                    });
                }
            }

            // NetBIOS probe
            if netbios_name.is_none() {
                let netbios_scanner = NetBiosScanner::new().with_timeout(2000);
                if let Some(result) = netbios_scanner.query_ip(ip) {
                    if let Some(eid) = endpoint_id {
                        // Save hostname
                        let _ = conn.execute(
                            "INSERT OR IGNORE INTO endpoint_attributes (endpoint_id, ip, hostname)
                             VALUES (?1, ?2, ?3)
                             ON CONFLICT(endpoint_id, ip, mac) DO UPDATE SET hostname = ?3
                             WHERE hostname IS NULL OR hostname = ''",
                            params![eid, ip_str, result.netbios_name],
                        );
                    }
                    netbios_name = Some(result.netbios_name);
                }
            }
        }
    }

    let found_something = snmp_info.is_some() || netbios_name.is_some();
    HttpResponse::Ok().json(ProbeEndpointResponse {
        success: found_something,
        message: if found_something {
            "Probe completed".to_string()
        } else {
            "No device info discovered".to_string()
        },
        snmp_info,
        netbios_name,
    })
}

#[derive(Deserialize)]
pub struct DeleteEndpointRequest {
    endpoint_name: String,
}

#[derive(Serialize)]
pub struct DeleteEndpointResponse {
    success: bool,
    message: String,
}

/// Delete an endpoint and all associated data (communications, attributes, scan results)
#[post("/api/endpoint/delete")]
pub async fn delete_endpoint(body: Json<DeleteEndpointRequest>) -> impl Responder {
    let conn = new_connection();

    // First, find the endpoint ID(s) matching the name
    let endpoint_ids: Vec<i64> = match conn.prepare(&format!(
        "SELECT DISTINCT e.id FROM endpoints e
         LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
         WHERE {} = ?1 COLLATE NOCASE
            OR LOWER(ea.hostname) = LOWER(?1)
            OR LOWER(ea.ip) = LOWER(?1)",
        DISPLAY_NAME_SQL
    )) {
        Ok(mut stmt) => match stmt.query_map([&body.endpoint_name], |row| row.get(0)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                eprintln!("Error querying for endpoint to delete: {}", e);
                return HttpResponse::InternalServerError().json(DeleteEndpointResponse {
                    success: false,
                    message: format!("Database query error: {}", e),
                });
            }
        },
        Err(e) => {
            eprintln!("Error preparing delete query: {}", e);
            return HttpResponse::InternalServerError().json(DeleteEndpointResponse {
                success: false,
                message: format!("Database error: {}", e),
            });
        }
    };

    if endpoint_ids.is_empty() {
        return HttpResponse::NotFound().json(DeleteEndpointResponse {
            success: false,
            message: format!("Endpoint '{}' not found", body.endpoint_name),
        });
    }

    // Delete in order to respect foreign key constraints
    let mut updated_comms = 0;
    let mut deleted_attrs = 0;
    let mut deleted_scans = 0;
    let mut deleted_endpoints = 0;

    for endpoint_id in &endpoint_ids {
        // Nullify this endpoint's ID in communications instead of deleting them
        // This preserves communication history for other endpoints
        updated_comms += conn
            .execute(
                "UPDATE communications SET src_endpoint_id = NULL WHERE src_endpoint_id = ?1",
                params![endpoint_id],
            )
            .unwrap_or(0);
        updated_comms += conn
            .execute(
                "UPDATE communications SET dst_endpoint_id = NULL WHERE dst_endpoint_id = ?1",
                params![endpoint_id],
            )
            .unwrap_or(0);

        // Delete scan results
        deleted_scans += conn
            .execute(
                "DELETE FROM scan_results WHERE endpoint_id = ?1",
                params![endpoint_id],
            )
            .unwrap_or(0);

        // Delete endpoint attributes
        deleted_attrs += conn
            .execute(
                "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
                params![endpoint_id],
            )
            .unwrap_or(0);

        // Delete open ports
        conn.execute(
            "DELETE FROM open_ports WHERE endpoint_id = ?1",
            params![endpoint_id],
        )
        .unwrap_or(0);

        // Delete scan results
        conn.execute(
            "DELETE FROM scan_results WHERE endpoint_id = ?1",
            params![endpoint_id],
        )
        .unwrap_or(0);

        // Delete the endpoint itself
        deleted_endpoints += conn
            .execute("DELETE FROM endpoints WHERE id = ?1", params![endpoint_id])
            .unwrap_or(0);
    }

    insert_notification(
        &conn,
        "endpoint_deleted",
        &format!("Endpoint '{}' deleted", body.endpoint_name),
        Some(&format!(
            "{} endpoint(s), {} attribute(s), {} scan result(s) removed",
            deleted_endpoints, deleted_attrs, deleted_scans
        )),
        Some(&body.endpoint_name),
    );

    HttpResponse::Ok().json(DeleteEndpointResponse {
        success: true,
        message: format!(
            "Deleted endpoint '{}': {} endpoint(s), {} attribute(s), {} scan result(s) (preserved {} communication records)",
            body.endpoint_name, deleted_endpoints, deleted_attrs, deleted_scans, updated_comms
        ),
    })
}

#[derive(Deserialize)]
pub struct MergeEndpointsRequest {
    /// The endpoint to keep (target) - can be name, custom_name, hostname, or IP
    target: String,
    /// The endpoint to merge and delete (source) - can be name, custom_name, hostname, or IP
    source: String,
}

#[derive(Serialize)]
pub struct MergeEndpointsResponse {
    success: bool,
    message: String,
}

/// Merge two endpoints into one, keeping the target and deleting the source
/// All communications, attributes, scan results, and ports from source are moved to target
#[post("/api/endpoint/merge")]
pub async fn merge_endpoints(body: Json<MergeEndpointsRequest>) -> impl Responder {
    let conn = new_connection();

    // Find the target endpoint ID
    let target_id: Option<i64> = match conn.prepare(&format!(
        "SELECT DISTINCT e.id FROM endpoints e
         LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
         WHERE {} = ?1 COLLATE NOCASE
            OR LOWER(ea.hostname) = LOWER(?1)
            OR LOWER(ea.ip) = LOWER(?1)
         LIMIT 1",
        DISPLAY_NAME_SQL
    )) {
        Ok(mut stmt) => stmt.query_row([&body.target], |row| row.get(0)).ok(),
        Err(e) => {
            eprintln!("Error preparing target query: {}", e);
            return HttpResponse::InternalServerError().json(MergeEndpointsResponse {
                success: false,
                message: format!("Database error: {}", e),
            });
        }
    };

    let target_id = match target_id {
        Some(id) => id,
        None => {
            return HttpResponse::NotFound().json(MergeEndpointsResponse {
                success: false,
                message: format!("Target endpoint '{}' not found", body.target),
            });
        }
    };

    // Find the source endpoint ID
    let source_id: Option<i64> = match conn.prepare(&format!(
        "SELECT DISTINCT e.id FROM endpoints e
         LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
         WHERE {} = ?1 COLLATE NOCASE
            OR LOWER(ea.hostname) = LOWER(?1)
            OR LOWER(ea.ip) = LOWER(?1)
         LIMIT 1",
        DISPLAY_NAME_SQL
    )) {
        Ok(mut stmt) => stmt.query_row([&body.source], |row| row.get(0)).ok(),
        Err(e) => {
            eprintln!("Error preparing source query: {}", e);
            return HttpResponse::InternalServerError().json(MergeEndpointsResponse {
                success: false,
                message: format!("Database error: {}", e),
            });
        }
    };

    let source_id = match source_id {
        Some(id) => id,
        None => {
            return HttpResponse::NotFound().json(MergeEndpointsResponse {
                success: false,
                message: format!("Source endpoint '{}' not found", body.source),
            });
        }
    };

    // Check they're not the same endpoint
    if target_id == source_id {
        return HttpResponse::BadRequest().json(MergeEndpointsResponse {
            success: false,
            message: "Cannot merge an endpoint with itself".to_string(),
        });
    }

    // Perform the merge
    let mut merged_comms = 0;
    let mut merged_attrs = 0;
    let mut merged_ports = 0;
    let mut merged_scans = 0;

    // Merge communications
    merged_comms += conn
        .execute(
            "UPDATE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
            params![target_id, source_id],
        )
        .unwrap_or(0);
    merged_comms += conn
        .execute(
            "UPDATE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
            params![target_id, source_id],
        )
        .unwrap_or(0);

    // Merge endpoint attributes (INSERT OR IGNORE to skip duplicates)
    merged_attrs += conn
        .execute(
            "INSERT OR IGNORE INTO endpoint_attributes (created_at, endpoint_id, mac, ip, hostname, dhcp_client_id, dhcp_vendor_class)
             SELECT created_at, ?1, mac, ip, hostname, dhcp_client_id, dhcp_vendor_class
             FROM endpoint_attributes
             WHERE endpoint_id = ?2",
            params![target_id, source_id],
        )
        .unwrap_or(0);

    // Delete source attributes after copying
    conn.execute(
        "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
        params![source_id],
    )
    .unwrap_or(0);

    // Merge open ports (UPDATE OR IGNORE to skip duplicates)
    merged_ports += conn
        .execute(
            "UPDATE OR IGNORE open_ports SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            params![target_id, source_id],
        )
        .unwrap_or(0);

    // Delete any remaining source ports (duplicates)
    conn.execute(
        "DELETE FROM open_ports WHERE endpoint_id = ?1",
        params![source_id],
    )
    .unwrap_or(0);

    // Merge scan results
    merged_scans += conn
        .execute(
            "UPDATE scan_results SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            params![target_id, source_id],
        )
        .unwrap_or(0);

    // Copy over any useful metadata from source that target doesn't have
    let _ = conn.execute(
        "UPDATE endpoints SET
            ssdp_model = COALESCE((SELECT ssdp_model FROM endpoints WHERE id = ?1), (SELECT ssdp_model FROM endpoints WHERE id = ?2)),
            ssdp_friendly_name = COALESCE((SELECT ssdp_friendly_name FROM endpoints WHERE id = ?1), (SELECT ssdp_friendly_name FROM endpoints WHERE id = ?2)),
            netbios_name = COALESCE((SELECT netbios_name FROM endpoints WHERE id = ?1), (SELECT netbios_name FROM endpoints WHERE id = ?2)),
            auto_device_type = COALESCE((SELECT auto_device_type FROM endpoints WHERE id = ?1), (SELECT auto_device_type FROM endpoints WHERE id = ?2))
         WHERE id = ?1",
        params![target_id, source_id],
    );

    // Reassign notifications so they point to the surviving endpoint
    let _ = conn.execute(
        "UPDATE notifications SET endpoint_id = ?1 WHERE endpoint_id = ?2",
        params![target_id, source_id],
    );

    // Delete the source endpoint
    let deleted = conn
        .execute("DELETE FROM endpoints WHERE id = ?1", params![source_id])
        .unwrap_or(0);

    if deleted > 0 {
        insert_notification(
            &conn,
            "endpoints_merged",
            &format!("Merged '{}' into '{}'", body.source, body.target),
            Some(&format!(
                "{} communication(s), {} attribute(s), {} port(s), {} scan result(s)",
                merged_comms, merged_attrs, merged_ports, merged_scans
            )),
            Some(&body.target),
        );

        HttpResponse::Ok().json(MergeEndpointsResponse {
            success: true,
            message: format!(
                "Merged '{}' into '{}': {} communication(s), {} attribute(s), {} port(s), {} scan result(s)",
                body.source, body.target, merged_comms, merged_attrs, merged_ports, merged_scans
            ),
        })
    } else {
        HttpResponse::InternalServerError().json(MergeEndpointsResponse {
            success: false,
            message: "Failed to delete source endpoint after merge".to_string(),
        })
    }
}

#[derive(Deserialize)]
pub struct ProbeModelRequest {
    ip: String,
}

#[derive(Serialize)]
pub struct ProbeModelResponse {
    success: bool,
    message: String,
    model: Option<String>,
}

/// Probe a device's web interface to detect its model
#[post("/api/endpoint/probe/model")]
pub async fn probe_endpoint_model(body: Json<ProbeModelRequest>) -> impl Responder {
    let ip = body.ip.clone();

    // Try to probe the device for its model (run in blocking thread for immediate execution)
    let ip_clone = ip.clone();
    let model = tokio::task::spawn_blocking(move || probe_hp_printer_model_blocking(&ip_clone))
        .await
        .ok()
        .flatten();

    if let Some(model) = model {
        // Find the endpoint and save the model
        let conn = match new_connection_result() {
            Ok(c) => c,
            Err(e) => {
                return HttpResponse::InternalServerError().json(ProbeModelResponse {
                    success: false,
                    message: format!("Database error: {}", e),
                    model: None,
                });
            }
        };

        // Find endpoint by IP and update the ssdp_model
        let update_result = conn.execute(
            "UPDATE endpoints SET ssdp_model = ?1
             WHERE id IN (SELECT endpoint_id FROM endpoint_attributes WHERE ip = ?2)
             AND (ssdp_model IS NULL OR ssdp_model = '')",
            params![model, ip],
        );

        match update_result {
            Ok(rows) => {
                if rows > 0 {
                    let eid: Option<i64> = conn.query_row(
                        "SELECT endpoint_id FROM endpoint_attributes WHERE ip = ?1 LIMIT 1",
                        params![ip], |row| row.get(0),
                    ).ok();
                    insert_notification_with_endpoint_id(
                        &conn, "model_identified",
                        &format!("Device model identified: {}", model),
                        None, None, eid,
                    );
                }
                HttpResponse::Ok().json(ProbeModelResponse {
                    success: true,
                    message: format!("Found model '{}', updated {} endpoint(s)", model, rows),
                    model: Some(model),
                })
            }
            Err(e) => HttpResponse::InternalServerError().json(ProbeModelResponse {
                success: false,
                message: format!("Found model '{}' but failed to save: {}", model, e),
                model: Some(model),
            }),
        }
    } else {
        HttpResponse::Ok().json(ProbeModelResponse {
            success: false,
            message: "Could not detect model from device web interface".to_string(),
            model: None,
        })
    }
}

// ============================================================================
// Device Control API Endpoints
// ============================================================================

#[derive(Deserialize)]
pub struct DeviceQuery {
    ip: String,
    device_type: Option<String>,
    hostname: Option<String>,
}

#[derive(Deserialize)]
pub struct DeviceCommandRequest {
    ip: String,
    command: String,
    device_type: String,
}

#[derive(Deserialize)]
pub struct LaunchAppRequest {
    ip: String,
    app_id: String,
    device_type: String,
}

#[get("/api/device/capabilities")]
pub async fn get_device_capabilities(query: Query<DeviceQuery>) -> impl Responder {
    let ip = query.ip.clone();
    let device_type = query.device_type.clone();
    let hostname = query.hostname.clone();

    // Run blocking device detection in a separate thread
    let capabilities = actix_web::web::block(move || {
        DeviceController::get_capabilities(&ip, device_type.as_deref(), hostname.as_deref())
    })
    .await;

    match capabilities {
        Ok(caps) => HttpResponse::Ok().json(caps),
        Err(_) => HttpResponse::InternalServerError().body("Failed to get device capabilities"),
    }
}

#[post("/api/device/command")]
pub async fn send_device_command(body: Json<DeviceCommandRequest>) -> impl Responder {
    let ip = body.ip.clone();
    let command = body.command.clone();
    let device_type = body.device_type.clone();

    let result =
        actix_web::web::block(move || DeviceController::send_command(&ip, &command, &device_type))
            .await;

    match result {
        Ok(r) if r.success => HttpResponse::Ok().json(r),
        Ok(r) => HttpResponse::BadRequest().json(r),
        Err(_) => HttpResponse::InternalServerError().body("Command failed"),
    }
}

#[post("/api/device/launch")]
pub async fn launch_device_app(body: Json<LaunchAppRequest>) -> impl Responder {
    let ip = body.ip.clone();
    let app_id = body.app_id.clone();
    let device_type = body.device_type.clone();

    let result =
        actix_web::web::block(move || DeviceController::launch_app(&ip, &app_id, &device_type))
            .await;

    match result {
        Ok(r) if r.success => HttpResponse::Ok().json(r),
        Ok(r) => HttpResponse::BadRequest().json(r),
        Err(_) => HttpResponse::InternalServerError().body("Launch failed"),
    }
}

#[derive(Deserialize)]
pub struct PairRequest {
    ip: String,
    device_type: String,
}

#[post("/api/device/pair")]
pub async fn pair_device(body: Json<PairRequest>) -> impl Responder {
    let ip = body.ip.clone();
    let device_type = body.device_type.clone();

    let result = actix_web::web::block(move || DeviceController::pair(&ip, &device_type)).await;

    match result {
        Ok(r) if r.success => HttpResponse::Ok().json(r),
        Ok(r) => HttpResponse::BadRequest().json(r),
        Err(_) => HttpResponse::InternalServerError().body("Pairing failed"),
    }
}

// ============================================================================
// LG ThinQ API Endpoints
// ============================================================================

#[derive(Deserialize)]
pub struct ThinQSetupRequest {
    pat_token: String,
    country_code: String,
}

#[derive(Serialize)]
pub struct ThinQStatusResponse {
    configured: bool,
    devices: Vec<ThinQDeviceInfo>,
}

#[derive(Serialize)]
pub struct ThinQDeviceInfo {
    device_id: String,
    device_type: String,
    name: String,
    model: Option<String>,
    online: bool,
}

#[post("/api/thinq/setup")]
pub async fn setup_thinq(body: Json<ThinQSetupRequest>) -> impl Responder {
    let pat_token = body.pat_token.clone();
    let country_code = body.country_code.clone();

    let result =
        actix_web::web::block(move || DeviceController::setup_thinq(&pat_token, &country_code))
            .await;

    match result {
        Ok(r) if r.success => HttpResponse::Ok().json(r),
        Ok(r) => HttpResponse::BadRequest().json(r),
        Err(_) => HttpResponse::InternalServerError().body("ThinQ setup failed"),
    }
}

#[get("/api/thinq/status")]
pub async fn get_thinq_status() -> impl Responder {
    let result = actix_web::web::block(move || {
        let configured = DeviceController::is_thinq_configured();
        let devices = if configured {
            DeviceController::list_thinq_devices()
                .unwrap_or_default()
                .into_iter()
                .map(|d| ThinQDeviceInfo {
                    device_id: d.device_id,
                    device_type: d.device_type,
                    name: d.device_alias,
                    model: d.model_name,
                    online: d.online,
                })
                .collect()
        } else {
            Vec::new()
        };

        ThinQStatusResponse {
            configured,
            devices,
        }
    })
    .await;

    match result {
        Ok(status) => HttpResponse::Ok().json(status),
        Err(_) => HttpResponse::InternalServerError().body("Failed to get ThinQ status"),
    }
}

#[get("/api/thinq/devices")]
pub async fn list_thinq_devices() -> impl Responder {
    let result = actix_web::web::block(move || {
        DeviceController::list_thinq_devices().map(|devices| {
            devices
                .into_iter()
                .map(|d| ThinQDeviceInfo {
                    device_id: d.device_id,
                    device_type: d.device_type,
                    name: d.device_alias,
                    model: d.model_name,
                    online: d.online,
                })
                .collect::<Vec<_>>()
        })
    })
    .await;

    match result {
        Ok(Ok(devices)) => HttpResponse::Ok().json(devices),
        Ok(Err(e)) => HttpResponse::BadRequest().body(e),
        Err(_) => HttpResponse::InternalServerError().body("Failed to list ThinQ devices"),
    }
}

#[post("/api/thinq/disconnect")]
pub async fn disconnect_thinq() -> impl Responder {
    let result = actix_web::web::block(DeviceController::disconnect_thinq).await;

    match result {
        Ok(success) => {
            if success {
                HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "message": "Disconnected from LG ThinQ"
                }))
            } else {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "message": "Failed to disconnect"
                }))
            }
        }
        Err(_) => HttpResponse::InternalServerError().body("Failed to disconnect ThinQ"),
    }
}

// ============================================================================
// Network Scanner API Endpoints
// ============================================================================

#[derive(Deserialize)]
pub struct StartScanRequest {
    scan_types: Vec<ScanType>,
}

#[derive(Serialize)]
pub struct StartScanResponse {
    success: bool,
    message: String,
}

#[post("/api/scan/start")]
pub async fn start_scan(body: Json<StartScanRequest>) -> impl Responder {
    let manager = get_scan_manager();
    let scan_types = body.scan_types.clone();

    match manager.start_scan(scan_types.clone()).await {
        Ok(()) => {
            let type_names: Vec<String> = scan_types.iter().map(|t| t.to_string()).collect();
            let details = format!("Scan types: {}", type_names.join(", "));
            tokio::task::spawn_blocking(move || {
                let conn = new_connection();
                insert_notification(
                    &conn,
                    "scan_started",
                    "Network scan started",
                    Some(&details),
                    None,
                );
            });

            HttpResponse::Ok().json(StartScanResponse {
                success: true,
                message: "Scan started".to_string(),
            })
        }
        Err(e) => HttpResponse::BadRequest().json(StartScanResponse {
            success: false,
            message: e,
        }),
    }
}

#[post("/api/scan/stop")]
pub async fn stop_scan() -> impl Responder {
    let manager = get_scan_manager();
    manager.stop_scan().await;

    tokio::task::spawn_blocking(|| {
        let conn = new_connection();
        insert_notification(&conn, "scan_stopped", "Network scan stopped", None, None);
    });

    HttpResponse::Ok().json(StartScanResponse {
        success: true,
        message: "Scan stopped".to_string(),
    })
}

#[get("/api/scan/status")]
pub async fn get_scan_status() -> impl Responder {
    let manager = get_scan_manager();
    let status = manager.get_status().await;

    HttpResponse::Ok().json(status)
}

#[get("/api/scan/capabilities")]
pub async fn get_scan_capabilities() -> impl Responder {
    let capabilities = check_scan_privileges();
    HttpResponse::Ok().json(capabilities)
}

#[get("/api/scan/config")]
pub async fn get_scan_config() -> impl Responder {
    let manager = get_scan_manager();
    let config = manager.get_config().await;

    HttpResponse::Ok().json(config)
}

#[post("/api/scan/config")]
pub async fn set_scan_config(body: Json<ScanConfig>) -> impl Responder {
    let manager = get_scan_manager();
    manager.set_config(body.into_inner()).await;

    HttpResponse::Ok().json(StartScanResponse {
        success: true,
        message: "Config updated".to_string(),
    })
}

// ============================================================================
// Scan Result Processing
// ============================================================================

/// Process a scan result and store in database with retry logic
fn process_scan_result(result: &ScanResult) -> Result<(), String> {
    const MAX_RETRIES: u32 = 5;

    for attempt in 1..=MAX_RETRIES {
        match process_scan_result_inner(result) {
            Ok(()) => return Ok(()),
            Err(e) if e.contains("database is locked") && attempt < MAX_RETRIES => {
                // Exponential backoff: 50ms, 100ms, 200ms, 400ms
                std::thread::sleep(std::time::Duration::from_millis(50 * (1 << (attempt - 1))));
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Err("Max retries exceeded".to_string())
}

/// Inner function that does the actual work
fn process_scan_result_inner(result: &ScanResult) -> Result<(), String> {
    let conn = new_connection();

    match result {
        ScanResult::Arp(arp) => {
            let ip_str = arp.ip.to_string();
            let mac_str = arp.mac.to_string();
            if let Ok((endpoint_id, is_new)) = EndPoint::get_or_insert_endpoint(
                &conn,
                Some(mac_str.clone()),
                Some(ip_str.clone()),
                None,
                &[],
            ) {
                if is_new {
                    insert_notification_with_endpoint_id(
                        &conn,
                        "endpoint_discovered",
                        &format!("New device discovered: {}", ip_str),
                        Some(&format!("MAC: {}", mac_str)),
                        Some(&ip_str),
                        Some(endpoint_id),
                    );
                }

                insert_scan_result(
                    &conn,
                    endpoint_id,
                    "arp",
                    Some(arp.response_time_ms as i64),
                    None,
                )?;

                // If this is an HP device, probe for printer model
                if get_mac_vendor(&mac_str).is_some_and(|v| v == "HP") {
                    let ip_for_probe = ip_str.clone();
                    tokio::task::spawn_blocking(move || {
                        probe_and_save_hp_printer_model_blocking(&ip_for_probe, endpoint_id);
                    });
                }
            }
        }
        ScanResult::Icmp(icmp) => {
            if icmp.alive {
                let ip_str = icmp.ip.to_string();
                // For ICMP (no MAC), only record if endpoint already exists
                // This prevents creating ghost entries for false positive pings
                if let Some(endpoint_id) = find_existing_endpoint_by_ip(&conn, &ip_str) {
                    let details = serde_json::json!({
                        "ttl": icmp.ttl,
                        "rtt_ms": icmp.rtt_ms,
                    });
                    insert_scan_result(
                        &conn,
                        endpoint_id,
                        "icmp",
                        icmp.rtt_ms.map(|r| r as i64),
                        Some(&details.to_string()),
                    )?;
                }
            }
        }
        ScanResult::Port(port) => {
            if port.open {
                let ip_str = port.ip.to_string();
                // For port scans (no MAC), only record if endpoint already exists
                if let Some(endpoint_id) = find_existing_endpoint_by_ip(&conn, &ip_str) {
                    insert_open_port(&conn, endpoint_id, port.port, port.service_name.as_deref())?;
                }
            }
        }
        ScanResult::Ssdp(ssdp) => {
            let ip_str = ssdp.ip.to_string();
            // For SSDP (no MAC), only record if endpoint already exists
            if let Some(endpoint_id) = find_existing_endpoint_by_ip(&conn, &ip_str) {
                let details = serde_json::json!({
                    "location": ssdp.location,
                    "server": ssdp.server,
                    "device_type": ssdp.device_type,
                    "friendly_name": ssdp.friendly_name,
                    "model_name": ssdp.model_name,
                });
                insert_scan_result(&conn, endpoint_id, "ssdp", None, Some(&details.to_string()))?;

                // If we got a model name from SSDP, save it to the endpoint
                // But first verify it's consistent with the endpoint's MAC vendor
                // to prevent mismatched data from IP address reassignments
                if let Some(ref model) = ssdp.model_name
                    && is_ssdp_model_consistent_with_endpoint(&conn, endpoint_id, model)
                {
                    // Update if empty OR if new model is more specific than current
                    let current_model: Option<String> = conn
                        .query_row(
                            "SELECT ssdp_model FROM endpoints WHERE id = ?1",
                            params![endpoint_id],
                            |row| row.get(0),
                        )
                        .ok()
                        .flatten();

                    let should_update = match &current_model {
                        None => true,
                        Some(current) if current.is_empty() => true,
                        Some(current) => is_more_specific_model(model, current),
                    };

                    if should_update {
                        let _ = conn.execute(
                            "UPDATE endpoints SET ssdp_model = ?1 WHERE id = ?2",
                            params![model, endpoint_id],
                        );

                        if current_model.as_ref().is_none_or(|m| m.is_empty()) {
                            insert_notification_with_endpoint_id(
                                &conn,
                                "model_identified",
                                &format!("Device model identified: {}", model),
                                None, None,
                                Some(endpoint_id),
                            );
                        } else if let Some(ref old) = current_model {
                            insert_notification_with_endpoint_id(
                                &conn,
                                "model_changed",
                                &format!("Device model updated: {}", model),
                                Some(&format!("Previous: {}", old)),
                                None,
                                Some(endpoint_id),
                            );
                        }
                    }
                }
                // If we got a friendly name from SSDP, save it
                // Update if empty OR if new name is more specific
                if let Some(ref friendly) = ssdp.friendly_name {
                    let current_friendly: Option<String> = conn
                        .query_row(
                            "SELECT ssdp_friendly_name FROM endpoints WHERE id = ?1",
                            params![endpoint_id],
                            |row| row.get(0),
                        )
                        .ok()
                        .flatten();

                    let should_update = match &current_friendly {
                        None => true,
                        Some(current) if current.is_empty() => true,
                        Some(current) => is_more_specific_model(friendly, current),
                    };

                    if should_update {
                        let _ = conn.execute(
                            "UPDATE endpoints SET ssdp_friendly_name = ?1 WHERE id = ?2",
                            params![friendly, endpoint_id],
                        );
                    }
                }
            }
        }
        ScanResult::Ndp(ndp) => {
            let ip_str = ndp.ip.to_string();
            let mac_str = ndp.mac.to_string();
            if let Ok((endpoint_id, is_new)) =
                EndPoint::get_or_insert_endpoint(&conn, Some(mac_str.clone()), Some(ip_str.clone()), None, &[])
            {
                if is_new {
                    insert_notification_with_endpoint_id(
                        &conn,
                        "endpoint_discovered",
                        &format!("New device discovered: {}", ip_str),
                        Some(&format!("MAC: {} (NDP)", mac_str)),
                        Some(&ip_str),
                        Some(endpoint_id),
                    );
                }

                insert_scan_result(
                    &conn,
                    endpoint_id,
                    "ndp",
                    Some(ndp.response_time_ms as i64),
                    None,
                )?;
            }
        }
        ScanResult::NetBios(netbios) => {
            let ip_str = netbios.ip.to_string();
            // For NetBIOS (no MAC from packet), only record if endpoint already exists
            if let Some(endpoint_id) = find_existing_endpoint_by_ip(&conn, &ip_str) {
                let details = serde_json::json!({
                    "netbios_name": netbios.netbios_name,
                    "group_name": netbios.group_name,
                    "mac": netbios.mac,
                });
                insert_scan_result(
                    &conn,
                    endpoint_id,
                    "netbios",
                    None,
                    Some(&details.to_string()),
                )?;

                // Save NetBIOS name to endpoint if not already set
                let _ = conn.execute(
                    "UPDATE endpoints SET netbios_name = ?1 WHERE id = ?2 AND (netbios_name IS NULL OR netbios_name = '')",
                    params![netbios.netbios_name, endpoint_id],
                );

                // Also update endpoint name if it's currently just an IP address
                let _ = conn.execute(
                    "UPDATE endpoints SET name = ?1 WHERE id = ?2 AND (name = ?3 OR name GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*')",
                    params![netbios.netbios_name, endpoint_id, ip_str],
                );
            }
        }
        ScanResult::Snmp(snmp) => {
            let ip_str = snmp.ip.to_string();
            // For SNMP (no MAC from packet), only record if endpoint already exists
            if let Some(endpoint_id) = find_existing_endpoint_by_ip(&conn, &ip_str) {
                let details = serde_json::json!({
                    "sys_descr": snmp.sys_descr,
                    "sys_object_id": snmp.sys_object_id,
                    "sys_name": snmp.sys_name,
                    "sys_location": snmp.sys_location,
                    "community": snmp.community,
                });
                insert_scan_result(&conn, endpoint_id, "snmp", None, Some(&details.to_string()))?;

                // Extract vendor/model info from sysDescr if available
                if let Some(ref sys_descr) = snmp.sys_descr {
                    let (vendor, model) = parse_snmp_sys_descr(sys_descr);

                    // Update vendor if we found one and endpoint doesn't have one
                    if let Some(v) = &vendor {
                        let rows = conn.execute(
                            "UPDATE endpoints SET vendor = ?1 WHERE id = ?2 AND (vendor IS NULL OR vendor = '')",
                            params![v, endpoint_id],
                        ).unwrap_or(0);
                        if rows > 0 {
                            insert_notification_with_endpoint_id(
                                &conn, "vendor_identified",
                                &format!("Vendor identified: {}", v),
                                None, None, Some(endpoint_id),
                            );
                        }
                    }

                    // Update model if we found one and endpoint doesn't have one
                    if let Some(m) = &model {
                        let rows = conn.execute(
                            "UPDATE endpoints SET model = ?1 WHERE id = ?2 AND (model IS NULL OR model = '')",
                            params![m, endpoint_id],
                        ).unwrap_or(0);
                        if rows > 0 {
                            insert_notification_with_endpoint_id(
                                &conn, "model_identified",
                                &format!("Device model identified: {}", m),
                                None, None, Some(endpoint_id),
                            );
                        }
                    }
                }

                // Update endpoint name from sysName if name is just an IP
                if let Some(ref sys_name) = snmp.sys_name
                    && !sys_name.is_empty()
                {
                    let _ = conn.execute(
                        "UPDATE endpoints SET name = ?1 WHERE id = ?2 AND (name = ?3 OR name GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*')",
                        params![sys_name, endpoint_id, ip_str],
                    );
                }
            }
        }
    }

    Ok(())
}

/// Find an existing endpoint by IP address (must have a MAC to be considered valid)
/// Returns None if no endpoint with a MAC exists for this IP
fn find_existing_endpoint_by_ip(conn: &Connection, ip: &str) -> Option<i64> {
    conn.query_row(
        "SELECT ea.endpoint_id FROM endpoint_attributes ea
         WHERE ea.ip = ?1 AND ea.mac IS NOT NULL AND ea.mac != ''
         LIMIT 1",
        params![ip],
        |row| row.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

/// Parse SNMP sysDescr to extract vendor and model information
/// Returns (vendor, model) as Option strings
fn parse_snmp_sys_descr(sys_descr: &str) -> (Option<String>, Option<String>) {
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
        if descr_lower.contains(pattern) {
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
fn is_ssdp_model_consistent_with_endpoint(
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
fn is_more_specific_model(new_model: &str, current_model: &str) -> bool {
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

/// Insert a scan result into the database
/// Note: Table is created at startup in SQLWriter to avoid schema locks
fn insert_scan_result(
    conn: &Connection,
    endpoint_id: i64,
    scan_type: &str,
    response_time_ms: Option<i64>,
    details: Option<&str>,
) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT INTO scan_results (endpoint_id, scan_type, scanned_at, response_time_ms, details) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![endpoint_id, scan_type, now, response_time_ms, details],
    ).map_err(|e| e.to_string())?;

    Ok(())
}

/// Insert an open port into the database
/// Note: Table is created at startup in SQLWriter to avoid schema locks
fn insert_open_port(
    conn: &Connection,
    endpoint_id: i64,
    port: u16,
    service_name: Option<&str>,
) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT OR REPLACE INTO open_ports (endpoint_id, port, protocol, service_name, last_seen_at) VALUES (?1, ?2, 'tcp', ?3, ?4)",
        params![endpoint_id, port as i64, service_name, now],
    ).map_err(|e| e.to_string())?;

    Ok(())
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

    let scan_interval: u64 = 525600; // Same default as index route
    let active_threshold = get_setting_i64("active_threshold_seconds", 120) as u64;

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
    // Build vendor lookup
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

    let endpoint_vendors: HashMap<String, String> = dropdown_endpoints_list
        .iter()
        .filter_map(|endpoint| {
            let endpoint_lower = endpoint.to_lowercase();
            let (_custom_model, ssdp_model, ssdp_friendly, custom_vendor) = endpoint_ssdp_models
                .get(&endpoint_lower)
                .map(|(cm, sm, sf, cv)| {
                    (cm.as_deref(), sm.as_deref(), sf.as_deref(), cv.as_deref())
                })
                .unwrap_or((None, None, None, None));

            let macs: Vec<String> = endpoint_ips_macs
                .get(&endpoint_lower)
                .map(|(_, m)| m.clone())
                .unwrap_or_default()
                .into_iter()
                .filter(|mac| {
                    get_mac_vendor(mac)
                        .map(|v| !component_vendors.contains(&v))
                        .unwrap_or(true)
                })
                .collect();

            characterize_vendor(
                custom_vendor,
                ssdp_friendly,
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
            let (custom_model, ssdp_model, _, _) = endpoint_ssdp_models
                .get(&endpoint_lower)
                .map(|(cm, sm, sf, cv)| {
                    (cm.as_deref(), sm.as_deref(), sf.as_deref(), cv.as_deref())
                })
                .unwrap_or((None, None, None, None));

            let macs: Vec<String> = endpoint_ips_macs
                .get(&endpoint_lower)
                .map(|(_, m)| m.clone())
                .unwrap_or_default();

            let vendor = endpoint_vendors.get(&endpoint_lower).map(|v| v.as_str());

            characterize_model(
                custom_model,
                ssdp_model,
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

// ============================================================================
// Export Endpoints
// ============================================================================

#[get("/api/export/endpoints.xlsx")]
pub async fn export_endpoints_xlsx() -> impl Responder {
    let scan_interval: u64 = 525600;

    // Get endpoint list
    let dropdown_future = tokio::task::spawn_blocking(move || dropdown_endpoints(scan_interval));
    let dropdown_endpoints_list = dropdown_future.await.unwrap_or_default();

    if dropdown_endpoints_list.is_empty() {
        return HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header((
                "Content-Disposition",
                "attachment; filename=\"endpoints.xlsx\"",
            ))
            .body(Vec::new());
    }

    // Run queries in parallel (same as get_endpoints_table)
    let dropdown_for_ips = dropdown_endpoints_list.clone();
    let dropdown_for_seen = dropdown_endpoints_list.clone();
    let dropdown_for_online = dropdown_endpoints_list.clone();
    let dropdown_for_types = dropdown_endpoints_list.clone();
    let dropdown_for_ssdp = dropdown_endpoints_list.clone();

    let ips_macs_future =
        tokio::task::spawn_blocking(move || get_endpoint_ips_and_macs(&dropdown_for_ips));
    let last_seen_future = tokio::task::spawn_blocking(move || {
        get_all_endpoints_last_seen(&dropdown_for_seen, scan_interval)
    });
    let online_status_future = tokio::task::spawn_blocking(move || {
        let active_threshold = get_setting_i64("active_threshold_seconds", 120) as u64;
        get_all_endpoints_online_status(&dropdown_for_online, active_threshold)
    });
    let all_types_future =
        tokio::task::spawn_blocking(move || get_all_endpoint_types(&dropdown_for_types));
    let ssdp_models_future =
        tokio::task::spawn_blocking(move || get_endpoint_ssdp_models(&dropdown_for_ssdp));

    let (
        ips_macs_result,
        last_seen_result,
        online_status_result,
        all_types_result,
        ssdp_models_result,
    ) = tokio::join!(
        ips_macs_future,
        last_seen_future,
        online_status_future,
        all_types_future,
        ssdp_models_future
    );

    let endpoint_ips_macs = ips_macs_result.unwrap_or_default();
    let endpoint_last_seen = last_seen_result.unwrap_or_default();
    let endpoint_online_status = online_status_result.unwrap_or_default();
    let (dropdown_types, _manual_overrides) = all_types_result.unwrap_or_default();
    let endpoint_ssdp_models = ssdp_models_result.unwrap_or_default();

    // Build vendor lookup
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

    let endpoint_vendors: HashMap<String, String> = dropdown_endpoints_list
        .iter()
        .filter_map(|endpoint| {
            let endpoint_lower = endpoint.to_lowercase();
            let (_custom_model, ssdp_model, ssdp_friendly, custom_vendor) = endpoint_ssdp_models
                .get(&endpoint_lower)
                .map(|(cm, sm, sf, cv)| {
                    (cm.as_deref(), sm.as_deref(), sf.as_deref(), cv.as_deref())
                })
                .unwrap_or((None, None, None, None));

            let macs: Vec<String> = endpoint_ips_macs
                .get(&endpoint_lower)
                .map(|(_, m)| m.clone())
                .unwrap_or_default()
                .into_iter()
                .filter(|mac| {
                    get_mac_vendor(mac)
                        .map(|v| !component_vendors.contains(&v))
                        .unwrap_or(true)
                })
                .collect();

            characterize_vendor(
                custom_vendor,
                ssdp_friendly,
                Some(endpoint.as_str()),
                &macs,
                ssdp_model,
            )
            .map(|c| (endpoint_lower, c.value))
        })
        .collect();

    // Build model lookup
    let endpoint_models: HashMap<String, String> = dropdown_endpoints_list
        .iter()
        .filter_map(|endpoint| {
            let endpoint_lower = endpoint.to_lowercase();
            let (custom_model, ssdp_model, _, _) = endpoint_ssdp_models
                .get(&endpoint_lower)
                .map(|(cm, sm, sf, cv)| {
                    (cm.as_deref(), sm.as_deref(), sf.as_deref(), cv.as_deref())
                })
                .unwrap_or((None, None, None, None));

            let macs: Vec<String> = endpoint_ips_macs
                .get(&endpoint_lower)
                .map(|(_, m)| m.clone())
                .unwrap_or_default();

            let vendor = endpoint_vendors.get(&endpoint_lower).map(|v| v.as_str());

            characterize_model(
                custom_model,
                ssdp_model,
                Some(endpoint.as_str()),
                &macs,
                vendor,
                None,
            )
            .map(|c| (endpoint_lower, c.value))
        })
        .collect();

    // Create Excel workbook
    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();
    worksheet.set_name("Endpoints").ok();

    // Header format
    let header_format = Format::new().set_bold();

    // Write headers
    let headers = [
        "Name",
        "IP",
        "MAC",
        "Vendor",
        "Model",
        "Device Type",
        "Last Seen",
        "Online",
    ];
    for (col, header) in headers.iter().enumerate() {
        worksheet
            .write_string_with_format(0, col as u16, *header, &header_format)
            .ok();
    }

    // Write data rows
    for (row_idx, endpoint) in dropdown_endpoints_list.iter().enumerate() {
        let row = (row_idx + 1) as u32;
        let endpoint_lower = endpoint.to_lowercase();

        let (ips, macs) = endpoint_ips_macs
            .get(&endpoint_lower)
            .cloned()
            .unwrap_or_default();

        worksheet.write_string(row, 0, endpoint).ok();
        worksheet.write_string(row, 1, ips.join(", ")).ok();
        worksheet.write_string(row, 2, macs.join(", ")).ok();
        worksheet
            .write_string(
                row,
                3,
                endpoint_vendors
                    .get(&endpoint_lower)
                    .map(|s| &**s)
                    .unwrap_or(""),
            )
            .ok();
        worksheet
            .write_string(
                row,
                4,
                endpoint_models
                    .get(&endpoint_lower)
                    .map(|s| &**s)
                    .unwrap_or(""),
            )
            .ok();
        worksheet
            .write_string(
                row,
                5,
                dropdown_types
                    .get(&endpoint_lower)
                    .map(|s| &**s)
                    .unwrap_or(""),
            )
            .ok();
        worksheet
            .write_string(
                row,
                6,
                endpoint_last_seen
                    .get(&endpoint_lower)
                    .map(|s| &**s)
                    .unwrap_or("-"),
            )
            .ok();
        worksheet
            .write_string(
                row,
                7,
                if *endpoint_online_status
                    .get(&endpoint_lower)
                    .unwrap_or(&false)
                {
                    "Yes"
                } else {
                    "No"
                },
            )
            .ok();
    }

    // Set column widths for readability
    worksheet.set_column_width(0, 30).ok(); // Name
    worksheet.set_column_width(1, 15).ok(); // IP
    worksheet.set_column_width(2, 20).ok(); // MAC
    worksheet.set_column_width(3, 15).ok(); // Vendor
    worksheet.set_column_width(4, 20).ok(); // Model
    worksheet.set_column_width(5, 15).ok(); // Device Type
    worksheet.set_column_width(6, 20).ok(); // Last Seen
    worksheet.set_column_width(7, 8).ok(); // Online

    // Save to buffer
    let buffer = match workbook.save_to_buffer() {
        Ok(buf) => buf,
        Err(e) => {
            eprintln!("Failed to create Excel file: {}", e);
            return HttpResponse::InternalServerError().body("Failed to create Excel file");
        }
    };

    HttpResponse::Ok()
        .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        .insert_header((
            "Content-Disposition",
            "attachment; filename=\"endpoints.xlsx\"",
        ))
        .body(buffer)
}

// ============================================================================
// Settings Endpoints
// ============================================================================

#[derive(Serialize)]
pub struct SettingsResponse {
    settings: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct UpdateSettingRequest {
    key: String,
    value: String,
}

#[derive(Serialize)]
pub struct UpdateSettingResponse {
    success: bool,
    message: String,
}

#[get("/api/settings")]
pub async fn get_settings() -> impl Responder {
    let settings = tokio::task::spawn_blocking(get_all_settings)
        .await
        .unwrap_or_default();

    HttpResponse::Ok().json(SettingsResponse { settings })
}

#[post("/api/settings")]
pub async fn update_setting(body: Json<UpdateSettingRequest>) -> impl Responder {
    let key = body.key.clone();
    let value = body.value.clone();

    let result = tokio::task::spawn_blocking(move || set_setting(&key, &value)).await;

    match result {
        Ok(Ok(())) => HttpResponse::Ok().json(UpdateSettingResponse {
            success: true,
            message: format!("Setting '{}' updated", body.key),
        }),
        _ => HttpResponse::InternalServerError().json(UpdateSettingResponse {
            success: false,
            message: "Failed to update setting".to_string(),
        }),
    }
}

// ============================================================================
// Capture Pause Endpoint
// ============================================================================

#[derive(Serialize)]
pub struct CapturePauseResponse {
    success: bool,
    paused: bool,
    message: String,
}

/// Get capture pause status
#[get("/api/capture/status")]
pub async fn get_capture_status() -> impl Responder {
    let paused = crate::is_capture_paused();
    HttpResponse::Ok().json(CapturePauseResponse {
        success: true,
        paused,
        message: if paused {
            "Capture is paused".to_string()
        } else {
            "Capture is running".to_string()
        },
    })
}

/// Toggle capture pause state
#[post("/api/capture/pause")]
pub async fn toggle_capture_pause() -> impl Responder {
    let currently_paused = crate::is_capture_paused();
    let new_state = !currently_paused;
    crate::set_capture_paused(new_state);

    HttpResponse::Ok().json(CapturePauseResponse {
        success: true,
        paused: new_state,
        message: if new_state {
            "Capture paused - live traffic will be ignored".to_string()
        } else {
            "Capture resumed - live traffic will be processed".to_string()
        },
    })
}

/// Set capture pause state explicitly
#[derive(Deserialize)]
pub struct SetCapturePauseRequest {
    paused: bool,
}

#[post("/api/capture/set-pause")]
pub async fn set_capture_pause(body: Json<SetCapturePauseRequest>) -> impl Responder {
    crate::set_capture_paused(body.paused);

    HttpResponse::Ok().json(CapturePauseResponse {
        success: true,
        paused: body.paused,
        message: if body.paused {
            "Capture paused - live traffic will be ignored".to_string()
        } else {
            "Capture resumed - live traffic will be processed".to_string()
        },
    })
}

// ============================================================================
// PCAP Upload Endpoint
// ============================================================================

#[derive(Serialize)]
pub struct PcapUploadResponse {
    success: bool,
    message: String,
    packet_count: Option<usize>,
    filename: Option<String>,
}

#[post("/api/pcap/upload")]
pub async fn upload_pcap(mut payload: Multipart) -> impl Responder {
    let mut file_data: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;
    let mut label: Option<String> = None;

    // Extract file and label from multipart form
    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => {
                return HttpResponse::BadRequest().json(PcapUploadResponse {
                    success: false,
                    message: format!("Error reading multipart field: {}", e),
                    packet_count: None,
                    filename: None,
                });
            }
        };

        let field_name = field.name().unwrap_or("").to_string();

        if field_name == "file" {
            // Get filename from content disposition
            if let Some(cd) = field.content_disposition() {
                filename = cd.get_filename().map(|s| s.to_string());
            }

            // Read file data
            let mut data = Vec::new();
            while let Some(chunk) = field.next().await {
                match chunk {
                    Ok(bytes) => data.extend_from_slice(&bytes),
                    Err(e) => {
                        return HttpResponse::BadRequest().json(PcapUploadResponse {
                            success: false,
                            message: format!("Error reading file data: {}", e),
                            packet_count: None,
                            filename: None,
                        });
                    }
                }
            }
            file_data = Some(data);
        } else if field_name == "label" {
            // Read label field
            let mut label_data = Vec::new();
            while let Some(chunk) = field.next().await {
                if let Ok(bytes) = chunk {
                    label_data.extend_from_slice(&bytes);
                }
            }
            if let Ok(label_str) = String::from_utf8(label_data) {
                let trimmed = label_str.trim();
                if !trimmed.is_empty() {
                    label = Some(trimmed.to_string());
                }
            }
        }
    }

    // Validate we got a file
    let data = match file_data {
        Some(d) if !d.is_empty() => d,
        _ => {
            return HttpResponse::BadRequest().json(PcapUploadResponse {
                success: false,
                message: "No file uploaded or file is empty".to_string(),
                packet_count: None,
                filename: None,
            });
        }
    };

    let original_filename = filename
        .clone()
        .unwrap_or_else(|| "upload.pcap".to_string());

    // If no label provided, use the filename
    let source_label = label.unwrap_or_else(|| original_filename.clone());

    // Write to temporary file
    let temp_path = format!("/tmp/pcap_upload_{}.pcap", uuid::Uuid::new_v4());
    match std::fs::File::create(&temp_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&data) {
                return HttpResponse::InternalServerError().json(PcapUploadResponse {
                    success: false,
                    message: format!("Failed to write temp file: {}", e),
                    packet_count: None,
                    filename: Some(original_filename),
                });
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(PcapUploadResponse {
                success: false,
                message: format!("Failed to create temp file: {}", e),
                packet_count: None,
                filename: Some(original_filename),
            });
        }
    }

    // Create a SQL writer for processing
    let sql_writer = SQLWriter::new().await;
    let sender = sql_writer.sender.clone();

    // Process the pcap file in a blocking task
    let temp_path_clone = temp_path.clone();
    let label_clone = source_label.clone();
    let result = tokio::task::spawn_blocking(move || {
        crate::pcap::process_pcap_file(&temp_path_clone, Some(label_clone), &sender)
    })
    .await;

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_path);

    // Give the SQL writer time to flush remaining packets
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    match result {
        Ok(Ok(packet_count)) => HttpResponse::Ok().json(PcapUploadResponse {
            success: true,
            message: format!(
                "Successfully processed {} packets from '{}'",
                packet_count, original_filename
            ),
            packet_count: Some(packet_count),
            filename: Some(original_filename),
        }),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(PcapUploadResponse {
            success: false,
            message: format!("Failed to process pcap file: {}", e),
            packet_count: None,
            filename: Some(original_filename),
        }),
        Err(e) => HttpResponse::InternalServerError().json(PcapUploadResponse {
            success: false,
            message: format!("Task execution error: {}", e),
            packet_count: None,
            filename: Some(original_filename),
        }),
    }
}

// ============================================================================
// Notifications
// ============================================================================

#[derive(Deserialize)]
pub struct NotificationsQuery {
    since: Option<i64>,
    limit: Option<i64>,
    offset: Option<i64>,
    search: Option<String>,
    include_dismissed: Option<bool>,
}

#[derive(Serialize)]
pub struct NotificationItem {
    id: i64,
    created_at: i64,
    event_type: String,
    title: String,
    details: Option<String>,
    endpoint_name: Option<String>,
    dismissed: bool,
    endpoint_ip: Option<String>,
    endpoint_mac: Option<String>,
}

#[derive(Serialize)]
pub struct NotificationsResponse {
    notifications: Vec<NotificationItem>,
    total: i64,
}

#[get("/api/notifications")]
pub async fn get_notifications(query: Query<NotificationsQuery>) -> impl Responder {
    let since = query.since.unwrap_or(0);
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    let include_dismissed = query.include_dismissed.unwrap_or(false);
    let search = query.search.clone().unwrap_or_default();

    let result = tokio::task::spawn_blocking(move || {
        let conn = new_connection();

        let has_search = !search.is_empty();
        let search_pattern = format!("%{}%", search);

        // Build WHERE clause (use n. prefix since we JOIN with endpoints)
        let mut conditions = vec!["n.created_at > ?1"];
        if !include_dismissed {
            conditions.push("n.dismissed = 0");
        }
        if has_search {
            conditions.push("(n.title LIKE ?4 OR COALESCE(n.details, '') LIKE ?4 OR COALESCE(n.endpoint_name, '') LIKE ?4 OR n.event_type LIKE ?4)");
        }
        let where_clause = conditions.join(" AND ");

        // Get total count
        let count_sql = format!("SELECT COUNT(*) FROM notifications n WHERE {}", where_clause);
        let total: i64 = if has_search {
            conn.query_row(&count_sql, params![since, limit, offset, search_pattern], |row| row.get(0))
        } else {
            conn.query_row(&count_sql, params![since], |row| row.get(0))
        }.unwrap_or(0);

        // Resolve current endpoint display name via LEFT JOIN when endpoint_id is available.
        // This fixes stale names (e.g. "unknown" or bare IPs) in notifications created before
        // the endpoint received a proper name via mDNS, DHCP, SNMP, etc.
        let resolve_name_sql = format!(
            "COALESCE(
                e.custom_name,
                CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%'
                     AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' THEN e.name END,
                (SELECT MIN(hostname) FROM endpoint_attributes WHERE endpoint_id = e.id
                 AND hostname IS NOT NULL AND hostname != ''
                 AND hostname NOT LIKE '%:%' AND hostname NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'),
                (SELECT MIN(ip) FROM endpoint_attributes WHERE endpoint_id = e.id
                 AND ip IS NOT NULL AND ip != ''),
                n.endpoint_name
            )"
        );

        // Get page of results with resolved endpoint names
        let sql = format!(
            "SELECT n.id, n.created_at, n.event_type, n.title, n.details, n.endpoint_name, n.dismissed,
                    {resolve_name} AS resolved_name,
                    (SELECT MIN(ip) FROM endpoint_attributes WHERE endpoint_id = e.id
                     AND ip IS NOT NULL AND ip != '') AS endpoint_ip,
                    (SELECT MIN(mac) FROM endpoint_attributes WHERE endpoint_id = e.id
                     AND mac IS NOT NULL AND mac != '') AS endpoint_mac
             FROM notifications n
             LEFT JOIN endpoints e ON n.endpoint_id = e.id
             WHERE {where_clause}
             ORDER BY n.created_at DESC LIMIT ?2 OFFSET ?3",
            resolve_name = resolve_name_sql,
            where_clause = where_clause
        );

        let map_row = |row: &rusqlite::Row| -> rusqlite::Result<NotificationItem> {
            let original_title: String = row.get(3)?;
            let original_endpoint_name: Option<String> = row.get(5)?;
            let resolved_name: Option<String> = row.get(7)?;

            // Rewrite the title if we have a resolved name that differs from the original
            let title = match (&resolved_name, &original_endpoint_name) {
                (Some(resolved), Some(original)) if resolved != original && !resolved.is_empty() => {
                    original_title.replace(original, resolved)
                }
                _ => original_title,
            };

            Ok(NotificationItem {
                id: row.get(0)?,
                created_at: row.get(1)?,
                event_type: row.get(2)?,
                title,
                details: row.get(4)?,
                endpoint_name: resolved_name.or(original_endpoint_name),
                dismissed: row.get::<_, i64>(6)? != 0,
                endpoint_ip: row.get(8)?,
                endpoint_mac: row.get(9)?,
            })
        };

        let notifications: Vec<NotificationItem> = if has_search {
            let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![since, limit, offset, search_pattern], map_row)
                .map_err(|e| e.to_string())?;
            rows.filter_map(|r| r.ok()).collect()
        } else {
            let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![since, limit, offset], map_row)
                .map_err(|e| e.to_string())?;
            rows.filter_map(|r| r.ok()).collect()
        };

        Ok::<_, String>((notifications, total))
    })
    .await;

    match result {
        Ok(Ok((notifications, total))) => HttpResponse::Ok().json(NotificationsResponse { notifications, total }),
        _ => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to fetch notifications"
        })),
    }
}

#[derive(Deserialize)]
pub struct DismissRequest {
    ids: Vec<i64>,
}

#[post("/api/notifications/dismiss")]
pub async fn dismiss_notifications(body: Json<DismissRequest>) -> impl Responder {
    let ids = body.ids.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = new_connection();
        let placeholders: Vec<String> = ids.iter().enumerate().map(|(i, _)| format!("?{}", i + 1)).collect();
        let sql = format!(
            "UPDATE notifications SET dismissed = 1 WHERE id IN ({})",
            placeholders.join(",")
        );
        let params: Vec<Box<dyn rusqlite::ToSql>> =
            ids.iter().map(|id| Box::new(*id) as Box<dyn rusqlite::ToSql>).collect();
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        conn.execute(&sql, refs.as_slice()).map_err(|e| e.to_string())
    })
    .await;

    match result {
        Ok(Ok(count)) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "dismissed": count
        })),
        _ => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": "Failed to dismiss notifications"
        })),
    }
}

#[post("/api/notifications/clear")]
pub async fn clear_notifications() -> impl Responder {
    let result = tokio::task::spawn_blocking(move || {
        let conn = new_connection();
        conn.execute("UPDATE notifications SET dismissed = 1 WHERE dismissed = 0", [])
            .map_err(|e| e.to_string())
    })
    .await;

    match result {
        Ok(Ok(count)) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "dismissed": count
        })),
        _ => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": "Failed to clear notifications"
        })),
    }
}
