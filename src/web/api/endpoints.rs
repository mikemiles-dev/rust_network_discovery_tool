//! Endpoint table, details, merge, classification, and reclassification API handlers.

use actix_web::web::Json;
use actix_web::{HttpResponse, Responder, get, post};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::db::{
    get_setting_i64, insert_notification, insert_notification_with_endpoint_id, new_connection,
    new_connection_result,
};
use crate::network::communication::extract_model_from_vendor_class;
use crate::network::endpoint::{
    EndPoint, characterize_model, characterize_vendor, get_hostname_vendor, get_mac_vendor,
    get_model_from_hostname, get_model_from_mac, get_model_from_vendor_and_type,
    get_vendor_from_model, infer_model_with_context, normalize_model_name, strip_local_suffix,
};

use crate::web::{
    DISPLAY_NAME_SQL, EndpointDetailsResponse, NodeQuery, dropdown_endpoints,
    get_all_endpoint_types,
    get_all_ips_macs_and_hostnames_from_single_hostname, get_all_protocols,
    get_bytes_for_endpoint, get_combined_endpoint_stats, get_endpoint_ips_and_macs,
    get_endpoint_ssdp_models, get_endpoints_for_protocol, get_ports_for_endpoint,
    get_protocols_for_endpoint, looks_like_ip, probe_and_save_hp_printer_model_blocking,
    probe_hp_printer_model_blocking,
};

use super::devices::get_probing_endpoints;
use super::scanning::parse_snmp_sys_descr;

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
// Probe API Endpoints
// ============================================================================

#[derive(Deserialize)]
pub struct ProbeRequest {
    ip: String,
}

#[derive(Serialize)]
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
                    (
                        "model_changed",
                        format!("Model set to '{}' for {}", m, body.endpoint_name),
                    )
                } else {
                    (
                        "model_changed",
                        format!("Model cleared for {}", body.endpoint_name),
                    )
                };
                insert_notification(&conn, event, &title, None, Some(&body.endpoint_name));
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
                    (
                        "vendor_changed",
                        format!("Vendor set to '{}' for {}", v, body.endpoint_name),
                    )
                } else {
                    (
                        "vendor_changed",
                        format!("Vendor cleared for {}", body.endpoint_name),
                    )
                };
                insert_notification(&conn, event, &title, None, Some(&body.endpoint_name));
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
                        let _ = insert_scan_result_db(
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
                                match conn.execute(
                                    "UPDATE endpoints SET snmp_vendor = ?1 WHERE id = ?2 AND (snmp_vendor IS NULL OR snmp_vendor = '')",
                                    params![v, eid],
                                ) {
                                    Ok(rows) if rows > 0 => {
                                        insert_notification_with_endpoint_id(
                                            &conn, "vendor_identified",
                                            &format!("Vendor identified: {}", v),
                                            None, None, Some(eid),
                                        );
                                    }
                                    Err(e) => eprintln!("Failed to save SNMP vendor: {}", e),
                                    _ => {}
                                }
                            }
                            if let Some(m) = &model {
                                match conn.execute(
                                    "UPDATE endpoints SET snmp_model = ?1 WHERE id = ?2 AND (snmp_model IS NULL OR snmp_model = '')",
                                    params![m, eid],
                                ) {
                                    Ok(rows) if rows > 0 => {
                                        insert_notification_with_endpoint_id(
                                            &conn, "model_identified",
                                            &format!("Device model identified: {}", m),
                                            None, None, Some(eid),
                                        );
                                    }
                                    Err(e) => eprintln!("Failed to save SNMP model: {}", e),
                                    _ => {}
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

/// Insert a scan result into the database (used by probe_endpoint)
fn insert_scan_result_db(
    conn: &rusqlite::Connection,
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
                    let eid: Option<i64> = conn
                        .query_row(
                            "SELECT endpoint_id FROM endpoint_attributes WHERE ip = ?1 LIMIT 1",
                            params![ip],
                            |row| row.get(0),
                        )
                        .ok();
                    insert_notification_with_endpoint_id(
                        &conn,
                        "model_identified",
                        &format!("Device model identified: {}", model),
                        None,
                        None,
                        eid,
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
