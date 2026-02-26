//! Network scanning API endpoints and scan result processing.

use actix_web::web::Json;
use actix_web::{HttpResponse, Responder, get, post};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tokio::sync::mpsc;

use crate::db::{insert_notification, insert_notification_with_endpoint_id, new_connection};
use crate::network::endpoint::{EndPoint, get_mac_vendor, is_valid_display_name};
use crate::scanner::manager::{ScanConfig, ScanManager};
use crate::scanner::{ScanResult, ScanType, check_scan_privileges};

use crate::web::probe_and_save_hp_printer_model_blocking;

// ============================================================================
// Global State
// ============================================================================

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
                                None,
                                None,
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

                // If endpoint still has no valid name, set it from SSDP friendly name or model
                try_set_endpoint_name_from_discovery(&conn, endpoint_id,
                    ssdp.friendly_name.as_deref().or(ssdp.model_name.as_deref()));
            }
        }
        ScanResult::Ndp(ndp) => {
            let ip_str = ndp.ip.to_string();
            let mac_str = ndp.mac.to_string();
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
                        match conn.execute(
                            "UPDATE endpoints SET snmp_vendor = ?1 WHERE id = ?2 AND (snmp_vendor IS NULL OR snmp_vendor = '')",
                            params![v, endpoint_id],
                        ) {
                            Ok(rows) if rows > 0 => {
                                insert_notification_with_endpoint_id(
                                    &conn, "vendor_identified",
                                    &format!("Vendor identified: {}", v),
                                    None, None, Some(endpoint_id),
                                );
                            }
                            Err(e) => eprintln!("Failed to save SNMP vendor: {}", e),
                            _ => {}
                        }
                    }

                    // Update model if we found one and endpoint doesn't have one
                    if let Some(m) = &model {
                        match conn.execute(
                            "UPDATE endpoints SET snmp_model = ?1 WHERE id = ?2 AND (snmp_model IS NULL OR snmp_model = '')",
                            params![m, endpoint_id],
                        ) {
                            Ok(rows) if rows > 0 => {
                                insert_notification_with_endpoint_id(
                                    &conn, "model_identified",
                                    &format!("Device model identified: {}", m),
                                    None, None, Some(endpoint_id),
                                );
                            }
                            Err(e) => eprintln!("Failed to save SNMP model: {}", e),
                            _ => {}
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

                // If name still not set, try vendor+model from SNMP sysDescr
                if let Some(ref sys_descr) = snmp.sys_descr {
                    let (vendor, model) = parse_snmp_sys_descr(sys_descr);
                    let name = model.or(vendor);
                    try_set_endpoint_name_from_discovery(&conn, endpoint_id, name.as_deref());
                }
            }
        }
    }

    Ok(())
}

/// Try to set endpoint name from a discovered name (SSDP friendly name, SNMP model, etc.)
/// Only updates if the endpoint currently has no valid display name.
/// Appends (2), (3), etc. if another endpoint already has the same name.
fn try_set_endpoint_name_from_discovery(conn: &Connection, endpoint_id: i64, name: Option<&str>) {
    let name = match name {
        Some(n) if !n.is_empty() && is_valid_display_name(n) => n,
        _ => return,
    };

    let current_name: String = conn
        .query_row(
            "SELECT COALESCE(name, '') FROM endpoints WHERE id = ?",
            params![endpoint_id],
            |row| row.get(0),
        )
        .unwrap_or_default();

    if !is_valid_display_name(&current_name) {
        let unique = EndPoint::make_unique_endpoint_name(conn, name, endpoint_id);
        let _ = conn.execute(
            "UPDATE endpoints SET name = ?1 WHERE id = ?2",
            params![unique, endpoint_id],
        );
    }
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
pub(super) fn parse_snmp_sys_descr(sys_descr: &str) -> (Option<String>, Option<String>) {
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
        // "hp " needs word boundary check to avoid matching "chapter", "graph ", etc.
        if *pattern == "hp " {
            if descr_lower.starts_with("hp ")
                || descr_lower.contains(" hp ")
                || descr_lower.contains("\nhp ")
            {
                vendor = Some(name.to_string());
                break;
            }
        } else if descr_lower.contains(pattern) {
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
