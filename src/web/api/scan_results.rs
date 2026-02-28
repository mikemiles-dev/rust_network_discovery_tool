//! Scan result processing and database persistence.

use rusqlite::{Connection, OptionalExtension, params};

use crate::db::{get_pool, insert_notification_with_endpoint_id};
use crate::network::endpoint::{EndPoint, get_mac_vendor, is_valid_display_name};
use crate::scanner::ScanResult;

use crate::web::probe_and_save_hp_printer_model_blocking;

use super::scan_models::{
    is_more_specific_model, is_ssdp_model_consistent_with_endpoint, parse_snmp_sys_descr,
};

/// Process a scan result and store in database with retry logic
pub(super) fn process_scan_result(result: &ScanResult) -> Result<(), String> {
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
    let conn = get_pool().get().expect("Failed to get pooled connection");

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
                try_set_endpoint_name_from_discovery(
                    &conn,
                    endpoint_id,
                    ssdp.friendly_name.as_deref().or(ssdp.model_name.as_deref()),
                );
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
