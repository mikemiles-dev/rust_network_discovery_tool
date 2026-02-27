//! Probe API endpoints: hostname, NetBIOS, ping, port scan, full endpoint probe, and model probe.

use actix_web::web::Json;
use actix_web::{HttpResponse, Responder, post};
use rusqlite::params;
use serde::Serialize;

use crate::db::{insert_notification_with_endpoint_id, new_connection, new_connection_result};
use crate::web::helpers::{EndpointNameRequest, IpRequest};
use crate::web::{DISPLAY_NAME_SQL, looks_like_ip, probe_hp_printer_model_blocking};

use super::super::scanning::parse_snmp_sys_descr;

#[derive(Serialize)]
pub struct ProbeResponse {
    ip: String,
    hostname: Option<String>,
    success: bool,
}

/// Probe a device for its hostname using reverse DNS/mDNS lookup
/// Also persists the hostname to the database if found
#[post("/api/probe-hostname")]
pub async fn probe_hostname(body: Json<IpRequest>) -> impl Responder {
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
pub async fn probe_netbios(body: Json<IpRequest>) -> impl Responder {
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

#[derive(Serialize)]
pub struct PingResponse {
    success: bool,
    latency_ms: Option<f64>,
    message: Option<String>,
}

/// Ping a device using ICMP echo
#[post("/api/ping")]
pub async fn ping_endpoint(body: Json<IpRequest>) -> impl Responder {
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
pub async fn port_scan_endpoint(body: Json<IpRequest>) -> impl Responder {
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
pub async fn probe_endpoint(body: Json<EndpointNameRequest>) -> impl Responder {
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

#[derive(Serialize)]
pub struct ProbeModelResponse {
    success: bool,
    message: String,
    model: Option<String>,
}

/// Probe a device's web interface to detect its model
#[post("/api/endpoint/probe/model")]
pub async fn probe_endpoint_model(body: Json<IpRequest>) -> impl Responder {
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
