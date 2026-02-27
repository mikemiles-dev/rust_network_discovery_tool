//! Web server module. Implements the Actix-web REST API and HTML UI for endpoint
//! browsing, scan control, device management, and PCAP file import.

mod api;
use api::*;

mod graph;

mod helpers;
pub(crate) use helpers::*;

mod index;
use index::*;

use actix_web::{App, HttpServer, web::Data};
use actix_web::{HttpResponse, Responder, get};
use pnet::datalink;
use rust_embed::RustEmbed;
use tera::Tera;
use tokio::task;

use crate::scanner::ScanType;

#[derive(RustEmbed)]
#[folder = "templates/"]
struct Templates;

#[derive(RustEmbed)]
#[folder = "static/"]
struct StaticAssets;

fn get_interfaces() -> Vec<String> {
    let interfaces = datalink::interfaces();
    interfaces.into_iter().map(|iface| iface.name).collect()
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
