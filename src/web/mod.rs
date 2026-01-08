use actix_web::{
    App, HttpServer,
    web::{Data, Query},
};
use actix_web::{HttpResponse, Responder, get};
use dns_lookup::get_hostname;
use pnet::datalink;
use rusqlite::named_params;
use rust_embed::RustEmbed;
use std::collections::HashSet;
use tera::{Context, Tera};
use tokio::task;

use crate::db::new_connection;
use crate::network::endpoint::EndPoint;
use crate::network::protocol::ProtocolPort;

use serde::{Deserialize, Serialize};

#[derive(RustEmbed)]
#[folder = "templates/"]
struct Templates;

#[derive(RustEmbed)]
#[folder = "static/"]
struct StaticAssets;

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Node {
    src_hostname: String,
    dst_hostname: String,
    sub_protocol: String,
    src_type: Option<&'static str>,
    dst_type: Option<&'static str>,
}

// Internal struct for query results
struct CommunicationRow {
    src_hostname: String,
    dst_hostname: String,
    sub_protocol: String,
    src_ip: Option<String>,
    dst_ip: Option<String>,
}

fn get_interfaces() -> Vec<String> {
    let interfaces = datalink::interfaces();
    interfaces.into_iter().map(|iface| iface.name).collect()
}

fn dropdown_endpoints(internal_minutes: u64) -> Vec<String> {
    let conn = new_connection();
    let mut stmt = conn
        .prepare(
            "
            SELECT DISTINCT e.NAME
            FROM endpoints e
            INNER JOIN communications c
                ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
                WHERE c.last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
                AND e.NAME IS NOT NULL AND e.NAME != ''
        ",
        )
        .expect("Failed to prepare statement");

    let rows = stmt
        .query_map([internal_minutes], |row| row.get(0))
        .expect("Failed to execute query");

    rows.filter_map(|row| row.ok())
        .filter_map(|hostname: String| {
            if hostname.is_empty() {
                None
            } else {
                Some(hostname)
            }
        })
        .collect::<Vec<String>>()
}

fn get_protocols_for_endpoint(hostname: String, internal_minutes: u64) -> Vec<String> {
    let conn = new_connection();
    let mut stmt = conn
        .prepare(
            "
            SELECT DISTINCT
                CASE
                    WHEN c.sub_protocol IS NOT NULL AND c.sub_protocol != ''
                    THEN c.ip_header_protocol || ':' || c.sub_protocol
                    ELSE c.ip_header_protocol
                END as protocol
            FROM communications c
            INNER JOIN endpoints src ON c.src_endpoint_id = src.id
            INNER JOIN endpoints dst ON c.dst_endpoint_id = dst.id
            WHERE c.last_seen_at >= (strftime('%s', 'now') - (:internal_minutes * 60))
                AND (LOWER(src.name) = LOWER(:hostname) OR LOWER(dst.name) = LOWER(:hostname))
            ORDER BY protocol
        ",
        )
        .expect("Failed to prepare statement");

    let rows = stmt
        .query_map(
            named_params! { ":hostname": hostname, ":internal_minutes": internal_minutes },
            |row| row.get::<_, String>(0),
        )
        .expect("Failed to execute query");

    rows.filter_map(|row| row.ok()).collect::<Vec<String>>()
}

fn get_all_ips_macs_and_hostnames_from_single_hostname(
    hostname: String,
    internal_minutes: u64,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let conn = new_connection();
    let mut stmt = conn
        .prepare(
            "
            SELECT DISTINCT ea.ip, ea.mac, ea.hostname
            FROM endpoint_attributes ea
            INNER JOIN endpoints e ON ea.endpoint_id = e.id
            WHERE ea.endpoint_id IN (
                SELECT DISTINCT e2.id
                FROM endpoints e2
                INNER JOIN communications c
                    ON e2.id = c.src_endpoint_id OR e2.id = c.dst_endpoint_id
                WHERE c.last_seen_at >= (strftime('%s', 'now') - (:internal_minutes * 60))
            )
            AND (
                ea.endpoint_id IN (
                    SELECT endpoint_id FROM endpoint_attributes
                    WHERE LOWER(hostname) = LOWER(:hostname)
                )
                OR ea.endpoint_id IN (
                    SELECT id FROM endpoints
                    WHERE LOWER(name) = LOWER(:hostname)
                )
            )
        ",
        )
        .expect("Failed to prepare statement");

    let rows = stmt
        .query_map(
            named_params! { ":hostname": hostname, ":internal_minutes": internal_minutes },
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .expect("Failed to execute query");

    let mut ips = HashSet::new();
    let mut macs = HashSet::new();
    let mut hostnames = HashSet::new();

    for (ip, mac, hostname) in rows.flatten() {
        ips.insert(ip.unwrap_or_default());
        macs.insert(mac.unwrap_or_default());
        let hostname_str = hostname.unwrap_or_default();
        if ips.contains(&hostname_str) {
            continue;
        }
        // Normalize to lowercase to prevent case-sensitive duplicates
        hostnames.insert(hostname_str.to_lowercase());
    }

    let mut ips: Vec<String> = ips.into_iter().filter(|s| !s.is_empty()).collect();
    let mut macs: Vec<String> = macs.into_iter().filter(|s| !s.is_empty()).collect();
    let mut hostnames: Vec<String> = hostnames.into_iter().filter(|s| !s.is_empty()).collect();

    ips.sort();
    macs.sort();
    hostnames.sort();

    (ips, macs, hostnames)
}

fn get_nodes(current_node: Option<String>, internal_minutes: u64) -> Vec<Node> {
    let current_node = match current_node {
        Some(hostname) => hostname,
        None => get_hostname().unwrap(),
    };

    let query = "
    SELECT
    src_endpoint.name AS src_hostname,
    dst_endpoint.name AS dst_hostname,
    c.destination_port as dst_port,
    c.ip_header_protocol as header_protocol,
    c.sub_protocol,
    (SELECT ip FROM endpoint_attributes WHERE endpoint_id = src_endpoint.id LIMIT 1) AS src_ip,
    (SELECT ip FROM endpoint_attributes WHERE endpoint_id = dst_endpoint.id LIMIT 1) AS dst_ip
    FROM communications AS c
    LEFT JOIN endpoints AS src_endpoint
    ON c.src_endpoint_id = src_endpoint.id
    LEFT JOIN endpoints AS dst_endpoint
    ON c.dst_endpoint_id = dst_endpoint.id
    WHERE (LOWER(src_endpoint.name) = LOWER(?1) OR LOWER(dst_endpoint.name) = LOWER(?1))
    AND c.last_seen_at >= (strftime('%s', 'now') - (?2 * 60))
    AND src_endpoint.name != '' AND dst_endpoint.name != ''
    AND src_endpoint.name IS NOT NULL AND dst_endpoint.name IS NOT NULL
    ";

    let conn = new_connection();
    let mut stmt = conn.prepare(query).expect("Failed to prepare statement");

    let rows = stmt
        .query_map([&current_node, &internal_minutes.to_string()], |row| {
            let dst_port = row.get::<_, Option<u16>>("dst_port")?.unwrap_or(0);
            let header_protocol = row.get::<_, String>("header_protocol")?;
            let sub_protocol = match row.get::<_, String>("sub_protocol") {
                Ok(proto) => format!("{}:{}", header_protocol, proto),
                Err(_) => {
                    if dst_port == 0 {
                        header_protocol
                    } else {
                        "Unknown".to_string()
                    }
                }
            };

            Ok(CommunicationRow {
                src_hostname: row.get("src_hostname")?,
                dst_hostname: row.get("dst_hostname")?,
                sub_protocol,
                src_ip: row.get::<_, Option<String>>("src_ip").ok().flatten(),
                dst_ip: row.get::<_, Option<String>>("dst_ip").ok().flatten(),
            })
        })
        .expect("Failed to execute query");

    // Group communications by source and destination to reduce visual clutter
    struct CommData {
        protocols: Vec<String>,
        src_ip: Option<String>,
        dst_ip: Option<String>,
    }

    let mut comm_map: std::collections::HashMap<(String, String), CommData> =
        std::collections::HashMap::new();

    for row in rows.flatten() {
        let key = (row.src_hostname.clone(), row.dst_hostname.clone());
        let entry = comm_map.entry(key).or_insert(CommData {
            protocols: vec![],
            src_ip: row.src_ip,
            dst_ip: row.dst_ip,
        });
        entry.protocols.push(row.sub_protocol);
    }

    // Convert back to Node structs with aggregated protocols
    comm_map
        .into_iter()
        .map(|((src, dst), mut data)| {
            // Remove duplicates and sort
            data.protocols.sort();
            data.protocols.dedup();

            // Limit to most important protocols to avoid clutter
            let protocol_label = if data.protocols.len() > 3 {
                format!(
                    "{} (+{})",
                    data.protocols[..2].join(", "),
                    data.protocols.len() - 2
                )
            } else {
                data.protocols.join(", ")
            };

            // Classify endpoints
            let src_type = EndPoint::classify_endpoint(data.src_ip);
            let dst_type = EndPoint::classify_endpoint(data.dst_ip);

            Node {
                src_hostname: src,
                dst_hostname: dst,
                sub_protocol: protocol_label,
                src_type,
                dst_type,
            }
        })
        .collect::<Vec<Node>>()
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

pub fn start(preferred_port: u16) {
    task::spawn_blocking(move || {
        println!("Starting web server");
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
                        .service(update_endpoint)
                        .service(index)
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

#[get("/update_endpoint")]
async fn update_endpoint(query: Query<UpdateEndpointQuery>) -> impl Responder {
    let conn = new_connection();

    // Update endpoints table where name matches OR where any endpoint_attribute matches
    let mut stmt = match conn.prepare(
        "
            UPDATE endpoints
            SET name = :new_hostname
            WHERE id IN (
                SELECT DISTINCT endpoint_id
                FROM endpoint_attributes
                WHERE LOWER(hostname) = LOWER(:hostname)
                   OR LOWER(ip) = LOWER(:hostname)
            )
            OR LOWER(name) = LOWER(:hostname)
        ",
    ) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to prepare statement: {}", e));
        }
    };

    match stmt.execute(
        named_params! { ":hostname": &query.hostname, ":new_hostname": &query.new_hostname },
    ) {
        Ok(rows_affected) => {
            if rows_affected == 0 {
                return HttpResponse::NotFound().body(format!(
                    "No endpoint found with identifier: {}",
                    query.hostname
                ));
            }
            HttpResponse::Ok().body(format!(
                "Endpoint updated ({} rows affected)",
                rows_affected
            ))
        }
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Failed to execute statement: {}", e))
        }
    }
}

// Define a handler function for the web request
#[get("/")]
async fn index(tera: Data<Tera>, query: Query<NodeQuery>) -> impl Responder {
    let hostname = get_hostname().unwrap_or_else(|_| "Unknown".to_string());
    let selected_endpoint = query.node.clone().unwrap_or_else(|| hostname.clone());

    let communications = get_nodes(query.node.clone(), query.scan_interval.unwrap_or(60));
    let endpoints = get_endpoints(&communications);
    let endpoint_types = get_endpoint_types(&communications);
    let interfaces = get_interfaces();
    let supported_protocols = ProtocolPort::get_supported_protocols();
    let dropdown_endpoints = dropdown_endpoints(query.scan_interval.unwrap_or(60));
    let (ips, macs, hostnames) = get_all_ips_macs_and_hostnames_from_single_hostname(
        selected_endpoint.clone(),
        query.scan_interval.unwrap_or(60),
    );
    let protocols =
        get_protocols_for_endpoint(selected_endpoint.clone(), query.scan_interval.unwrap_or(60));
    let ports: Vec<String> = vec![];

    let mut context = Context::new();
    context.insert("communications", &communications);
    context.insert("endpoints", &endpoints);
    context.insert("endpoint_types", &endpoint_types);
    context.insert("interfaces", &interfaces);
    context.insert("hostname", &hostname);
    context.insert("endpoint", &selected_endpoint);
    context.insert("supported_protocols", &supported_protocols);
    context.insert("selected_node", &query.node);
    context.insert("dropdown_endpoints", &dropdown_endpoints);
    context.insert("scan_interval", &query.scan_interval.unwrap_or(60));
    context.insert("ips", &ips);
    context.insert("macs", &macs);
    context.insert("hostnames", &hostnames);
    context.insert("ports", &ports);
    context.insert("protocols", &protocols);

    let rendered = tera
        .render("index.html", &context)
        .expect("Failed to render template");

    HttpResponse::Ok().body(rendered)
}

#[derive(Deserialize)]
struct UpdateEndpointQuery {
    hostname: String,
    new_hostname: String,
}

#[derive(Deserialize)]
struct NodeQuery {
    node: Option<String>,
    scan_interval: Option<u64>,
}
