use actix_web::{
    App, HttpServer,
    web::{Data, Query},
};
use actix_web::{HttpResponse, Responder, get};
use dns_lookup::get_hostname;
use pnet::datalink;
use rust_embed::RustEmbed;
use std::collections::HashSet;
use tera::{Context, Tera};
use tokio::task;

use crate::db::new_connection;
use crate::network::endpoint::EndPoint;
use crate::network::protocol::ProtocolPort;
use rusqlite::{Connection, params};

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

    let mut endpoints: Vec<String> = rows
        .filter_map(|row| row.ok())
        .filter_map(|hostname: String| {
            if hostname.is_empty() {
                None
            } else {
                Some(hostname)
            }
        })
        .collect();

    // Get the local hostname
    let local_hostname = get_hostname().unwrap_or_else(|_| "Unknown".to_string());

    // Sort endpoints with local hostname first
    endpoints.sort_by(|a, b| {
        if a == &local_hostname {
            std::cmp::Ordering::Less
        } else if b == &local_hostname {
            std::cmp::Ordering::Greater
        } else {
            a.cmp(b)
        }
    });

    endpoints
}

fn get_protocols_for_endpoint(hostname: String, internal_minutes: u64) -> Vec<String> {
    let conn = new_connection();

    // Resolve the hostname/IP/MAC to endpoint IDs
    let endpoint_ids = resolve_identifier_to_endpoint_ids(&conn, &hostname);

    if endpoint_ids.is_empty() {
        return Vec::new();
    }

    // Build IN clause for endpoint IDs
    let placeholders = endpoint_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");

    let query = format!(
        "
        SELECT DISTINCT
            COALESCE(NULLIF(c.sub_protocol, ''), c.ip_header_protocol) as protocol
        FROM communications c
        WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
            AND (c.src_endpoint_id IN ({}) OR c.dst_endpoint_id IN ({}))
        ORDER BY protocol
        ",
        placeholders, placeholders
    );

    let mut stmt = conn.prepare(&query).expect("Failed to prepare statement");

    // Build parameters: internal_minutes + endpoint_ids (2 times for src and dst)
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    params.push(Box::new(internal_minutes));
    for _ in 0..2 {
        for id in &endpoint_ids {
            params.push(Box::new(*id));
        }
    }

    let params_ref: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    let rows = stmt
        .query_map(params_ref.as_slice(), |row| row.get::<_, String>(0))
        .expect("Failed to execute query");

    rows.filter_map(|row| row.ok()).collect::<Vec<String>>()
}

fn get_ports_for_endpoint(hostname: String, internal_minutes: u64) -> Vec<String> {
    let conn = new_connection();

    // Resolve the hostname/IP/MAC to endpoint IDs
    let endpoint_ids = resolve_identifier_to_endpoint_ids(&conn, &hostname);

    if endpoint_ids.is_empty() {
        return Vec::new();
    }

    // Build IN clause for endpoint IDs
    let placeholders = endpoint_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");

    let query = format!(
        "
        SELECT DISTINCT
            CASE
                WHEN c.src_endpoint_id IN ({0}) THEN c.destination_port
                WHEN c.dst_endpoint_id IN ({0}) THEN c.source_port
            END as port
        FROM communications c
        WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
            AND (c.src_endpoint_id IN ({0}) OR c.dst_endpoint_id IN ({0}))
            AND port IS NOT NULL
        ORDER BY CAST(port AS INTEGER)
        ",
        placeholders
    );

    let mut stmt = conn.prepare(&query).expect("Failed to prepare statement");

    // Build parameters: internal_minutes + endpoint_ids (4 times for the 4 IN clauses: 2 in CASE, 2 in WHERE)
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    params.push(Box::new(internal_minutes));
    for _ in 0..4 {
        for id in &endpoint_ids {
            params.push(Box::new(*id));
        }
    }

    let params_ref: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    let rows = stmt
        .query_map(params_ref.as_slice(), |row| row.get::<_, i64>(0))
        .expect("Failed to execute query");

    rows.filter_map(|row| row.ok())
        .map(|port| port.to_string())
        .collect::<Vec<String>>()
}

fn get_all_ips_macs_and_hostnames_from_single_hostname(
    hostname: String,
    internal_minutes: u64,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let conn = new_connection();

    // Resolve the hostname/IP/MAC to endpoint IDs
    let endpoint_ids = resolve_identifier_to_endpoint_ids(&conn, &hostname);

    if endpoint_ids.is_empty() {
        return (Vec::new(), Vec::new(), Vec::new());
    }

    // Build IN clause for endpoint IDs
    let placeholders = endpoint_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");

    let query = format!(
        "
        SELECT DISTINCT ea.ip, ea.mac, ea.hostname
        FROM endpoint_attributes ea
        INNER JOIN endpoints e ON ea.endpoint_id = e.id
        WHERE ea.endpoint_id IN (
            SELECT DISTINCT e2.id
            FROM endpoints e2
            INNER JOIN communications c
                ON e2.id = c.src_endpoint_id OR e2.id = c.dst_endpoint_id
            WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
        )
        AND ea.endpoint_id IN ({})
        ",
        placeholders
    );

    let mut stmt = conn.prepare(&query).expect("Failed to prepare statement");

    // Build parameters: internal_minutes + endpoint_ids
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    params.push(Box::new(internal_minutes));
    for id in &endpoint_ids {
        params.push(Box::new(*id));
    }

    let params_ref: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    let rows = stmt
        .query_map(params_ref.as_slice(), |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
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

/// Resolve an identifier (hostname, IP, or MAC) to endpoint IDs
/// Returns a Vec of endpoint IDs that match the identifier
fn resolve_identifier_to_endpoint_ids(conn: &Connection, identifier: &str) -> Vec<i64> {
    let mut endpoint_ids = Vec::new();

    // Try matching by endpoint name
    if let Ok(mut stmt) = conn.prepare("SELECT id FROM endpoints WHERE LOWER(name) = LOWER(?1)")
        && let Ok(rows) = stmt.query_map([identifier], |row| row.get::<_, i64>(0))
    {
        endpoint_ids.extend(rows.flatten());
    }

    // Try matching by IP or MAC in endpoint_attributes
    if let Ok(mut stmt) = conn.prepare(
        "SELECT DISTINCT endpoint_id FROM endpoint_attributes
         WHERE LOWER(ip) = LOWER(?1) OR LOWER(mac) = LOWER(?1)",
    ) && let Ok(rows) = stmt.query_map([identifier], |row| row.get::<_, i64>(0))
    {
        endpoint_ids.extend(rows.flatten());
    }

    endpoint_ids.sort_unstable();
    endpoint_ids.dedup();
    endpoint_ids
}

fn get_nodes(current_node: Option<String>, internal_minutes: u64) -> Vec<Node> {
    let current_node = match current_node {
        Some(hostname) => hostname,
        None => get_hostname().unwrap(),
    };

    let conn = new_connection();

    // Resolve the current_node identifier to endpoint IDs
    let endpoint_ids = resolve_identifier_to_endpoint_ids(&conn, &current_node);

    if endpoint_ids.is_empty() {
        return Vec::new();
    }

    // Build IN clause for endpoint IDs
    let placeholders = endpoint_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");

    let query = format!(
        "
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
    WHERE (c.src_endpoint_id IN ({}) OR c.dst_endpoint_id IN ({}))
    AND c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
    AND src_endpoint.name != '' AND dst_endpoint.name != ''
    AND src_endpoint.name IS NOT NULL AND dst_endpoint.name IS NOT NULL
    ",
        placeholders, placeholders
    );

    let mut stmt = conn.prepare(&query).expect("Failed to prepare statement");

    // Build parameters: endpoint_ids twice (for src and dst) + internal_minutes
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    for id in &endpoint_ids {
        params.push(Box::new(*id));
    }
    for id in &endpoint_ids {
        params.push(Box::new(*id));
    }
    params.push(Box::new(internal_minutes));

    let params_ref: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    let rows = stmt
        .query_map(params_ref.as_slice(), |row| {
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
            })
        })
        .expect("Failed to execute query");

    // Group by source and destination, collecting all protocols
    type CommKey = (String, String);
    type CommData = (Vec<String>, Option<String>, Option<String>);
    let mut comm_map: std::collections::HashMap<CommKey, CommData> =
        std::collections::HashMap::new();

    for row in rows.flatten() {
        let key = (row.src_hostname.clone(), row.dst_hostname.clone());
        let entry = comm_map
            .entry(key)
            .or_insert((vec![], row.src_ip.clone(), row.dst_ip.clone()));
        if !entry.0.contains(&row.sub_protocol) {
            entry.0.push(row.sub_protocol);
        }
    }

    // Convert to nodes with aggregated protocols
    comm_map
        .into_iter()
        .map(|((src, dst), (protocols, src_ip, dst_ip))| {
            let src_type = EndPoint::classify_endpoint(src_ip, Some(src.clone()));
            let dst_type = EndPoint::classify_endpoint(dst_ip, Some(dst.clone()));

            // Join protocols with comma for display, but keep them separate for filtering
            let sub_protocol = protocols.join(",");

            Node {
                src_hostname: src,
                dst_hostname: dst,
                sub_protocol,
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

fn get_all_endpoint_types(endpoints: &[String]) -> std::collections::HashMap<String, &'static str> {
    let conn = new_connection();
    let mut types = std::collections::HashMap::new();

    for endpoint in endpoints {
        // Get IP address for this endpoint from endpoint_attributes
        let mut stmt = conn
            .prepare(
                "SELECT ea.ip
             FROM endpoint_attributes ea
             INNER JOIN endpoints e ON ea.endpoint_id = e.id
             WHERE e.name = ?1 AND ea.ip IS NOT NULL
             LIMIT 1",
            )
            .expect("Failed to prepare statement");

        let ip = stmt
            .query_row([endpoint], |row| {
                let ip_value: Option<String> = row.get(0).ok();
                Ok(ip_value)
            })
            .ok()
            .flatten();

        // First check network-level classification (gateway, internet)
        if let Some(endpoint_type) = EndPoint::classify_endpoint(ip.clone(), Some(endpoint.clone()))
        {
            types.insert(endpoint.clone(), endpoint_type);
        } else {
            // If no network-level classification, check device type based on ports
            // Get ports for this endpoint
            let mut port_stmt = conn
                .prepare(
                    "SELECT DISTINCT
                        CASE
                            WHEN LOWER(src.name) = LOWER(?1) THEN c.destination_port
                            WHEN LOWER(dst.name) = LOWER(?1) THEN c.source_port
                        END as port
                    FROM communications c
                    INNER JOIN endpoints src ON c.src_endpoint_id = src.id
                    INNER JOIN endpoints dst ON c.dst_endpoint_id = dst.id
                    WHERE (LOWER(src.name) = LOWER(?1) OR LOWER(dst.name) = LOWER(?1))
                        AND port IS NOT NULL",
                )
                .expect("Failed to prepare port query statement");

            let ports: Vec<u16> = port_stmt
                .query_map([endpoint], |row| {
                    let port: Option<i64> = row.get(0).ok();
                    Ok(port.and_then(|p| u16::try_from(p).ok()))
                })
                .ok()
                .map(|rows| rows.filter_map(|row| row.ok()).flatten().collect())
                .unwrap_or_default();

            if let Some(device_type) =
                EndPoint::classify_device_type(Some(endpoint), ip.as_deref(), &ports)
            {
                types.insert(endpoint.clone(), device_type);
            }
        }
    }

    types
}

#[derive(Serialize)]
struct BytesStats {
    bytes_in: i64,
    bytes_out: i64,
}

fn get_bytes_for_endpoint(hostname: String, internal_minutes: u64) -> BytesStats {
    let conn = new_connection();

    // Bytes received (where this endpoint is the destination)
    let bytes_in: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(c.bytes), 0)
             FROM communications c
             JOIN endpoints dst ON c.dst_endpoint_id = dst.id
             WHERE LOWER(dst.name) = LOWER(?1)
             AND c.last_seen_at >= (strftime('%s', 'now') - (?2 * 60))",
            params![&hostname, &internal_minutes.to_string()],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Bytes sent (where this endpoint is the source)
    let bytes_out: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(c.bytes), 0)
             FROM communications c
             JOIN endpoints src ON c.src_endpoint_id = src.id
             WHERE LOWER(src.name) = LOWER(?1)
             AND c.last_seen_at >= (strftime('%s', 'now') - (?2 * 60))",
            params![&hostname, &internal_minutes.to_string()],
            |row| row.get(0),
        )
        .unwrap_or(0);

    BytesStats {
        bytes_in,
        bytes_out,
    }
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

// Define a handler function for the web request
#[get("/")]
async fn index(tera: Data<Tera>, query: Query<NodeQuery>) -> impl Responder {
    let hostname = get_hostname().unwrap_or_else(|_| "Unknown".to_string());
    let selected_endpoint = query.node.clone().unwrap_or_else(|| hostname.clone());

    let communications = get_nodes(query.node.clone(), query.scan_interval.unwrap_or(60));
    let endpoints = get_endpoints(&communications);
    let interfaces = get_interfaces();
    let supported_protocols = ProtocolPort::get_supported_protocols();
    let dropdown_endpoints = dropdown_endpoints(query.scan_interval.unwrap_or(60));
    let mut endpoint_types = get_endpoint_types(&communications);
    let dropdown_types = get_all_endpoint_types(&dropdown_endpoints);
    // Merge dropdown types into endpoint_types
    for (endpoint, type_str) in dropdown_types {
        endpoint_types.entry(endpoint).or_insert(type_str);
    }
    // Ensure all dropdown endpoints have a type (default to "device" if not classified)
    for endpoint in &dropdown_endpoints {
        endpoint_types.entry(endpoint.clone()).or_insert("device");
    }
    // Also ensure all endpoints from communications have a type
    for endpoint in &endpoints {
        endpoint_types.entry(endpoint.clone()).or_insert("device");
    }
    let (ips, macs, hostnames) = get_all_ips_macs_and_hostnames_from_single_hostname(
        selected_endpoint.clone(),
        query.scan_interval.unwrap_or(60),
    );
    let protocols =
        get_protocols_for_endpoint(selected_endpoint.clone(), query.scan_interval.unwrap_or(60));
    let ports =
        get_ports_for_endpoint(selected_endpoint.clone(), query.scan_interval.unwrap_or(60));
    let bytes_stats =
        get_bytes_for_endpoint(selected_endpoint.clone(), query.scan_interval.unwrap_or(60));

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
    context.insert("bytes_in", &bytes_stats.bytes_in);
    context.insert("bytes_out", &bytes_stats.bytes_out);

    let rendered = tera
        .render("index.html", &context)
        .expect("Failed to render template");

    HttpResponse::Ok().body(rendered)
}

#[derive(Deserialize)]
struct NodeQuery {
    node: Option<String>,
    scan_interval: Option<u64>,
}
