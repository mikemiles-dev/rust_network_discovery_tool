use actix_files::Files;
use actix_web::{
    App, HttpServer,
    web::{Data, Query},
};
use actix_web::{HttpResponse, Responder, get};
use dns_lookup::get_hostname;
use pnet::datalink;
use rusqlite::named_params;
use std::collections::HashSet;
use tera::{Context, Tera};
use tokio::task;

use crate::db::new_connection;
use crate::network::protocol::ProtocolPort;

use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Node {
    src_hostname: String,
    dst_hostname: String,
    sub_protocol: String,
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

fn get_all_ips_macs_and_hostnames_from_single_hostname(
    hostname: String,
    internal_minutes: u64,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let conn = new_connection();
    let mut stmt = conn
        .prepare("
            SELECT ip, mac, hostname FROM endpoint_attributes
            WHERE endpoint_id IN (
            SELECT DISTINCT e.id
            FROM endpoints e
            INNER JOIN communications c
                ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
                WHERE c.last_seen_at >= (strftime('%s', 'now') - (:internal_minutes * 60))
            )
            AND endpoint_id = (SELECT endpoint_id FROM endpoint_attributes WHERE LOWER(hostname) = LOWER(:hostname) LIMIT 1)
        ")
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
    c.sub_protocol
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

            Ok((
                row.get::<_, String>("src_hostname")?,
                row.get::<_, String>("dst_hostname")?,
                sub_protocol,
            ))
        })
        .expect("Failed to execute query");

    rows.filter_map(|row| match row.as_ref() {
        Ok(r) => Some(Node {
            src_hostname: r.0.clone(),
            dst_hostname: r.1.clone(),
            sub_protocol: r.2.clone(),
        }),
        Err(_e) => None,
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

pub fn start() {
    task::spawn_blocking(move || {
        println!("Starting web server");
        let sys = actix_rt::System::new();
        let tera = match Tera::new("templates/**/*") {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Failed to load templates: {}", e);
                eprintln!("Web server will not start");
                return;
            }
        };
        sys.block_on(async {
            let server = match HttpServer::new(move || {
                App::new()
                    .app_data(Data::new(tera.clone()))
                    .service(Files::new("/static", "static").show_files_listing())
                    .service(update_endpoint)
                    .service(index)
            })
            .bind(("127.0.0.1", 8080))
            {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to bind web server to 127.0.0.1:8080: {}", e);
                    return;
                }
            };

            println!("Web server listening on http://127.0.0.1:8080");
            if let Err(e) = server.run().await {
                eprintln!("Web server error: {}", e);
            }
        })
    });
}

#[get("/update_endpoint")]
async fn update_endpoint(query: Query<UpdateEndpointQuery>) -> impl Responder {
    let conn = new_connection();
    let mut stmt = match conn.prepare(
        "
            UPDATE endpoints
            SET name = :new_hostname
            WHERE LOWER(name) = LOWER(:hostname)
        ",
    ) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to prepare statement: {}", e));
        }
    };

    if let Err(e) = stmt.execute(
        named_params! { ":hostname": &query.hostname, ":new_hostname": &query.new_hostname },
    ) {
        return HttpResponse::InternalServerError()
            .body(format!("Failed to execute statement: {}", e));
    }

    HttpResponse::Ok().body("Endpoint updated")
}

// Define a handler function for the web request
#[get("/")]
async fn index(tera: Data<Tera>, query: Query<NodeQuery>) -> impl Responder {
    let communications = get_nodes(query.node.clone(), query.scan_interval.unwrap_or(60));
    let endpoints = get_endpoints(&communications);
    let interfaces = get_interfaces();
    let hostname = get_hostname().unwrap_or_else(|_| "Unknown".to_string());
    let supported_protocols = ProtocolPort::get_supported_protocols();
    let dropdown_endpoints = dropdown_endpoints(query.scan_interval.unwrap_or(60));
    let (ips, macs, hostnames) = get_all_ips_macs_and_hostnames_from_single_hostname(
        query.node.clone().unwrap_or_default(),
        query.scan_interval.unwrap_or(60),
    );
    let ports: Vec<String> = vec![];
    let protocols: Vec<String> = vec![];

    let mut context = Context::new();
    context.insert("communications", &communications);
    context.insert("endpoints", &endpoints);
    context.insert("interfaces", &interfaces);
    context.insert("hostname", &hostname);
    context.insert(
        "endpoint",
        &query.node.clone().unwrap_or_else(|| hostname.clone()),
    );
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
