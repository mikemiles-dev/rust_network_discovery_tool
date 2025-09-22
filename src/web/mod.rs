use actix_files::Files;
use actix_web::{
    App, HttpServer,
    web::{Data, Query},
};
use actix_web::{HttpResponse, Responder, get};
use dns_lookup::get_hostname;
use pnet::datalink;
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

fn dropdown_endpoints() -> Vec<String> {
    let conn = new_connection();
    let mut stmt = conn
        .prepare(
            "
            SELECT NAME FROM endpoints
            WHERE NAME IS NOT NULL AND NAME != ''
        ",
        )
        .expect("Failed to prepare statement");

    let rows = stmt
        .query_map([], |row| row.get(0))
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
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let conn = new_connection();
    let mut stmt = conn
        .prepare("SELECT  ip, mac, hostname FROM endpoint_attributes WHERE endpoint_id = (SELECT endpoint_id FROM endpoint_attributes WHERE LOWER(hostname) = LOWER(?1) LIMIT 1)
        ")
        .expect("Failed to prepare statement");

    let rows = stmt
        .query_map([hostname], |row| {
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
        if ips.contains(&hostname.clone().unwrap_or_default()) {
            continue;
        }
        hostnames.insert(hostname.unwrap_or_default());
    }

    let mut ips: Vec<String> = ips.into_iter().filter(|s| !s.is_empty()).collect();
    let mut macs: Vec<String> = macs.into_iter().filter(|s| !s.is_empty()).collect();
    let mut hostnames: Vec<String> = hostnames.into_iter().filter(|s| !s.is_empty()).collect();

    ips.sort();
    macs.sort();
    hostnames.sort();

    (ips, macs, hostnames)
}

fn get_nodes(current_node: Option<String>) -> Vec<Node> {
    let current_node = match current_node {
        Some(hostname) => hostname,
        None => get_hostname().unwrap(),
    };

    let query = format!(
        "
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
WHERE (LOWER(src_endpoint.name) = LOWER('{}') OR LOWER(dst_endpoint.name) = LOWER('{}'))
    AND c.created_at >= (strftime('%s', 'now') - 3600)
    AND src_endpoint.name != '' AND dst_endpoint.name != ''
    AND src_endpoint.name IS NOT NULL AND dst_endpoint.name IS NOT NULL
    ",
        current_node, current_node
    );

    let conn = new_connection();
    let mut stmt = conn.prepare(&query).expect("Failed to prepare statement");

    let rows = stmt
        .query_map([], |row| {
            let dst_port = row.get::<_, Option<u16>>("dst_port")?.unwrap_or(0);
            let header_protocol = row.get::<_, String>("header_protocol")?;
            let sub_protocol = match row.get::<_, String>("sub_protocol") {
                Ok(proto) => format!("{}:{}", header_protocol, proto),
                Err(_) => {
                    if dst_port == 0 {
                        header_protocol
                    } else {
                        format!("Unknown({})", dst_port)
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
        let tera = Tera::new("templates/**/*").unwrap();
        sys.block_on(async {
            HttpServer::new(move || {
                App::new()
                    .app_data(Data::new(tera.clone()))
                    .service(Files::new("/static", "static").show_files_listing())
                    .service(index)
            })
            .bind(("127.0.0.1", 8080))
            .unwrap()
            .run()
            .await
        })
        .expect("Failed to start Web server");
    });
}

// Define a handler function for the web request
#[get("/")]
async fn index(tera: Data<Tera>, query: Query<NodeQuery>) -> impl Responder {
    let communications = get_nodes(query.node.clone());
    let endpoints = get_endpoints(&communications);
    let interfaces = get_interfaces();
    let hostname = get_hostname().unwrap_or_else(|_| "Unknown".to_string());
    let supported_protocols = ProtocolPort::get_supported_protocols();
    let dropdown_endpoints = dropdown_endpoints();
    let (ips, macs, hostnames) =
        get_all_ips_macs_and_hostnames_from_single_hostname(query.node.clone().unwrap_or_default());
    let ports: Vec<String> = vec![];
    let protocols: Vec<String> = vec![];

    let mut context = Context::new();
    context.insert("communications", &communications);
    context.insert("endpoints", &endpoints);
    context.insert("interfaces", &interfaces);
    context.insert("hostname", &hostname);
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
struct NodeQuery {
    node: Option<String>,
    scan_interval: Option<u64>,
}
