use actix_files::Files;
use actix_web::{
    App, HttpServer,
    web::{Data, Query},
};
use actix_web::{HttpResponse, Responder, get};
use dns_lookup::get_hostname;
use pnet::datalink;
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

fn get_all_endpoint_nodes() -> Vec<String> {
    let conn = new_connection();
    let mut stmt = conn
        .prepare("SELECT DISTINCT hostname FROM endpoints WHERE hostname IS NOT NULL")
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

fn get_nodes(current_node: Option<String>) -> Vec<Node> {
    let current_node = match current_node {
        Some(hostname) => hostname,
        None => get_hostname().unwrap(),
    };

    let query = format!(
        "
        SELECT
            src_e.hostname AS src_hostname,
            dst_e.hostname AS dst_hostname,
            c.destination_port AS dst_port,
            c.ip_header_protocol as header_protocol,
            c.sub_protocol
        FROM
            communications AS c
        LEFT JOIN
            endpoints AS src_e
            ON c.src_endpoint_id = src_e.id
        LEFT JOIN
            endpoints AS dst_e
            ON c.dst_endpoint_id = dst_e.id
        WHERE c.created_at BETWEEN (STRFTIME('%s', 'now') - 3600) AND STRFTIME('%s', 'now')
        AND c.ip_header_protocol IS NOT 'unknown'
        AND c.source_port is NOT NULL
        AND c.destination_port is NOT NULL
        AND (src_e.hostname = '{}' OR dst_e.hostname = '{}')
        GROUP BY
            src_hostname,
            dst_hostname,
            sub_protocol;
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
    let protocols = ProtocolPort::get_all_protocols();
    let all_endpoint_nodes = get_all_endpoint_nodes();

    let mut context = Context::new();
    context.insert("communications", &communications);
    context.insert("endpoints", &endpoints);
    context.insert("interfaces", &interfaces);
    context.insert("hostname", &hostname);
    context.insert("protocols", &protocols);
    context.insert("selected_node", &query.node);
    context.insert("all_endpoint_nodes", &all_endpoint_nodes);
    context.insert("scan_interval", &query.scan_interval.unwrap_or(60));

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
