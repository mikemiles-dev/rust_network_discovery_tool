use actix_web::{HttpResponse, Responder, get, http::header, web::Data};
use dns_lookup::get_hostname;
use tera::{Context, Tera};

use crate::{network::communication, writer::new_connection};

use serde::Serialize;

#[derive(Default, Debug, Serialize)]
pub struct Node {
    src_hostname: String,
    dst_hostname: String,
    sub_protocol: String,
}

fn get_interfaces() -> Vec<String> {
    let query = r#"
        SELECT interface FROM endpoints GROUP BY interface;
    "#;

    let conn = new_connection();
    let mut stmt = conn.prepare(query).expect("Failed to prepare statement");

    let rows = stmt
        .query_map([], |row| Ok((row.get::<_, String>("interface")?,)))
        .expect("Failed to execute query");

    let interfaces = rows
        .filter_map(|row| match row.as_ref() {
            Ok(r) => Some(r.0.clone()),
            Err(_e) => None,
        })
        .collect::<Vec<String>>();
    interfaces
}

fn get_nodes() -> Vec<Node> {
    let query = r#"
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
        AND c.ip_header_protocol IS NOT "Icmpv6"
        GROUP BY
            src_hostname,
            dst_hostname,
            sub_protocol;
    "#;

    let conn = new_connection();
    let mut stmt = conn.prepare(query).expect("Failed to prepare statement");

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

    let communications = rows
        .filter_map(|row| match row.as_ref() {
            Ok(r) => Some(Node {
                src_hostname: r.0.clone(),
                dst_hostname: r.1.clone(),
                sub_protocol: r.2.clone(),
            }),
            Err(_e) => None,
        })
        .collect::<Vec<Node>>();

    communications
}

fn get_endpoints(communications: &Vec<Node>) -> Vec<String> {
    let endpoints = communications.iter().fold(vec![], |mut acc, comm| {
        if !acc.contains(&comm.src_hostname) {
            acc.push(comm.src_hostname.clone());
        }
        if !acc.contains(&comm.dst_hostname) {
            acc.push(comm.dst_hostname.clone());
        }
        acc
    });
    endpoints
}

// Define a handler function for the web request
#[get("/")]
async fn index(tera: Data<Tera>) -> impl Responder {
    let communications = get_nodes();
    let endpoints = get_endpoints(&communications);
    let interfaces = get_interfaces();
    let hostname = get_hostname().unwrap_or_else(|_| "Unknown".to_string());

    // format!("Hello, Actix!, {:?}", rows_string)
    let mut context = Context::new();

    context.insert("communications", &communications);
    context.insert("endpoints", &endpoints);
    context.insert("interfaces", &interfaces);
    context.insert("hostname", &hostname);

    let rendered = tera
        .render("index.html", &context)
        .expect("Failed to render template");

    HttpResponse::Ok().body(rendered)
}
