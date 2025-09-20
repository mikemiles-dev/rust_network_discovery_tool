use actix_web::{HttpResponse, Responder, get, web::Data};
use tera::{Context, Tera};

use crate::{network::communication, writer::new_connection};

use serde::Serialize;
use serde_json::json;

#[derive(Default, Debug, Serialize)]
pub struct Node {
    src_ip: String,
    dst_ip: String,
    sub_protocol: String,
}

// Define a handler function for the web request
#[get("/")]
async fn index(tera: Data<Tera>) -> impl Responder {
    let query = r#"
        SELECT
            src_e.ip AS src_ip,
            dst_e.ip AS dst_ip,
            c.sub_protocol
        FROM
            communications AS c
        right JOIN
            endpoints AS src_e
            ON c.src_endpoint_id = src_e.id
        LEFT JOIN
            endpoints AS dst_e
            ON c.dst_endpoint_id = dst_e.id
        GROUP BY
            src_ip,
            dst_ip;
    "#;

    let conn = new_connection();
    let mut stmt = conn.prepare(query).expect("Failed to prepare statement");

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>("src_ip")?,
                row.get::<_, String>("dst_ip")?,
                row.get::<_, String>("sub_protocol")?,
            ))
        })
        .expect("Failed to execute query");

    let communications = rows
        .filter_map(|row| match row.as_ref() {
            Ok(r) => Some(Node {
                src_ip: r.0.clone(),
                dst_ip: r.1.clone(),
                sub_protocol: r.2.clone(),
            }),
            Err(_e) => None,
        })
        .collect::<Vec<Node>>();

    let endpoints = communications.iter().fold(vec![], |mut acc, comm| {
        if !acc.contains(&comm.src_ip) {
            acc.push(comm.src_ip.clone());
        }
        if !acc.contains(&comm.dst_ip) {
            acc.push(comm.dst_ip.clone());
        }
        acc
    });

    // format!("Hello, Actix!, {:?}", rows_string)
    let mut context = Context::new();

    context.insert("communications", &communications);
    context.insert("endpoints", &endpoints);

    let rendered = tera
        .render("index.html", &context)
        .expect("Failed to render template");

    HttpResponse::Ok().body(rendered)
}
