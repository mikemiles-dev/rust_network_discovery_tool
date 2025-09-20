use actix_web::{HttpResponse, Responder, get, web::Data};
use tera::{Context, Tera};

use crate::writer::new_connection;

use serde::Serialize;

#[derive(Default, Debug, Serialize)]
pub struct Node {
    src_hostname: String,
    dst_hostname: String,
    sub_protocol: String,
}

// Define a handler function for the web request
#[get("/")]
async fn index(tera: Data<Tera>) -> impl Responder {
    let query = r#"
        SELECT
            src_e.hostname AS src_hostname,
            dst_e.hostname AS dst_hostname,
            c.sub_protocol
        FROM
            communications AS c
        LEFT JOIN
            endpoints AS src_e
            ON c.src_endpoint_id = src_e.id
        LEFT JOIN
            endpoints AS dst_e
            ON c.dst_endpoint_id = dst_e.id
        WHERE c.created_at BETWEEN (STRFTIME('%s', 'now') - 3600) AND STRFTIME('%s', 'now');
        GROUP BY
            src_ip,
            dst_ip,
            sub_protocol
    "#;

    let conn = new_connection();
    let mut stmt = conn.prepare(query).expect("Failed to prepare statement");

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>("src_hostname")?,
                row.get::<_, String>("dst_hostname")?,
                row.get::<_, String>("sub_protocol")
                    .unwrap_or("Unknown".to_string()),
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

    let endpoints = communications.iter().fold(vec![], |mut acc, comm| {
        if !acc.contains(&comm.src_hostname) {
            acc.push(comm.src_hostname.clone());
        }
        if !acc.contains(&comm.dst_hostname) {
            acc.push(comm.dst_hostname.clone());
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
