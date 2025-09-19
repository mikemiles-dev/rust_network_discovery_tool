use actix_web::{HttpResponse, Responder, get, web::Data};
use tera::{Context, Tera};

use crate::writer::new_connection;

// Define a handler function for the web request
#[get("/")]
async fn index(tera: Data<Tera>) -> impl Responder {
    // let query = r#"
    //     SELECT
    //         src_e.ip AS src_ip,
    //         dst_e.ip AS dst_ip,
    //         c.sub_protocol
    //     FROM
    //         communications AS c
    //     LEFT JOIN
    //         endpoints AS src_e
    //         ON c.src_endpoint_id = src_e.id
    //     LEFT JOIN
    //         endpoints AS dst_e
    //         ON c.dst_endpoint_id = dst_e.id
    //     WHERE
    //         c.sub_protocol NOT IN ('HTTPS', 'HTTP', 'DNS')
    //     GROUP BY
    //         src_ip,
    //         dst_ip;
    // "#;

    // let conn = new_connection();
    // let mut stmt = conn.prepare(query).expect("Failed to prepare statement");

    // let rows = stmt
    //     .query_map([], |row| {
    //         Ok((
    //             row.get::<_, String>("src_ip")?,
    //             row.get::<_, String>("dst_ip")?,
    //             row.get::<_, String>("sub_protocol")?,
    //         ))
    //     })
    //     .expect("Failed to execute query");

    // let rows_string = rows
    //     .map(|r| format!("{:?}", r.unwrap()))
    //     .collect::<Vec<String>>()
    //     .join(", ");

    // format!("Hello, Actix!, {:?}", rows_string)
    let mut context = Context::new();
    context.insert("name", &"World");

    let rendered = tera
        .render("index.html", &context)
        .expect("Failed to render template");

    HttpResponse::Ok().body(rendered)
}
