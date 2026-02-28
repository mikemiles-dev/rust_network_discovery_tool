//! DNS-related API endpoints.

use actix_web::{HttpResponse, Responder, get};

use crate::db::get_pool;
use crate::web::get_dns_entries;

// ============================================================================
// DNS API Endpoints
// ============================================================================

#[get("/api/dns-entries")]
pub async fn get_dns_entries_api() -> impl Responder {
    HttpResponse::Ok().json(get_dns_entries())
}

#[derive(serde::Serialize)]
pub struct InternetDestinationsResponse {
    destinations: Vec<crate::network::endpoint::InternetDestination>,
}

/// Get all internet destinations
#[get("/api/internet")]
pub async fn get_internet_destinations() -> impl Responder {
    let result = tokio::task::spawn_blocking(|| {
        let conn = get_pool().get().expect("Failed to get pooled connection");
        crate::network::endpoint::EndPoint::get_internet_destinations(&conn)
    })
    .await;

    match result {
        Ok(Ok(destinations)) => {
            HttpResponse::Ok().json(InternetDestinationsResponse { destinations })
        }
        Ok(Err(e)) => {
            eprintln!("Failed to get internet destinations: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch internet destinations"
            }))
        }
        Err(e) => {
            eprintln!("Task error getting internet destinations: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal error"
            }))
        }
    }
}
