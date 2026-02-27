//! Endpoint API handlers: probing, details, CRUD operations, protocol queries, and table data.

mod crud;
mod details;
mod probing;
mod table;

pub use crud::*;
pub use details::*;
pub use probing::*;
pub use table::*;

use actix_web::{HttpResponse, Responder, get};
use serde::{Deserialize, Serialize};

use crate::web::{
    DEFAULT_SCAN_INTERVAL_MINUTES, NodeQuery, get_all_protocols, get_endpoints_for_protocol,
};

// ============================================================================
// Protocol API Endpoints
// ============================================================================

#[derive(Serialize)]
pub struct ProtocolEndpointsResponse {
    protocol: String,
    endpoints: Vec<String>,
}

#[derive(Deserialize)]
pub struct ProtocolQuery {
    scan_interval: Option<u64>,
    from_endpoint: Option<String>,
}

#[get("/api/protocol/{protocol}/endpoints")]
pub async fn get_protocol_endpoints(
    path: actix_web::web::Path<String>,
    query: actix_web::web::Query<ProtocolQuery>,
) -> impl Responder {
    let protocol = path.into_inner();
    let internal_minutes = query.scan_interval.unwrap_or(DEFAULT_SCAN_INTERVAL_MINUTES);

    let endpoints =
        get_endpoints_for_protocol(&protocol, internal_minutes, query.from_endpoint.as_deref());

    HttpResponse::Ok().json(ProtocolEndpointsResponse {
        protocol,
        endpoints,
    })
}

#[derive(Serialize)]
pub struct AllProtocolsResponse {
    protocols: Vec<String>,
}

#[get("/api/protocols")]
pub async fn get_all_protocols_api(query: actix_web::web::Query<NodeQuery>) -> impl Responder {
    let internal_minutes = query.scan_interval.unwrap_or(DEFAULT_SCAN_INTERVAL_MINUTES);
    let protocols = get_all_protocols(internal_minutes);
    HttpResponse::Ok().json(AllProtocolsResponse { protocols })
}
