//! Network scanning API endpoints.

use actix_web::web::Json;
use actix_web::{HttpResponse, Responder, get, post};
use serde::Deserialize;
use std::sync::OnceLock;
use tokio::sync::mpsc;

use crate::db::{insert_notification, new_connection};
use crate::scanner::manager::{ScanConfig, ScanManager};
use crate::scanner::{ScanResult, ScanType, check_scan_privileges};

use super::scan_results::process_scan_result;

pub use super::scan_models::parse_snmp_sys_descr;

/// Global scan manager instance
static SCAN_MANAGER: OnceLock<std::sync::Arc<ScanManager>> = OnceLock::new();

pub fn get_scan_manager() -> std::sync::Arc<ScanManager> {
    SCAN_MANAGER
        .get_or_init(|| {
            let (tx, mut rx) = mpsc::channel::<ScanResult>(1000);

            // Spawn a task to process scan results
            tokio::spawn(async move {
                while let Some(result) = rx.recv().await {
                    // Process scan result - create/update endpoint in database
                    if let Err(e) = process_scan_result(&result) {
                        eprintln!("Error processing scan result: {}", e);
                    }
                }
            });

            std::sync::Arc::new(ScanManager::new(tx))
        })
        .clone()
}

#[derive(Deserialize)]
pub struct StartScanRequest {
    scan_types: Vec<ScanType>,
}

use crate::web::helpers::ApiResponse;

#[post("/api/scan/start")]
pub async fn start_scan(body: Json<StartScanRequest>) -> impl Responder {
    let manager = get_scan_manager();
    let scan_types = body.scan_types.clone();

    match manager.start_scan(scan_types.clone()).await {
        Ok(()) => {
            let type_names: Vec<String> = scan_types.iter().map(|t| t.to_string()).collect();
            let details = format!("Scan types: {}", type_names.join(", "));
            tokio::task::spawn_blocking(move || {
                let conn = new_connection();
                insert_notification(
                    &conn,
                    "scan_started",
                    "Network scan started",
                    Some(&details),
                    None,
                );
            });

            HttpResponse::Ok().json(ApiResponse {
                success: true,
                message: "Scan started".to_string(),
            })
        }
        Err(e) => HttpResponse::BadRequest().json(ApiResponse {
            success: false,
            message: e,
        }),
    }
}

#[post("/api/scan/stop")]
pub async fn stop_scan() -> impl Responder {
    let manager = get_scan_manager();
    manager.stop_scan().await;

    tokio::task::spawn_blocking(|| {
        let conn = new_connection();
        insert_notification(&conn, "scan_stopped", "Network scan stopped", None, None);
    });

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        message: "Scan stopped".to_string(),
    })
}

#[get("/api/scan/status")]
pub async fn get_scan_status() -> impl Responder {
    let manager = get_scan_manager();
    let status = manager.get_status().await;

    HttpResponse::Ok().json(status)
}

#[get("/api/scan/capabilities")]
pub async fn get_scan_capabilities() -> impl Responder {
    let capabilities = check_scan_privileges();
    HttpResponse::Ok().json(capabilities)
}

#[get("/api/scan/config")]
pub async fn get_scan_config() -> impl Responder {
    let manager = get_scan_manager();
    let config = manager.get_config().await;

    HttpResponse::Ok().json(config)
}

#[post("/api/scan/config")]
pub async fn set_scan_config(body: Json<ScanConfig>) -> impl Responder {
    let manager = get_scan_manager();
    manager.set_config(body.into_inner()).await;

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        message: "Config updated".to_string(),
    })
}
