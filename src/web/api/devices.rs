//! Device control API endpoints (LG, Samsung, Roku, HP probe, etc.).

use actix_web::web::{Json, Query};
use actix_web::{HttpResponse, Responder, get, post};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use crate::device_control::DeviceController;

// ============================================================================
// Global State
// ============================================================================

/// Track endpoints currently being probed to prevent duplicate probes
static PROBING_ENDPOINTS: OnceLock<Mutex<HashSet<i64>>> = OnceLock::new();

pub fn get_probing_endpoints() -> &'static Mutex<HashSet<i64>> {
    PROBING_ENDPOINTS.get_or_init(|| Mutex::new(HashSet::new()))
}

// ============================================================================
// Device Control API Endpoints
// ============================================================================

#[derive(Deserialize)]
pub struct DeviceQuery {
    ip: String,
    device_type: Option<String>,
    hostname: Option<String>,
}

#[derive(Deserialize)]
pub struct DeviceCommandRequest {
    ip: String,
    command: String,
    device_type: String,
}

#[derive(Deserialize)]
pub struct LaunchAppRequest {
    ip: String,
    app_id: String,
    device_type: String,
}

#[get("/api/device/capabilities")]
pub async fn get_device_capabilities(query: Query<DeviceQuery>) -> impl Responder {
    let ip = query.ip.clone();
    let device_type = query.device_type.clone();
    let hostname = query.hostname.clone();

    // Run blocking device detection in a separate thread
    let capabilities = actix_web::web::block(move || {
        DeviceController::get_capabilities(&ip, device_type.as_deref(), hostname.as_deref())
    })
    .await;

    match capabilities {
        Ok(caps) => HttpResponse::Ok().json(caps),
        Err(_) => HttpResponse::InternalServerError().body("Failed to get device capabilities"),
    }
}

#[post("/api/device/command")]
pub async fn send_device_command(body: Json<DeviceCommandRequest>) -> impl Responder {
    let ip = body.ip.clone();
    let command = body.command.clone();
    let device_type = body.device_type.clone();

    let result =
        actix_web::web::block(move || DeviceController::send_command(&ip, &command, &device_type))
            .await;

    match result {
        Ok(r) if r.success => HttpResponse::Ok().json(r),
        Ok(r) => HttpResponse::BadRequest().json(r),
        Err(_) => HttpResponse::InternalServerError().body("Command failed"),
    }
}

#[post("/api/device/launch")]
pub async fn launch_device_app(body: Json<LaunchAppRequest>) -> impl Responder {
    let ip = body.ip.clone();
    let app_id = body.app_id.clone();
    let device_type = body.device_type.clone();

    let result =
        actix_web::web::block(move || DeviceController::launch_app(&ip, &app_id, &device_type))
            .await;

    match result {
        Ok(r) if r.success => HttpResponse::Ok().json(r),
        Ok(r) => HttpResponse::BadRequest().json(r),
        Err(_) => HttpResponse::InternalServerError().body("Launch failed"),
    }
}

#[derive(Deserialize)]
pub struct PairRequest {
    ip: String,
    device_type: String,
}

#[post("/api/device/pair")]
pub async fn pair_device(body: Json<PairRequest>) -> impl Responder {
    let ip = body.ip.clone();
    let device_type = body.device_type.clone();

    let result = actix_web::web::block(move || DeviceController::pair(&ip, &device_type)).await;

    match result {
        Ok(r) if r.success => HttpResponse::Ok().json(r),
        Ok(r) => HttpResponse::BadRequest().json(r),
        Err(_) => HttpResponse::InternalServerError().body("Pairing failed"),
    }
}

// ============================================================================
// LG ThinQ API Endpoints
// ============================================================================

#[derive(Deserialize)]
pub struct ThinQSetupRequest {
    pat_token: String,
    country_code: String,
}

#[derive(Serialize)]
pub struct ThinQStatusResponse {
    configured: bool,
    devices: Vec<ThinQDeviceInfo>,
}

#[derive(Serialize)]
pub struct ThinQDeviceInfo {
    device_id: String,
    device_type: String,
    name: String,
    model: Option<String>,
    online: bool,
}

#[post("/api/thinq/setup")]
pub async fn setup_thinq(body: Json<ThinQSetupRequest>) -> impl Responder {
    let pat_token = body.pat_token.clone();
    let country_code = body.country_code.clone();

    let result =
        actix_web::web::block(move || DeviceController::setup_thinq(&pat_token, &country_code))
            .await;

    match result {
        Ok(r) if r.success => HttpResponse::Ok().json(r),
        Ok(r) => HttpResponse::BadRequest().json(r),
        Err(_) => HttpResponse::InternalServerError().body("ThinQ setup failed"),
    }
}

#[get("/api/thinq/status")]
pub async fn get_thinq_status() -> impl Responder {
    let result = actix_web::web::block(move || {
        let configured = DeviceController::is_thinq_configured();
        let devices = if configured {
            DeviceController::list_thinq_devices()
                .unwrap_or_default()
                .into_iter()
                .map(|d| ThinQDeviceInfo {
                    device_id: d.device_id,
                    device_type: d.device_type,
                    name: d.device_alias,
                    model: d.model_name,
                    online: d.online,
                })
                .collect()
        } else {
            Vec::new()
        };

        ThinQStatusResponse {
            configured,
            devices,
        }
    })
    .await;

    match result {
        Ok(status) => HttpResponse::Ok().json(status),
        Err(_) => HttpResponse::InternalServerError().body("Failed to get ThinQ status"),
    }
}

#[get("/api/thinq/devices")]
pub async fn list_thinq_devices() -> impl Responder {
    let result = actix_web::web::block(move || {
        DeviceController::list_thinq_devices().map(|devices| {
            devices
                .into_iter()
                .map(|d| ThinQDeviceInfo {
                    device_id: d.device_id,
                    device_type: d.device_type,
                    name: d.device_alias,
                    model: d.model_name,
                    online: d.online,
                })
                .collect::<Vec<_>>()
        })
    })
    .await;

    match result {
        Ok(Ok(devices)) => HttpResponse::Ok().json(devices),
        Ok(Err(e)) => HttpResponse::BadRequest().body(e),
        Err(_) => HttpResponse::InternalServerError().body("Failed to list ThinQ devices"),
    }
}

#[post("/api/thinq/disconnect")]
pub async fn disconnect_thinq() -> impl Responder {
    let result = actix_web::web::block(DeviceController::disconnect_thinq).await;

    match result {
        Ok(success) => {
            if success {
                HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "message": "Disconnected from LG ThinQ"
                }))
            } else {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "message": "Failed to disconnect"
                }))
            }
        }
        Err(_) => HttpResponse::InternalServerError().body("Failed to disconnect ThinQ"),
    }
}
