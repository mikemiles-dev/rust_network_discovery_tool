//! Endpoint management API handlers: classify, rename, set model/vendor, delete, and merge.

use actix_web::web::Json;
use actix_web::{HttpResponse, Responder, post};
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::db::{insert_notification, new_connection};
use crate::network::endpoint::EndPoint;
use crate::web::helpers::ApiResponse;

#[derive(Deserialize)]
pub struct ClassifyRequest {
    endpoint_name: String,
    device_type: Option<String>,
}

#[post("/api/endpoint/classify")]
pub async fn set_endpoint_type(body: Json<ClassifyRequest>) -> impl Responder {
    let conn = new_connection();

    // If device_type is "auto" or empty, clear the manual override
    let device_type = match &body.device_type {
        Some(t) if t == "auto" || t.is_empty() => None,
        Some(t) => Some(t.as_str()),
        None => None,
    };

    match EndPoint::set_manual_device_type(&conn, &body.endpoint_name, device_type) {
        Ok(rows_updated) => {
            if rows_updated > 0 {
                insert_notification(
                    &conn,
                    "endpoint_reclassified",
                    &format!(
                        "Endpoint '{}' type {}",
                        body.endpoint_name,
                        device_type
                            .map(|t| format!("set to '{}'", t))
                            .unwrap_or_else(|| "cleared".to_string()),
                    ),
                    None,
                    Some(&body.endpoint_name),
                );

                HttpResponse::Ok().json(ApiResponse {
                    success: true,
                    message: format!(
                        "Device type {} for {}",
                        device_type
                            .map(|t| format!("set to '{}'", t))
                            .unwrap_or_else(|| "cleared".to_string()),
                        body.endpoint_name
                    ),
                })
            } else {
                HttpResponse::NotFound().json(ApiResponse {
                    success: false,
                    message: format!("Endpoint '{}' not found", body.endpoint_name),
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: format!("Database error: {}", e),
        }),
    }
}

#[derive(Deserialize)]
pub struct RenameRequest {
    endpoint_name: String,
    custom_name: Option<String>,
}

#[derive(Serialize)]
pub struct RenameResponse {
    success: bool,
    message: String,
    original_name: Option<String>,
}

#[post("/api/endpoint/rename")]
pub async fn rename_endpoint(body: Json<RenameRequest>) -> impl Responder {
    let conn = new_connection();

    // If custom_name is empty string, treat as None (clear the custom name)
    let custom_name = match &body.custom_name {
        Some(n) if n.is_empty() => None,
        Some(n) => Some(n.as_str()),
        None => None,
    };

    // When clearing the custom name, get the original name first so the UI can redirect
    let original_name = if custom_name.is_none() {
        EndPoint::get_original_name(&conn, &body.endpoint_name)
    } else {
        None
    };

    match EndPoint::set_custom_name(&conn, &body.endpoint_name, custom_name) {
        Ok(rows_updated) => {
            if rows_updated > 0 {
                insert_notification(
                    &conn,
                    "endpoint_renamed",
                    &format!(
                        "Endpoint '{}' renamed to '{}'",
                        body.endpoint_name,
                        custom_name.unwrap_or("(original)")
                    ),
                    None,
                    Some(&body.endpoint_name),
                );

                HttpResponse::Ok().json(RenameResponse {
                    success: true,
                    message: format!(
                        "Custom name {} for {}",
                        custom_name
                            .map(|n| format!("set to '{}'", n))
                            .unwrap_or_else(|| "cleared".to_string()),
                        body.endpoint_name
                    ),
                    original_name,
                })
            } else {
                HttpResponse::NotFound().json(RenameResponse {
                    success: false,
                    message: format!("Endpoint '{}' not found", body.endpoint_name),
                    original_name: None,
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(RenameResponse {
            success: false,
            message: format!("Database error: {}", e),
            original_name: None,
        }),
    }
}

#[derive(Deserialize)]
pub struct SetModelRequest {
    endpoint_name: String,
    model: Option<String>,
}

#[post("/api/endpoint/model")]
pub async fn set_endpoint_model(body: Json<SetModelRequest>) -> impl Responder {
    let conn = new_connection();

    // If model is "auto" or empty, clear the custom model
    let model = match &body.model {
        Some(m) if m == "auto" || m.is_empty() => None,
        Some(m) => Some(m.as_str()),
        None => None,
    };

    match EndPoint::set_custom_model(&conn, &body.endpoint_name, model) {
        Ok(rows_updated) => {
            if rows_updated > 0 {
                let (event, title) = if let Some(m) = model {
                    (
                        "model_changed",
                        format!("Model set to '{}' for {}", m, body.endpoint_name),
                    )
                } else {
                    (
                        "model_changed",
                        format!("Model cleared for {}", body.endpoint_name),
                    )
                };
                insert_notification(&conn, event, &title, None, Some(&body.endpoint_name));
                HttpResponse::Ok().json(ApiResponse {
                    success: true,
                    message: format!(
                        "Model {} for {}",
                        model
                            .map(|m| format!("set to '{}'", m))
                            .unwrap_or_else(|| "cleared".to_string()),
                        body.endpoint_name
                    ),
                })
            } else {
                HttpResponse::NotFound().json(ApiResponse {
                    success: false,
                    message: format!("Endpoint '{}' not found", body.endpoint_name),
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: format!("Database error: {}", e),
        }),
    }
}

#[derive(Deserialize)]
pub struct SetVendorRequest {
    endpoint_name: String,
    vendor: Option<String>,
}

#[post("/api/endpoint/vendor")]
pub async fn set_endpoint_vendor(body: Json<SetVendorRequest>) -> impl Responder {
    let conn = new_connection();

    // If vendor is "auto" or empty, clear the custom vendor
    let vendor = match &body.vendor {
        Some(v) if v == "auto" || v.is_empty() => None,
        Some(v) => Some(v.as_str()),
        None => None,
    };

    match EndPoint::set_custom_vendor(&conn, &body.endpoint_name, vendor) {
        Ok(rows_updated) => {
            if rows_updated > 0 {
                let (event, title) = if let Some(v) = vendor {
                    (
                        "vendor_changed",
                        format!("Vendor set to '{}' for {}", v, body.endpoint_name),
                    )
                } else {
                    (
                        "vendor_changed",
                        format!("Vendor cleared for {}", body.endpoint_name),
                    )
                };
                insert_notification(&conn, event, &title, None, Some(&body.endpoint_name));
                HttpResponse::Ok().json(ApiResponse {
                    success: true,
                    message: format!(
                        "Vendor {} for {}",
                        vendor
                            .map(|v| format!("set to '{}'", v))
                            .unwrap_or_else(|| "cleared".to_string()),
                        body.endpoint_name
                    ),
                })
            } else {
                HttpResponse::NotFound().json(ApiResponse {
                    success: false,
                    message: format!("Endpoint '{}' not found", body.endpoint_name),
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: format!("Database error: {}", e),
        }),
    }
}

#[derive(Deserialize)]
pub struct DeleteEndpointRequest {
    endpoint_name: String,
}

/// Delete an endpoint and all associated data (communications, attributes, scan results)
#[post("/api/endpoint/delete")]
pub async fn delete_endpoint(body: Json<DeleteEndpointRequest>) -> impl Responder {
    let conn = new_connection();

    // First, find the endpoint ID(s) matching the name
    let endpoint_ids = match crate::web::helpers::find_endpoint_ids(&conn, &body.endpoint_name) {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("Error querying for endpoint to delete: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Database error: {}", e),
            });
        }
    };

    if endpoint_ids.is_empty() {
        return HttpResponse::NotFound().json(ApiResponse {
            success: false,
            message: format!("Endpoint '{}' not found", body.endpoint_name),
        });
    }

    // Delete in order to respect foreign key constraints
    let mut updated_comms = 0;
    let mut deleted_attrs = 0;
    let mut deleted_scans = 0;
    let mut deleted_endpoints = 0;

    for endpoint_id in &endpoint_ids {
        // Nullify this endpoint's ID in communications instead of deleting them
        // This preserves communication history for other endpoints
        updated_comms += conn
            .execute(
                "UPDATE communications SET src_endpoint_id = NULL WHERE src_endpoint_id = ?1",
                params![endpoint_id],
            )
            .unwrap_or(0);
        updated_comms += conn
            .execute(
                "UPDATE communications SET dst_endpoint_id = NULL WHERE dst_endpoint_id = ?1",
                params![endpoint_id],
            )
            .unwrap_or(0);

        // Delete scan results
        deleted_scans += conn
            .execute(
                "DELETE FROM scan_results WHERE endpoint_id = ?1",
                params![endpoint_id],
            )
            .unwrap_or(0);

        // Delete endpoint attributes
        deleted_attrs += conn
            .execute(
                "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
                params![endpoint_id],
            )
            .unwrap_or(0);

        // Delete open ports
        conn.execute(
            "DELETE FROM open_ports WHERE endpoint_id = ?1",
            params![endpoint_id],
        )
        .unwrap_or(0);

        // Delete scan results
        conn.execute(
            "DELETE FROM scan_results WHERE endpoint_id = ?1",
            params![endpoint_id],
        )
        .unwrap_or(0);

        // Delete the endpoint itself
        deleted_endpoints += conn
            .execute("DELETE FROM endpoints WHERE id = ?1", params![endpoint_id])
            .unwrap_or(0);
    }

    insert_notification(
        &conn,
        "endpoint_deleted",
        &format!("Endpoint '{}' deleted", body.endpoint_name),
        Some(&format!(
            "{} endpoint(s), {} attribute(s), {} scan result(s) removed",
            deleted_endpoints, deleted_attrs, deleted_scans
        )),
        Some(&body.endpoint_name),
    );

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        message: format!(
            "Deleted endpoint '{}': {} endpoint(s), {} attribute(s), {} scan result(s) (preserved {} communication records)",
            body.endpoint_name, deleted_endpoints, deleted_attrs, deleted_scans, updated_comms
        ),
    })
}

#[derive(Deserialize)]
pub struct MergeEndpointsRequest {
    /// The endpoint to keep (target) - can be name, custom_name, hostname, or IP
    target: String,
    /// The endpoint to merge and delete (source) - can be name, custom_name, hostname, or IP
    source: String,
}

/// Merge two endpoints into one, keeping the target and deleting the source
/// All communications, attributes, scan results, and ports from source are moved to target
#[post("/api/endpoint/merge")]
pub async fn merge_endpoints(body: Json<MergeEndpointsRequest>) -> impl Responder {
    let conn = new_connection();

    // Find the target endpoint ID
    let target_id = match crate::web::helpers::find_endpoint_id(&conn, &body.target) {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse {
                success: false,
                message: format!("Target endpoint '{}' not found", body.target),
            });
        }
        Err(e) => {
            eprintln!("Error preparing target query: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Database error: {}", e),
            });
        }
    };

    // Find the source endpoint ID
    let source_id = match crate::web::helpers::find_endpoint_id(&conn, &body.source) {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse {
                success: false,
                message: format!("Source endpoint '{}' not found", body.source),
            });
        }
        Err(e) => {
            eprintln!("Error preparing source query: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Database error: {}", e),
            });
        }
    };

    // Check they're not the same endpoint
    if target_id == source_id {
        return HttpResponse::BadRequest().json(ApiResponse {
            success: false,
            message: "Cannot merge an endpoint with itself".to_string(),
        });
    }

    // Perform the merge
    let mut merged_comms = 0;
    let mut merged_attrs = 0;
    let mut merged_ports = 0;
    let mut merged_scans = 0;

    // Merge communications
    merged_comms += conn
        .execute(
            "UPDATE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
            params![target_id, source_id],
        )
        .unwrap_or(0);
    merged_comms += conn
        .execute(
            "UPDATE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
            params![target_id, source_id],
        )
        .unwrap_or(0);

    // Merge endpoint attributes (INSERT OR IGNORE to skip duplicates)
    merged_attrs += conn
        .execute(
            "INSERT OR IGNORE INTO endpoint_attributes (created_at, endpoint_id, mac, ip, hostname, dhcp_client_id, dhcp_vendor_class)
             SELECT created_at, ?1, mac, ip, hostname, dhcp_client_id, dhcp_vendor_class
             FROM endpoint_attributes
             WHERE endpoint_id = ?2",
            params![target_id, source_id],
        )
        .unwrap_or(0);

    // Delete source attributes after copying
    conn.execute(
        "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
        params![source_id],
    )
    .unwrap_or(0);

    // Merge open ports (UPDATE OR IGNORE to skip duplicates)
    merged_ports += conn
        .execute(
            "UPDATE OR IGNORE open_ports SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            params![target_id, source_id],
        )
        .unwrap_or(0);

    // Delete any remaining source ports (duplicates)
    conn.execute(
        "DELETE FROM open_ports WHERE endpoint_id = ?1",
        params![source_id],
    )
    .unwrap_or(0);

    // Merge scan results
    merged_scans += conn
        .execute(
            "UPDATE scan_results SET endpoint_id = ?1 WHERE endpoint_id = ?2",
            params![target_id, source_id],
        )
        .unwrap_or(0);

    // Copy over any useful metadata from source that target doesn't have
    let _ = conn.execute(
        "UPDATE endpoints SET
            ssdp_model = COALESCE((SELECT ssdp_model FROM endpoints WHERE id = ?1), (SELECT ssdp_model FROM endpoints WHERE id = ?2)),
            ssdp_friendly_name = COALESCE((SELECT ssdp_friendly_name FROM endpoints WHERE id = ?1), (SELECT ssdp_friendly_name FROM endpoints WHERE id = ?2)),
            netbios_name = COALESCE((SELECT netbios_name FROM endpoints WHERE id = ?1), (SELECT netbios_name FROM endpoints WHERE id = ?2)),
            auto_device_type = COALESCE((SELECT auto_device_type FROM endpoints WHERE id = ?1), (SELECT auto_device_type FROM endpoints WHERE id = ?2))
         WHERE id = ?1",
        params![target_id, source_id],
    );

    // Reassign notifications so they point to the surviving endpoint
    let _ = conn.execute(
        "UPDATE notifications SET endpoint_id = ?1 WHERE endpoint_id = ?2",
        params![target_id, source_id],
    );

    // Delete the source endpoint
    let deleted = conn
        .execute("DELETE FROM endpoints WHERE id = ?1", params![source_id])
        .unwrap_or(0);

    if deleted > 0 {
        insert_notification(
            &conn,
            "endpoints_merged",
            &format!("Merged '{}' into '{}'", body.source, body.target),
            Some(&format!(
                "{} communication(s), {} attribute(s), {} port(s), {} scan result(s)",
                merged_comms, merged_attrs, merged_ports, merged_scans
            )),
            Some(&body.target),
        );

        HttpResponse::Ok().json(ApiResponse {
            success: true,
            message: format!(
                "Merged '{}' into '{}': {} communication(s), {} attribute(s), {} port(s), {} scan result(s)",
                body.source, body.target, merged_comms, merged_attrs, merged_ports, merged_scans
            ),
        })
    } else {
        HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: "Failed to delete source endpoint after merge".to_string(),
        })
    }
}
