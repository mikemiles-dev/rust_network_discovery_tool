//! Settings, notifications, and capture control API endpoints.

use actix_web::web::{Json, Query};
use actix_web::{HttpResponse, Responder, get, post};
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::db::{get_all_settings, new_connection, set_setting};
use crate::web::helpers::ApiResponse;

// ============================================================================
// Settings Endpoints
// ============================================================================

#[derive(Serialize)]
pub struct SettingsResponse {
    settings: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct UpdateSettingRequest {
    key: String,
    value: String,
}

#[get("/api/settings")]
pub async fn get_settings() -> impl Responder {
    let settings = tokio::task::spawn_blocking(get_all_settings)
        .await
        .unwrap_or_default();

    HttpResponse::Ok().json(SettingsResponse { settings })
}

#[post("/api/settings")]
pub async fn update_setting(body: Json<UpdateSettingRequest>) -> impl Responder {
    let key = body.key.clone();
    let value = body.value.clone();

    let result = tokio::task::spawn_blocking(move || set_setting(&key, &value)).await;

    match result {
        Ok(Ok(())) => HttpResponse::Ok().json(ApiResponse {
            success: true,
            message: format!("Setting '{}' updated", body.key),
        }),
        _ => HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: "Failed to update setting".to_string(),
        }),
    }
}

// ============================================================================
// Capture Pause Endpoint
// ============================================================================

#[derive(Serialize)]
pub struct CapturePauseResponse {
    success: bool,
    paused: bool,
    message: String,
}

/// Get capture pause status
#[get("/api/capture/status")]
pub async fn get_capture_status() -> impl Responder {
    let paused = crate::is_capture_paused();
    HttpResponse::Ok().json(CapturePauseResponse {
        success: true,
        paused,
        message: if paused {
            "Capture is paused".to_string()
        } else {
            "Capture is running".to_string()
        },
    })
}

/// Toggle capture pause state
#[post("/api/capture/pause")]
pub async fn toggle_capture_pause() -> impl Responder {
    let currently_paused = crate::is_capture_paused();
    let new_state = !currently_paused;
    crate::set_capture_paused(new_state);

    HttpResponse::Ok().json(CapturePauseResponse {
        success: true,
        paused: new_state,
        message: if new_state {
            "Capture paused - live traffic will be ignored".to_string()
        } else {
            "Capture resumed - live traffic will be processed".to_string()
        },
    })
}

/// Set capture pause state explicitly
#[derive(Deserialize)]
pub struct SetCapturePauseRequest {
    paused: bool,
}

#[post("/api/capture/set-pause")]
pub async fn set_capture_pause(body: Json<SetCapturePauseRequest>) -> impl Responder {
    crate::set_capture_paused(body.paused);

    HttpResponse::Ok().json(CapturePauseResponse {
        success: true,
        paused: body.paused,
        message: if body.paused {
            "Capture paused - live traffic will be ignored".to_string()
        } else {
            "Capture resumed - live traffic will be processed".to_string()
        },
    })
}

// ============================================================================
// Notifications
// ============================================================================

#[derive(Deserialize)]
pub struct NotificationsQuery {
    since: Option<i64>,
    limit: Option<i64>,
    offset: Option<i64>,
    search: Option<String>,
    include_dismissed: Option<bool>,
}

#[derive(Serialize)]
pub struct NotificationItem {
    id: i64,
    created_at: i64,
    event_type: String,
    title: String,
    details: Option<String>,
    endpoint_name: Option<String>,
    dismissed: bool,
    endpoint_ip: Option<String>,
    endpoint_mac: Option<String>,
}

#[derive(Serialize)]
pub struct NotificationsResponse {
    notifications: Vec<NotificationItem>,
    total: i64,
}

#[get("/api/notifications")]
pub async fn get_notifications(query: Query<NotificationsQuery>) -> impl Responder {
    let since = query.since.unwrap_or(0);
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    let include_dismissed = query.include_dismissed.unwrap_or(false);
    let search = query.search.clone().unwrap_or_default();

    let result = tokio::task::spawn_blocking(move || {
        let conn = new_connection();

        let has_search = !search.is_empty();
        let search_pattern = format!("%{}%", search);

        // Build WHERE clause (use n. prefix since we JOIN with endpoints)
        let mut conditions = vec!["n.created_at > ?1"];
        if !include_dismissed {
            conditions.push("n.dismissed = 0");
        }
        if has_search {
            conditions.push("(n.title LIKE ?4 OR COALESCE(n.details, '') LIKE ?4 OR COALESCE(n.endpoint_name, '') LIKE ?4 OR n.event_type LIKE ?4)");
        }
        let where_clause = conditions.join(" AND ");

        // Get total count
        let count_sql = format!("SELECT COUNT(*) FROM notifications n WHERE {}", where_clause);
        let total: i64 = if has_search {
            conn.query_row(&count_sql, params![since, limit, offset, search_pattern], |row| row.get(0))
        } else {
            conn.query_row(&count_sql, params![since], |row| row.get(0))
        }.unwrap_or(0);

        // Resolve current endpoint display name via LEFT JOIN when endpoint_id is available.
        // This fixes stale names (e.g. "unknown" or bare IPs) in notifications created before
        // the endpoint received a proper name via mDNS, DHCP, SNMP, etc.
        let resolve_name_sql = "COALESCE(
                e.custom_name,
                CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%'
                     AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' THEN e.name END,
                (SELECT MIN(hostname) FROM endpoint_attributes WHERE endpoint_id = e.id
                 AND hostname IS NOT NULL AND hostname != ''
                 AND hostname NOT LIKE '%:%' AND hostname NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'),
                (SELECT MIN(ip) FROM endpoint_attributes WHERE endpoint_id = e.id
                 AND ip IS NOT NULL AND ip != ''),
                n.endpoint_name
            )"
        .to_string();

        // Get page of results with resolved endpoint names
        let sql = format!(
            "SELECT n.id, n.created_at, n.event_type, n.title, n.details, n.endpoint_name, n.dismissed,
                    {resolve_name} AS resolved_name,
                    (SELECT MIN(ip) FROM endpoint_attributes WHERE endpoint_id = e.id
                     AND ip IS NOT NULL AND ip != '') AS endpoint_ip,
                    (SELECT MIN(mac) FROM endpoint_attributes WHERE endpoint_id = e.id
                     AND mac IS NOT NULL AND mac != '') AS endpoint_mac
             FROM notifications n
             LEFT JOIN endpoints e ON n.endpoint_id = e.id
             WHERE {where_clause}
             ORDER BY n.created_at DESC LIMIT ?2 OFFSET ?3",
            resolve_name = resolve_name_sql,
            where_clause = where_clause
        );

        let map_row = |row: &rusqlite::Row| -> rusqlite::Result<NotificationItem> {
            let original_title: String = row.get(3)?;
            let original_endpoint_name: Option<String> = row.get(5)?;
            let resolved_name: Option<String> = row.get(7)?;

            // Rewrite the title if we have a resolved name that differs from the original
            let title = match (&resolved_name, &original_endpoint_name) {
                (Some(resolved), Some(original)) if resolved != original && !resolved.is_empty() => {
                    original_title.replace(original, resolved)
                }
                _ => original_title,
            };

            Ok(NotificationItem {
                id: row.get(0)?,
                created_at: row.get(1)?,
                event_type: row.get(2)?,
                title,
                details: row.get(4)?,
                endpoint_name: resolved_name.or(original_endpoint_name),
                dismissed: row.get::<_, i64>(6)? != 0,
                endpoint_ip: row.get(8)?,
                endpoint_mac: row.get(9)?,
            })
        };

        let notifications: Vec<NotificationItem> = if has_search {
            let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![since, limit, offset, search_pattern], map_row)
                .map_err(|e| e.to_string())?;
            rows.filter_map(|r| r.ok()).collect()
        } else {
            let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![since, limit, offset], map_row)
                .map_err(|e| e.to_string())?;
            rows.filter_map(|r| r.ok()).collect()
        };

        Ok::<_, String>((notifications, total))
    })
    .await;

    match result {
        Ok(Ok((notifications, total))) => HttpResponse::Ok().json(NotificationsResponse {
            notifications,
            total,
        }),
        _ => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to fetch notifications"
        })),
    }
}

#[derive(Deserialize)]
pub struct DismissRequest {
    ids: Vec<i64>,
}

#[post("/api/notifications/dismiss")]
pub async fn dismiss_notifications(body: Json<DismissRequest>) -> impl Responder {
    let ids = body.ids.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = new_connection();
        let placeholders: Vec<String> = ids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect();
        let sql = format!(
            "UPDATE notifications SET dismissed = 1 WHERE id IN ({})",
            placeholders.join(",")
        );
        let params: Vec<Box<dyn rusqlite::ToSql>> = ids
            .iter()
            .map(|id| Box::new(*id) as Box<dyn rusqlite::ToSql>)
            .collect();
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        conn.execute(&sql, refs.as_slice())
            .map_err(|e| e.to_string())
    })
    .await;

    match result {
        Ok(Ok(count)) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "dismissed": count
        })),
        _ => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": "Failed to dismiss notifications"
        })),
    }
}

#[post("/api/notifications/clear")]
pub async fn clear_notifications() -> impl Responder {
    let result = tokio::task::spawn_blocking(move || {
        let conn = new_connection();
        conn.execute(
            "UPDATE notifications SET dismissed = 1 WHERE dismissed = 0",
            [],
        )
        .map_err(|e| e.to_string())
    })
    .await;

    match result {
        Ok(Ok(count)) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "dismissed": count
        })),
        _ => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": "Failed to clear notifications"
        })),
    }
}

/// Lightweight identity endpoint used to detect if another instance is already running.
#[get("/api/instance")]
pub async fn get_instance() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "app": "awareness",
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
    }))
}
