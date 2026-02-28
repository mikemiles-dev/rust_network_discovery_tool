//! Database query helpers, shared types, and SQL constants for the web module.

mod endpoint_queries;
mod model_queries;
mod protocol_queries;
mod types;

pub(crate) use endpoint_queries::*;
pub(crate) use model_queries::*;
pub(crate) use protocol_queries::*;
pub(crate) use types::*;

use std::collections::HashMap;

use rusqlite::params;

use crate::db::{get_pool, insert_notification_with_endpoint_id};
use crate::network::endpoint::{is_valid_display_name, strip_local_suffix};
use crate::network::mdns_lookup::MDnsLookup;

/// Try a fallible database operation; on error log and return the given default.
macro_rules! try_db {
    ($expr:expr, $default:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                eprintln!("database error: {e}");
                return $default;
            }
        }
    };
}

// Re-export the macro for use in sub-modules and sibling modules
pub(crate) use try_db;

/// SQL fragment for computing a consistent display_name for endpoints.
/// IMPORTANT: All queries that need display_name must use this exact pattern
/// to ensure consistent lookups across HashMaps with lowercase keys.
///
/// Priority: custom_name > valid name > MIN(hostname) > MIN(ip) > name
/// UUID pattern excluded: 36 chars with format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
pub(crate) const DISPLAY_NAME_SQL: &str = "COALESCE(e.custom_name,
    CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%' AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' AND NOT (LENGTH(e.name) = 36 AND e.name GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*') THEN e.name END,
    (SELECT MIN(hostname) FROM endpoint_attributes WHERE endpoint_id = e.id
     AND hostname IS NOT NULL AND hostname != ''
     AND hostname NOT LIKE '%:%' AND hostname NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
     AND NOT (LENGTH(hostname) = 36 AND hostname GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*')),
    (SELECT MIN(ip) FROM endpoint_attributes WHERE endpoint_id = e.id
     AND ip IS NOT NULL AND ip != ''),
    CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%' AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' AND NOT (LENGTH(e.name) = 36 AND e.name GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*') THEN e.name END)";

/// Build a SQL IN clause placeholder string for a given number of parameters
pub(crate) fn build_in_placeholders(count: usize) -> String {
    (0..count).map(|_| "?").collect::<Vec<_>>().join(",")
}

/// Build a boxed parameter vector from i64 slice (for endpoint IDs)
pub(crate) fn box_i64_params(ids: &[i64]) -> Vec<Box<dyn rusqlite::ToSql>> {
    ids.iter()
        .map(|id| Box::new(*id) as Box<dyn rusqlite::ToSql>)
        .collect()
}

/// Convert boxed params to reference slice for query execution
pub(crate) fn params_to_refs(params: &[Box<dyn rusqlite::ToSql>]) -> Vec<&dyn rusqlite::ToSql> {
    params.iter().map(|p| p.as_ref()).collect()
}

/// Find all endpoint IDs matching a display name, hostname, or IP (case-insensitive)
pub(crate) fn find_endpoint_ids(
    conn: &rusqlite::Connection,
    name: &str,
) -> Result<Vec<i64>, rusqlite::Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT DISTINCT e.id FROM endpoints e
         LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
         WHERE {DISPLAY_NAME_SQL} = ?1 COLLATE NOCASE
            OR LOWER(ea.hostname) = LOWER(?1)
            OR LOWER(ea.ip) = LOWER(?1)"
    ))?;
    let ids = stmt
        .query_map([name], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(ids)
}

/// Find the first endpoint ID matching a display name, hostname, or IP
pub(crate) fn find_endpoint_id(
    conn: &rusqlite::Connection,
    name: &str,
) -> Result<Option<i64>, rusqlite::Error> {
    Ok(find_endpoint_ids(conn, name)?.into_iter().next())
}

/// Check if a string looks like an IP address (IPv4 or IPv6)
pub(crate) fn looks_like_ip(s: &str) -> bool {
    // IPv6: contains colons
    if s.contains(':') {
        return true;
    }
    // IPv4: all parts are numeric when split by dots
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return true;
    }
    false
}

/// Try to resolve an IP-like name using mDNS cache or reverse DNS lookup
pub(crate) fn resolve_from_mdns_cache(name: &str) -> Option<String> {
    if looks_like_ip(name) {
        // probe_hostname checks cache first, then tries reverse DNS lookup
        MDnsLookup::probe_hostname(name)
            .map(|h| strip_local_suffix(&h))
            .filter(|h| is_valid_display_name(h))
    } else {
        None
    }
}

/// Check if a model string looks like an HP printer model
pub(crate) fn is_hp_printer_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.contains("hp ")
        || lower.starts_with("hp")
        || lower.contains("laserjet")
        || lower.contains("officejet")
        || lower.contains("deskjet")
        || lower.contains("envy")
}

/// Extract text content between HTML tags (case-insensitive tag matching)
pub(crate) fn extract_tag_content<'a>(
    html: &'a str,
    html_lower: &str,
    tag: &str,
) -> Option<&'a str> {
    let open_tag = format!("<{}>", tag);
    let close_tag = format!("</{}>", tag);
    let start = html_lower.find(&open_tag)?;
    let content_start = start + open_tag.len();
    let end_offset = html_lower[content_start..].find(&close_tag)?;
    Some(html[content_start..content_start + end_offset].trim())
}

/// Probe an HP printer's web interface to get its model name (blocking version)
/// HP printers typically expose their model in the HTML title or body
pub(crate) fn probe_hp_printer_model_blocking(ip: &str) -> Option<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;

    let url = format!("http://{}/", ip);
    let html = client.get(&url).send().ok()?.text().ok()?;
    let html_lower = html.to_lowercase();

    // Try title tag first - HP printers typically have titles like "HP Color LaserJet MFP M283fdw"
    if let Some(title) = extract_tag_content(&html, &html_lower, "title") {
        // Clean up the title - remove IP address and extra whitespace
        let model = title
            .split("&nbsp;")
            .next()
            .unwrap_or(title)
            .split("  ")
            .next()
            .unwrap_or(title)
            .trim();

        if is_hp_printer_model(model) {
            return Some(model.to_string());
        }
    }

    // Try h1 tag (common in HP printer pages)
    if let Some(h1_content) = extract_tag_content(&html, &html_lower, "h1")
        && is_hp_printer_model(h1_content)
    {
        return Some(h1_content.to_string());
    }

    None
}

/// Probe an HP printer and save the model to the database if found (blocking)
pub(crate) fn probe_and_save_hp_printer_model_blocking(ip: &str, endpoint_id: i64) {
    if let Some(model) = probe_hp_printer_model_blocking(ip) {
        // Save the model to the database
        if let Ok(conn) = get_pool().get() {
            let rows = conn.execute(
                "UPDATE endpoints SET ssdp_model = ?1 WHERE id = ?2 AND (ssdp_model IS NULL OR ssdp_model = '')",
                params![model, endpoint_id],
            ).unwrap_or(0);
            if rows > 0 {
                insert_notification_with_endpoint_id(
                    &conn,
                    "model_identified",
                    &format!("Device model identified: {}", model),
                    None,
                    None,
                    Some(endpoint_id),
                );
            }
        }
    }
}

/// Get combined endpoint stats (bytes, last_seen, online) in a single query
pub(crate) fn get_combined_endpoint_stats(
    endpoints: &[String],
    scan_interval: u64,
    active_threshold: u64,
) -> HashMap<String, EndpointStats> {
    let mut result: HashMap<String, EndpointStats> = HashMap::new();

    // Initialize all endpoints with defaults
    for endpoint in endpoints {
        result.insert(
            endpoint.to_lowercase(),
            EndpointStats {
                bytes: 0,
                last_seen: "-".to_string(),
                online: false,
            },
        );
    }

    let conn = try_db!(get_pool().get(), result);

    // UNION ALL to allow each branch to use its composite index
    let mut stmt = try_db!(
        conn.prepare(&format!(
            "SELECT
                {DISPLAY_NAME_SQL} AS display_name,
                COALESCE(SUM(c.bytes), 0) as total_bytes,
                MAX(c.last_seen_at) as last_seen
             FROM endpoints e
             INNER JOIN (
                 SELECT src_endpoint_id AS endpoint_id, bytes, last_seen_at FROM communications WHERE last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
                 UNION ALL
                 SELECT dst_endpoint_id AS endpoint_id, bytes, last_seen_at FROM communications WHERE last_seen_at >= (strftime('%s', 'now') - (?2 * 60))
             ) c ON e.id = c.endpoint_id
             GROUP BY e.id"
        )),
        result
    );

    let now = chrono::Utc::now().timestamp();
    let online_threshold = now - active_threshold as i64;

    let rows = try_db!(
        stmt.query_map([scan_interval, scan_interval], |row| {
            let name: String = row.get(0)?;
            let bytes: i64 = row.get(1)?;
            let last_seen: i64 = row.get(2)?;
            Ok((name, bytes, last_seen))
        }),
        result
    );

    for row in rows.flatten() {
        let (name, bytes, last_seen_ts) = row;
        let name_lower = name.to_lowercase();

        if let Some(stats) = result.get_mut(&name_lower) {
            stats.bytes = bytes;
            stats.online = last_seen_ts >= online_threshold;

            // Format last_seen as relative time
            let seconds_ago = now - last_seen_ts;
            stats.last_seen = if seconds_ago < 60 {
                "Just now".to_string()
            } else if seconds_ago < 3600 {
                format!("{}m ago", seconds_ago / 60)
            } else if seconds_ago < 86400 {
                format!("{}h ago", seconds_ago / 3600)
            } else {
                format!("{}d ago", seconds_ago / 86400)
            };
        }
    }

    result
}
