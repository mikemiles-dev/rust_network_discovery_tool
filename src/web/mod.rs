//! Web server module. Implements the Actix-web REST API and HTML UI for endpoint
//! browsing, scan control, device management, and PCAP file import.

mod api;
use api::*;

use actix_web::{
    App, HttpServer,
    web::{Data, Query},
};
use actix_web::{HttpResponse, Responder, get};
use dns_lookup::get_hostname;
use pnet::datalink;
use rust_embed::RustEmbed;
use std::collections::{HashMap, HashSet};
use tera::{Context, Tera};
use tokio::task;

use crate::db::{
    get_setting_i64, insert_notification_with_endpoint_id, new_connection_result,
};

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
use crate::network::communication::extract_model_from_vendor_class;
use crate::network::endpoint::{
    EndPoint, characterize_model, characterize_vendor, get_mac_vendor, get_model_from_hostname,
    get_model_from_mac, get_model_from_vendor_and_type, infer_model_with_context,
    is_valid_display_name, normalize_model_name, strip_local_suffix,
};
use crate::network::mdns_lookup::MDnsLookup;
use crate::network::protocol::ProtocolPort;
use crate::scanner::ScanType;
use rusqlite::{Connection, params};

// Combined endpoint stats (bytes, last_seen, online) from single query
#[derive(Clone)]
pub(super) struct EndpointStats {
    pub(super) bytes: i64,
    pub(super) last_seen: String,
    pub(super) online: bool,
}

/// Get combined endpoint stats (bytes, last_seen, online) in a single query
pub(super) fn get_combined_endpoint_stats(
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

    let conn = try_db!(new_connection_result(), result);

    // Single query to get bytes, last_seen for all endpoints
    let mut stmt = try_db!(
        conn.prepare(&format!(
            "SELECT
                {DISPLAY_NAME_SQL} AS display_name,
                COALESCE(SUM(c.bytes), 0) as total_bytes,
                MAX(c.last_seen_at) as last_seen
             FROM endpoints e
             INNER JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
             WHERE c.last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
             GROUP BY e.id"
        )),
        result
    );

    let now = chrono::Utc::now().timestamp();
    let online_threshold = now - active_threshold as i64;

    let rows = try_db!(
        stmt.query_map([scan_interval], |row| {
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

use serde::{Deserialize, Serialize};

// ============================================================================
// SQL Helper Functions and Constants
// ============================================================================

/// SQL fragment for computing a consistent display_name for endpoints.
/// IMPORTANT: All queries that need display_name must use this exact pattern
/// to ensure consistent lookups across HashMaps with lowercase keys.
///
/// Priority: custom_name > valid name > MIN(hostname) > MIN(ip) > name
/// UUID pattern excluded: 36 chars with format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
pub(super) const DISPLAY_NAME_SQL: &str = "COALESCE(e.custom_name,
    CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%' AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' AND NOT (LENGTH(e.name) = 36 AND e.name GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*') THEN e.name END,
    (SELECT MIN(hostname) FROM endpoint_attributes WHERE endpoint_id = e.id
     AND hostname IS NOT NULL AND hostname != ''
     AND hostname NOT LIKE '%:%' AND hostname NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
     AND NOT (LENGTH(hostname) = 36 AND hostname GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*')),
    (SELECT MIN(ip) FROM endpoint_attributes WHERE endpoint_id = e.id
     AND ip IS NOT NULL AND ip != ''),
    CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%' AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' AND NOT (LENGTH(e.name) = 36 AND e.name GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*') THEN e.name END)";

/// Build a SQL IN clause placeholder string for a given number of parameters
pub(super) fn build_in_placeholders(count: usize) -> String {
    (0..count).map(|_| "?").collect::<Vec<_>>().join(",")
}

/// Build a boxed parameter vector from i64 slice (for endpoint IDs)
pub(super) fn box_i64_params(ids: &[i64]) -> Vec<Box<dyn rusqlite::ToSql>> {
    ids.iter()
        .map(|id| Box::new(*id) as Box<dyn rusqlite::ToSql>)
        .collect()
}

/// Convert boxed params to reference slice for query execution
pub(super) fn params_to_refs(params: &[Box<dyn rusqlite::ToSql>]) -> Vec<&dyn rusqlite::ToSql> {
    params.iter().map(|p| p.as_ref()).collect()
}

// ============================================================================
// Type Definitions
// ============================================================================

#[derive(RustEmbed)]
#[folder = "templates/"]
struct Templates;

#[derive(RustEmbed)]
#[folder = "static/"]
struct StaticAssets;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    src_hostname: String,
    dst_hostname: String,
    sub_protocol: String,
    src_type: Option<&'static str>,
    dst_type: Option<&'static str>,
    src_port: Option<String>,
    dst_port: Option<String>,
}

// Internal struct for query results
struct CommunicationRow {
    src_hostname: String,
    dst_hostname: String,
    sub_protocol: String,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
}

fn get_interfaces() -> Vec<String> {
    let interfaces = datalink::interfaces();
    interfaces.into_iter().map(|iface| iface.name).collect()
}

/// Check if a string looks like an IP address (IPv4 or IPv6)
pub(super) fn looks_like_ip(s: &str) -> bool {
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
pub(super) fn resolve_from_mdns_cache(name: &str) -> Option<String> {
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
pub(super) fn is_hp_printer_model(model: &str) -> bool {
    let lower = model.to_lowercase();
    lower.contains("hp ")
        || lower.starts_with("hp")
        || lower.contains("laserjet")
        || lower.contains("officejet")
        || lower.contains("deskjet")
        || lower.contains("envy")
}

/// Extract text content between HTML tags (case-insensitive tag matching)
pub(super) fn extract_tag_content<'a>(
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
pub(super) fn probe_hp_printer_model_blocking(ip: &str) -> Option<String> {
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
pub(super) fn probe_and_save_hp_printer_model_blocking(ip: &str, endpoint_id: i64) {
    if let Some(model) = probe_hp_printer_model_blocking(ip) {
        // Save the model to the database
        if let Ok(conn) = new_connection_result() {
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

pub(super) fn dropdown_endpoints(internal_minutes: u64) -> Vec<String> {
    let conn = match new_connection_result() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dropdown_endpoints: failed to open database: {}", e);
            return Vec::new();
        }
    };
    // Use JOIN instead of correlated subquery for better performance
    // Fall back to IP address if no valid hostname exists (will be resolved via mDNS)
    // Filter out endpoints that ONLY have locally administered (randomized) MACs
    let mut stmt = match conn
        .prepare(
            "
            SELECT DISTINCT COALESCE(e.custom_name,
                CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%' AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' AND NOT (LENGTH(e.name) = 36 AND e.name GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*') THEN e.name END,
                ea_best.hostname,
                ea_ip.ip,
                CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%' AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' AND NOT (LENGTH(e.name) = 36 AND e.name GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*') THEN e.name END) AS display_name
            FROM endpoints e
            INNER JOIN communications c
                ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
            LEFT JOIN (
                SELECT endpoint_id, MIN(hostname) AS hostname
                FROM endpoint_attributes
                WHERE hostname IS NOT NULL AND hostname != ''
                  AND hostname NOT LIKE '%:%'
                  AND hostname NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
                  AND NOT (LENGTH(hostname) = 36 AND hostname GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*')
                GROUP BY endpoint_id
            ) ea_best ON ea_best.endpoint_id = e.id
            LEFT JOIN (
                SELECT endpoint_id, MIN(ip) AS ip
                FROM endpoint_attributes
                WHERE ip IS NOT NULL AND ip != ''
                GROUP BY endpoint_id
            ) ea_ip ON ea_ip.endpoint_id = e.id
            WHERE c.last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
            AND (
                -- Has at least one real (non-locally-administered) MAC
                EXISTS (
                    SELECT 1 FROM endpoint_attributes ea2
                    WHERE ea2.endpoint_id = e.id
                    AND ea2.mac IS NOT NULL AND ea2.mac != ''
                    AND UPPER(SUBSTR(ea2.mac, 2, 1)) NOT IN ('2', '6', 'A', 'E')
                )
                OR
                -- Has a user-set custom name
                e.custom_name IS NOT NULL
                OR
                -- Has a valid hostname (identified even without real MAC)
                (e.name IS NOT NULL AND e.name != ''
                 AND e.name NOT LIKE '%:%'
                 AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
                 AND NOT (LENGTH(e.name) = 36 AND e.name GLOB
                   '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*'))
            )
        ",
        ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("dropdown_endpoints: failed to prepare statement: {}", e);
            return Vec::new();
        }
    };

    let rows = match stmt.query_map([internal_minutes], |row| row.get(0)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dropdown_endpoints: failed to execute query: {}", e);
            return Vec::new();
        }
    };

    let mut endpoints: Vec<String> = rows
        .filter_map(|row| row.ok())
        .filter_map(|hostname: String| {
            if hostname.is_empty() {
                None
            } else {
                // If the hostname looks like an IP, try to resolve it from mDNS cache
                Some(resolve_from_mdns_cache(&hostname).unwrap_or(hostname))
            }
        })
        .collect();

    // Get the local hostname (strip .local suffix to match stored endpoint names)
    let local_hostname =
        strip_local_suffix(&get_hostname().unwrap_or_else(|_| "Unknown".to_string()));

    // Sort endpoints with local hostname first
    endpoints.sort_by(|a, b| {
        if a == &local_hostname {
            std::cmp::Ordering::Less
        } else if b == &local_hostname {
            std::cmp::Ordering::Greater
        } else {
            a.cmp(b)
        }
    });

    endpoints
}

pub(super) fn get_protocols_for_endpoint(hostname: String, internal_minutes: u64) -> Vec<String> {
    let conn = try_db!(new_connection_result(), Vec::new());

    let endpoint_ids = resolve_identifier_to_endpoint_ids(&conn, &hostname);
    if endpoint_ids.is_empty() {
        return Vec::new();
    }

    let placeholders = build_in_placeholders(endpoint_ids.len());
    let query = format!(
        "SELECT DISTINCT
            COALESCE(NULLIF(c.sub_protocol, ''), c.ip_header_protocol) as protocol
        FROM communications c
        WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
            AND (c.src_endpoint_id IN ({0}) OR c.dst_endpoint_id IN ({0}))
        ORDER BY protocol",
        placeholders
    );

    let mut stmt = try_db!(conn.prepare(&query), Vec::new());

    // Build parameters: internal_minutes + endpoint_ids (2 times for src and dst)
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(internal_minutes)];
    params.extend(box_i64_params(&endpoint_ids));
    params.extend(box_i64_params(&endpoint_ids));

    let rows = try_db!(
        stmt.query_map(params_to_refs(&params).as_slice(), |row| {
            row.get::<_, String>(0)
        }),
        Vec::new()
    );

    rows.filter_map(|row| row.ok()).collect()
}

/// Get endpoints using a protocol, optionally filtered to only those communicating with a specific endpoint
pub(super) fn get_endpoints_for_protocol(
    protocol: &str,
    internal_minutes: u64,
    from_endpoint: Option<&str>,
) -> Vec<String> {
    let conn = try_db!(new_connection_result(), Vec::new());

    match from_endpoint {
        Some(endpoint) => {
            // Get endpoints that communicated with the specified endpoint over this protocol
            let endpoint_ids = resolve_identifier_to_endpoint_ids(&conn, endpoint);
            if endpoint_ids.is_empty() {
                return Vec::new();
            }

            let placeholders = build_in_placeholders(endpoint_ids.len());
            let query = format!(
                "SELECT DISTINCT e.name
                FROM endpoints e
                INNER JOIN communications c ON (c.src_endpoint_id = e.id OR c.dst_endpoint_id = e.id)
                WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
                    AND (COALESCE(NULLIF(c.sub_protocol, ''), c.ip_header_protocol) = ?)
                    AND e.name IS NOT NULL AND e.name != ''
                    AND (
                        (c.src_endpoint_id IN ({0}) AND c.dst_endpoint_id = e.id)
                        OR (c.dst_endpoint_id IN ({0}) AND c.src_endpoint_id = e.id)
                    )
                ORDER BY e.name",
                placeholders
            );

            let mut stmt = try_db!(conn.prepare(&query), Vec::new());

            let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> =
                vec![Box::new(internal_minutes), Box::new(protocol.to_string())];
            params_vec.extend(box_i64_params(&endpoint_ids));
            params_vec.extend(box_i64_params(&endpoint_ids));

            let rows = try_db!(
                stmt.query_map(params_to_refs(&params_vec).as_slice(), |row| {
                    row.get::<_, String>(0)
                }),
                Vec::new()
            );

            rows.filter_map(|row| row.ok()).collect()
        }
        None => {
            // Get all endpoints using this protocol
            let query = "SELECT DISTINCT e.name
                FROM endpoints e
                INNER JOIN communications c ON (c.src_endpoint_id = e.id OR c.dst_endpoint_id = e.id)
                WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
                    AND (COALESCE(NULLIF(c.sub_protocol, ''), c.ip_header_protocol) = ?)
                    AND e.name IS NOT NULL AND e.name != ''
                ORDER BY e.name";

            let mut stmt = try_db!(conn.prepare(query), Vec::new());

            let rows = try_db!(
                stmt.query_map(params![internal_minutes, protocol], |row| {
                    row.get::<_, String>(0)
                }),
                Vec::new()
            );

            rows.filter_map(|row| row.ok()).collect()
        }
    }
}

/// Get all protocols seen across all endpoints
pub(super) fn get_all_protocols(internal_minutes: u64) -> Vec<String> {
    let conn = try_db!(new_connection_result(), Vec::new());

    let query =
        "SELECT DISTINCT COALESCE(NULLIF(c.sub_protocol, ''), c.ip_header_protocol) as protocol
        FROM communications c
        WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
        ORDER BY protocol";

    let mut stmt = try_db!(conn.prepare(query), Vec::new());

    let rows = try_db!(
        stmt.query_map(params![internal_minutes], |row| row.get::<_, String>(0)),
        Vec::new()
    );

    rows.filter_map(|row| row.ok()).collect()
}

pub(super) fn get_ports_for_endpoint(hostname: String, internal_minutes: u64) -> Vec<String> {
    let conn = try_db!(new_connection_result(), Vec::new());

    let endpoint_ids = resolve_identifier_to_endpoint_ids(&conn, &hostname);
    if endpoint_ids.is_empty() {
        return Vec::new();
    }

    let placeholders = build_in_placeholders(endpoint_ids.len());
    // Only get destination ports where endpoint is the destination (listening ports)
    // Excludes ephemeral ports (49152-65535) which are just used for receiving responses
    let query = format!(
        "SELECT DISTINCT c.destination_port as port
        FROM communications c
        LEFT JOIN endpoints AS src_endpoint ON c.src_endpoint_id = src_endpoint.id
        LEFT JOIN endpoints AS dst_endpoint ON c.dst_endpoint_id = dst_endpoint.id
        WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
            AND c.dst_endpoint_id IN ({0})
            AND c.destination_port IS NOT NULL
            AND c.destination_port < 49152
            AND src_endpoint.name != '' AND dst_endpoint.name != ''
            AND src_endpoint.name IS NOT NULL AND dst_endpoint.name IS NOT NULL
        ORDER BY CAST(port AS INTEGER)",
        placeholders
    );

    let mut stmt = try_db!(conn.prepare(&query), Vec::new());

    // Build parameters: internal_minutes + endpoint_ids (1 time for the IN clause)
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(internal_minutes)];
    params.extend(box_i64_params(&endpoint_ids));

    let rows = try_db!(
        stmt.query_map(params_to_refs(&params).as_slice(), |row| {
            row.get::<_, i64>(0)
        }),
        Vec::new()
    );

    rows.filter_map(|row| row.ok())
        .map(|port| port.to_string())
        .collect()
}

/// Extract listening ports from communications data (already filtered for graph)
/// Only shows destination ports where endpoint is the destination (ports it's listening on)
/// Excludes ephemeral ports (49152-65535) which are just used for receiving responses
pub(super) fn get_ports_from_communications(
    communications: &[Node],
    selected_endpoint: &str,
) -> Vec<String> {
    let mut ports: std::collections::HashSet<i64> = std::collections::HashSet::new();

    for node in communications {
        // Only get destination port when endpoint is the destination (listening port)
        // Skip ephemeral ports (49152+)
        if node.dst_hostname == selected_endpoint
            && let Some(ref port_str) = node.dst_port
        {
            for p in port_str.split(',') {
                if let Ok(port) = p.trim().parse::<i64>()
                    && port < 49152
                {
                    ports.insert(port);
                }
            }
        }
    }

    let mut ports_vec: Vec<i64> = ports.into_iter().collect();
    ports_vec.sort();
    ports_vec.into_iter().map(|p| p.to_string()).collect()
}

pub(super) fn get_endpoint_ips_and_macs(
    endpoints: &[String],
) -> HashMap<String, (Vec<String>, Vec<String>)> {
    let mut result: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();

    // Initialize all endpoints with empty vectors (use lowercase keys for case-insensitive matching)
    for endpoint in endpoints {
        result.insert(endpoint.to_lowercase(), (Vec::new(), Vec::new()));
    }

    let conn = try_db!(new_connection_result(), result);

    // Single batch query to get all IPs and MACs with their display names
    let mut stmt = try_db!(
        conn.prepare(&format!(
            "SELECT {DISPLAY_NAME_SQL} AS display_name, ea.ip, ea.mac
             FROM endpoints e
             INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id"
        )),
        result
    );

    let rows = try_db!(
        stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let ip: Option<String> = row.get(1)?;
            let mac: Option<String> = row.get(2)?;
            Ok((name, ip, mac))
        }),
        result
    );

    for row in rows.flatten() {
        let (name, ip, mac) = row;
        // Use lowercase for case-insensitive matching
        if let Some((ips, macs)) = result.get_mut(&name.to_lowercase()) {
            if let Some(ip_str) = ip
                && !ip_str.is_empty()
                && !ips.contains(&ip_str)
            {
                ips.push(ip_str);
            }
            if let Some(mac_str) = mac
                && !mac_str.is_empty()
                && !macs.contains(&mac_str)
            {
                macs.push(mac_str);
            }
        }
    }

    // Sort all the vectors
    for (ips, macs) in result.values_mut() {
        ips.sort();
        macs.sort();
    }

    result
}

/// Get DHCP vendor class for all endpoints (for model identification)
pub(super) fn get_endpoint_vendor_classes(endpoints: &[String]) -> HashMap<String, String> {
    let mut result: HashMap<String, String> = HashMap::new();

    // Build lowercase set for case-insensitive matching
    let endpoints_lower: HashSet<String> = endpoints.iter().map(|e| e.to_lowercase()).collect();

    let conn = try_db!(new_connection_result(), result);

    let mut stmt = try_db!(
        conn.prepare(&format!(
            "SELECT {DISPLAY_NAME_SQL} AS display_name, ea.dhcp_vendor_class
             FROM endpoints e
             INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
             WHERE ea.dhcp_vendor_class IS NOT NULL AND ea.dhcp_vendor_class != ''"
        )),
        result
    );

    let rows = try_db!(
        stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let vendor_class: String = row.get(1)?;
            Ok((name, vendor_class))
        }),
        result
    );

    for row in rows.flatten() {
        let (name, vendor_class) = row;
        let name_lower = name.to_lowercase();
        // Only store for endpoints we care about (case-insensitive), and prefer first non-empty value
        if endpoints_lower.contains(&name_lower) && !result.contains_key(&name_lower) {
            result.insert(name_lower, vendor_class);
        }
    }

    result
}

/// Model/Vendor data tuple: (custom_model, ssdp_model, ssdp_friendly_name, custom_vendor)
pub(super) type EndpointModelData = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Get model, vendor, and SNMP data for all endpoints
/// Returns: (custom_model, ssdp_model, ssdp_friendly_name, custom_vendor, snmp_vendor, snmp_model)
pub(super) fn get_endpoint_ssdp_models(
    _endpoints: &[String],
) -> HashMap<String, EndpointModelData> {
    let conn = match new_connection_result() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("get_endpoint_ssdp_models: failed to open database: {}", e);
            return HashMap::new();
        }
    };
    let mut result: HashMap<String, EndpointModelData> = HashMap::new();

    // Use the same DISPLAY_NAME_SQL as dropdown_endpoints to ensure consistent key lookup
    // This query computes the display_name exactly as dropdown_endpoints would
    let query = format!(
        "SELECT {DISPLAY_NAME_SQL} AS display_name,
                e.custom_model, e.ssdp_model, e.ssdp_friendly_name, e.custom_vendor, e.snmp_vendor, e.snmp_model
         FROM endpoints e
         WHERE e.custom_model IS NOT NULL OR e.ssdp_model IS NOT NULL OR e.ssdp_friendly_name IS NOT NULL
            OR e.custom_vendor IS NOT NULL OR e.snmp_vendor IS NOT NULL OR e.snmp_model IS NOT NULL"
    );

    let mut stmt = match conn.prepare(&query) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "get_endpoint_ssdp_models: failed to prepare statement: {}",
                e
            );
            return result;
        }
    };

    let rows = match stmt.query_map([], |row| {
        let display_name: Option<String> = row.get(0)?;
        let custom_model: Option<String> = row.get(1)?;
        let ssdp_model: Option<String> = row.get(2)?;
        let friendly_name: Option<String> = row.get(3)?;
        let custom_vendor: Option<String> = row.get(4)?;
        let snmp_vendor: Option<String> = row.get(5)?;
        let snmp_model: Option<String> = row.get(6)?;
        Ok((
            display_name,
            custom_model,
            ssdp_model,
            friendly_name,
            custom_vendor,
            snmp_vendor,
            snmp_model,
        ))
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("get_endpoint_ssdp_models: failed to execute query: {}", e);
            return result;
        }
    };

    for row in rows.flatten() {
        let (
            display_name,
            custom_model,
            ssdp_model,
            friendly_name,
            custom_vendor,
            snmp_vendor,
            snmp_model,
        ) = row;
        let data = (
            custom_model,
            ssdp_model,
            friendly_name,
            custom_vendor,
            snmp_vendor,
            snmp_model,
        );

        // Store under the computed display name - this matches what dropdown_endpoints returns
        if let Some(ref dn) = display_name
            && !dn.is_empty()
        {
            result.insert(dn.to_lowercase(), data);
        }
    }

    result
}

pub(super) fn get_all_ips_macs_and_hostnames_from_single_hostname(
    hostname: String,
    internal_minutes: u64,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let conn = try_db!(new_connection_result(), (Vec::new(), Vec::new(), Vec::new()));

    let endpoint_ids = resolve_identifier_to_endpoint_ids(&conn, &hostname);
    if endpoint_ids.is_empty() {
        return (Vec::new(), Vec::new(), Vec::new());
    }

    let placeholders = build_in_placeholders(endpoint_ids.len());
    let query = format!(
        "SELECT DISTINCT ea.ip, ea.mac, ea.hostname
        FROM endpoint_attributes ea
        INNER JOIN endpoints e ON ea.endpoint_id = e.id
        WHERE ea.endpoint_id IN (
            SELECT DISTINCT e2.id
            FROM endpoints e2
            INNER JOIN communications c
                ON e2.id = c.src_endpoint_id OR e2.id = c.dst_endpoint_id
            WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
        )
        AND ea.endpoint_id IN ({})",
        placeholders
    );

    let mut stmt = try_db!(conn.prepare(&query), (Vec::new(), Vec::new(), Vec::new()));

    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(internal_minutes)];
    params.extend(box_i64_params(&endpoint_ids));

    let rows = try_db!(
        stmt.query_map(params_to_refs(&params).as_slice(), |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        }),
        (Vec::new(), Vec::new(), Vec::new())
    );

    let mut ips = HashSet::new();
    let mut macs = HashSet::new();
    let mut hostnames = HashSet::new();

    for (ip, mac, hostname) in rows.flatten() {
        ips.insert(ip.unwrap_or_default());
        macs.insert(mac.unwrap_or_default());
        let hostname_str = hostname.unwrap_or_default();
        if ips.contains(&hostname_str) {
            continue;
        }
        // Normalize to lowercase to prevent case-sensitive duplicates
        hostnames.insert(hostname_str.to_lowercase());
    }

    let mut ips: Vec<String> = ips.into_iter().filter(|s| !s.is_empty()).collect();
    let mut macs: Vec<String> = macs.into_iter().filter(|s| !s.is_empty()).collect();
    let mut hostnames: Vec<String> = hostnames.into_iter().filter(|s| !s.is_empty()).collect();

    ips.sort();
    macs.sort();
    hostnames.sort();

    (ips, macs, hostnames)
}

/// Resolve an identifier (hostname, IP, or MAC) to endpoint IDs
/// Returns a Vec of endpoint IDs that match the identifier
pub(super) fn resolve_identifier_to_endpoint_ids(conn: &Connection, identifier: &str) -> Vec<i64> {
    let mut endpoint_ids = Vec::new();

    // Try matching by endpoint name first (exact match has priority)
    // If there are multiple endpoints with the same name, return only the most recently active one
    if let Ok(mut stmt) = conn.prepare(
        "SELECT e.id FROM endpoints e
         LEFT JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
         WHERE LOWER(e.name) = LOWER(?1) OR LOWER(e.custom_name) = LOWER(?1)
         GROUP BY e.id
         ORDER BY MAX(c.last_seen_at) DESC
         LIMIT 1",
    ) && let Ok(rows) = stmt.query_map([identifier], |row| row.get::<_, i64>(0))
    {
        endpoint_ids.extend(rows.flatten());
    }

    // If we found an exact name match, return only that endpoint
    // This prevents IP/MAC conflicts where multiple devices shared the same IP over time
    if !endpoint_ids.is_empty() {
        return endpoint_ids;
    }

    // Only try IP/MAC/hostname matching if there was no exact name match
    // Note: hostname is stored in endpoint_attributes, not endpoints.name
    if let Ok(mut stmt) = conn.prepare(
        "SELECT DISTINCT endpoint_id FROM endpoint_attributes
         WHERE LOWER(ip) = LOWER(?1) OR LOWER(mac) = LOWER(?1) OR LOWER(hostname) = LOWER(?1)",
    ) && let Ok(rows) = stmt.query_map([identifier], |row| row.get::<_, i64>(0))
    {
        endpoint_ids.extend(rows.flatten());
    }

    endpoint_ids.sort_unstable();
    endpoint_ids.dedup();
    endpoint_ids
}

/// Resolve an IP or MAC identifier to the current display name of the matching endpoint.
/// Uses `resolve_identifier_to_endpoint_ids` to find the endpoint, then queries its display name.
pub(super) fn resolve_identifier_to_display_name(
    conn: &Connection,
    identifier: &str,
) -> Option<String> {
    let ids = resolve_identifier_to_endpoint_ids(conn, identifier);
    let first_id = ids.first()?;
    let sql = format!("SELECT {DISPLAY_NAME_SQL} FROM endpoints e WHERE e.id = ?1");
    conn.query_row(&sql, [first_id], |row| row.get::<_, Option<String>>(0))
        .ok()
        .flatten()
}

fn get_nodes(current_node: Option<String>, internal_minutes: u64) -> Vec<Node> {
    let conn = try_db!(new_connection_result(), Vec::new());

    // If no node specified, show all communications (overall network view)
    // If node is specified, filter to only that endpoint's communications
    let endpoint_ids = match current_node {
        Some(hostname) => {
            let ids = resolve_identifier_to_endpoint_ids(&conn, &hostname);
            if ids.is_empty() {
                return Vec::new();
            }
            Some(ids)
        }
        None => None,
    };

    // Use CTE to pre-compute display names and IPs for each endpoint
    // This avoids correlated subqueries which are slow
    // Filter out endpoints that ONLY have locally administered (randomized) MACs
    // Locally administered MACs have 2nd hex digit of 2, 6, A, or E
    let endpoint_info_cte = "
        WITH endpoint_info AS (
            SELECT
                e.id,
                COALESCE(e.custom_name,
                    CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%' AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' AND NOT (LENGTH(e.name) = 36 AND e.name GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*') THEN e.name END,
                    MIN(CASE WHEN ea.hostname IS NOT NULL AND ea.hostname != '' AND NOT (LENGTH(ea.hostname) = 36 AND ea.hostname GLOB '[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*') THEN ea.hostname END)) AS display_name,
                MIN(ea.ip) AS ip
            FROM endpoints e
            LEFT JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
            WHERE (
                -- Has at least one real (non-locally-administered) MAC
                EXISTS (
                    SELECT 1 FROM endpoint_attributes ea2
                    WHERE ea2.endpoint_id = e.id
                    AND ea2.mac IS NOT NULL
                    AND ea2.mac != ''
                    AND UPPER(SUBSTR(ea2.mac, 2, 1)) NOT IN ('2', '6', 'A', 'E')
                )
                OR
                -- Or has no MACs at all (allow IP-only endpoints)
                NOT EXISTS (
                    SELECT 1 FROM endpoint_attributes ea3
                    WHERE ea3.endpoint_id = e.id
                    AND ea3.mac IS NOT NULL
                    AND ea3.mac != ''
                )
            )
            GROUP BY e.id
        )";

    // Build query - either filtered by endpoint or show all
    let (query, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = match &endpoint_ids {
        Some(ids) => {
            let placeholders = build_in_placeholders(ids.len());
            let query = format!(
                "{endpoint_info_cte}
                SELECT
                    src_info.display_name AS src_hostname,
                    dst_info.display_name AS dst_hostname,
                    c.source_port as src_port,
                    c.destination_port as dst_port,
                    c.ip_header_protocol as header_protocol,
                    c.sub_protocol,
                    src_info.ip AS src_ip,
                    dst_info.ip AS dst_ip
                FROM communications AS c
                INNER JOIN endpoint_info AS src_info ON c.src_endpoint_id = src_info.id
                INNER JOIN endpoint_info AS dst_info ON c.dst_endpoint_id = dst_info.id
                WHERE (c.src_endpoint_id IN ({0}) OR c.dst_endpoint_id IN ({0}))
                AND c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
                AND src_info.display_name IS NOT NULL AND src_info.display_name != ''
                AND dst_info.display_name IS NOT NULL AND dst_info.display_name != ''",
                placeholders
            );

            let mut params = box_i64_params(ids);
            params.extend(box_i64_params(ids));
            params.push(Box::new(internal_minutes));
            (query, params)
        }
        None => {
            let query = format!(
                "{endpoint_info_cte}
                SELECT
                    src_info.display_name AS src_hostname,
                    dst_info.display_name AS dst_hostname,
                    c.source_port as src_port,
                    c.destination_port as dst_port,
                    c.ip_header_protocol as header_protocol,
                    c.sub_protocol,
                    src_info.ip AS src_ip,
                    dst_info.ip AS dst_ip
                FROM communications AS c
                INNER JOIN endpoint_info AS src_info ON c.src_endpoint_id = src_info.id
                INNER JOIN endpoint_info AS dst_info ON c.dst_endpoint_id = dst_info.id
                WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
                AND src_info.display_name IS NOT NULL AND src_info.display_name != ''
                AND dst_info.display_name IS NOT NULL AND dst_info.display_name != ''"
            );

            (query, vec![Box::new(internal_minutes)])
        }
    };

    let mut stmt = try_db!(conn.prepare(&query), Vec::new());

    let rows = try_db!(
        stmt.query_map(params_to_refs(&params).as_slice(), |row| {
            let header_protocol = row.get::<_, String>("header_protocol")?;
            let sub_protocol = row
                .get::<_, Option<String>>("sub_protocol")?
                .filter(|s| !s.is_empty())
                .unwrap_or(header_protocol);

            Ok(CommunicationRow {
                src_hostname: row.get("src_hostname")?,
                dst_hostname: row.get("dst_hostname")?,
                sub_protocol,
                src_ip: row.get::<_, Option<String>>("src_ip").ok().flatten(),
                dst_ip: row.get::<_, Option<String>>("dst_ip").ok().flatten(),
                src_port: row.get::<_, Option<u16>>("src_port").ok().flatten(),
                dst_port: row.get::<_, Option<u16>>("dst_port").ok().flatten(),
            })
        }),
        Vec::new()
    );

    // Group by source and destination, collecting all protocols and ports
    type CommKey = (String, String);
    type CommData = (
        Vec<String>,
        Option<String>,
        Option<String>,
        Vec<u16>,
        Vec<u16>,
    );
    let mut comm_map: std::collections::HashMap<CommKey, CommData> =
        std::collections::HashMap::new();

    for row in rows.flatten() {
        let key = (row.src_hostname.clone(), row.dst_hostname.clone());
        let entry = comm_map.entry(key).or_insert((
            vec![],
            row.src_ip.clone(),
            row.dst_ip.clone(),
            vec![],
            vec![],
        ));
        if !entry.0.contains(&row.sub_protocol) {
            entry.0.push(row.sub_protocol);
        }
        // Add source port if present and not already in list
        if let Some(src_port) = row.src_port
            && !entry.3.contains(&src_port)
        {
            entry.3.push(src_port);
        }
        // Add destination port if present and not already in list
        if let Some(dst_port) = row.dst_port
            && !entry.4.contains(&dst_port)
        {
            entry.4.push(dst_port);
        }
    }

    // Convert to nodes with aggregated protocols and ports
    comm_map
        .into_iter()
        .map(
            |((src, dst), (protocols, src_ip, dst_ip, src_ports, dst_ports))| {
                let src_type = EndPoint::classify_endpoint(src_ip, Some(src.clone()));
                let dst_type = EndPoint::classify_endpoint(dst_ip, Some(dst.clone()));

                // Join protocols with comma for display, but keep them separate for filtering
                let sub_protocol = protocols.join(",");

                // Join all ports with comma for filtering (convert Vec<u16> to comma-separated string)
                let src_port = if src_ports.is_empty() {
                    None
                } else {
                    Some(
                        src_ports
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                };
                let dst_port = if dst_ports.is_empty() {
                    None
                } else {
                    Some(
                        dst_ports
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                };

                // Try to resolve IP-like hostnames from mDNS cache
                let src_resolved = resolve_from_mdns_cache(&src).unwrap_or(src);
                let dst_resolved = resolve_from_mdns_cache(&dst).unwrap_or(dst);

                Node {
                    src_hostname: src_resolved,
                    dst_hostname: dst_resolved,
                    sub_protocol,
                    src_type,
                    dst_type,
                    src_port,
                    dst_port,
                }
            },
        )
        .collect()
}

fn get_endpoints(communications: &[Node]) -> Vec<String> {
    communications.iter().fold(vec![], |mut acc, comm| {
        if !acc.contains(&comm.src_hostname) {
            acc.push(comm.src_hostname.clone());
        }
        if !acc.contains(&comm.dst_hostname) {
            acc.push(comm.dst_hostname.clone());
        }
        acc
    })
}

fn get_endpoint_types(communications: &[Node]) -> std::collections::HashMap<String, &'static str> {
    let mut types = std::collections::HashMap::new();
    for comm in communications {
        if let Some(src_type) = comm.src_type {
            types.entry(comm.src_hostname.clone()).or_insert(src_type);
        }
        if let Some(dst_type) = comm.dst_type {
            types.entry(comm.dst_hostname.clone()).or_insert(dst_type);
        }
    }
    types
}

pub(super) fn get_all_endpoint_types(
    endpoints: &[String],
) -> (
    std::collections::HashMap<String, &'static str>,
    std::collections::HashSet<String>,
) {
    let conn = try_db!(new_connection_result(), (std::collections::HashMap::new(), std::collections::HashSet::new()));
    let mut types = std::collections::HashMap::new();
    let mut manual_overrides = std::collections::HashSet::new();

    // Get all manual device types first
    let manual_types = EndPoint::get_all_manual_device_types(&conn);

    // Build lookup maps for manual types (case-insensitive)
    let manual_types_lower: HashMap<String, String> = manual_types
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    // Get all auto-detected device types (persisted from first detection)
    let auto_types = EndPoint::get_all_auto_device_types(&conn);
    let auto_types_lower: HashMap<String, String> = auto_types
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    // Batch fetch all IPs for all endpoints in one query
    let mut all_ips: HashMap<String, Vec<String>> = HashMap::new();
    if let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT {DISPLAY_NAME_SQL} AS display_name, ea.ip
         FROM endpoints e
         INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
         WHERE ea.ip IS NOT NULL"
    )) && let Ok(rows) = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let ip: String = row.get(1)?;
        Ok((name, ip))
    }) {
        for row in rows.flatten() {
            // Use lowercase keys for case-insensitive lookups
            all_ips.entry(row.0.to_lowercase()).or_default().push(row.1);
        }
    }

    // Batch fetch all MACs for all endpoints in one query
    let mut all_macs: HashMap<String, Vec<String>> = HashMap::new();
    if let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT {DISPLAY_NAME_SQL} AS display_name, ea.mac
         FROM endpoints e
         INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
         WHERE ea.mac IS NOT NULL"
    )) && let Ok(rows) = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let mac: String = row.get(1)?;
        Ok((name, mac))
    }) {
        for row in rows.flatten() {
            // Use lowercase keys for case-insensitive lookups
            all_macs
                .entry(row.0.to_lowercase())
                .or_default()
                .push(row.1);
        }
    }

    // Batch fetch all OPEN ports for all endpoints from port scanner results
    // Only use ports that are actually LISTENING on the device (from open_ports table)
    // NOT communication ports, which would include traffic the device initiates
    // (e.g., a computer sending to port 9100 would incorrectly be classified as a printer)
    let mut all_ports: HashMap<String, Vec<u16>> = HashMap::new();
    if let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT {DISPLAY_NAME_SQL} AS display_name, op.port
         FROM endpoints e
         INNER JOIN open_ports op ON e.id = op.endpoint_id
         GROUP BY e.id, op.port"
    )) && let Ok(rows) = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let port: i64 = row.get(1)?;
        Ok((name, port))
    }) {
        for row in rows.flatten() {
            if let Ok(port) = u16::try_from(row.1) {
                // Use lowercase keys for case-insensitive lookups
                all_ports
                    .entry(row.0.to_lowercase())
                    .or_default()
                    .push(port);
            }
        }
    }

    // Batch fetch all SSDP models for all endpoints (for soundbar/TV classification)
    let mut all_ssdp_models: HashMap<String, String> = HashMap::new();
    if let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT {DISPLAY_NAME_SQL} AS display_name, e.ssdp_model
         FROM endpoints e
         WHERE e.ssdp_model IS NOT NULL AND e.ssdp_model != ''"
    )) && let Ok(rows) = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let model: String = row.get(1)?;
        Ok((name, model))
    }) {
        for row in rows.flatten() {
            // Use lowercase keys for case-insensitive lookups
            all_ssdp_models.insert(row.0.to_lowercase(), row.1);
        }
    }

    // Now classify each endpoint using the batch-fetched data
    for endpoint in endpoints {
        let endpoint_lower = endpoint.to_lowercase();

        // Check for manual override first (case-insensitive)
        if let Some(manual_type) = manual_types_lower.get(&endpoint_lower) {
            let static_type: &'static str = match manual_type.as_str() {
                "local" => "local",
                "gateway" => "gateway",
                "internet" => "internet",
                "printer" => "printer",
                "tv" => "tv",
                "gaming" => "gaming",
                "phone" => "phone",
                "virtualization" => "virtualization",
                "soundbar" => "soundbar",
                "appliance" => "appliance",
                _ => "other",
            };
            types.insert(endpoint.clone(), static_type);
            manual_overrides.insert(endpoint.clone());
            continue;
        }

        // Check for stored auto-detected type (persists across renames)
        // BUT: re-classify "local" and "other" devices if we now have better data (SSDP model)
        if let Some(auto_type) = auto_types_lower.get(&endpoint_lower) {
            let should_reclassify = (auto_type == "local" || auto_type == "other")
                && all_ssdp_models.contains_key(&endpoint_lower);

            if !should_reclassify {
                let static_type: &'static str = match auto_type.as_str() {
                    "local" => "local",
                    "gateway" => "gateway",
                    "internet" => "internet",
                    "printer" => "printer",
                    "tv" => "tv",
                    "gaming" => "gaming",
                    "phone" => "phone",
                    "virtualization" => "virtualization",
                    "soundbar" => "soundbar",
                    "appliance" => "appliance",
                    _ => "other",
                };
                types.insert(endpoint.clone(), static_type);
                continue;
            }
            // Fall through to re-classify with new SSDP data
        }

        // Get IPs from batch data (case-insensitive), or try to extract from hostname
        let mut ips = all_ips.get(&endpoint_lower).cloned().unwrap_or_default();
        if ips.is_empty() {
            // Try to parse IP from hostname pattern: xxx-xxx-xxx-xxx.domain
            let parts: Vec<&str> = endpoint.split('.').collect();
            if let Some(first_part) = parts.first() {
                let ip_candidate = first_part.replace('-', ".");
                if ip_candidate.parse::<std::net::IpAddr>().is_ok() {
                    ips.push(ip_candidate);
                }
            }
        }

        let macs = all_macs.get(&endpoint_lower).cloned().unwrap_or_default();
        let ports = all_ports.get(&endpoint_lower).cloned().unwrap_or_default();
        let ssdp_model = all_ssdp_models.get(&endpoint_lower);

        // First check network-level classification (gateway, internet)
        // Use first IP for network-level classification
        let first_ip = ips.first().cloned();
        if let Some(endpoint_type) =
            EndPoint::classify_endpoint(first_ip.clone(), Some(endpoint.clone()))
        {
            types.insert(endpoint.clone(), endpoint_type);
            // Store the auto-detected type for persistence
            let _ = EndPoint::set_auto_device_type(&conn, endpoint, endpoint_type);
        } else if let Some(device_type) = EndPoint::classify_device_type(
            Some(endpoint),
            &ips,
            &ports,
            &macs,
            ssdp_model.map(|s| s.as_str()),
        ) {
            types.insert(endpoint.clone(), device_type);
            // Store the auto-detected type for persistence
            let _ = EndPoint::set_auto_device_type(&conn, endpoint, device_type);
        } else if let Some(ref ip_str) = first_ip {
            // Only classify as local if the IP is actually on the local network
            if EndPoint::is_on_local_network(ip_str) {
                types.insert(endpoint.clone(), "local");
                // Store the auto-detected type for persistence
                let _ = EndPoint::set_auto_device_type(&conn, endpoint, "local");
            }
        }
    }

    (types, manual_overrides)
}

#[derive(Serialize, Default)]
pub(super) struct BytesStats {
    pub(super) bytes_in: i64,
    pub(super) bytes_out: i64,
}

#[derive(serde::Serialize)]
pub(super) struct EndpointDetailsResponse {
    pub(super) endpoint_name: String,
    pub(super) device_type: String,
    pub(super) is_manual_override: bool,
    pub(super) device_vendor: String,
    pub(super) device_model: String,
    pub(super) ips: Vec<String>,
    pub(super) macs: Vec<String>,
    pub(super) hostnames: Vec<String>,
    pub(super) ports: Vec<String>,
    pub(super) protocols: Vec<String>,
    pub(super) bytes_in: i64,
    pub(super) bytes_out: i64,
}

#[derive(serde::Serialize)]
pub(super) struct DnsEntryView {
    pub(super) ip: String,
    pub(super) hostname: String,
    pub(super) services: String,
    pub(super) timestamp: String,
}

pub(super) fn get_dns_entries() -> Vec<DnsEntryView> {
    use std::time::UNIX_EPOCH;

    let entries = MDnsLookup::get_all_entries();
    entries
        .into_iter()
        .map(|e| {
            let timestamp = e
                .timestamp
                .duration_since(UNIX_EPOCH)
                .map(|d| {
                    let secs = d.as_secs();
                    let dt = chrono::DateTime::from_timestamp(secs as i64, 0).unwrap_or_default();
                    dt.format("%b %d, %Y, %I:%M:%S %p").to_string()
                })
                .unwrap_or_else(|_| "Unknown".to_string());

            DnsEntryView {
                ip: e.ip,
                hostname: e.hostname,
                services: e.services.join(", "),
                timestamp,
            }
        })
        .collect()
}

// API handlers have been moved to api.rs

pub(super) fn get_bytes_for_endpoint(hostname: String, internal_minutes: u64) -> BytesStats {
    let conn = try_db!(new_connection_result(), BytesStats::default());

    // Bytes received (where this endpoint is the destination)
    let bytes_in: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(c.bytes), 0)
             FROM communications c
             JOIN endpoints dst ON c.dst_endpoint_id = dst.id
             WHERE (LOWER(dst.name) = LOWER(?1)
                    OR LOWER(dst.custom_name) = LOWER(?1)
                    OR dst.id IN (SELECT endpoint_id FROM endpoint_attributes WHERE LOWER(hostname) = LOWER(?1)))
             AND c.last_seen_at >= (strftime('%s', 'now') - (?2 * 60))",
            params![&hostname, &internal_minutes.to_string()],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Bytes sent (where this endpoint is the source)
    let bytes_out: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(c.bytes), 0)
             FROM communications c
             JOIN endpoints src ON c.src_endpoint_id = src.id
             WHERE (LOWER(src.name) = LOWER(?1)
                    OR LOWER(src.custom_name) = LOWER(?1)
                    OR src.id IN (SELECT endpoint_id FROM endpoint_attributes WHERE LOWER(hostname) = LOWER(?1)))
             AND c.last_seen_at >= (strftime('%s', 'now') - (?2 * 60))",
            params![&hostname, &internal_minutes.to_string()],
            |row| row.get(0),
        )
        .unwrap_or(0);

    BytesStats {
        bytes_in,
        bytes_out,
    }
}

pub(super) fn get_all_endpoints_bytes(
    endpoints: &[String],
    internal_minutes: u64,
) -> HashMap<String, i64> {
    let mut result: HashMap<String, i64> = HashMap::new();

    // Initialize all endpoints with 0 bytes (use lowercase keys for case-insensitive matching)
    for endpoint in endpoints {
        result.insert(endpoint.to_lowercase(), 0);
    }

    let conn = try_db!(new_connection_result(), result);

    // Single query to get all bytes data at once
    let mut stmt = try_db!(
        conn.prepare(&format!(
            "SELECT {DISPLAY_NAME_SQL} AS display_name, COALESCE(SUM(c.bytes), 0) as total_bytes
             FROM endpoints e
             INNER JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
             WHERE c.last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
             GROUP BY e.id"
        )),
        result
    );

    let rows = try_db!(
        stmt.query_map([internal_minutes], |row| {
            let name: String = row.get(0)?;
            let bytes: i64 = row.get(1)?;
            Ok((name, bytes))
        }),
        result
    );

    for row in rows.flatten() {
        let (name, bytes) = row;
        // Use lowercase for case-insensitive matching
        if let Some(existing) = result.get_mut(&name.to_lowercase()) {
            *existing = bytes;
        }
    }

    result
}

pub(super) fn get_all_endpoints_last_seen(
    endpoints: &[String],
    internal_minutes: u64,
) -> HashMap<String, String> {
    let mut result: HashMap<String, String> = HashMap::new();

    // Initialize all endpoints with empty string (use lowercase keys for case-insensitive matching)
    for endpoint in endpoints {
        result.insert(endpoint.to_lowercase(), String::new());
    }

    let conn = try_db!(new_connection_result(), result);

    // Single query to get last_seen_at for each endpoint
    // Uses DISPLAY_NAME_SQL constant for consistency with other queries
    let mut stmt = try_db!(
        conn.prepare(&format!(
            "SELECT
                {DISPLAY_NAME_SQL} AS display_name,
                MAX(c.last_seen_at) as last_seen
             FROM endpoints e
             INNER JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
             WHERE c.last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
             GROUP BY e.id"
        )),
        result
    );

    let rows = try_db!(
        stmt.query_map([internal_minutes], |row| {
            let name: String = row.get(0)?;
            let last_seen: i64 = row.get(1)?;
            Ok((name, last_seen))
        }),
        result
    );

    let now = chrono::Utc::now().timestamp();

    for row in rows.flatten() {
        let (name, last_seen) = row;
        // Use lowercase for case-insensitive matching
        if let Some(existing) = result.get_mut(&name.to_lowercase()) {
            // Format as relative time
            let seconds_ago = now - last_seen;
            let formatted = if seconds_ago < 60 {
                "Just now".to_string()
            } else if seconds_ago < 3600 {
                format!("{}m ago", seconds_ago / 60)
            } else if seconds_ago < 86400 {
                format!("{}h ago", seconds_ago / 3600)
            } else {
                format!("{}d ago", seconds_ago / 86400)
            };
            *existing = formatted;
        }
    }

    result
}

/// Get online status for all endpoints
/// An endpoint is considered "online" if it had traffic within the threshold (in seconds)
pub(super) fn get_all_endpoints_online_status(
    endpoints: &[String],
    threshold_seconds: u64,
) -> HashMap<String, bool> {
    let mut result: HashMap<String, bool> = HashMap::new();

    // Initialize all endpoints as offline (use lowercase keys for case-insensitive matching)
    for endpoint in endpoints {
        result.insert(endpoint.to_lowercase(), false);
    }

    let conn = try_db!(new_connection_result(), result);

    // Single query to get endpoints with recent traffic within threshold
    let mut stmt = try_db!(
        conn.prepare(&format!(
            "SELECT
                {DISPLAY_NAME_SQL} AS display_name
             FROM endpoints e
             INNER JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
             WHERE c.last_seen_at >= (strftime('%s', 'now') - ?1)
             GROUP BY e.id"
        )),
        result
    );

    let rows = try_db!(
        stmt.query_map([threshold_seconds], |row| {
            let name: String = row.get(0)?;
            Ok(name)
        }),
        result
    );

    for row in rows.flatten() {
        // Use lowercase for case-insensitive matching
        if let Some(existing) = result.get_mut(&row.to_lowercase()) {
            *existing = true;
        }
    }

    result
}

/// Check if another instance of this application is already running on any of the
/// candidate ports. Returns `Some((port, pid))` if a running instance is found.
fn detect_existing_instance(ports: &[u16]) -> Option<(u16, u32)> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .ok()?;

    for &port in ports {
        if let Ok(resp) = client
            .get(format!("http://127.0.0.1:{}/api/instance", port))
            .send()
            && let Ok(json) = resp.json::<serde_json::Value>()
            && json.get("app").and_then(|v| v.as_str()) == Some("awareness")
        {
            let pid = json.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            return Some((port, pid));
        }
    }
    None
}

pub fn start(preferred_port: u16) {
    task::spawn_blocking(move || {
        println!("Starting web server");

        // Check if another instance is already running
        let check_ports = [preferred_port, 8081, 8082, 8083, 8084];
        if let Some((port, pid)) = detect_existing_instance(&check_ports) {
            eprintln!(
                "Another instance is already running on http://127.0.0.1:{} (PID {})",
                port, pid
            );
            eprintln!("Stop the existing instance before starting a new one.");
            std::process::exit(1);
        }

        let sys = actix_rt::System::new();

        // Load templates from embedded files
        let mut tera = Tera::default();
        for file in Templates::iter() {
            let file_name = file.as_ref();
            if let Some(content) = Templates::get(file_name) {
                let template_str = std::str::from_utf8(content.data.as_ref())
                    .expect("Template file is not valid UTF-8");
                if let Err(e) = tera.add_raw_template(file_name, template_str) {
                    eprintln!("Failed to load template {}: {}", file_name, e);
                    eprintln!("Web server will not start");
                    return;
                }
            }
        }

        sys.block_on(async {
            // Try to bind to the preferred port, then fallback ports
            let fallback_ports = [preferred_port, 8081, 8082, 8083, 8084];
            let mut bound_port = None;
            let mut last_error = None;

            for port in fallback_ports {
                let tera_clone = tera.clone();
                match HttpServer::new(move || {
                    App::new()
                        .app_data(Data::new(tera_clone.clone()))
                        .service(static_files)
                        .service(index)
                        .service(set_endpoint_type)
                        .service(rename_endpoint)
                        .service(set_endpoint_model)
                        .service(set_endpoint_vendor)
                        .service(probe_endpoint)
                        .service(delete_endpoint)
                        .service(merge_endpoints)
                        .service(probe_endpoint_model)
                        .service(get_dns_entries_api)
                        .service(get_internet_destinations)
                        .service(probe_hostname)
                        .service(probe_netbios)
                        .service(ping_endpoint)
                        .service(port_scan_endpoint)
                        .service(get_endpoint_details)
                        .service(get_protocol_endpoints)
                        .service(get_all_protocols_api)
                        .service(get_device_capabilities)
                        .service(send_device_command)
                        .service(launch_device_app)
                        .service(pair_device)
                        .service(setup_thinq)
                        .service(get_thinq_status)
                        .service(list_thinq_devices)
                        .service(disconnect_thinq)
                        .service(start_scan)
                        .service(stop_scan)
                        .service(get_scan_status)
                        .service(get_scan_capabilities)
                        .service(get_scan_config)
                        .service(set_scan_config)
                        .service(get_endpoints_table)
                        .service(export_endpoints_xlsx)
                        .service(get_settings)
                        .service(update_setting)
                        .service(get_capture_status)
                        .service(toggle_capture_pause)
                        .service(set_capture_pause)
                        .service(upload_pcap)
                        .service(get_notifications)
                        .service(dismiss_notifications)
                        .service(clear_notifications)
                        .service(get_instance)
                })
                .bind(("127.0.0.1", port))
                {
                    Ok(server) => {
                        if port != preferred_port {
                            println!(
                                "Port {} was already in use, using port {} instead",
                                preferred_port, port
                            );
                        }
                        println!("Web server listening on http://127.0.0.1:{}", port);

                        // Start initial network scan on startup with ALL scan types
                        tokio::spawn(async {
                            // Small delay to let the server fully initialize
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            let manager = get_scan_manager();
                            // Use all scan types for the initial scan to get comprehensive discovery
                            let scan_types = vec![
                                ScanType::Arp,
                                ScanType::Icmp,
                                ScanType::Ndp,
                                ScanType::Ssdp,
                                ScanType::NetBios,
                                ScanType::Port,
                            ];
                            println!("Starting initial network scan (all types)...");
                            if let Err(e) = manager.start_scan(scan_types).await {
                                eprintln!("Failed to start initial scan: {}", e);
                            }
                        });

                        if let Err(e) = server.run().await {
                            eprintln!("Web server error: {}", e);
                        }
                        bound_port = Some(port);
                        break;
                    }
                    Err(e) => {
                        last_error = Some((port, e));
                    }
                }
            }

            if bound_port.is_none()
                && let Some((port, e)) = last_error
            {
                eprintln!("Failed to bind web server to any port.");
                eprintln!("Tried ports: {:?}", fallback_ports);
                eprintln!("Last error on port {}: {}", port, e);
                eprintln!();
                eprintln!("Possible solutions:");
                eprintln!("  1. Stop any other processes using these ports");
                eprintln!("  2. Set a different port using the WEB_PORT environment variable");
                eprintln!("     Example: WEB_PORT=9000 ./awareness");
            }
        })
    });
}

#[get("/static/{filename:.*}")]
async fn static_files(path: actix_web::web::Path<String>) -> impl Responder {
    let filename = path.into_inner();
    match StaticAssets::get(&filename) {
        Some(content) => {
            let mime_type = mime_guess::from_path(&filename)
                .first_or_octet_stream()
                .to_string();
            HttpResponse::Ok()
                .content_type(mime_type)
                .body(content.data.into_owned())
        }
        None => HttpResponse::NotFound().body("File not found"),
    }
}

// Define a handler function for the web request
#[get("/")]
async fn index(tera: Data<Tera>, query: Query<NodeQuery>) -> impl Responder {
    let hostname = strip_local_suffix(&get_hostname().unwrap_or_else(|_| "Unknown".to_string()));
    let scan_interval = query.scan_interval.unwrap_or(525600);

    // Resolve ip=/mac= query params to an effective node name
    let effective_node: Option<String> = if query.node.is_some() {
        query.node.clone()
    } else if let Some(ref ip) = query.ip {
        let ip_clone = ip.clone();
        let resolved = task::spawn_blocking(move || {
            let conn = new_connection_result().ok()?;
            resolve_identifier_to_display_name(&conn, &ip_clone)
        })
        .await
        .ok()
        .flatten();
        Some(resolved.unwrap_or_else(|| ip.clone()))
    } else if let Some(ref mac) = query.mac {
        let mac_clone = mac.clone();
        let resolved = task::spawn_blocking(move || {
            let conn = new_connection_result().ok()?;
            resolve_identifier_to_display_name(&conn, &mac_clone)
        })
        .await
        .ok()
        .flatten();
        Some(resolved.unwrap_or_else(|| mac.clone()))
    } else {
        None
    };

    let selected_endpoint = effective_node.clone().unwrap_or_default();

    // Phase 1: Run independent queries in parallel
    let query_node_1 = effective_node.clone();
    let nodes_future = tokio::task::spawn_blocking(move || get_nodes(query_node_1, scan_interval));
    let dropdown_future = tokio::task::spawn_blocking(move || dropdown_endpoints(scan_interval));
    let interfaces_future = tokio::task::spawn_blocking(get_interfaces);

    let (communications_result, dropdown_result, interfaces_result) =
        tokio::join!(nodes_future, dropdown_future, interfaces_future);

    let communications = communications_result.unwrap_or_default();
    let mut dropdown_endpoints = dropdown_result.unwrap_or_default();
    let interfaces = interfaces_result.unwrap_or_default();

    let mut endpoints = get_endpoints(&communications);

    // If a specific node was selected but isn't in the endpoints list, add it
    // This handles isolated endpoints with no communications
    if let Some(ref selected_node) = effective_node
        && !endpoints.contains(selected_node)
    {
        endpoints.push(selected_node.clone());
    }
    // Also add to dropdown_endpoints so the node appears in the list
    if let Some(ref selected_node) = effective_node
        && !dropdown_endpoints.contains(selected_node)
    {
        dropdown_endpoints.push(selected_node.clone());
    }
    let supported_protocols = ProtocolPort::get_supported_protocols();

    // Phase 2: Run queries that depend on dropdown_endpoints in parallel
    let dropdown_for_ips = dropdown_endpoints.clone();
    let dropdown_for_vendor = dropdown_endpoints.clone();
    let dropdown_for_bytes = dropdown_endpoints.clone();
    let dropdown_for_seen = dropdown_endpoints.clone();
    let dropdown_for_online = dropdown_endpoints.clone();
    let dropdown_for_types = dropdown_endpoints.clone();
    let dropdown_for_ssdp = dropdown_endpoints.clone();

    let ips_macs_future =
        tokio::task::spawn_blocking(move || get_endpoint_ips_and_macs(&dropdown_for_ips));
    let vendor_classes_future =
        tokio::task::spawn_blocking(move || get_endpoint_vendor_classes(&dropdown_for_vendor));
    let bytes_future = tokio::task::spawn_blocking(move || {
        get_all_endpoints_bytes(&dropdown_for_bytes, scan_interval)
    });
    let last_seen_future = tokio::task::spawn_blocking(move || {
        get_all_endpoints_last_seen(&dropdown_for_seen, scan_interval)
    });
    let online_status_future = tokio::task::spawn_blocking(move || {
        // Get active threshold from settings (default 120 seconds = 2 minutes)
        let active_threshold = get_setting_i64("active_threshold_seconds", 120) as u64;
        get_all_endpoints_online_status(&dropdown_for_online, active_threshold)
    });
    let all_types_future =
        tokio::task::spawn_blocking(move || get_all_endpoint_types(&dropdown_for_types));
    let ssdp_models_future =
        tokio::task::spawn_blocking(move || get_endpoint_ssdp_models(&dropdown_for_ssdp));

    let (
        ips_macs_result,
        vendor_classes_result,
        bytes_result,
        last_seen_result,
        online_status_result,
        all_types_result,
        ssdp_models_result,
    ) = tokio::join!(
        ips_macs_future,
        vendor_classes_future,
        bytes_future,
        last_seen_future,
        online_status_future,
        all_types_future,
        ssdp_models_future
    );

    let endpoint_ips_macs = ips_macs_result.unwrap_or_default();
    let endpoint_dhcp_vendor_classes = vendor_classes_result.unwrap_or_default();
    let endpoint_bytes = bytes_result.unwrap_or_default();
    let endpoint_last_seen = last_seen_result.unwrap_or_default();
    let endpoint_online_status = online_status_result.unwrap_or_default();
    let (dropdown_types, manual_overrides) = all_types_result.unwrap_or_default();
    let endpoint_ssdp_models = ssdp_models_result.unwrap_or_default();

    // Build vendor lookup for all endpoints (hostname first, then MAC)
    // Hostname detection is more accurate for devices with generic WiFi chips
    // Component manufacturers that shouldn't be shown as device vendors
    let component_vendors = [
        "Espressif",
        "Tuya",
        "Realtek",
        "MediaTek",
        "Qualcomm",
        "Broadcom",
        "Marvell",
        "USI",
        "Wisol",
        "Murata",
        "AzureWave",
    ];
    // Build vendor lookup using characterize_vendor for clean priority handling
    let endpoint_vendors: HashMap<String, String> =
        dropdown_endpoints
            .iter()
            .filter_map(|endpoint| {
                let endpoint_lower = endpoint.to_lowercase();

                // Get data from various sources
                let (
                    _custom_model,
                    ssdp_model,
                    ssdp_friendly,
                    custom_vendor,
                    snmp_vendor,
                    _snmp_model,
                ) = endpoint_ssdp_models
                    .get(&endpoint_lower)
                    .map(|(cm, sm, sf, cv, sv, snm)| {
                        (
                            cm.as_deref(),
                            sm.as_deref(),
                            sf.as_deref(),
                            cv.as_deref(),
                            sv.as_deref(),
                            snm.as_deref(),
                        )
                    })
                    .unwrap_or((None, None, None, None, None, None));

                let macs: Vec<String> = endpoint_ips_macs
                    .get(&endpoint_lower)
                    .map(|(_, m)| m.clone())
                    .unwrap_or_default()
                    // Filter out component manufacturers
                    .into_iter()
                    .filter(|mac| {
                        get_mac_vendor(mac)
                            .map(|v| !component_vendors.contains(&v))
                            .unwrap_or(true)
                    })
                    .collect();

                // Use characterize_vendor for clean priority-based selection
                characterize_vendor(
                    custom_vendor,
                    ssdp_friendly,
                    snmp_vendor,
                    Some(endpoint.as_str()),
                    &macs,
                    ssdp_model,
                )
                .map(|c| (endpoint_lower, c.value))
            })
            .collect();

    // Extract unique vendor names for the vendor dropdown filter
    let mut unique_vendors: Vec<String> = endpoint_vendors
        .values()
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    unique_vendors.sort();

    // Build model lookup using characterize_model for clean priority handling
    let endpoint_models: HashMap<String, String> = dropdown_endpoints
        .iter()
        .filter_map(|endpoint| {
            let endpoint_lower = endpoint.to_lowercase();

            // Get data from various sources
            let (custom_model, ssdp_model, _, _, _, snmp_model) = endpoint_ssdp_models
                .get(&endpoint_lower)
                .map(|(cm, sm, sf, cv, sv, snm)| {
                    (
                        cm.as_deref(),
                        sm.as_deref(),
                        sf.as_deref(),
                        cv.as_deref(),
                        sv.as_deref(),
                        snm.as_deref(),
                    )
                })
                .unwrap_or((None, None, None, None, None, None));

            let macs: Vec<String> = endpoint_ips_macs
                .get(&endpoint_lower)
                .map(|(_, m)| m.clone())
                .unwrap_or_default();

            let vendor = endpoint_vendors.get(&endpoint_lower).map(|v| v.as_str());

            // Use characterize_model for clean priority-based selection
            // Note: device_type is None here; vendor+type inference happens in second pass below
            characterize_model(
                custom_model,
                ssdp_model,
                snmp_model,
                Some(endpoint.as_str()),
                &macs,
                vendor,
                None, // device_type added in second pass
            )
            .map(|c| (endpoint_lower, c.value))
        })
        .collect();

    let mut endpoint_types = get_endpoint_types(&communications);
    // Merge dropdown types into endpoint_types
    // Manual overrides should take priority, so use insert() for those
    for (endpoint, type_str) in dropdown_types {
        if manual_overrides.contains(&endpoint) {
            // Manual override - always use this type
            endpoint_types.insert(endpoint, type_str);
        } else {
            endpoint_types.entry(endpoint).or_insert(type_str);
        }
    }
    // Ensure all dropdown endpoints have a type (default to "other" if not classified)
    for endpoint in &dropdown_endpoints {
        endpoint_types.entry(endpoint.clone()).or_insert("other");
    }
    // Also ensure all endpoints from communications have a type
    for endpoint in &endpoints {
        endpoint_types.entry(endpoint.clone()).or_insert("other");
    }
    // Always classify local device as "local"
    endpoint_types.insert(hostname.clone(), "local");
    // Ensure the selected endpoint is always in endpoint_types (for URL navigation)
    if !selected_endpoint.is_empty() {
        endpoint_types
            .entry(selected_endpoint.clone())
            .or_insert("other");
    }

    // Second pass: enhance models using vendor + device type for endpoints without models
    let mut endpoint_models = endpoint_models;
    for (endpoint, device_type) in &endpoint_types {
        let endpoint_lower = endpoint.to_lowercase();
        // Use lowercase for case-insensitive lookups
        if !endpoint_models.contains_key(&endpoint_lower)
            && let Some(vendor) = endpoint_vendors.get(&endpoint_lower)
            && let Some(model) = get_model_from_vendor_and_type(vendor, device_type)
        {
            endpoint_models.insert(endpoint_lower, model);
        }
    }

    // Convert manual_overrides to Vec for serialization
    let manual_overrides: Vec<String> = manual_overrides.into_iter().collect();

    // Phase 3: Run selected endpoint queries in parallel
    let selected_for_ips = selected_endpoint.clone();
    let selected_for_protocols = selected_endpoint.clone();
    let selected_for_bytes = selected_endpoint.clone();

    let ips_macs_hostnames_future = tokio::task::spawn_blocking(move || {
        get_all_ips_macs_and_hostnames_from_single_hostname(selected_for_ips, scan_interval)
    });
    let protocols_future = tokio::task::spawn_blocking(move || {
        get_protocols_for_endpoint(selected_for_protocols, scan_interval)
    });
    let bytes_stats_future = tokio::task::spawn_blocking(move || {
        get_bytes_for_endpoint(selected_for_bytes, scan_interval)
    });

    // Ports query depends on whether a node is selected
    let ports_future = if effective_node.is_some() {
        // Use in-memory data, no DB query needed
        let comms = communications.clone();
        let selected = selected_endpoint.clone();
        tokio::task::spawn_blocking(move || get_ports_from_communications(&comms, &selected))
    } else {
        let selected_for_ports = selected_endpoint.clone();
        tokio::task::spawn_blocking(move || {
            get_ports_for_endpoint(selected_for_ports, scan_interval)
        })
    };

    let (ips_macs_hostnames_result, protocols_result, bytes_stats_result, ports_result) = tokio::join!(
        ips_macs_hostnames_future,
        protocols_future,
        bytes_stats_future,
        ports_future
    );

    let (ips, macs, hostnames) = ips_macs_hostnames_result.unwrap_or_default();
    let protocols = protocols_result.unwrap_or_default();
    let bytes_stats = bytes_stats_result.unwrap_or_else(|_| BytesStats::default());
    let ports = ports_result.unwrap_or_default();

    // Build MAC vendor lookup
    let mac_vendors: HashMap<String, String> = macs
        .iter()
        .filter_map(|mac| get_mac_vendor(mac).map(|vendor| (mac.clone(), vendor.to_string())))
        .collect();
    const COMPONENT_VENDORS: &[&str] = &[
        "Espressif",
        "Tuya",
        "Realtek",
        "MediaTek",
        "Qualcomm",
        "Broadcom",
        "Marvell",
        "USI",
        "Wisol",
        "Murata",
    ];

    // Get model/vendor data including custom_vendor and snmp_vendor
    let selected_lower = selected_endpoint.to_lowercase();
    let models_data = endpoint_ssdp_models.get(&selected_lower);

    let (
        detail_custom_vendor,
        detail_ssdp_friendly,
        detail_snmp_vendor,
        detail_ssdp_model,
        detail_snmp_model,
    ) = models_data
        .map(|(_, sm, sf, cv, sv, snm)| {
            (
                cv.as_deref(),
                sf.as_deref(),
                sv.as_deref(),
                sm.as_deref(),
                snm.as_deref(),
            )
        })
        .unwrap_or((None, None, None, None, None));

    // Filter out component manufacturers from MACs for vendor detection
    let vendor_macs: Vec<String> = macs
        .iter()
        .filter(|mac| {
            get_mac_vendor(mac)
                .map(|v| !COMPONENT_VENDORS.contains(&v))
                .unwrap_or(true)
        })
        .cloned()
        .collect();

    let device_vendor: String = characterize_vendor(
        detail_custom_vendor,
        detail_ssdp_friendly,
        detail_snmp_vendor,
        Some(selected_endpoint.as_str()),
        &vendor_macs,
        detail_ssdp_model,
    )
    .map(|c| c.value)
    .unwrap_or_default();

    // Get model: custom_model first, then SSDP/SNMP (with normalization), hostname, MAC, DHCP vendor class, vendor+type fallback

    // Check custom_model first (user-set model takes priority)
    let device_model: String = models_data
        .and_then(|(custom_model_opt, _, _, _, _, _)| custom_model_opt.clone())
        .or_else(|| {
            // Try SSDP model with normalization
            models_data
                .and_then(|(_, ssdp_model_opt, _, _, _, _)| ssdp_model_opt.as_ref())
                .and_then(|model| {
                    let vendor_ref = if device_vendor.is_empty() {
                        None
                    } else {
                        Some(device_vendor.as_str())
                    };
                    normalize_model_name(model, vendor_ref).or_else(|| Some(model.to_string()))
                })
        })
        .or_else(|| {
            // Try SNMP model (device self-reported via sysDescr)
            detail_snmp_model.map(|m| m.to_string())
        })
        .or_else(|| get_model_from_hostname(&selected_endpoint))
        .or_else(|| {
            // Context-aware MAC detection for Amazon devices etc.
            let has_ssdp = models_data
                .is_some_and(|(_, ssdp, friendly, _, _, _)| ssdp.is_some() || friendly.is_some());
            macs.iter().find_map(|mac| {
                infer_model_with_context(mac, has_ssdp, false, false, &[])
                    .or_else(|| get_model_from_mac(mac))
            })
        })
        .or_else(|| {
            // Try DHCP vendor class (e.g., "samsung:SM-G998B")
            endpoint_dhcp_vendor_classes
                .get(&selected_endpoint)
                .and_then(|vc| extract_model_from_vendor_class(vc))
        })
        .or_else(|| {
            // Use vendor + device type for more specific model
            let device_type = endpoint_types
                .get(&selected_endpoint)
                .copied()
                .unwrap_or("other");
            if !device_vendor.is_empty() {
                get_model_from_vendor_and_type(&device_vendor, device_type)
            } else {
                None
            }
        })
        .unwrap_or_default();

    // Ensure the selected endpoint's vendor/model are in the lookup maps
    // This handles cases where the endpoint was added via URL but its data
    // wasn't found in batch queries (e.g., mDNS-resolved names)
    let mut endpoint_vendors = endpoint_vendors;
    if !device_vendor.is_empty() {
        endpoint_vendors
            .entry(selected_lower.clone())
            .or_insert(device_vendor.clone());
    }
    if !device_model.is_empty() {
        endpoint_models
            .entry(selected_lower)
            .or_insert(device_model.clone());
    }

    let mut context = Context::new();
    context.insert("communications", &communications);
    context.insert("endpoints", &endpoints);
    context.insert("endpoint_types", &endpoint_types);
    context.insert("interfaces", &interfaces);
    context.insert("hostname", &hostname);
    context.insert("endpoint", &selected_endpoint);
    context.insert("supported_protocols", &supported_protocols);
    context.insert("selected_node", &effective_node);
    context.insert("dropdown_endpoints", &dropdown_endpoints);
    context.insert("endpoint_ips_macs", &endpoint_ips_macs);
    context.insert("endpoint_vendors", &endpoint_vendors);
    context.insert("unique_vendors", &unique_vendors);
    context.insert("endpoint_models", &endpoint_models);
    context.insert("endpoint_bytes", &endpoint_bytes);
    context.insert("endpoint_last_seen", &endpoint_last_seen);
    context.insert("endpoint_online_status", &endpoint_online_status);
    context.insert("ips", &ips);
    context.insert("macs", &macs);
    context.insert("mac_vendors", &mac_vendors);
    context.insert("device_vendor", &device_vendor);
    context.insert("device_model", &device_model);
    context.insert("hostnames", &hostnames);
    context.insert("ports", &ports);
    context.insert("protocols", &protocols);
    context.insert("bytes_in", &bytes_stats.bytes_in);
    context.insert("bytes_out", &bytes_stats.bytes_out);
    context.insert("dns_entries", &get_dns_entries());
    context.insert("manual_overrides", &manual_overrides);

    let rendered = tera
        .render("index.html", &context)
        .expect("Failed to render template");

    HttpResponse::Ok().body(rendered)
}

#[derive(serde::Deserialize)]
pub(super) struct NodeQuery {
    pub(super) node: Option<String>,
    pub(super) ip: Option<String>,
    pub(super) mac: Option<String>,
    pub(super) scan_interval: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looks_like_ip_ipv4() {
        assert!(looks_like_ip("192.168.1.1"));
        assert!(looks_like_ip("10.0.0.1"));
        assert!(looks_like_ip("255.255.255.255"));
        assert!(looks_like_ip("0.0.0.0"));
    }

    #[test]
    fn test_looks_like_ip_ipv6() {
        assert!(looks_like_ip("::1"));
        assert!(looks_like_ip("fe80::1"));
        assert!(looks_like_ip("2001:db8::1"));
        assert!(looks_like_ip("::ffff:192.168.1.1"));
    }

    #[test]
    fn test_looks_like_ip_hostnames() {
        assert!(!looks_like_ip("my-macbook.local"));
        assert!(!looks_like_ip("router"));
        assert!(!looks_like_ip("nintendo-switch"));
        assert!(!looks_like_ip("LG-Dishwasher"));
        assert!(!looks_like_ip("host.domain.com"));
    }

    #[test]
    fn test_looks_like_ip_edge_cases() {
        // Not quite an IP - wrong number of octets
        assert!(!looks_like_ip("192.168.1"));
        assert!(!looks_like_ip("192.168.1.1.1"));
        // Contains numbers but is a hostname
        assert!(!looks_like_ip("host123"));
        assert!(!looks_like_ip("192host"));
    }

    #[test]
    fn test_case_insensitive_hashmap_pattern() {
        // This tests the pattern used throughout the codebase for case-insensitive lookups
        let mut map: HashMap<String, String> = HashMap::new();

        // Insert with lowercase key
        map.insert("my-macbook.local".to_lowercase(), "value1".to_string());
        map.insert("nintendo-switch".to_lowercase(), "value2".to_string());

        // Lookup should work regardless of case
        assert_eq!(
            map.get(&"My-MacBook.local".to_lowercase()),
            Some(&"value1".to_string())
        );
        assert_eq!(
            map.get(&"MY-MACBOOK.LOCAL".to_lowercase()),
            Some(&"value1".to_string())
        );
        assert_eq!(
            map.get(&"Nintendo-Switch".to_lowercase()),
            Some(&"value2".to_string())
        );
        assert_eq!(
            map.get(&"NINTENDO-SWITCH".to_lowercase()),
            Some(&"value2".to_string())
        );
    }

    #[test]
    fn test_case_insensitive_hashset_contains() {
        // Test HashSet pattern used for endpoint lookups
        let endpoints = vec![
            "My-MacBook.local".to_string(),
            "Nintendo-Switch".to_string(),
            "LG-Dishwasher".to_string(),
        ];

        let endpoints_lower: HashSet<String> = endpoints.iter().map(|e| e.to_lowercase()).collect();

        // All case variations should be found
        assert!(endpoints_lower.contains(&"my-macbook.local".to_string()));
        assert!(endpoints_lower.contains(&"MY-MACBOOK.LOCAL".to_lowercase()));
        assert!(endpoints_lower.contains(&"nintendo-switch".to_string()));
        assert!(endpoints_lower.contains(&"NINTENDO-SWITCH".to_lowercase()));
    }

    #[test]
    fn test_build_in_placeholders() {
        assert_eq!(build_in_placeholders(0), "");
        assert_eq!(build_in_placeholders(1), "?");
        assert_eq!(build_in_placeholders(3), "?,?,?");
        assert_eq!(build_in_placeholders(5), "?,?,?,?,?");
    }

    #[test]
    fn test_display_name_sql_constant_format() {
        // Verify the DISPLAY_NAME_SQL constant has expected structure
        assert!(DISPLAY_NAME_SQL.contains("COALESCE"));
        assert!(DISPLAY_NAME_SQL.contains("e.custom_name"));
        assert!(DISPLAY_NAME_SQL.contains("e.name"));
        assert!(DISPLAY_NAME_SQL.contains("MIN(hostname)"));
        assert!(DISPLAY_NAME_SQL.contains("MIN(ip)"));
        // Verify it filters out IP-like values
        assert!(DISPLAY_NAME_SQL.contains("NOT LIKE '%:%'")); // IPv6 filter
        assert!(DISPLAY_NAME_SQL.contains("NOT GLOB")); // IPv4 filter
    }
}
