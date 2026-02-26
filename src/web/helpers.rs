//! Database query helpers, shared types, and SQL constants for the web module.
//! Extracted from `mod.rs` to reduce file size and improve maintainability.

use std::collections::{HashMap, HashSet};

use dns_lookup::get_hostname;
use rusqlite::{Connection, params};
use serde::Serialize;

use crate::db::{
    insert_notification_with_endpoint_id, new_connection_result,
};
use crate::network::endpoint::{
    EndPoint, is_valid_display_name, strip_local_suffix,
};
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

// Re-export the macro for use in mod.rs
pub(super) use try_db;

// ============================================================================
// SQL Helper Functions and Constants
// ============================================================================

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

// ============================================================================
// Type Definitions
// ============================================================================

// Combined endpoint stats (bytes, last_seen, online) from single query
#[derive(Clone)]
pub(crate) struct EndpointStats {
    pub(crate) bytes: i64,
    pub(crate) last_seen: String,
    pub(crate) online: bool,
}

#[derive(serde::Serialize)]
pub(crate) struct EndpointDetailsResponse {
    pub(crate) endpoint_name: String,
    pub(crate) device_type: String,
    pub(crate) is_manual_override: bool,
    pub(crate) device_vendor: String,
    pub(crate) device_model: String,
    pub(crate) ips: Vec<String>,
    pub(crate) macs: Vec<String>,
    pub(crate) hostnames: Vec<String>,
    pub(crate) ports: Vec<String>,
    pub(crate) protocols: Vec<String>,
    pub(crate) bytes_in: i64,
    pub(crate) bytes_out: i64,
}

#[derive(serde::Deserialize)]
pub(crate) struct NodeQuery {
    pub(crate) node: Option<String>,
    pub(crate) ip: Option<String>,
    pub(crate) mac: Option<String>,
    pub(crate) scan_interval: Option<u64>,
}

#[derive(serde::Serialize)]
pub(crate) struct DnsEntryView {
    pub(crate) ip: String,
    pub(crate) hostname: String,
    pub(crate) services: String,
    pub(crate) timestamp: String,
}

#[derive(Serialize, Default)]
pub(crate) struct BytesStats {
    pub(crate) bytes_in: i64,
    pub(crate) bytes_out: i64,
}

/// Model/Vendor data tuple: (custom_model, ssdp_model, ssdp_friendly_name, custom_vendor)
pub(crate) type EndpointModelData = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

// ============================================================================
// Helper Functions
// ============================================================================

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

pub(crate) fn dropdown_endpoints(internal_minutes: u64) -> Vec<String> {
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

pub(crate) fn get_protocols_for_endpoint(hostname: String, internal_minutes: u64) -> Vec<String> {
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
pub(crate) fn get_endpoints_for_protocol(
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
pub(crate) fn get_all_protocols(internal_minutes: u64) -> Vec<String> {
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

pub(crate) fn get_ports_for_endpoint(hostname: String, internal_minutes: u64) -> Vec<String> {
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

pub(crate) fn get_endpoint_ips_and_macs(
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
pub(crate) fn get_endpoint_vendor_classes(endpoints: &[String]) -> HashMap<String, String> {
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

/// Get model, vendor, and SNMP data for all endpoints
/// Returns: (custom_model, ssdp_model, ssdp_friendly_name, custom_vendor, snmp_vendor, snmp_model)
pub(crate) fn get_endpoint_ssdp_models(
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

pub(crate) fn get_all_ips_macs_and_hostnames_from_single_hostname(
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
pub(crate) fn resolve_identifier_to_endpoint_ids(conn: &Connection, identifier: &str) -> Vec<i64> {
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
pub(crate) fn resolve_identifier_to_display_name(
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

pub(crate) fn get_all_endpoint_types(
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

pub(crate) fn get_bytes_for_endpoint(hostname: String, internal_minutes: u64) -> BytesStats {
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

pub(crate) fn get_all_endpoints_bytes(
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

pub(crate) fn get_all_endpoints_last_seen(
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
pub(crate) fn get_all_endpoints_online_status(
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

pub(crate) fn get_dns_entries() -> Vec<DnsEntryView> {
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
