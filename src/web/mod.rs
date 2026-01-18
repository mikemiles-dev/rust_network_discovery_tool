use actix_multipart::Multipart;
use actix_web::{
    App, HttpServer,
    web::{Data, Json, Query},
};
use actix_web::{HttpResponse, Responder, get, post};
use dns_lookup::get_hostname;
use futures_util::StreamExt;
use pnet::datalink;
use rust_embed::RustEmbed;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use tera::{Context, Tera};
use tokio::task;

use crate::db::{
    SQLWriter, get_all_settings, get_setting_i64, new_connection, new_connection_result,
    set_setting,
};
use crate::network::communication::extract_model_from_vendor_class;
use crate::network::device_control::DeviceController;
use crate::network::endpoint::{
    EndPoint, get_hostname_vendor, get_mac_vendor, get_model_from_hostname, get_model_from_mac,
    get_model_from_vendor_and_type, infer_model_with_context, normalize_model_name,
    strip_local_suffix,
};
use crate::network::mdns_lookup::MDnsLookup;
use crate::network::protocol::ProtocolPort;
use crate::scanner::manager::{ScanConfig, ScanManager};
use crate::scanner::{ScanResult, ScanType, check_scan_privileges};
use rusqlite::{Connection, OptionalExtension, params};
use std::sync::{Mutex, OnceLock};
use tokio::sync::mpsc;

// Track endpoints currently being probed to prevent duplicate probes
static PROBING_ENDPOINTS: OnceLock<Mutex<HashSet<i64>>> = OnceLock::new();

fn get_probing_endpoints() -> &'static Mutex<HashSet<i64>> {
    PROBING_ENDPOINTS.get_or_init(|| Mutex::new(HashSet::new()))
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
const DISPLAY_NAME_SQL: &str = "COALESCE(e.custom_name,
    CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%' AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' THEN e.name END,
    (SELECT MIN(hostname) FROM endpoint_attributes WHERE endpoint_id = e.id
     AND hostname IS NOT NULL AND hostname != ''
     AND hostname NOT LIKE '%:%' AND hostname NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'),
    (SELECT MIN(ip) FROM endpoint_attributes WHERE endpoint_id = e.id
     AND ip IS NOT NULL AND ip != ''),
    e.name)";

/// Build a SQL IN clause placeholder string for a given number of parameters
fn build_in_placeholders(count: usize) -> String {
    (0..count).map(|_| "?").collect::<Vec<_>>().join(",")
}

/// Build a boxed parameter vector from i64 slice (for endpoint IDs)
fn box_i64_params(ids: &[i64]) -> Vec<Box<dyn rusqlite::ToSql>> {
    ids.iter()
        .map(|id| Box::new(*id) as Box<dyn rusqlite::ToSql>)
        .collect()
}

/// Convert boxed params to reference slice for query execution
fn params_to_refs(params: &[Box<dyn rusqlite::ToSql>]) -> Vec<&dyn rusqlite::ToSql> {
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
fn looks_like_ip(s: &str) -> bool {
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
fn resolve_from_mdns_cache(name: &str) -> Option<String> {
    if looks_like_ip(name) {
        // probe_hostname checks cache first, then tries reverse DNS lookup
        MDnsLookup::probe_hostname(name).map(|h| strip_local_suffix(&h))
    } else {
        None
    }
}

/// Probe an HP printer's web interface to get its model name (blocking version)
/// HP printers typically expose their model in the HTML title or body
fn probe_hp_printer_model_blocking(ip: &str) -> Option<String> {
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    // Try to fetch the printer's main page
    let url = format!("http://{}/", ip);
    let response = match client.get(&url).send() {
        Ok(r) => r,
        Err(_) => return None,
    };

    let html = match response.text() {
        Ok(t) => t,
        Err(_) => return None,
    };

    // Convert to lowercase for case-insensitive tag matching
    let html_lower = html.to_lowercase();

    // Try to extract model from HTML title tag
    // HP printers typically have titles like "HP Color LaserJet MFP M283fdw"
    if let Some(start) = html_lower.find("<title>") {
        let title_start = start + 7;
        if let Some(end_offset) = html_lower[title_start..].find("</title>") {
            // Use original case HTML for the actual content
            let title = html[title_start..title_start + end_offset].trim();
            // Clean up the title - remove IP address and extra whitespace
            let model = title
                .split("&nbsp;")
                .next()
                .unwrap_or(title)
                .split("  ")
                .next()
                .unwrap_or(title)
                .trim();

            // Only return if it looks like an HP model
            let model_lower = model.to_lowercase();
            if model_lower.contains("hp ")
                || model_lower.starts_with("hp")
                || model_lower.contains("laserjet")
                || model_lower.contains("officejet")
                || model_lower.contains("deskjet")
                || model_lower.contains("envy")
            {
                return Some(model.to_string());
            }
        }
    }

    // Try to extract from <h1> tag (common in HP printer pages)
    if let Some(start) = html_lower.find("<h1>") {
        let h1_start = start + 4;
        if let Some(end_offset) = html_lower[h1_start..].find("</h1>") {
            let h1_content = html[h1_start..h1_start + end_offset].trim();
            let h1_lower = h1_content.to_lowercase();
            if h1_lower.contains("hp ") || h1_lower.starts_with("hp") {
                return Some(h1_content.to_string());
            }
        }
    }

    None
}

/// Probe an HP printer and save the model to the database if found (blocking)
fn probe_and_save_hp_printer_model_blocking(ip: &str, endpoint_id: i64) {
    if let Some(model) = probe_hp_printer_model_blocking(ip) {
        // Save the model to the database
        if let Ok(conn) = new_connection_result() {
            match conn.execute(
                "UPDATE endpoints SET ssdp_model = ?1 WHERE id = ?2 AND (ssdp_model IS NULL OR ssdp_model = '')",
                params![model, endpoint_id],
            ) {
                Ok(rows) => eprintln!("HP probe updated {} rows for endpoint {}", rows, endpoint_id),
                Err(e) => eprintln!("HP probe DB error: {}", e),
            }
        }
    }
}

fn dropdown_endpoints(internal_minutes: u64) -> Vec<String> {
    let conn = new_connection();
    // Use JOIN instead of correlated subquery for better performance
    // Fall back to IP address if no valid hostname exists (will be resolved via mDNS)
    let mut stmt = conn
        .prepare(
            "
            SELECT DISTINCT COALESCE(e.custom_name,
                CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%' AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' THEN e.name END,
                ea_best.hostname,
                ea_ip.ip,
                e.name) AS display_name
            FROM endpoints e
            INNER JOIN communications c
                ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
            LEFT JOIN (
                SELECT endpoint_id, MIN(hostname) AS hostname
                FROM endpoint_attributes
                WHERE hostname IS NOT NULL AND hostname != ''
                  AND hostname NOT LIKE '%:%'
                  AND hostname NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
                GROUP BY endpoint_id
            ) ea_best ON ea_best.endpoint_id = e.id
            LEFT JOIN (
                SELECT endpoint_id, MIN(ip) AS ip
                FROM endpoint_attributes
                WHERE ip IS NOT NULL AND ip != ''
                GROUP BY endpoint_id
            ) ea_ip ON ea_ip.endpoint_id = e.id
            WHERE c.last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
        ",
        )
        .expect("Failed to prepare statement");

    let rows = stmt
        .query_map([internal_minutes], |row| row.get(0))
        .expect("Failed to execute query");

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

fn get_protocols_for_endpoint(hostname: String, internal_minutes: u64) -> Vec<String> {
    let conn = new_connection();

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

    let mut stmt = conn.prepare(&query).expect("Failed to prepare statement");

    // Build parameters: internal_minutes + endpoint_ids (2 times for src and dst)
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(internal_minutes)];
    params.extend(box_i64_params(&endpoint_ids));
    params.extend(box_i64_params(&endpoint_ids));

    let rows = stmt
        .query_map(params_to_refs(&params).as_slice(), |row| {
            row.get::<_, String>(0)
        })
        .expect("Failed to execute query");

    rows.filter_map(|row| row.ok()).collect()
}

/// Get endpoints using a protocol, optionally filtered to only those communicating with a specific endpoint
fn get_endpoints_for_protocol(
    protocol: &str,
    internal_minutes: u64,
    from_endpoint: Option<&str>,
) -> Vec<String> {
    let conn = new_connection();

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

            let mut stmt = conn.prepare(&query).expect("Failed to prepare statement");

            let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> =
                vec![Box::new(internal_minutes), Box::new(protocol.to_string())];
            params_vec.extend(box_i64_params(&endpoint_ids));
            params_vec.extend(box_i64_params(&endpoint_ids));

            let rows = stmt
                .query_map(params_to_refs(&params_vec).as_slice(), |row| {
                    row.get::<_, String>(0)
                })
                .expect("Failed to execute query");

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

            let mut stmt = conn.prepare(query).expect("Failed to prepare statement");

            let rows = stmt
                .query_map(params![internal_minutes, protocol], |row| {
                    row.get::<_, String>(0)
                })
                .expect("Failed to execute query");

            rows.filter_map(|row| row.ok()).collect()
        }
    }
}

/// Get all protocols seen across all endpoints
fn get_all_protocols(internal_minutes: u64) -> Vec<String> {
    let conn = new_connection();

    let query =
        "SELECT DISTINCT COALESCE(NULLIF(c.sub_protocol, ''), c.ip_header_protocol) as protocol
        FROM communications c
        WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
        ORDER BY protocol";

    let mut stmt = conn.prepare(query).expect("Failed to prepare statement");

    let rows = stmt
        .query_map(params![internal_minutes], |row| row.get::<_, String>(0))
        .expect("Failed to execute query");

    rows.filter_map(|row| row.ok()).collect()
}

fn get_ports_for_endpoint(hostname: String, internal_minutes: u64) -> Vec<String> {
    let conn = new_connection();

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

    let mut stmt = conn.prepare(&query).expect("Failed to prepare statement");

    // Build parameters: internal_minutes + endpoint_ids (1 time for the IN clause)
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(internal_minutes)];
    params.extend(box_i64_params(&endpoint_ids));

    let rows = stmt
        .query_map(params_to_refs(&params).as_slice(), |row| {
            row.get::<_, i64>(0)
        })
        .expect("Failed to execute query");

    rows.filter_map(|row| row.ok())
        .map(|port| port.to_string())
        .collect()
}

/// Extract listening ports from communications data (already filtered for graph)
/// Only shows destination ports where endpoint is the destination (ports it's listening on)
/// Excludes ephemeral ports (49152-65535) which are just used for receiving responses
fn get_ports_from_communications(communications: &[Node], selected_endpoint: &str) -> Vec<String> {
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

fn get_endpoint_ips_and_macs(endpoints: &[String]) -> HashMap<String, (Vec<String>, Vec<String>)> {
    let conn = new_connection();
    let mut result: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();

    // Initialize all endpoints with empty vectors (use lowercase keys for case-insensitive matching)
    for endpoint in endpoints {
        result.insert(endpoint.to_lowercase(), (Vec::new(), Vec::new()));
    }

    // Single batch query to get all IPs and MACs with their display names
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {DISPLAY_NAME_SQL} AS display_name, ea.ip, ea.mac
             FROM endpoints e
             INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id"
        ))
        .expect("Failed to prepare batch IPs/MACs statement");

    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let ip: Option<String> = row.get(1)?;
            let mac: Option<String> = row.get(2)?;
            Ok((name, ip, mac))
        })
        .expect("Failed to execute batch IPs/MACs query");

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
fn get_endpoint_vendor_classes(endpoints: &[String]) -> HashMap<String, String> {
    let conn = new_connection();
    let mut result: HashMap<String, String> = HashMap::new();

    // Build lowercase set for case-insensitive matching
    let endpoints_lower: HashSet<String> = endpoints.iter().map(|e| e.to_lowercase()).collect();

    let mut stmt = conn
        .prepare(&format!(
            "SELECT {DISPLAY_NAME_SQL} AS display_name, ea.dhcp_vendor_class
             FROM endpoints e
             INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
             WHERE ea.dhcp_vendor_class IS NOT NULL AND ea.dhcp_vendor_class != ''"
        ))
        .expect("Failed to prepare vendor class statement");

    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let vendor_class: String = row.get(1)?;
            Ok((name, vendor_class))
        })
        .expect("Failed to execute vendor class query");

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
type EndpointModelData = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Get SSDP model, friendly name, custom model, and custom vendor for all endpoints
/// Returns: (custom_model, ssdp_model, ssdp_friendly_name, custom_vendor)
fn get_endpoint_ssdp_models(endpoints: &[String]) -> HashMap<String, EndpointModelData> {
    let conn = new_connection();
    let mut result: HashMap<String, EndpointModelData> = HashMap::new();

    // Build lowercase set for case-insensitive matching
    let endpoints_lower: HashSet<String> = endpoints.iter().map(|e| e.to_lowercase()).collect();

    let mut stmt = conn
        .prepare(&format!(
            "SELECT {DISPLAY_NAME_SQL} AS display_name, e.custom_model, e.ssdp_model, e.ssdp_friendly_name, e.custom_vendor
             FROM endpoints e
             WHERE e.custom_model IS NOT NULL OR e.ssdp_model IS NOT NULL OR e.ssdp_friendly_name IS NOT NULL OR e.custom_vendor IS NOT NULL"
        ))
        .expect("Failed to prepare SSDP models statement");

    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let custom_model: Option<String> = row.get(1)?;
            let ssdp_model: Option<String> = row.get(2)?;
            let friendly_name: Option<String> = row.get(3)?;
            let custom_vendor: Option<String> = row.get(4)?;
            Ok((name, custom_model, ssdp_model, friendly_name, custom_vendor))
        })
        .expect("Failed to execute SSDP models query");

    for row in rows.flatten() {
        let (name, custom_model, ssdp_model, friendly_name, custom_vendor) = row;
        let name_lower = name.to_lowercase();
        if endpoints_lower.contains(&name_lower)
            && (custom_model.is_some()
                || ssdp_model.is_some()
                || friendly_name.is_some()
                || custom_vendor.is_some())
        {
            result.insert(
                name_lower,
                (custom_model, ssdp_model, friendly_name, custom_vendor),
            );
        }
    }

    result
}

fn get_all_ips_macs_and_hostnames_from_single_hostname(
    hostname: String,
    internal_minutes: u64,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let conn = new_connection();

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

    let mut stmt = conn.prepare(&query).expect("Failed to prepare statement");

    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(internal_minutes)];
    params.extend(box_i64_params(&endpoint_ids));

    let rows = stmt
        .query_map(params_to_refs(&params).as_slice(), |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .expect("Failed to execute query");

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
fn resolve_identifier_to_endpoint_ids(conn: &Connection, identifier: &str) -> Vec<i64> {
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

fn get_nodes(current_node: Option<String>, internal_minutes: u64) -> Vec<Node> {
    let conn = new_connection();

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
    let endpoint_info_cte = "
        WITH endpoint_info AS (
            SELECT
                e.id,
                COALESCE(e.custom_name,
                    CASE WHEN e.name IS NOT NULL AND e.name != '' AND e.name NOT LIKE '%:%' AND e.name NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' THEN e.name END,
                    MIN(CASE WHEN ea.hostname IS NOT NULL AND ea.hostname != '' THEN ea.hostname END)) AS display_name,
                MIN(ea.ip) AS ip
            FROM endpoints e
            LEFT JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
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

    let mut stmt = conn.prepare(&query).expect("Failed to prepare statement");

    let rows = stmt
        .query_map(params_to_refs(&params).as_slice(), |row| {
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
        })
        .expect("Failed to execute query");

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

fn get_all_endpoint_types(
    endpoints: &[String],
) -> (
    std::collections::HashMap<String, &'static str>,
    std::collections::HashSet<String>,
) {
    let conn = new_connection();
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
    {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {DISPLAY_NAME_SQL} AS display_name, ea.ip
                 FROM endpoints e
                 INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
                 WHERE ea.ip IS NOT NULL"
            ))
            .expect("Failed to prepare IP batch statement");

        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let ip: String = row.get(1)?;
                Ok((name, ip))
            })
            .expect("Failed to execute IP batch query");

        for row in rows.flatten() {
            // Use lowercase keys for case-insensitive lookups
            all_ips.entry(row.0.to_lowercase()).or_default().push(row.1);
        }
    }

    // Batch fetch all MACs for all endpoints in one query
    let mut all_macs: HashMap<String, Vec<String>> = HashMap::new();
    {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {DISPLAY_NAME_SQL} AS display_name, ea.mac
                 FROM endpoints e
                 INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
                 WHERE ea.mac IS NOT NULL"
            ))
            .expect("Failed to prepare MAC batch statement");

        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let mac: String = row.get(1)?;
                Ok((name, mac))
            })
            .expect("Failed to execute MAC batch query");

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
    {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {DISPLAY_NAME_SQL} AS display_name, op.port
                 FROM endpoints e
                 INNER JOIN open_ports op ON e.id = op.endpoint_id
                 GROUP BY e.id, op.port"
            ))
            .expect("Failed to prepare port batch statement");

        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let port: i64 = row.get(1)?;
                Ok((name, port))
            })
            .expect("Failed to execute port batch query");

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
    {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {DISPLAY_NAME_SQL} AS display_name, e.ssdp_model
                 FROM endpoints e
                 WHERE e.ssdp_model IS NOT NULL AND e.ssdp_model != ''"
            ))
            .expect("Failed to prepare SSDP model batch statement");

        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let model: String = row.get(1)?;
                Ok((name, model))
            })
            .expect("Failed to execute SSDP model batch query");

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
        if let Some(auto_type) = auto_types_lower.get(&endpoint_lower) {
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
struct BytesStats {
    bytes_in: i64,
    bytes_out: i64,
}

#[derive(Serialize)]
struct EndpointDetailsResponse {
    endpoint_name: String,
    device_type: String,
    is_manual_override: bool,
    device_vendor: String,
    device_model: String,
    ips: Vec<String>,
    macs: Vec<String>,
    hostnames: Vec<String>,
    ports: Vec<String>,
    protocols: Vec<String>,
    bytes_in: i64,
    bytes_out: i64,
}

#[derive(Serialize)]
struct DnsEntryView {
    ip: String,
    hostname: String,
    services: String,
    timestamp: String,
}

fn get_dns_entries() -> Vec<DnsEntryView> {
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

#[get("/api/dns-entries")]
async fn get_dns_entries_api() -> impl Responder {
    HttpResponse::Ok().json(get_dns_entries())
}

#[derive(serde::Serialize)]
struct InternetDestinationsResponse {
    destinations: Vec<crate::network::endpoint::InternetDestination>,
}

/// Get all internet destinations
#[get("/api/internet")]
async fn get_internet_destinations() -> impl Responder {
    let result = task::spawn_blocking(|| {
        let conn = new_connection();
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

#[derive(serde::Deserialize)]
struct ProbeRequest {
    ip: String,
}

#[derive(serde::Serialize)]
struct ProbeResponse {
    ip: String,
    hostname: Option<String>,
    success: bool,
}

/// Probe a device for its hostname using reverse DNS/mDNS lookup
/// Also persists the hostname to the database if found
#[post("/api/probe-hostname")]
async fn probe_hostname(body: Json<ProbeRequest>) -> impl Responder {
    use crate::network::mdns_lookup::MDnsLookup;

    let hostname = MDnsLookup::probe_hostname(&body.ip);

    // If we found a real hostname (not just the IP back), save it to the database
    if let Some(ref h) = hostname
        && !looks_like_ip(h)
    {
        let ip_clone = body.ip.clone();
        let hostname_clone = h.clone();
        // Spawn a blocking task to update the database
        tokio::task::spawn_blocking(move || {
            if let Ok(conn) = new_connection_result() {
                // Update hostname in endpoint_attributes where ip matches
                let _ = conn.execute(
                    "UPDATE endpoint_attributes SET hostname = ?1 WHERE ip = ?2 AND (hostname IS NULL OR hostname = ?2 OR hostname LIKE '%:%' OR hostname GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*')",
                    rusqlite::params![hostname_clone, ip_clone],
                );
            }
        });
    }

    HttpResponse::Ok().json(ProbeResponse {
        ip: body.ip.clone(),
        hostname: hostname.clone(),
        success: hostname.is_some(),
    })
}

#[derive(Deserialize)]
struct PingRequest {
    ip: String,
}

#[derive(Serialize)]
struct PingResponse {
    success: bool,
    latency_ms: Option<f64>,
    message: Option<String>,
}

/// Ping a device using ICMP echo
#[post("/api/ping")]
async fn ping_endpoint(body: Json<PingRequest>) -> impl Responder {
    use std::net::IpAddr;
    use std::process::Command;
    use std::time::Instant;

    let ip = body.ip.clone();

    // Validate IP address
    if ip.parse::<IpAddr>().is_err() {
        return HttpResponse::BadRequest().json(PingResponse {
            success: false,
            latency_ms: None,
            message: Some("Invalid IP address".to_string()),
        });
    }

    // Use system ping command (works without root on most systems)
    // macOS uses -t for timeout, Linux uses -W
    let start = Instant::now();
    #[cfg(target_os = "macos")]
    let output = Command::new("ping")
        .args(["-c", "1", "-t", "2", &ip])
        .output();
    #[cfg(not(target_os = "macos"))]
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "2", &ip])
        .output();

    match output {
        Ok(result) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            if result.status.success() {
                // Try to parse actual latency from ping output
                let stdout = String::from_utf8_lossy(&result.stdout);
                let latency = parse_ping_latency(&stdout).unwrap_or(elapsed);
                HttpResponse::Ok().json(PingResponse {
                    success: true,
                    latency_ms: Some(latency),
                    message: None,
                })
            } else {
                HttpResponse::Ok().json(PingResponse {
                    success: false,
                    latency_ms: None,
                    message: Some("Host unreachable".to_string()),
                })
            }
        }
        Err(e) => HttpResponse::Ok().json(PingResponse {
            success: false,
            latency_ms: None,
            message: Some(format!("Ping failed: {}", e)),
        }),
    }
}

/// Parse latency from ping output (e.g., "time=1.23 ms")
fn parse_ping_latency(output: &str) -> Option<f64> {
    for line in output.lines() {
        if let Some(time_idx) = line.find("time=") {
            let after_time = &line[time_idx + 5..];
            if let Some(latency) = after_time.find(" ms").and_then(|idx| after_time[..idx].parse::<f64>().ok()) {
                return Some(latency);
            }
            // Also try without space (time=1.23ms)
            if let Some(latency) = after_time.find("ms").and_then(|idx| after_time[..idx].parse::<f64>().ok()) {
                return Some(latency);
            }
        }
    }
    None
}

#[derive(Deserialize)]
struct PortScanRequest {
    ip: String,
}

#[derive(Serialize)]
struct OpenPort {
    port: u16,
    service: Option<String>,
}

#[derive(Serialize)]
struct PortScanResponse {
    success: bool,
    open_ports: Vec<OpenPort>,
    message: Option<String>,
}

/// Scan common ports on a device
#[post("/api/port-scan")]
async fn port_scan_endpoint(body: Json<PortScanRequest>) -> impl Responder {
    use std::net::{IpAddr, SocketAddr, TcpStream};
    use std::time::Duration;

    let ip = body.ip.clone();

    // Validate IP address
    let ip_addr: IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => {
            return HttpResponse::BadRequest().json(PortScanResponse {
                success: false,
                open_ports: vec![],
                message: Some("Invalid IP address".to_string()),
            });
        }
    };

    // Common ports to scan
    let ports_to_scan: Vec<(u16, &str)> = vec![
        (21, "FTP"),
        (22, "SSH"),
        (23, "Telnet"),
        (25, "SMTP"),
        (53, "DNS"),
        (80, "HTTP"),
        (110, "POP3"),
        (143, "IMAP"),
        (443, "HTTPS"),
        (445, "SMB"),
        (993, "IMAPS"),
        (995, "POP3S"),
        (3389, "RDP"),
        (5000, "UPnP"),
        (5900, "VNC"),
        (8080, "HTTP-Alt"),
        (8443, "HTTPS-Alt"),
        (8888, "HTTP-Alt"),
        (9000, "HTTP-Alt"),
    ];

    // Scan ports concurrently
    let ip_for_scan = ip_addr;
    let open_ports = tokio::task::spawn_blocking(move || {
        let mut open = Vec::new();
        let timeout = Duration::from_millis(500);

        for (port, service) in ports_to_scan {
            let addr = SocketAddr::new(ip_for_scan, port);
            if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                open.push(OpenPort {
                    port,
                    service: Some(service.to_string()),
                });
            }
        }
        open
    })
    .await
    .unwrap_or_default();

    HttpResponse::Ok().json(PortScanResponse {
        success: true,
        open_ports,
        message: None,
    })
}

#[get("/api/endpoint/{name}/details")]
async fn get_endpoint_details(
    path: actix_web::web::Path<String>,
    query: actix_web::web::Query<NodeQuery>,
) -> impl Responder {
    let endpoint_name = path.into_inner();
    let internal_minutes = query.scan_interval.unwrap_or(525600);

    // Run all blocking DB operations in a separate thread pool
    let result = tokio::task::spawn_blocking(move || {
        get_endpoint_details_blocking(endpoint_name, internal_minutes)
    })
    .await;

    match result {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to fetch endpoint details"
        })),
    }
}

/// Blocking implementation of endpoint details fetching
fn get_endpoint_details_blocking(
    endpoint_name: String,
    internal_minutes: u64,
) -> EndpointDetailsResponse {
    // Get IPs, MACs, and hostnames
    let (ips, macs, hostnames) = get_all_ips_macs_and_hostnames_from_single_hostname(
        endpoint_name.clone(),
        internal_minutes,
    );

    // Get device type for this endpoint
    let conn = new_connection();
    let manual_types = EndPoint::get_all_manual_device_types(&conn);
    let auto_types = EndPoint::get_all_auto_device_types(&conn);

    // Check for manual override first (case-insensitive)
    let manual_type = manual_types
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&endpoint_name))
        .map(|(_, v)| v.clone());

    // Check for stored auto-detected type (persists across renames)
    let stored_auto_type = auto_types
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&endpoint_name))
        .map(|(_, v)| v.clone());

    // Get SSDP model for this endpoint (for device classification)
    let ssdp_model: Option<String> = conn
        .query_row(
            &format!(
                "SELECT e.ssdp_model FROM endpoints e WHERE {} = ?1 COLLATE NOCASE AND e.ssdp_model IS NOT NULL",
                DISPLAY_NAME_SQL
            ),
            [&endpoint_name],
            |row| row.get(0),
        )
        .ok();

    // Get local hostname for comparison
    let local_hostname =
        strip_local_suffix(&get_hostname().unwrap_or_else(|_| "Unknown".to_string()));

    let (device_type, is_manual_override) = if let Some(mt) = manual_type {
        (mt, true)
    } else if let Some(at) = stored_auto_type {
        // Use stored auto-detected type (persists across renames)
        (at, false)
    } else if endpoint_name.eq_ignore_ascii_case(&local_hostname) {
        // This is the local machine
        let _ = EndPoint::set_auto_device_type(&conn, &endpoint_name, "local");
        ("local".to_string(), false)
    } else {
        // First check network-level classification (gateway, internet)
        let first_ip = ips.first().cloned();
        if let Some(network_type) =
            EndPoint::classify_endpoint(first_ip.clone(), Some(endpoint_name.clone()))
        {
            let _ = EndPoint::set_auto_device_type(&conn, &endpoint_name, network_type);
            (network_type.to_string(), false)
        } else {
            // Use EndPoint::classify_device_type for device-specific detection
            let auto_type = EndPoint::classify_device_type(
                Some(&endpoint_name),
                &ips,
                &[],
                &macs,
                ssdp_model.as_deref(),
            )
            .unwrap_or_else(|| {
                // Fallback: if on local network, classify as "local", otherwise "other"
                if let Some(ref ip_str) = first_ip {
                    if EndPoint::is_on_local_network(ip_str) {
                        "local"
                    } else {
                        "other"
                    }
                } else {
                    "other"
                }
            });
            let _ = EndPoint::set_auto_device_type(&conn, &endpoint_name, auto_type);
            (auto_type.to_string(), false)
        }
    };

    // Get device vendor from MAC or hostname
    // Prefer hostname vendor over component manufacturers (Espressif, Tuya, etc.)
    let mac_vendor = macs.iter().find_map(|mac| get_mac_vendor(mac));
    let hostname_vendor = get_hostname_vendor(&endpoint_name);

    // Component vendors - these make chips/modules used by other manufacturers
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

    let device_vendor: String = match (hostname_vendor, mac_vendor) {
        // Hostname vendor identified (e.g., LG from "ldf7774st") - prefer it
        (Some(hv), _) => hv,
        // MAC vendor is a component manufacturer - don't show it
        (None, Some(mv)) if COMPONENT_VENDORS.contains(&mv) => "",
        // MAC vendor is a product manufacturer - show it
        (None, Some(mv)) => mv,
        // No vendor identified
        (None, None) => "",
    }
    .to_string();

    // Get DHCP vendor class for this endpoint (if available)
    let dhcp_vendor_class: Option<String> = conn
        .query_row(
            "SELECT ea.dhcp_vendor_class
         FROM endpoints e
         INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
         WHERE (LOWER(e.name) = LOWER(?1) OR LOWER(e.custom_name) = LOWER(?1))
         AND ea.dhcp_vendor_class IS NOT NULL AND ea.dhcp_vendor_class != ''
         LIMIT 1",
            rusqlite::params![&endpoint_name],
            |row| row.get(0),
        )
        .ok();

    // Get custom_model and SSDP model for this endpoint
    let (custom_model, ssdp_model): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT e.custom_model, e.ssdp_model
         FROM endpoints e
         WHERE (LOWER(e.name) = LOWER(?1) OR LOWER(e.custom_name) = LOWER(?1))
         LIMIT 1",
            rusqlite::params![&endpoint_name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or((None, None));

    // Check if device has SSDP info (for context-aware model detection)
    // Check for non-empty string, not just Some()
    let has_ssdp = ssdp_model.as_ref().is_some_and(|m| !m.is_empty());

    // Auto-probe HP devices without a model
    // Check for None OR empty string since database might have either
    let needs_model = custom_model.as_ref().is_none_or(|m| m.is_empty())
        && ssdp_model.as_ref().is_none_or(|m| m.is_empty());

    // Debug logging for HP probe
    if device_vendor == "HP" {
        eprintln!(
            "HP device check: vendor={}, custom_model={:?}, ssdp_model={:?}, needs_model={}",
            device_vendor, custom_model, ssdp_model, needs_model
        );
    }

    if device_vendor == "HP"
        && needs_model
        && let Some(ip) = ips.first().cloned()
        && let Ok(endpoint_id) = conn.query_row(
            "SELECT e.id FROM endpoints e WHERE LOWER(e.name) = LOWER(?1) OR LOWER(e.custom_name) = LOWER(?1) LIMIT 1",
            rusqlite::params![&endpoint_name],
            |row| row.get::<_, i64>(0),
        )
    {
        // Check if already probing this endpoint to prevent duplicate probes
        let should_probe = {
            let mut probing = get_probing_endpoints().lock().unwrap();
            if probing.contains(&endpoint_id) {
                false
            } else {
                probing.insert(endpoint_id);
                true
            }
        };

        if should_probe {
            eprintln!("Auto-probing HP device at {} (endpoint {})", ip, endpoint_id);
            // Spawn a thread for the probe (we're already in a blocking context)
            std::thread::spawn(move || {
                probe_and_save_hp_printer_model_blocking(&ip, endpoint_id);
                // Remove from probing set when done
                let mut probing = get_probing_endpoints().lock().unwrap();
                probing.remove(&endpoint_id);
            });
        }
    }

    // Get device model: custom_model first, then SSDP (with normalization), hostname, MAC, DHCP vendor class, vendor+type fallback
    let device_model: String = custom_model
        .or_else(|| {
            ssdp_model.as_ref().and_then(|model| {
                // Try to normalize the SSDP model (e.g., QN43LS03TAFXZA -> Samsung The Frame)
                let vendor_ref = if device_vendor.is_empty() {
                    None
                } else {
                    Some(device_vendor.as_str())
                };
                normalize_model_name(model, vendor_ref).or_else(|| Some(model.clone()))
            })
        })
        .or_else(|| get_model_from_hostname(&endpoint_name))
        .or_else(|| {
            // Context-aware MAC detection for Amazon devices etc.
            macs.iter().find_map(|mac| {
                infer_model_with_context(mac, has_ssdp, false, false, &[])
                    .or_else(|| get_model_from_mac(mac))
            })
        })
        .or_else(|| {
            // Try DHCP vendor class (e.g., "samsung:SM-G998B")
            dhcp_vendor_class
                .as_ref()
                .and_then(|vc| extract_model_from_vendor_class(vc))
        })
        .or_else(|| {
            // Use vendor + device type for more specific model
            if !device_vendor.is_empty() {
                get_model_from_vendor_and_type(&device_vendor, &device_type)
            } else {
                None
            }
        })
        .unwrap_or_default();

    // Get protocols
    let protocols = get_protocols_for_endpoint(endpoint_name.clone(), internal_minutes);

    // Get ports
    let ports = get_ports_for_endpoint(endpoint_name.clone(), internal_minutes);

    // Get bytes stats
    let bytes_stats = get_bytes_for_endpoint(endpoint_name.clone(), internal_minutes);

    EndpointDetailsResponse {
        endpoint_name,
        device_type,
        is_manual_override,
        device_vendor,
        device_model,
        ips,
        macs,
        hostnames,
        ports,
        protocols,
        bytes_in: bytes_stats.bytes_in,
        bytes_out: bytes_stats.bytes_out,
    }
}

#[derive(Serialize)]
struct ProtocolEndpointsResponse {
    protocol: String,
    endpoints: Vec<String>,
}

#[derive(Deserialize)]
struct ProtocolQuery {
    scan_interval: Option<u64>,
    from_endpoint: Option<String>,
}

#[get("/api/protocol/{protocol}/endpoints")]
async fn get_protocol_endpoints(
    path: actix_web::web::Path<String>,
    query: actix_web::web::Query<ProtocolQuery>,
) -> impl Responder {
    let protocol = path.into_inner();
    let internal_minutes = query.scan_interval.unwrap_or(525600);

    let endpoints =
        get_endpoints_for_protocol(&protocol, internal_minutes, query.from_endpoint.as_deref());

    HttpResponse::Ok().json(ProtocolEndpointsResponse {
        protocol,
        endpoints,
    })
}

#[derive(Serialize)]
struct AllProtocolsResponse {
    protocols: Vec<String>,
}

#[get("/api/protocols")]
async fn get_all_protocols_api(query: actix_web::web::Query<NodeQuery>) -> impl Responder {
    let internal_minutes = query.scan_interval.unwrap_or(525600);
    let protocols = get_all_protocols(internal_minutes);
    HttpResponse::Ok().json(AllProtocolsResponse { protocols })
}

fn get_bytes_for_endpoint(hostname: String, internal_minutes: u64) -> BytesStats {
    let conn = new_connection();

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

fn get_all_endpoints_bytes(endpoints: &[String], internal_minutes: u64) -> HashMap<String, i64> {
    let conn = new_connection();
    let mut result: HashMap<String, i64> = HashMap::new();

    // Initialize all endpoints with 0 bytes (use lowercase keys for case-insensitive matching)
    for endpoint in endpoints {
        result.insert(endpoint.to_lowercase(), 0);
    }

    // Single query to get all bytes data at once
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {DISPLAY_NAME_SQL} AS display_name, COALESCE(SUM(c.bytes), 0) as total_bytes
             FROM endpoints e
             INNER JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
             WHERE c.last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
             GROUP BY e.id"
        ))
        .expect("Failed to prepare statement");

    let rows = stmt
        .query_map([internal_minutes], |row| {
            let name: String = row.get(0)?;
            let bytes: i64 = row.get(1)?;
            Ok((name, bytes))
        })
        .expect("Failed to execute query");

    for row in rows.flatten() {
        let (name, bytes) = row;
        // Use lowercase for case-insensitive matching
        if let Some(existing) = result.get_mut(&name.to_lowercase()) {
            *existing = bytes;
        }
    }

    result
}

fn get_all_endpoints_last_seen(
    endpoints: &[String],
    internal_minutes: u64,
) -> HashMap<String, String> {
    let conn = new_connection();
    let mut result: HashMap<String, String> = HashMap::new();

    // Initialize all endpoints with empty string (use lowercase keys for case-insensitive matching)
    for endpoint in endpoints {
        result.insert(endpoint.to_lowercase(), String::new());
    }

    // Single query to get last_seen_at for each endpoint
    // Uses DISPLAY_NAME_SQL constant for consistency with other queries
    let mut stmt = conn
        .prepare(&format!(
            "SELECT
                {DISPLAY_NAME_SQL} AS display_name,
                MAX(c.last_seen_at) as last_seen
             FROM endpoints e
             INNER JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
             WHERE c.last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
             GROUP BY e.id"
        ))
        .expect("Failed to prepare statement");

    let rows = stmt
        .query_map([internal_minutes], |row| {
            let name: String = row.get(0)?;
            let last_seen: i64 = row.get(1)?;
            Ok((name, last_seen))
        })
        .expect("Failed to execute query");

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
fn get_all_endpoints_online_status(
    endpoints: &[String],
    threshold_seconds: u64,
) -> HashMap<String, bool> {
    let conn = new_connection();
    let mut result: HashMap<String, bool> = HashMap::new();

    // Initialize all endpoints as offline (use lowercase keys for case-insensitive matching)
    for endpoint in endpoints {
        result.insert(endpoint.to_lowercase(), false);
    }

    // Single query to get endpoints with recent traffic within threshold
    let mut stmt = conn
        .prepare(&format!(
            "SELECT
                {DISPLAY_NAME_SQL} AS display_name
             FROM endpoints e
             INNER JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
             WHERE c.last_seen_at >= (strftime('%s', 'now') - ?1)
             GROUP BY e.id"
        ))
        .expect("Failed to prepare statement");

    let rows = stmt
        .query_map([threshold_seconds], |row| {
            let name: String = row.get(0)?;
            Ok(name)
        })
        .expect("Failed to execute query");

    for row in rows.flatten() {
        // Use lowercase for case-insensitive matching
        if let Some(existing) = result.get_mut(&row.to_lowercase()) {
            *existing = true;
        }
    }

    result
}

pub fn start(preferred_port: u16) {
    task::spawn_blocking(move || {
        println!("Starting web server");
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
                        .service(delete_endpoint)
                        .service(probe_endpoint_model)
                        .service(get_dns_entries_api)
                        .service(get_internet_destinations)
                        .service(probe_hostname)
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
                        .service(get_settings)
                        .service(update_setting)
                        .service(upload_pcap)
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

                        // Start initial network scan on startup
                        tokio::spawn(async {
                            // Small delay to let the server fully initialize
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            let manager = get_scan_manager();
                            let config = manager.get_config().await;
                            let scan_types: Vec<ScanType> =
                                config.enabled_scanners.into_iter().collect();
                            if !scan_types.is_empty() {
                                println!("Starting initial network scan...");
                                if let Err(e) = manager.start_scan(scan_types).await {
                                    eprintln!("Failed to start initial scan: {}", e);
                                }
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
    let selected_endpoint = query.node.clone().unwrap_or_default();
    let scan_interval = query.scan_interval.unwrap_or(525600);

    // Phase 1: Run independent queries in parallel
    let query_node_1 = query.node.clone();
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
    if let Some(ref selected_node) = query.node
        && !endpoints.contains(selected_node)
    {
        endpoints.push(selected_node.clone());
    }
    // Also add to dropdown_endpoints so the node appears in the list
    if let Some(ref selected_node) = query.node
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
        // Get active threshold from settings (default 60 seconds = 1 minute)
        let active_threshold = get_setting_i64("active_threshold_seconds", 60) as u64;
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
    let endpoint_vendors: HashMap<String, String> = dropdown_endpoints
        .iter()
        .filter_map(|endpoint| {
            let endpoint_lower = endpoint.to_lowercase();

            // Check custom_vendor first (user-set vendor takes priority)
            if let Some((_, _, _, Some(custom_vendor))) = endpoint_ssdp_models.get(&endpoint_lower)
            {
                return Some((endpoint_lower, custom_vendor.clone()));
            }

            // Try hostname-based detection (catches PS4, Xbox, etc.)
            if let Some(vendor) = get_hostname_vendor(endpoint) {
                return Some((endpoint_lower, vendor.to_string()));
            }
            // Fall back to MAC-based detection, but filter out component manufacturers
            // Use lowercase for case-insensitive lookup
            let mac_vendor = endpoint_ips_macs
                .get(&endpoint_lower)
                .and_then(|(_, macs)| {
                    macs.iter().find_map(|mac| {
                        get_mac_vendor(mac).filter(|v| !component_vendors.contains(v))
                    })
                });
            mac_vendor.map(|v| (endpoint_lower, v.to_string()))
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

    // Build model lookup for all endpoints (custom_model first, then SSDP, hostname, MAC, DHCP vendor class)
    let endpoint_models: HashMap<String, String> = dropdown_endpoints
        .iter()
        .filter_map(|endpoint| {
            let endpoint_lower = endpoint.to_lowercase();
            // Get vendor for this endpoint (used for model normalization)
            let vendor = endpoint_vendors.get(&endpoint_lower).map(|v| v.as_str());

            // Check custom_model first (user-set model takes priority)
            if let Some((Some(custom_model), _, _, _)) = endpoint_ssdp_models.get(&endpoint_lower) {
                return Some((endpoint_lower.clone(), custom_model.clone()));
            }

            // Try SSDP/UPnP model (most accurate for TVs and media devices)
            if let Some((_, Some(ssdp_model), _, _)) = endpoint_ssdp_models.get(&endpoint_lower) {
                // Try to normalize the model name (e.g., QN43LS03TAFXZA -> Samsung The Frame)
                if let Some(normalized) = normalize_model_name(ssdp_model, vendor) {
                    return Some((endpoint_lower.clone(), normalized));
                }
                return Some((endpoint_lower.clone(), ssdp_model.clone()));
            }

            // Try hostname-based detection
            if let Some(model) = get_model_from_hostname(endpoint) {
                return Some((endpoint_lower.clone(), model));
            }

            // Fall back to context-aware MAC-based detection (for Amazon devices etc.)
            if let Some((_, macs)) = endpoint_ips_macs.get(&endpoint_lower) {
                // Check if device has SSDP info (indicates it's not a "silent" device like Echo)
                let has_ssdp = endpoint_ssdp_models
                    .get(&endpoint_lower)
                    .is_some_and(|(_, ssdp, friendly, _)| ssdp.is_some() || friendly.is_some());
                // Note: We don't have open ports data here, so pass empty slice
                // Full context-aware detection happens in get_endpoint_details
                for mac in macs {
                    if let Some(model) = infer_model_with_context(mac, has_ssdp, false, false, &[])
                    {
                        return Some((endpoint_lower.clone(), model));
                    }
                    if let Some(model) = get_model_from_mac(mac) {
                        return Some((endpoint_lower.clone(), model));
                    }
                }
            }

            // Fall back to DHCP vendor class (e.g., "samsung:SM-G998B" -> "SM-G998B")
            if let Some(vendor_class) = endpoint_dhcp_vendor_classes.get(&endpoint_lower)
                && let Some(model) = extract_model_from_vendor_class(vendor_class)
            {
                return Some((endpoint_lower, model));
            }
            None
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
    let ports_future = if query.node.is_some() {
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
    // Get first vendor for display next to device type
    // Prefer hostname vendor over component manufacturers (Espressif, Tuya, etc.)
    let mac_vendor = macs.iter().find_map(|mac| get_mac_vendor(mac));
    let hostname_vendor = get_hostname_vendor(&selected_endpoint);

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

    let device_vendor: String = match (hostname_vendor, mac_vendor) {
        (Some(hv), _) => hv,
        (None, Some(mv)) if COMPONENT_VENDORS.contains(&mv) => "",
        (None, Some(mv)) => mv,
        (None, None) => "",
    }
    .to_string();

    // Get model: custom_model first, then SSDP (with normalization), hostname, MAC, DHCP vendor class, vendor+type fallback
    let selected_lower = selected_endpoint.to_lowercase();
    let models_data = endpoint_ssdp_models.get(&selected_lower);

    // Check custom_model first (user-set model takes priority)
    let device_model: String = models_data
        .and_then(|(custom_model_opt, _, _, _)| custom_model_opt.clone())
        .or_else(|| {
            // Try SSDP model with normalization
            models_data
                .and_then(|(_, ssdp_model_opt, _, _)| ssdp_model_opt.as_ref())
                .and_then(|model| {
                    let vendor_ref = if device_vendor.is_empty() {
                        None
                    } else {
                        Some(device_vendor.as_str())
                    };
                    normalize_model_name(model, vendor_ref).or_else(|| Some(model.to_string()))
                })
        })
        .or_else(|| get_model_from_hostname(&selected_endpoint))
        .or_else(|| {
            // Context-aware MAC detection for Amazon devices etc.
            let has_ssdp = models_data
                .is_some_and(|(_, ssdp, friendly, _)| ssdp.is_some() || friendly.is_some());
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
    let selected_lower = selected_endpoint.to_lowercase();
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
    context.insert("selected_node", &query.node);
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

#[derive(Deserialize)]
struct NodeQuery {
    node: Option<String>,
    scan_interval: Option<u64>,
}

#[derive(Deserialize)]
struct ClassifyRequest {
    endpoint_name: String,
    device_type: Option<String>,
}

#[derive(Serialize)]
struct ClassifyResponse {
    success: bool,
    message: String,
}

#[post("/api/endpoint/classify")]
async fn set_endpoint_type(body: Json<ClassifyRequest>) -> impl Responder {
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
                HttpResponse::Ok().json(ClassifyResponse {
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
                HttpResponse::NotFound().json(ClassifyResponse {
                    success: false,
                    message: format!("Endpoint '{}' not found", body.endpoint_name),
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(ClassifyResponse {
            success: false,
            message: format!("Database error: {}", e),
        }),
    }
}

#[derive(Deserialize)]
struct RenameRequest {
    endpoint_name: String,
    custom_name: Option<String>,
}

#[derive(Serialize)]
struct RenameResponse {
    success: bool,
    message: String,
    original_name: Option<String>,
}

#[post("/api/endpoint/rename")]
async fn rename_endpoint(body: Json<RenameRequest>) -> impl Responder {
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
struct SetModelRequest {
    endpoint_name: String,
    model: Option<String>,
}

#[derive(Serialize)]
struct SetModelResponse {
    success: bool,
    message: String,
}

#[post("/api/endpoint/model")]
async fn set_endpoint_model(body: Json<SetModelRequest>) -> impl Responder {
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
                HttpResponse::Ok().json(SetModelResponse {
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
                HttpResponse::NotFound().json(SetModelResponse {
                    success: false,
                    message: format!("Endpoint '{}' not found", body.endpoint_name),
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(SetModelResponse {
            success: false,
            message: format!("Database error: {}", e),
        }),
    }
}

#[derive(Deserialize)]
struct SetVendorRequest {
    endpoint_name: String,
    vendor: Option<String>,
}

#[derive(Serialize)]
struct SetVendorResponse {
    success: bool,
    message: String,
}

#[post("/api/endpoint/vendor")]
async fn set_endpoint_vendor(body: Json<SetVendorRequest>) -> impl Responder {
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
                HttpResponse::Ok().json(SetVendorResponse {
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
                HttpResponse::NotFound().json(SetVendorResponse {
                    success: false,
                    message: format!("Endpoint '{}' not found", body.endpoint_name),
                })
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(SetVendorResponse {
            success: false,
            message: format!("Database error: {}", e),
        }),
    }
}

#[derive(Deserialize)]
struct DeleteEndpointRequest {
    endpoint_name: String,
}

#[derive(Serialize)]
struct DeleteEndpointResponse {
    success: bool,
    message: String,
}

/// Delete an endpoint and all associated data (communications, attributes, scan results)
#[post("/api/endpoint/delete")]
async fn delete_endpoint(body: Json<DeleteEndpointRequest>) -> impl Responder {
    let conn = new_connection();

    // First, find the endpoint ID(s) matching the name
    let endpoint_ids: Vec<i64> = match conn.prepare(&format!(
        "SELECT DISTINCT e.id FROM endpoints e
         LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
         WHERE {} = ?1 COLLATE NOCASE
            OR LOWER(ea.hostname) = LOWER(?1)
            OR LOWER(ea.ip) = LOWER(?1)",
        DISPLAY_NAME_SQL
    )) {
        Ok(mut stmt) => match stmt.query_map([&body.endpoint_name], |row| row.get(0)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                eprintln!("Error querying for endpoint to delete: {}", e);
                return HttpResponse::InternalServerError().json(DeleteEndpointResponse {
                    success: false,
                    message: format!("Database query error: {}", e),
                });
            }
        },
        Err(e) => {
            eprintln!("Error preparing delete query: {}", e);
            return HttpResponse::InternalServerError().json(DeleteEndpointResponse {
                success: false,
                message: format!("Database error: {}", e),
            });
        }
    };

    if endpoint_ids.is_empty() {
        return HttpResponse::NotFound().json(DeleteEndpointResponse {
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

        // Delete the endpoint itself
        deleted_endpoints += conn
            .execute("DELETE FROM endpoints WHERE id = ?1", params![endpoint_id])
            .unwrap_or(0);
    }

    HttpResponse::Ok().json(DeleteEndpointResponse {
        success: true,
        message: format!(
            "Deleted endpoint '{}': {} endpoint(s), {} attribute(s), {} scan result(s) (preserved {} communication records)",
            body.endpoint_name, deleted_endpoints, deleted_attrs, deleted_scans, updated_comms
        ),
    })
}

#[derive(Deserialize)]
struct ProbeModelRequest {
    ip: String,
}

#[derive(Serialize)]
struct ProbeModelResponse {
    success: bool,
    message: String,
    model: Option<String>,
}

/// Probe a device's web interface to detect its model
#[post("/api/endpoint/probe")]
async fn probe_endpoint_model(body: Json<ProbeModelRequest>) -> impl Responder {
    let ip = body.ip.clone();

    // Try to probe the device for its model (run in blocking thread for immediate execution)
    let ip_clone = ip.clone();
    let model = tokio::task::spawn_blocking(move || probe_hp_printer_model_blocking(&ip_clone))
        .await
        .ok()
        .flatten();

    if let Some(model) = model {
        // Find the endpoint and save the model
        let conn = match new_connection_result() {
            Ok(c) => c,
            Err(e) => {
                return HttpResponse::InternalServerError().json(ProbeModelResponse {
                    success: false,
                    message: format!("Database error: {}", e),
                    model: None,
                });
            }
        };

        // Find endpoint by IP and update the ssdp_model
        let update_result = conn.execute(
            "UPDATE endpoints SET ssdp_model = ?1
             WHERE id IN (SELECT endpoint_id FROM endpoint_attributes WHERE ip = ?2)
             AND (ssdp_model IS NULL OR ssdp_model = '')",
            params![model, ip],
        );

        match update_result {
            Ok(rows) => HttpResponse::Ok().json(ProbeModelResponse {
                success: true,
                message: format!("Found model '{}', updated {} endpoint(s)", model, rows),
                model: Some(model),
            }),
            Err(e) => HttpResponse::InternalServerError().json(ProbeModelResponse {
                success: false,
                message: format!("Found model '{}' but failed to save: {}", model, e),
                model: Some(model),
            }),
        }
    } else {
        HttpResponse::Ok().json(ProbeModelResponse {
            success: false,
            message: "Could not detect model from device web interface".to_string(),
            model: None,
        })
    }
}

// Device Control API

#[derive(Deserialize)]
struct DeviceQuery {
    ip: String,
    device_type: Option<String>,
    hostname: Option<String>,
}

#[derive(Deserialize)]
struct DeviceCommandRequest {
    ip: String,
    command: String,
    device_type: String,
}

#[derive(Deserialize)]
struct LaunchAppRequest {
    ip: String,
    app_id: String,
    device_type: String,
}

#[get("/api/device/capabilities")]
async fn get_device_capabilities(query: Query<DeviceQuery>) -> impl Responder {
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
async fn send_device_command(body: Json<DeviceCommandRequest>) -> impl Responder {
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
async fn launch_device_app(body: Json<LaunchAppRequest>) -> impl Responder {
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
struct PairRequest {
    ip: String,
    device_type: String,
}

#[post("/api/device/pair")]
async fn pair_device(body: Json<PairRequest>) -> impl Responder {
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
struct ThinQSetupRequest {
    pat_token: String,
    country_code: String,
}

#[derive(Serialize)]
struct ThinQStatusResponse {
    configured: bool,
    devices: Vec<ThinQDeviceInfo>,
}

#[derive(Serialize)]
struct ThinQDeviceInfo {
    device_id: String,
    device_type: String,
    name: String,
    model: Option<String>,
    online: bool,
}

#[post("/api/thinq/setup")]
async fn setup_thinq(body: Json<ThinQSetupRequest>) -> impl Responder {
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
async fn get_thinq_status() -> impl Responder {
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
async fn list_thinq_devices() -> impl Responder {
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
async fn disconnect_thinq() -> impl Responder {
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

// ============================================================================
// Network Scanner API Endpoints
// ============================================================================

/// Global scan manager instance
static SCAN_MANAGER: OnceLock<std::sync::Arc<ScanManager>> = OnceLock::new();

fn get_scan_manager() -> std::sync::Arc<ScanManager> {
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

/// Process a scan result and store in database with retry logic
fn process_scan_result(result: &ScanResult) -> Result<(), String> {
    const MAX_RETRIES: u32 = 5;

    for attempt in 1..=MAX_RETRIES {
        match process_scan_result_inner(result) {
            Ok(()) => return Ok(()),
            Err(e) if e.contains("database is locked") && attempt < MAX_RETRIES => {
                // Exponential backoff: 50ms, 100ms, 200ms, 400ms
                std::thread::sleep(std::time::Duration::from_millis(50 * (1 << (attempt - 1))));
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Err("Max retries exceeded".to_string())
}

/// Inner function that does the actual work
fn process_scan_result_inner(result: &ScanResult) -> Result<(), String> {
    let conn = new_connection();

    match result {
        ScanResult::Arp(arp) => {
            let ip_str = arp.ip.to_string();
            let mac_str = arp.mac.to_string();
            if let Ok(endpoint_id) = EndPoint::get_or_insert_endpoint(
                &conn,
                Some(mac_str.clone()),
                Some(ip_str.clone()),
                None,
                &[],
            ) {
                insert_scan_result(
                    &conn,
                    endpoint_id,
                    "arp",
                    Some(arp.response_time_ms as i64),
                    None,
                )?;

                // If this is an HP device, probe for printer model
                if get_mac_vendor(&mac_str).is_some_and(|v| v == "HP") {
                    let ip_for_probe = ip_str.clone();
                    tokio::task::spawn_blocking(move || {
                        probe_and_save_hp_printer_model_blocking(&ip_for_probe, endpoint_id);
                    });
                }
            }
        }
        ScanResult::Icmp(icmp) => {
            if icmp.alive {
                let ip_str = icmp.ip.to_string();
                // For ICMP (no MAC), only record if endpoint already exists
                // This prevents creating ghost entries for false positive pings
                if let Some(endpoint_id) = find_existing_endpoint_by_ip(&conn, &ip_str) {
                    let details = serde_json::json!({
                        "ttl": icmp.ttl,
                        "rtt_ms": icmp.rtt_ms,
                    });
                    insert_scan_result(
                        &conn,
                        endpoint_id,
                        "icmp",
                        icmp.rtt_ms.map(|r| r as i64),
                        Some(&details.to_string()),
                    )?;
                }
            }
        }
        ScanResult::Port(port) => {
            if port.open {
                let ip_str = port.ip.to_string();
                // For port scans (no MAC), only record if endpoint already exists
                if let Some(endpoint_id) = find_existing_endpoint_by_ip(&conn, &ip_str) {
                    insert_open_port(&conn, endpoint_id, port.port, port.service_name.as_deref())?;
                }
            }
        }
        ScanResult::Ssdp(ssdp) => {
            let ip_str = ssdp.ip.to_string();
            // For SSDP (no MAC), only record if endpoint already exists
            if let Some(endpoint_id) = find_existing_endpoint_by_ip(&conn, &ip_str) {
                let details = serde_json::json!({
                    "location": ssdp.location,
                    "server": ssdp.server,
                    "device_type": ssdp.device_type,
                    "friendly_name": ssdp.friendly_name,
                    "model_name": ssdp.model_name,
                });
                insert_scan_result(&conn, endpoint_id, "ssdp", None, Some(&details.to_string()))?;

                // If we got a model name from SSDP, save it to the endpoint
                if let Some(ref model) = ssdp.model_name {
                    let _ = conn.execute(
                        "UPDATE endpoints SET ssdp_model = ?1 WHERE id = ?2 AND (ssdp_model IS NULL OR ssdp_model = '')",
                        params![model, endpoint_id],
                    );
                }
                // If we got a friendly name from SSDP, save it
                if let Some(ref friendly) = ssdp.friendly_name {
                    let _ = conn.execute(
                        "UPDATE endpoints SET ssdp_friendly_name = ?1 WHERE id = ?2 AND (ssdp_friendly_name IS NULL OR ssdp_friendly_name = '')",
                        params![friendly, endpoint_id],
                    );
                }
            }
        }
        ScanResult::Ndp(ndp) => {
            let ip_str = ndp.ip.to_string();
            let mac_str = ndp.mac.to_string();
            if let Ok(endpoint_id) =
                EndPoint::get_or_insert_endpoint(&conn, Some(mac_str), Some(ip_str), None, &[])
            {
                insert_scan_result(
                    &conn,
                    endpoint_id,
                    "ndp",
                    Some(ndp.response_time_ms as i64),
                    None,
                )?;
            }
        }
    }

    Ok(())
}

/// Find an existing endpoint by IP address (must have a MAC to be considered valid)
/// Returns None if no endpoint with a MAC exists for this IP
fn find_existing_endpoint_by_ip(conn: &Connection, ip: &str) -> Option<i64> {
    conn.query_row(
        "SELECT ea.endpoint_id FROM endpoint_attributes ea
         WHERE ea.ip = ?1 AND ea.mac IS NOT NULL AND ea.mac != ''
         LIMIT 1",
        params![ip],
        |row| row.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

/// Insert a scan result into the database
/// Note: Table is created at startup in SQLWriter to avoid schema locks
fn insert_scan_result(
    conn: &Connection,
    endpoint_id: i64,
    scan_type: &str,
    response_time_ms: Option<i64>,
    details: Option<&str>,
) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT INTO scan_results (endpoint_id, scan_type, scanned_at, response_time_ms, details) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![endpoint_id, scan_type, now, response_time_ms, details],
    ).map_err(|e| e.to_string())?;

    Ok(())
}

/// Insert an open port into the database
/// Note: Table is created at startup in SQLWriter to avoid schema locks
fn insert_open_port(
    conn: &Connection,
    endpoint_id: i64,
    port: u16,
    service_name: Option<&str>,
) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT OR REPLACE INTO open_ports (endpoint_id, port, protocol, service_name, last_seen_at) VALUES (?1, ?2, 'tcp', ?3, ?4)",
        params![endpoint_id, port as i64, service_name, now],
    ).map_err(|e| e.to_string())?;

    Ok(())
}

#[derive(Deserialize)]
struct StartScanRequest {
    scan_types: Vec<ScanType>,
}

#[derive(Serialize)]
struct StartScanResponse {
    success: bool,
    message: String,
}

#[post("/api/scan/start")]
async fn start_scan(body: Json<StartScanRequest>) -> impl Responder {
    let manager = get_scan_manager();
    let scan_types = body.scan_types.clone();

    match manager.start_scan(scan_types).await {
        Ok(()) => HttpResponse::Ok().json(StartScanResponse {
            success: true,
            message: "Scan started".to_string(),
        }),
        Err(e) => HttpResponse::BadRequest().json(StartScanResponse {
            success: false,
            message: e,
        }),
    }
}

#[post("/api/scan/stop")]
async fn stop_scan() -> impl Responder {
    let manager = get_scan_manager();
    manager.stop_scan().await;

    HttpResponse::Ok().json(StartScanResponse {
        success: true,
        message: "Scan stopped".to_string(),
    })
}

#[get("/api/scan/status")]
async fn get_scan_status() -> impl Responder {
    let manager = get_scan_manager();
    let status = manager.get_status().await;

    HttpResponse::Ok().json(status)
}

#[get("/api/scan/capabilities")]
async fn get_scan_capabilities() -> impl Responder {
    let capabilities = check_scan_privileges();
    HttpResponse::Ok().json(capabilities)
}

#[get("/api/scan/config")]
async fn get_scan_config() -> impl Responder {
    let manager = get_scan_manager();
    let config = manager.get_config().await;

    HttpResponse::Ok().json(config)
}

#[post("/api/scan/config")]
async fn set_scan_config(body: Json<ScanConfig>) -> impl Responder {
    let manager = get_scan_manager();
    manager.set_config(body.into_inner()).await;

    HttpResponse::Ok().json(StartScanResponse {
        success: true,
        message: "Config updated".to_string(),
    })
}

// ============================================================================
// Settings Endpoints
// ============================================================================

#[derive(Serialize)]
struct SettingsResponse {
    settings: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
struct UpdateSettingRequest {
    key: String,
    value: String,
}

#[derive(Serialize)]
struct UpdateSettingResponse {
    success: bool,
    message: String,
}

#[get("/api/settings")]
async fn get_settings() -> impl Responder {
    let settings = tokio::task::spawn_blocking(get_all_settings)
        .await
        .unwrap_or_default();

    HttpResponse::Ok().json(SettingsResponse { settings })
}

#[post("/api/settings")]
async fn update_setting(body: Json<UpdateSettingRequest>) -> impl Responder {
    let key = body.key.clone();
    let value = body.value.clone();

    let result = tokio::task::spawn_blocking(move || set_setting(&key, &value)).await;

    match result {
        Ok(Ok(())) => HttpResponse::Ok().json(UpdateSettingResponse {
            success: true,
            message: format!("Setting '{}' updated", body.key),
        }),
        _ => HttpResponse::InternalServerError().json(UpdateSettingResponse {
            success: false,
            message: "Failed to update setting".to_string(),
        }),
    }
}

// ============================================================================
// PCAP Upload Endpoint
// ============================================================================

#[derive(Serialize)]
struct PcapUploadResponse {
    success: bool,
    message: String,
    packet_count: Option<usize>,
    filename: Option<String>,
}

#[post("/api/pcap/upload")]
async fn upload_pcap(mut payload: Multipart) -> impl Responder {
    let mut file_data: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;
    let mut label: Option<String> = None;

    // Extract file and label from multipart form
    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => {
                return HttpResponse::BadRequest().json(PcapUploadResponse {
                    success: false,
                    message: format!("Error reading multipart field: {}", e),
                    packet_count: None,
                    filename: None,
                });
            }
        };

        let field_name = field.name().unwrap_or("").to_string();

        if field_name == "file" {
            // Get filename from content disposition
            if let Some(cd) = field.content_disposition() {
                filename = cd.get_filename().map(|s| s.to_string());
            }

            // Read file data
            let mut data = Vec::new();
            while let Some(chunk) = field.next().await {
                match chunk {
                    Ok(bytes) => data.extend_from_slice(&bytes),
                    Err(e) => {
                        return HttpResponse::BadRequest().json(PcapUploadResponse {
                            success: false,
                            message: format!("Error reading file data: {}", e),
                            packet_count: None,
                            filename: None,
                        });
                    }
                }
            }
            file_data = Some(data);
        } else if field_name == "label" {
            // Read label field
            let mut label_data = Vec::new();
            while let Some(chunk) = field.next().await {
                if let Ok(bytes) = chunk {
                    label_data.extend_from_slice(&bytes);
                }
            }
            if let Ok(label_str) = String::from_utf8(label_data) {
                let trimmed = label_str.trim();
                if !trimmed.is_empty() {
                    label = Some(trimmed.to_string());
                }
            }
        }
    }

    // Validate we got a file
    let data = match file_data {
        Some(d) if !d.is_empty() => d,
        _ => {
            return HttpResponse::BadRequest().json(PcapUploadResponse {
                success: false,
                message: "No file uploaded or file is empty".to_string(),
                packet_count: None,
                filename: None,
            });
        }
    };

    let original_filename = filename
        .clone()
        .unwrap_or_else(|| "upload.pcap".to_string());

    // If no label provided, use the filename
    let source_label = label.unwrap_or_else(|| original_filename.clone());

    // Write to temporary file
    let temp_path = format!("/tmp/pcap_upload_{}.pcap", uuid::Uuid::new_v4());
    match std::fs::File::create(&temp_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&data) {
                return HttpResponse::InternalServerError().json(PcapUploadResponse {
                    success: false,
                    message: format!("Failed to write temp file: {}", e),
                    packet_count: None,
                    filename: Some(original_filename),
                });
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(PcapUploadResponse {
                success: false,
                message: format!("Failed to create temp file: {}", e),
                packet_count: None,
                filename: Some(original_filename),
            });
        }
    }

    // Create a SQL writer for processing
    let sql_writer = SQLWriter::new().await;
    let sender = sql_writer.sender.clone();

    // Process the pcap file in a blocking task
    let temp_path_clone = temp_path.clone();
    let label_clone = source_label.clone();
    let result = task::spawn_blocking(move || {
        crate::pcap::process_pcap_file(&temp_path_clone, Some(label_clone), &sender)
    })
    .await;

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_path);

    // Give the SQL writer time to flush remaining packets
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    match result {
        Ok(Ok(packet_count)) => HttpResponse::Ok().json(PcapUploadResponse {
            success: true,
            message: format!(
                "Successfully processed {} packets from '{}'",
                packet_count, original_filename
            ),
            packet_count: Some(packet_count),
            filename: Some(original_filename),
        }),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(PcapUploadResponse {
            success: false,
            message: format!("Failed to process pcap file: {}", e),
            packet_count: None,
            filename: Some(original_filename),
        }),
        Err(e) => HttpResponse::InternalServerError().json(PcapUploadResponse {
            success: false,
            message: format!("Task execution error: {}", e),
            packet_count: None,
            filename: Some(original_filename),
        }),
    }
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
