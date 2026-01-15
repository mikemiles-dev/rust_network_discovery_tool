use actix_web::{
    App, HttpServer,
    web::{Data, Json, Query},
};
use actix_web::{HttpResponse, Responder, get, post};
use dns_lookup::get_hostname;
use pnet::datalink;
use rust_embed::RustEmbed;
use std::collections::{HashMap, HashSet};
use tera::{Context, Tera};
use tokio::task;

use crate::db::new_connection;
use crate::network::communication::extract_model_from_vendor_class;
use crate::network::device_control::DeviceController;
use crate::network::endpoint::{
    EndPoint, get_hostname_vendor, get_mac_vendor, get_model_from_hostname, get_model_from_mac,
    get_model_from_vendor_and_type,
};
use crate::network::mdns_lookup::MDnsLookup;
use crate::network::protocol::ProtocolPort;
use crate::scanner::manager::{ScanConfig, ScanManager};
use crate::scanner::{ScanResult, ScanType, check_scan_privileges};
use rusqlite::{Connection, params};
use std::sync::OnceLock;
use tokio::sync::mpsc;

use serde::{Deserialize, Serialize};

// ============================================================================
// SQL Helper Functions
// ============================================================================

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

#[derive(Default, Debug, Serialize, Deserialize)]
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

fn dropdown_endpoints(internal_minutes: u64) -> Vec<String> {
    let conn = new_connection();
    let mut stmt = conn
        .prepare(
            "
            SELECT DISTINCT COALESCE(e.custom_name, e.name,
                (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = e.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS display_name
            FROM endpoints e
            INNER JOIN communications c
                ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
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
                Some(hostname)
            }
        })
        .collect();

    // Get the local hostname
    let local_hostname = get_hostname().unwrap_or_else(|_| "Unknown".to_string());

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

fn get_ports_for_endpoint(hostname: String, internal_minutes: u64) -> Vec<String> {
    let conn = new_connection();

    let endpoint_ids = resolve_identifier_to_endpoint_ids(&conn, &hostname);
    if endpoint_ids.is_empty() {
        return Vec::new();
    }

    let placeholders = build_in_placeholders(endpoint_ids.len());
    let query = format!(
        "SELECT DISTINCT
            CASE
                WHEN c.src_endpoint_id IN ({0}) THEN c.destination_port
                WHEN c.dst_endpoint_id IN ({0}) THEN c.source_port
            END as port
        FROM communications c
        LEFT JOIN endpoints AS src_endpoint ON c.src_endpoint_id = src_endpoint.id
        LEFT JOIN endpoints AS dst_endpoint ON c.dst_endpoint_id = dst_endpoint.id
        WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
            AND (c.src_endpoint_id IN ({0}) OR c.dst_endpoint_id IN ({0}))
            AND port IS NOT NULL
            AND src_endpoint.name != '' AND dst_endpoint.name != ''
            AND src_endpoint.name IS NOT NULL AND dst_endpoint.name IS NOT NULL
        ORDER BY CAST(port AS INTEGER)",
        placeholders
    );

    let mut stmt = conn.prepare(&query).expect("Failed to prepare statement");

    // Build parameters: internal_minutes + endpoint_ids (4 times for the 4 IN clauses)
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(internal_minutes)];
    for _ in 0..4 {
        params.extend(box_i64_params(&endpoint_ids));
    }

    let rows = stmt
        .query_map(params_to_refs(&params).as_slice(), |row| {
            row.get::<_, i64>(0)
        })
        .expect("Failed to execute query");

    rows.filter_map(|row| row.ok())
        .map(|port| port.to_string())
        .collect()
}

/// Extract ports from communications data (already filtered for graph)
/// This ensures ports shown match what's visible in the graph
fn get_ports_from_communications(communications: &[Node], selected_endpoint: &str) -> Vec<String> {
    let mut ports: std::collections::HashSet<i64> = std::collections::HashSet::new();

    for node in communications {
        // Get port where selected endpoint is involved
        if node.src_hostname == selected_endpoint
            && let Some(ref port_str) = node.dst_port
        {
            for p in port_str.split(',') {
                if let Ok(port) = p.trim().parse::<i64>() {
                    ports.insert(port);
                }
            }
        }
        if node.dst_hostname == selected_endpoint
            && let Some(ref port_str) = node.src_port
        {
            for p in port_str.split(',') {
                if let Ok(port) = p.trim().parse::<i64>() {
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

    // Initialize all endpoints with empty vectors
    for endpoint in endpoints {
        result.insert(endpoint.clone(), (Vec::new(), Vec::new()));
    }

    // Single batch query to get all IPs and MACs with their display names
    let mut stmt = conn
        .prepare(
            "SELECT
                COALESCE(e.custom_name, e.name,
                    (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = e.id
                     AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS display_name,
                ea.ip,
                ea.mac
             FROM endpoints e
             INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id",
        )
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
        if let Some((ips, macs)) = result.get_mut(&name) {
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

    let mut stmt = conn
        .prepare(
            "SELECT
                COALESCE(e.custom_name, e.name,
                    (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = e.id
                     AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS display_name,
                ea.dhcp_vendor_class
             FROM endpoints e
             INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
             WHERE ea.dhcp_vendor_class IS NOT NULL AND ea.dhcp_vendor_class != ''",
        )
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
        // Only store for endpoints we care about, and prefer first non-empty value
        if endpoints.contains(&name) && !result.contains_key(&name) {
            result.insert(name, vendor_class);
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

    // Build query - either filtered by endpoint or show all
    let (query, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = match &endpoint_ids {
        Some(ids) => {
            let placeholders = build_in_placeholders(ids.len());
            let query = format!(
                "SELECT
                COALESCE(src_endpoint.custom_name, src_endpoint.name,
                         (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = src_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS src_hostname,
                COALESCE(dst_endpoint.custom_name, dst_endpoint.name,
                         (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = dst_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS dst_hostname,
                c.source_port as src_port,
                c.destination_port as dst_port,
                c.ip_header_protocol as header_protocol,
                c.sub_protocol,
                (SELECT ip FROM endpoint_attributes WHERE endpoint_id = src_endpoint.id LIMIT 1) AS src_ip,
                (SELECT ip FROM endpoint_attributes WHERE endpoint_id = dst_endpoint.id LIMIT 1) AS dst_ip
                FROM communications AS c
                LEFT JOIN endpoints AS src_endpoint ON c.src_endpoint_id = src_endpoint.id
                LEFT JOIN endpoints AS dst_endpoint ON c.dst_endpoint_id = dst_endpoint.id
                WHERE (c.src_endpoint_id IN ({0}) OR c.dst_endpoint_id IN ({0}))
                AND c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
                AND COALESCE(src_endpoint.custom_name, src_endpoint.name,
                             (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = src_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) IS NOT NULL
                AND COALESCE(src_endpoint.custom_name, src_endpoint.name,
                             (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = src_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) != ''
                AND COALESCE(dst_endpoint.custom_name, dst_endpoint.name,
                             (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = dst_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) IS NOT NULL
                AND COALESCE(dst_endpoint.custom_name, dst_endpoint.name,
                             (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = dst_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) != ''",
                placeholders
            );

            let mut params = box_i64_params(ids);
            params.extend(box_i64_params(ids));
            params.push(Box::new(internal_minutes));
            (query, params)
        }
        None => {
            let query = "SELECT
                COALESCE(src_endpoint.custom_name, src_endpoint.name,
                         (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = src_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS src_hostname,
                COALESCE(dst_endpoint.custom_name, dst_endpoint.name,
                         (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = dst_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS dst_hostname,
                c.source_port as src_port,
                c.destination_port as dst_port,
                c.ip_header_protocol as header_protocol,
                c.sub_protocol,
                (SELECT ip FROM endpoint_attributes WHERE endpoint_id = src_endpoint.id LIMIT 1) AS src_ip,
                (SELECT ip FROM endpoint_attributes WHERE endpoint_id = dst_endpoint.id LIMIT 1) AS dst_ip
                FROM communications AS c
                LEFT JOIN endpoints AS src_endpoint ON c.src_endpoint_id = src_endpoint.id
                LEFT JOIN endpoints AS dst_endpoint ON c.dst_endpoint_id = dst_endpoint.id
                WHERE c.last_seen_at >= (strftime('%s', 'now') - (? * 60))
                AND COALESCE(src_endpoint.custom_name, src_endpoint.name,
                             (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = src_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) IS NOT NULL
                AND COALESCE(src_endpoint.custom_name, src_endpoint.name,
                             (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = src_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) != ''
                AND COALESCE(dst_endpoint.custom_name, dst_endpoint.name,
                             (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = dst_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) IS NOT NULL
                AND COALESCE(dst_endpoint.custom_name, dst_endpoint.name,
                             (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = dst_endpoint.id AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) != ''".to_string();

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

                Node {
                    src_hostname: src,
                    dst_hostname: dst,
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

    // Batch fetch all IPs for all endpoints in one query
    let mut all_ips: HashMap<String, String> = HashMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT
                    COALESCE(e.custom_name, e.name,
                        (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = e.id
                         AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS display_name,
                    ea.ip
                 FROM endpoints e
                 INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
                 WHERE ea.ip IS NOT NULL
                 GROUP BY e.id",
            )
            .expect("Failed to prepare IP batch statement");

        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let ip: String = row.get(1)?;
                Ok((name, ip))
            })
            .expect("Failed to execute IP batch query");

        for row in rows.flatten() {
            all_ips.insert(row.0, row.1);
        }
    }

    // Batch fetch all MACs for all endpoints in one query
    let mut all_macs: HashMap<String, Vec<String>> = HashMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT
                    COALESCE(e.custom_name, e.name,
                        (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = e.id
                         AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS display_name,
                    ea.mac
                 FROM endpoints e
                 INNER JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
                 WHERE ea.mac IS NOT NULL",
            )
            .expect("Failed to prepare MAC batch statement");

        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let mac: String = row.get(1)?;
                Ok((name, mac))
            })
            .expect("Failed to execute MAC batch query");

        for row in rows.flatten() {
            all_macs.entry(row.0).or_default().push(row.1);
        }
    }

    // Batch fetch all ports for all endpoints in one query
    let mut all_ports: HashMap<String, Vec<u16>> = HashMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT
                    COALESCE(e.custom_name, e.name,
                        (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = e.id
                         AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS display_name,
                    COALESCE(c.source_port, c.destination_port) as port
                 FROM endpoints e
                 INNER JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
                 WHERE c.source_port IS NOT NULL OR c.destination_port IS NOT NULL
                 GROUP BY e.id, port",
            )
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
                all_ports.entry(row.0).or_default().push(port);
            }
        }
    }

    // Now classify each endpoint using the batch-fetched data
    for endpoint in endpoints {
        // Check for manual override first (case-insensitive)
        if let Some(manual_type) = manual_types_lower.get(&endpoint.to_lowercase()) {
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

        // Get IP from batch data, or try to extract from hostname
        let mut ip = all_ips.get(endpoint).cloned();
        if ip.is_none() {
            // Try to parse IP from hostname pattern: xxx-xxx-xxx-xxx.domain
            let parts: Vec<&str> = endpoint.split('.').collect();
            if let Some(first_part) = parts.first() {
                let ip_candidate = first_part.replace('-', ".");
                if ip_candidate.parse::<std::net::IpAddr>().is_ok() {
                    ip = Some(ip_candidate);
                }
            }
        }

        let macs = all_macs.get(endpoint).cloned().unwrap_or_default();
        let ports = all_ports.get(endpoint).cloned().unwrap_or_default();

        // First check network-level classification (gateway, internet)
        if let Some(endpoint_type) = EndPoint::classify_endpoint(ip.clone(), Some(endpoint.clone()))
        {
            types.insert(endpoint.clone(), endpoint_type);
        } else if let Some(device_type) =
            EndPoint::classify_device_type(Some(endpoint), ip.as_deref(), &ports, &macs)
        {
            types.insert(endpoint.clone(), device_type);
        } else if let Some(ref ip_str) = ip {
            // Only classify as local if the IP is actually on the local network
            if EndPoint::is_on_local_network(ip_str) {
                types.insert(endpoint.clone(), "local");
            }
        }
    }

    (types, manual_overrides)
}

#[derive(Serialize)]
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
                    dt.format("%Y-%m-%d %H:%M:%S").to_string()
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

#[get("/api/endpoint/{name}/details")]
async fn get_endpoint_details(
    path: actix_web::web::Path<String>,
    query: actix_web::web::Query<NodeQuery>,
) -> impl Responder {
    let endpoint_name = path.into_inner();
    let internal_minutes = query.scan_interval.unwrap_or(60);

    // Get IPs, MACs, and hostnames
    let (ips, macs, hostnames) = get_all_ips_macs_and_hostnames_from_single_hostname(
        endpoint_name.clone(),
        internal_minutes,
    );

    // Get device type for this endpoint
    let conn = new_connection();
    let manual_types = EndPoint::get_all_manual_device_types(&conn);

    // Check for manual override first (case-insensitive)
    let manual_type = manual_types
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&endpoint_name))
        .map(|(_, v)| v.clone());

    let (device_type, is_manual_override) = if let Some(mt) = manual_type {
        (mt, true)
    } else {
        // Use EndPoint::classify_device_type for automatic detection
        let auto_type = EndPoint::classify_device_type(
            Some(&endpoint_name),
            ips.first().map(|s| s.as_str()),
            &[],
            &macs,
        )
        .unwrap_or("Unknown");
        (auto_type.to_string(), false)
    };

    // Get device vendor from MAC or hostname
    let device_vendor: String = macs
        .iter()
        .find_map(|mac| get_mac_vendor(mac))
        .or_else(|| get_hostname_vendor(&endpoint_name))
        .unwrap_or("")
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

    // Get device model: hostname first, then MAC, then DHCP vendor class, then vendor+type fallback
    let device_model: String = get_model_from_hostname(&endpoint_name)
        .or_else(|| macs.iter().find_map(|mac| get_model_from_mac(mac)))
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

    let response = EndpointDetailsResponse {
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
    };

    HttpResponse::Ok().json(response)
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

    // Initialize all endpoints with 0 bytes
    for endpoint in endpoints {
        result.insert(endpoint.clone(), 0);
    }

    // Single query to get all bytes data at once
    // Get display_name for each endpoint and sum bytes
    let mut stmt = conn
        .prepare(
            "SELECT
                COALESCE(e.custom_name, e.name,
                    (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = e.id
                     AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS display_name,
                COALESCE(SUM(c.bytes), 0) as total_bytes
             FROM endpoints e
             INNER JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
             WHERE c.last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
             GROUP BY e.id",
        )
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
        if let Some(existing) = result.get_mut(&name) {
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

    // Initialize all endpoints with empty string (never seen)
    for endpoint in endpoints {
        result.insert(endpoint.clone(), String::new());
    }

    // Single query to get last_seen_at for each endpoint
    let mut stmt = conn
        .prepare(
            "SELECT
                COALESCE(e.custom_name, e.name,
                    (SELECT hostname FROM endpoint_attributes WHERE endpoint_id = e.id
                     AND hostname IS NOT NULL AND hostname != '' LIMIT 1)) AS display_name,
                MAX(c.last_seen_at) as last_seen
             FROM endpoints e
             INNER JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
             WHERE c.last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
             GROUP BY e.id",
        )
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
        if let Some(existing) = result.get_mut(&name) {
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
                        .service(get_dns_entries_api)
                        .service(get_endpoint_details)
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
    let hostname = get_hostname().unwrap_or_else(|_| "Unknown".to_string());
    let selected_endpoint = query.node.clone().unwrap_or_else(|| hostname.clone());

    let communications = get_nodes(query.node.clone(), query.scan_interval.unwrap_or(60));

    let mut endpoints = get_endpoints(&communications);

    // If a specific node was selected but isn't in the endpoints list, add it
    // This handles isolated endpoints with no communications
    if let Some(ref selected_node) = query.node
        && !endpoints.contains(selected_node)
    {
        endpoints.push(selected_node.clone());
    }
    let interfaces = get_interfaces();
    let supported_protocols = ProtocolPort::get_supported_protocols();

    let dropdown_endpoints = dropdown_endpoints(query.scan_interval.unwrap_or(60));
    let endpoint_ips_macs = get_endpoint_ips_and_macs(&dropdown_endpoints);

    // Build vendor lookup for all endpoints (hostname first, then MAC)
    // Hostname detection is more accurate for devices with generic WiFi chips
    // Component manufacturers that shouldn't be shown as device vendors
    let component_vendors = [
        "AzureWave",
        "Realtek",
        "Qualcomm",
        "MediaTek",
        "Broadcom",
        "Intel",
    ];
    let endpoint_vendors: HashMap<String, String> = dropdown_endpoints
        .iter()
        .filter_map(|endpoint| {
            // Try hostname-based detection first (catches PS4, Xbox, etc.)
            if let Some(vendor) = get_hostname_vendor(endpoint) {
                return Some((endpoint.clone(), vendor.to_string()));
            }
            // Fall back to MAC-based detection, but filter out component manufacturers
            let mac_vendor = endpoint_ips_macs.get(endpoint).and_then(|(_, macs)| {
                macs.iter()
                    .find_map(|mac| get_mac_vendor(mac).filter(|v| !component_vendors.contains(v)))
            });
            mac_vendor.map(|v| (endpoint.clone(), v.to_string()))
        })
        .collect();

    // Fetch DHCP vendor classes for model identification
    let endpoint_dhcp_vendor_classes = get_endpoint_vendor_classes(&dropdown_endpoints);

    // Build model lookup for all endpoints (hostname first, then MAC, then DHCP vendor class)
    let endpoint_models: HashMap<String, String> = dropdown_endpoints
        .iter()
        .filter_map(|endpoint| {
            // Try hostname-based detection first
            if let Some(model) = get_model_from_hostname(endpoint) {
                return Some((endpoint.clone(), model));
            }
            // Fall back to MAC-based detection
            if let Some((_, macs)) = endpoint_ips_macs.get(endpoint) {
                for mac in macs {
                    if let Some(model) = get_model_from_mac(mac) {
                        return Some((endpoint.clone(), model));
                    }
                }
            }
            // Fall back to DHCP vendor class (e.g., "samsung:SM-G998B" -> "SM-G998B")
            if let Some(vendor_class) = endpoint_dhcp_vendor_classes.get(endpoint)
                && let Some(model) = extract_model_from_vendor_class(vendor_class)
            {
                return Some((endpoint.clone(), model));
            }
            None
        })
        .collect();

    let endpoint_bytes =
        get_all_endpoints_bytes(&dropdown_endpoints, query.scan_interval.unwrap_or(60));
    let endpoint_last_seen =
        get_all_endpoints_last_seen(&dropdown_endpoints, query.scan_interval.unwrap_or(60));
    let mut endpoint_types = get_endpoint_types(&communications);
    let (dropdown_types, manual_overrides) = get_all_endpoint_types(&dropdown_endpoints);
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

    // Second pass: enhance models using vendor + device type for endpoints without models
    let mut endpoint_models = endpoint_models;
    for (endpoint, device_type) in &endpoint_types {
        if !endpoint_models.contains_key(endpoint)
            && let Some(vendor) = endpoint_vendors.get(endpoint)
            && let Some(model) = get_model_from_vendor_and_type(vendor, device_type)
        {
            endpoint_models.insert(endpoint.clone(), model);
        }
    }

    // Convert manual_overrides to Vec for serialization
    let manual_overrides: Vec<String> = manual_overrides.into_iter().collect();

    let (ips, macs, hostnames) = get_all_ips_macs_and_hostnames_from_single_hostname(
        selected_endpoint.clone(),
        query.scan_interval.unwrap_or(60),
    );
    // Build MAC vendor lookup
    let mac_vendors: HashMap<String, String> = macs
        .iter()
        .filter_map(|mac| get_mac_vendor(mac).map(|vendor| (mac.clone(), vendor.to_string())))
        .collect();
    // Get first vendor for display next to device type (MAC first, then hostname fallback)
    let device_vendor: String = macs
        .iter()
        .find_map(|mac| get_mac_vendor(mac))
        .or_else(|| get_hostname_vendor(&selected_endpoint))
        .unwrap_or("")
        .to_string();
    // Get model: hostname first, then MAC, then DHCP vendor class, then vendor+type fallback
    let device_model: String = get_model_from_hostname(&selected_endpoint)
        .or_else(|| macs.iter().find_map(|mac| get_model_from_mac(mac)))
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
    let protocols =
        get_protocols_for_endpoint(selected_endpoint.clone(), query.scan_interval.unwrap_or(60));
    // Use ports from communications data when a node is selected (matches graph)
    // Otherwise use database query for all ports
    let ports = if query.node.is_some() {
        get_ports_from_communications(&communications, &selected_endpoint)
    } else {
        get_ports_for_endpoint(selected_endpoint.clone(), query.scan_interval.unwrap_or(60))
    };
    let bytes_stats =
        get_bytes_for_endpoint(selected_endpoint.clone(), query.scan_interval.unwrap_or(60));

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
    context.insert("endpoint_models", &endpoint_models);
    context.insert("endpoint_bytes", &endpoint_bytes);
    context.insert("endpoint_last_seen", &endpoint_last_seen);
    context.insert("scan_interval", &query.scan_interval.unwrap_or(60));
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
            if let Ok(endpoint_id) =
                EndPoint::get_or_insert_endpoint(&conn, Some(mac_str), Some(ip_str), None, &[])
            {
                insert_scan_result(
                    &conn,
                    endpoint_id,
                    "arp",
                    Some(arp.response_time_ms as i64),
                    None,
                )?;
            }
        }
        ScanResult::Icmp(icmp) => {
            if icmp.alive {
                let ip_str = icmp.ip.to_string();
                if let Ok(endpoint_id) =
                    EndPoint::get_or_insert_endpoint(&conn, None, Some(ip_str), None, &[])
                {
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
                if let Ok(endpoint_id) =
                    EndPoint::get_or_insert_endpoint(&conn, None, Some(ip_str), None, &[])
                {
                    insert_open_port(&conn, endpoint_id, port.port, port.service_name.as_deref())?;
                }
            }
        }
        ScanResult::Ssdp(ssdp) => {
            let ip_str = ssdp.ip.to_string();
            if let Ok(endpoint_id) =
                EndPoint::get_or_insert_endpoint(&conn, None, Some(ip_str), None, &[])
            {
                let details = serde_json::json!({
                    "location": ssdp.location,
                    "server": ssdp.server,
                    "device_type": ssdp.device_type,
                });
                insert_scan_result(&conn, endpoint_id, "ssdp", None, Some(&details.to_string()))?;
            }
        }
    }

    Ok(())
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
