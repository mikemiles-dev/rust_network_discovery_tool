//! Protocol and port queries for endpoint communications.

use rusqlite::params;

use crate::db::new_connection_result;

use super::endpoint_queries::resolve_identifier_to_endpoint_ids;
use super::try_db;
use super::{box_i64_params, build_in_placeholders, params_to_refs};

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
