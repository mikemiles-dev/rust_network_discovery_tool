//! Graph node types and communication graph queries.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::helpers::*;
use crate::db::new_connection_result;
use crate::network::endpoint::EndPoint;

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

/// Extract listening ports from communications data (already filtered for graph)
/// Only shows destination ports where endpoint is the destination (ports it's listening on)
/// Excludes ephemeral ports (49152-65535) which are just used for receiving responses
pub(super) fn get_ports_from_communications(
    communications: &[Node],
    selected_endpoint: &str,
) -> Vec<String> {
    let mut ports: HashSet<i64> = HashSet::new();

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

pub(super) fn get_nodes(current_node: Option<String>, internal_minutes: u64) -> Vec<Node> {
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

pub(super) fn get_endpoints(communications: &[Node]) -> Vec<String> {
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

pub(super) fn get_endpoint_types(
    communications: &[Node],
) -> std::collections::HashMap<String, &'static str> {
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
