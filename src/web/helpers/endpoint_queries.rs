//! Endpoint listing, resolution, and classification queries.

use std::collections::{HashMap, HashSet};

use dns_lookup::get_hostname;
use rusqlite::Connection;

use crate::db::new_connection_result;
use crate::network::endpoint::{EndPoint, strip_local_suffix};
use crate::network::mdns_lookup::MDnsLookup;

use super::DISPLAY_NAME_SQL;
use super::try_db;
use super::types::DnsEntryView;
use super::resolve_from_mdns_cache;
use super::{box_i64_params, build_in_placeholders, params_to_refs};

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
