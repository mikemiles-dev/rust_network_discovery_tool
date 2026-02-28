//! Model, vendor, DHCP vendor class, and bytes/bandwidth queries.

use std::collections::{HashMap, HashSet};

use rusqlite::params;

use crate::db::get_pool;

use super::DISPLAY_NAME_SQL;
use super::try_db;
use super::types::{BytesStats, EndpointModelData};

pub(crate) fn get_endpoint_ips_and_macs(
    endpoints: &[String],
) -> HashMap<String, (Vec<String>, Vec<String>)> {
    let mut result: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();

    // Initialize all endpoints with empty vectors (use lowercase keys for case-insensitive matching)
    for endpoint in endpoints {
        result.insert(endpoint.to_lowercase(), (Vec::new(), Vec::new()));
    }

    let conn = try_db!(get_pool().get(), result);

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

    let conn = try_db!(get_pool().get(), result);

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
    let conn = match get_pool().get() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("get_endpoint_ssdp_models: failed to get connection: {}", e);
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
        let data = EndpointModelData {
            custom_model,
            ssdp_model,
            ssdp_friendly_name: friendly_name,
            custom_vendor,
            snmp_vendor,
            snmp_model,
        };

        // Store under the computed display name - this matches what dropdown_endpoints returns
        if let Some(ref dn) = display_name
            && !dn.is_empty()
        {
            result.insert(dn.to_lowercase(), data);
        }
    }

    result
}

pub(crate) fn get_bytes_for_endpoint(hostname: String, internal_minutes: u64) -> BytesStats {
    let conn = try_db!(get_pool().get(), BytesStats::default());

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

    let conn = try_db!(get_pool().get(), result);

    // UNION ALL to allow each branch to use its composite index
    let mut stmt = try_db!(
        conn.prepare(&format!(
            "SELECT {DISPLAY_NAME_SQL} AS display_name, COALESCE(SUM(c.bytes), 0) as total_bytes
             FROM endpoints e
             INNER JOIN (
                 SELECT src_endpoint_id AS endpoint_id, bytes FROM communications WHERE last_seen_at >= (strftime('%s', 'now') - (?1 * 60))
                 UNION ALL
                 SELECT dst_endpoint_id AS endpoint_id, bytes FROM communications WHERE last_seen_at >= (strftime('%s', 'now') - (?2 * 60))
             ) c ON e.id = c.endpoint_id
             GROUP BY e.id"
        )),
        result
    );

    let rows = try_db!(
        stmt.query_map([internal_minutes, internal_minutes], |row| {
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
