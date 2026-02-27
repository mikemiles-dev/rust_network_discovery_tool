//! Hotspot gateway detection and merge logic.
//!
//! Identifies hotspot gateway endpoints (public IPv6 addresses with no MAC,
//! no hostname, and only ICMPv6 traffic) and merges them into their
//! corresponding phone endpoints.

use rusqlite::Connection;

use super::merge_maintenance::merge_endpoint_into;

/// Check if an endpoint matches the hotspot gateway pattern:
/// 1. Public IPv6 address (not link-local fe80::)
/// 2. No MAC address associated
/// 3. No proper hostname (name is null, empty, or an IPv6 address)
/// 4. Only ICMPv6 traffic (router advertisements, neighbor discovery)
fn is_hotspot_gateway_candidate(conn: &Connection, endpoint_id: i64) -> bool {
    // Check 1: Has public IPv6, no MAC, no proper hostname
    let has_ipv6_no_mac: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM endpoint_attributes ea
                JOIN endpoints e ON e.id = ea.endpoint_id
                WHERE ea.endpoint_id = ?1
                  AND ea.ip LIKE '%:%:%:%:%'
                  AND ea.ip NOT LIKE 'fe80:%'
                  AND (ea.mac IS NULL OR ea.mac = '')
                  AND (e.name IS NULL OR e.name = '' OR e.name LIKE '%:%')
            )",
            [endpoint_id],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if !has_ipv6_no_mac {
        return false;
    }

    // Check 2: Only ICMPv6 traffic (or no traffic at all)
    let has_only_icmpv6: bool = conn
        .query_row(
            "SELECT NOT EXISTS(
                SELECT 1 FROM communications
                WHERE (src_endpoint_id = ?1 OR dst_endpoint_id = ?1)
                  AND ip_header_protocol IS NOT NULL
                  AND ip_header_protocol NOT IN ('Icmpv6', 'Hopopt', '')
            )",
            [endpoint_id],
            |row| row.get(0),
        )
        .unwrap_or(false);

    has_only_icmpv6
}

/// Find a phone endpoint that could be the hotspot host
/// Returns the endpoint ID if found
fn find_phone_for_hotspot_gateway(conn: &Connection, gateway_endpoint_id: i64) -> Option<i64> {
    // Find phone endpoints that could be providing hotspot
    // Criteria:
    // 1. Has a link-local fe80:: address (typical for hotspot phones)
    // 2. Has a phone-like hostname (iphone, ipad, galaxy, pixel, etc.)
    // 3. Different endpoint ID from the gateway
    // Note: We don't require MAC because the phone acting as hotspot gateway
    // may not have its MAC captured - only link-local IPv6 is visible
    conn.query_row(
        "SELECT DISTINCT e.id FROM endpoints e
         JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
         WHERE e.id != ?1
           AND (
               LOWER(e.name) LIKE '%iphone%'
               OR LOWER(e.name) LIKE '%ipad%'
               OR LOWER(e.name) LIKE '%galaxy%'
               OR LOWER(e.name) LIKE '%pixel%'
               OR LOWER(e.name) LIKE '%android%'
               OR LOWER(e.name) LIKE 'sm-%'
           )
           AND ea.ip LIKE 'fe80:%'
         LIMIT 1",
        rusqlite::params![gateway_endpoint_id],
        |row| row.get(0),
    )
    .ok()
}

/// Merge hotspot gateway endpoints into their corresponding phone endpoints
/// Hotspot gateways are identified by:
/// - Public IPv6 address (not fe80::)
/// - No MAC address
/// - No proper hostname
/// - Only ICMPv6 traffic
pub(super) fn merge_hotspot_gateways_into_phones(conn: &Connection) -> rusqlite::Result<usize> {
    let mut merged_count = 0;

    // Find all endpoints that look like hotspot gateways
    // (no proper hostname, no MAC, public IPv6 address)
    let gateway_candidates: Vec<i64> = conn
        .prepare(
            "SELECT DISTINCT e.id
             FROM endpoints e
             JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
             WHERE (e.name IS NULL OR e.name = '' OR e.name LIKE '%:%')
               AND ea.ip LIKE '%:%:%:%:%'
               AND ea.ip NOT LIKE 'fe80:%'
               AND (ea.mac IS NULL OR ea.mac = '')
               AND e.custom_name IS NULL
               AND e.custom_vendor IS NULL
               AND e.manual_device_type IS NULL",
        )?
        .query_map([], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();

    for gateway_id in gateway_candidates {
        // Verify it matches the full hotspot gateway pattern (ICMPv6 only)
        if !is_hotspot_gateway_candidate(conn, gateway_id) {
            continue;
        }

        // Find a phone to merge into
        let Some(phone_id) = find_phone_for_hotspot_gateway(conn, gateway_id) else {
            continue;
        };

        merge_endpoint_into(conn, phone_id, gateway_id)?;

        // Get phone name for logging
        let phone_name: String = conn
            .query_row(
                "SELECT name FROM endpoints WHERE id = ?1",
                [phone_id],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| format!("endpoint {}", phone_id));

        eprintln!(
            "Merged hotspot gateway into phone endpoint '{}'",
            phone_name
        );
        merged_count += 1;
    }

    Ok(merged_count)
}
