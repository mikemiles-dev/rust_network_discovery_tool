use dns_lookup::{get_hostname, lookup_addr};
use pnet::datalink::interfaces;
use rusqlite::{Connection, Result, params};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use crate::network::endpoint_attribute::EndPointAttribute;
use crate::network::mdns_lookup::MDnsLookup;

use super::classification::*;
use super::constants::*;
use super::detection::*;
use super::patterns::*;
use super::types::*;

#[derive(Default, Debug)]
pub struct EndPoint;

impl EndPoint {
    /// Classify an endpoint as Gateway, Internet, or LocalNetwork based on IP address and hostname
    pub fn classify_endpoint(ip: Option<String>, hostname: Option<String>) -> Option<&'static str> {
        let ip_is_local = ip
            .as_ref()
            .is_some_and(|ip_str| Self::is_on_local_network(ip_str));

        // Check if it's the default gateway
        if let Some(ref ip_str) = ip {
            if let Some(gateway_ip) = Self::get_default_gateway()
                && gateway_ip == *ip_str
            {
                return Some(CLASSIFICATION_GATEWAY);
            }

            // Check if it's a common router IP
            if Self::is_common_router_ip(ip_str) {
                return Some(CLASSIFICATION_GATEWAY);
            }

            // Check if it's on the local network - if not, it's internet
            if !ip_is_local {
                return Some(CLASSIFICATION_INTERNET);
            }
        }

        // Check if hostname indicates a router/gateway
        if let Some(ref hostname_str) = hostname {
            if Self::is_router_hostname(hostname_str) {
                return Some(CLASSIFICATION_GATEWAY);
            }

            // Only check hostname for internet classification if we don't have a local IP
            // If the IP is local, trust the IP - hostname suffix doesn't matter
            // This prevents ISP-specific suffixes (like .attlocal.net) from being misclassified
            if !ip_is_local && Self::is_internet_hostname(hostname_str) {
                return Some(CLASSIFICATION_INTERNET);
            }
        }

        // Local network device, no special classification
        None
    }

    /// Check if hostname looks like an internet domain
    fn is_internet_hostname(hostname: &str) -> bool {
        // Skip if it looks like an IP address
        if hostname.contains(':') || hostname.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return false;
        }
        // Skip local hostnames
        let lower = hostname.to_lowercase();
        if lower.ends_with(".local")
            || lower.ends_with(".lan")
            || lower.ends_with(".home")
            || lower.ends_with(".internal")
            || lower.ends_with(".localdomain")
            || lower.ends_with(".attlocal.net") // AT&T local network suffix
            || lower.ends_with(".home.arpa")    // RFC 8375 home network
            || lower.ends_with(".mynetwork")
            || lower.ends_with(".homenet")
            || lower.ends_with(".router")
            || !lower.contains('.')
        {
            return false;
        }
        // Has a dot and a TLD-like suffix - likely internet
        true
    }

    /// Check if IP is a common router/gateway address
    fn is_common_router_ip(ip: &str) -> bool {
        matches!(
            ip,
            "192.168.0.1"
                | "192.168.1.1"
                | "192.168.2.1"
                | "192.168.1.254"
                | "10.0.0.1"
                | "10.0.1.1"
                | "10.1.1.1"
                | "10.10.1.1"
                | "172.16.0.1"
                | "172.16.1.1"
                | "192.168.0.254"
                | "192.168.1.253"
                | "192.168.100.1"
                | "192.168.254.254"
        )
    }

    /// Check if hostname indicates a router or gateway
    fn is_router_hostname(hostname: &str) -> bool {
        let lower = hostname.to_lowercase();
        lower.contains("router")
            || lower.contains("gateway")
            || lower.contains("-gw")
            || lower.starts_with("gw-")
            || lower.starts_with("gw.")
            || lower == "gw"
            || lower.contains(".gateway.")
            || lower.contains(".gw.")
            || lower.contains("firewall")
            || lower.contains("pfsense")
            || lower.contains("opnsense")
            || lower.contains("ubiquiti")
            || lower.contains("unifi")
            || lower.contains("edgerouter")
            || lower.contains("mikrotik")
            // Ubiquiti Dream Machine variants
            || lower.starts_with("udm-")
            || lower.starts_with("udm.")
            || lower == "udm"
            || lower.starts_with("udmpro")
            || lower.starts_with("udm-pro")
            || lower.starts_with("udm-se")
            // Linksys/Netgear/Asus patterns
            || lower.contains("linksys")
            || lower.contains("netgear")
            || lower.starts_with("asus-rt")
            || lower.starts_with("rt-") // Asus RT- series routers
    }

    /// Classify device type based on hostname, ports, MACs, and mDNS services
    /// Returns device-specific classification (printer, tv, gaming) or None
    /// This is separate from network-level classification (gateway, internet)
    pub fn classify_device_type(
        hostname: Option<&str>,
        ips: &[String],
        ports: &[u16],
        macs: &[String],
        model: Option<&str>,
    ) -> Option<&'static str> {
        // Pre-compute lowercase hostname once
        let lower_hostname = hostname.map(|h| h.to_lowercase());
        let lower = lower_hostname.as_deref();

        // Check SSDP/UPnP model first - most reliable for identifying device type
        if let Some(m) = model
            && is_soundbar_model(m)
        {
            return Some(CLASSIFICATION_SOUNDBAR);
        }

        // Check for TV models (Samsung Frame, QLED, LG OLED, etc.)
        if let Some(m) = model
            && is_tv_model(m)
        {
            return Some(CLASSIFICATION_TV);
        }

        // Check for LG ThinQ appliances FIRST (they advertise AirPlay but aren't TVs)
        if let Some(h) = lower
            && is_lg_appliance(h)
        {
            return Some(CLASSIFICATION_APPLIANCE);
        }

        // Check hostname patterns FIRST - most reliable for user devices
        // This prevents mDNS services from misclassifying computers/phones as TVs
        if let Some(h) = lower {
            // Order matters: check more specific patterns first
            if is_printer_hostname(h) {
                return Some(CLASSIFICATION_PRINTER);
            }
            if is_phone_hostname(h) {
                return Some(CLASSIFICATION_PHONE);
            }
            if is_gaming_hostname(h) {
                return Some(CLASSIFICATION_GAMING);
            }
            if is_tv_hostname(h) {
                return Some(CLASSIFICATION_TV);
            }
            if is_vm_hostname(h) {
                return Some(CLASSIFICATION_VIRTUALIZATION);
            }
            if is_soundbar_hostname(h) {
                return Some(CLASSIFICATION_SOUNDBAR);
            }
            if is_appliance_hostname(h) {
                return Some(CLASSIFICATION_APPLIANCE);
            }
        }

        // Check mDNS service advertisements for ALL IPs
        // This catches smart devices that don't have distinctive hostnames
        for ip_str in ips {
            let services = crate::network::mdns_lookup::MDnsLookup::get_services(ip_str);
            if let Some(classification) = classify_by_services(&services, lower) {
                return Some(classification);
            }
        }

        // MAC-based detection (identifies devices by vendor OUI)
        // Check gateway first - networking equipment vendors
        if is_gateway_mac(macs) {
            return Some(CLASSIFICATION_GATEWAY);
        }
        // Check phone - Apple devices without desktop services are likely iPhones/iPads
        if is_phone_mac(macs, ips, lower) {
            return Some(CLASSIFICATION_PHONE);
        }
        if is_gaming_mac(macs) {
            return Some(CLASSIFICATION_GAMING);
        }
        if is_tv_mac(macs) {
            return Some(CLASSIFICATION_TV);
        }
        if is_appliance_mac(macs) {
            return Some(CLASSIFICATION_APPLIANCE);
        }

        // Computer detection based on port combinations
        // RDP (3389) or VNC (5900) combined with file sharing ports indicates a computer
        if is_computer_by_ports(ports) {
            return Some(CLASSIFICATION_COMPUTER);
        }

        // Port-based detection (less reliable, fallback)
        for &port in ports {
            if let Some(classification) = classify_by_port(port) {
                return Some(classification);
            }
        }

        None
    }

    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL,
                name TEXT
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_created_at ON endpoints (created_at);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_name ON endpoints (name);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_name_lower ON endpoints (LOWER(name));",
            [],
        )?;
        // Migration: Add manual_device_type column if it doesn't exist
        let has_column: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'manual_device_type'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_column {
            conn.execute(
                "ALTER TABLE endpoints ADD COLUMN manual_device_type TEXT",
                [],
            )?;
        }
        // Migration: Add custom_name column if it doesn't exist
        let has_custom_name_column: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'custom_name'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_custom_name_column {
            conn.execute("ALTER TABLE endpoints ADD COLUMN custom_name TEXT", [])?;
        }

        // Migration: Add ssdp_model column for UPnP model name
        let has_ssdp_model: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'ssdp_model'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_ssdp_model {
            conn.execute("ALTER TABLE endpoints ADD COLUMN ssdp_model TEXT", [])?;
        }

        // Migration: Add ssdp_friendly_name column for UPnP friendly name
        let has_ssdp_friendly_name: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'ssdp_friendly_name'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_ssdp_friendly_name {
            conn.execute(
                "ALTER TABLE endpoints ADD COLUMN ssdp_friendly_name TEXT",
                [],
            )?;
        }

        // Migration: Add custom_model column for manual model override
        let has_custom_model: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'custom_model'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_custom_model {
            conn.execute("ALTER TABLE endpoints ADD COLUMN custom_model TEXT", [])?;
        }

        // Migration: Add custom_vendor column for manual vendor override
        let has_custom_vendor: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'custom_vendor'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_custom_vendor {
            conn.execute("ALTER TABLE endpoints ADD COLUMN custom_vendor TEXT", [])?;
        }

        // Migration: Add auto_device_type column for persisting auto-detected device type
        let has_auto_device_type: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'auto_device_type'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_auto_device_type {
            conn.execute("ALTER TABLE endpoints ADD COLUMN auto_device_type TEXT", [])?;
        }

        // Migration: Add netbios_name column for NetBIOS discovered names
        let has_netbios_name: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'netbios_name'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_netbios_name {
            conn.execute("ALTER TABLE endpoints ADD COLUMN netbios_name TEXT", [])?;
        }

        // Create internet_destinations table for tracking external hosts
        conn.execute(
            "CREATE TABLE IF NOT EXISTS internet_destinations (
                id INTEGER PRIMARY KEY,
                hostname TEXT NOT NULL UNIQUE,
                first_seen_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                packet_count INTEGER DEFAULT 1,
                bytes_in INTEGER DEFAULT 0,
                bytes_out INTEGER DEFAULT 0
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_internet_destinations_hostname ON internet_destinations (hostname);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_internet_destinations_last_seen ON internet_destinations (last_seen_at);",
            [],
        )?;

        Ok(())
    }

    /// Insert or update an internet destination (external host)
    /// This is called when traffic is detected to/from a non-local IP
    pub fn insert_or_update_internet_destination(
        conn: &Connection,
        hostname: &str,
        bytes: i64,
        is_outbound: bool,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Try to insert a new record
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO internet_destinations (hostname, first_seen_at, last_seen_at, packet_count, bytes_in, bytes_out)
             VALUES (?1, ?2, ?2, 1, ?3, ?4)",
            params![
                hostname,
                now,
                if is_outbound { 0i64 } else { bytes },
                if is_outbound { bytes } else { 0i64 }
            ],
        )?;

        // If insert was ignored (record exists), update instead
        if inserted == 0 {
            if is_outbound {
                conn.execute(
                    "UPDATE internet_destinations SET last_seen_at = ?1, packet_count = packet_count + 1, bytes_out = bytes_out + ?2 WHERE hostname = ?3",
                    params![now, bytes, hostname],
                )?;
            } else {
                conn.execute(
                    "UPDATE internet_destinations SET last_seen_at = ?1, packet_count = packet_count + 1, bytes_in = bytes_in + ?2 WHERE hostname = ?3",
                    params![now, bytes, hostname],
                )?;
            }
        }

        Ok(())
    }

    /// Get all internet destinations sorted by last_seen_at descending
    pub fn get_internet_destinations(conn: &Connection) -> Result<Vec<InternetDestination>> {
        let mut stmt = conn.prepare(
            "SELECT id, hostname, first_seen_at, last_seen_at, packet_count, bytes_in, bytes_out
             FROM internet_destinations
             WHERE hostname NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
               AND hostname NOT LIKE '%:%'
               AND hostname NOT LIKE '%.local'
               AND hostname LIKE '%.%'
             ORDER BY last_seen_at DESC",
        )?;

        let destinations = stmt
            .query_map([], |row| {
                Ok(InternetDestination {
                    id: row.get(0)?,
                    hostname: row.get(1)?,
                    first_seen_at: row.get(2)?,
                    last_seen_at: row.get(3)?,
                    packet_count: row.get(4)?,
                    bytes_in: row.get(5)?,
                    bytes_out: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(destinations)
    }

    /// Set the manual device type for an endpoint by name or custom_name
    /// Pass None to clear the manual override and revert to automatic classification
    pub fn set_manual_device_type(
        conn: &Connection,
        endpoint_name: &str,
        device_type: Option<&str>,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET manual_device_type = ? WHERE LOWER(name) = LOWER(?) OR LOWER(custom_name) = LOWER(?)",
            params![device_type, endpoint_name, endpoint_name],
        )
    }

    /// Set the auto-detected device type for an endpoint (persists across renames)
    pub fn set_auto_device_type(
        conn: &Connection,
        endpoint_name: &str,
        device_type: &str,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET auto_device_type = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![device_type, endpoint_name],
        )
    }

    /// Get all auto-detected device types (for endpoints without manual overrides)
    /// Returns a map of display_name -> auto_device_type
    pub fn get_all_auto_device_types(conn: &Connection) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT COALESCE(custom_name, name), auto_device_type FROM endpoints WHERE auto_device_type IS NOT NULL AND auto_device_type != '' AND (name IS NOT NULL OR custom_name IS NOT NULL)",
        ) && let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                map.insert(row.0, row.1);
            }
        }
        map
    }

    /// Set a custom name for an endpoint by name, existing custom_name, or hostname in endpoint_attributes
    /// Pass None to clear the custom name and revert to auto-discovered hostname
    pub fn set_custom_name(
        conn: &Connection,
        endpoint_name: &str,
        custom_name: Option<&str>,
    ) -> Result<usize> {
        // Must join with endpoint_attributes because endpoints.name may be NULL
        // and the actual hostname is stored in endpoint_attributes.hostname
        conn.execute(
            "UPDATE endpoints SET custom_name = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![custom_name, endpoint_name],
        )
    }

    /// Set a custom model for an endpoint by name, custom_name, or hostname in endpoint_attributes
    /// Pass None to clear the custom model and revert to auto-detected model
    pub fn set_custom_model(
        conn: &Connection,
        endpoint_name: &str,
        custom_model: Option<&str>,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET custom_model = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![custom_model, endpoint_name],
        )
    }

    /// Set a custom vendor for an endpoint by name, custom_name, or hostname in endpoint_attributes
    /// Pass None to clear the custom vendor and revert to auto-detected vendor
    pub fn set_custom_vendor(
        conn: &Connection,
        endpoint_name: &str,
        custom_vendor: Option<&str>,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET custom_vendor = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![custom_vendor, endpoint_name],
        )
    }

    /// Get the original name of an endpoint (the name field, not custom_name)
    /// This is used when clearing a custom name to redirect to the original URL
    pub fn get_original_name(conn: &Connection, endpoint_name: &str) -> Option<String> {
        conn.query_row(
            "SELECT COALESCE(e.name, ea.hostname, ea.ip) FROM endpoints e
             LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
             WHERE LOWER(e.name) = LOWER(?1)
                OR LOWER(e.custom_name) = LOWER(?1)
                OR LOWER(ea.hostname) = LOWER(?1)
                OR LOWER(ea.ip) = LOWER(?1)
             LIMIT 1",
            params![endpoint_name],
            |row| row.get(0),
        )
        .ok()
    }

    /// Get all manual device types as a HashMap
    pub fn get_all_manual_device_types(conn: &Connection) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT COALESCE(custom_name, name), manual_device_type FROM endpoints WHERE manual_device_type IS NOT NULL AND (name IS NOT NULL OR custom_name IS NOT NULL)",
        ) && let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                map.insert(row.0, row.1);
            }
        }
        map
    }

    fn insert_endpoint_with_dhcp(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        hostname: Option<String>,
        dhcp_client_id: Option<String>,
        dhcp_vendor_class: Option<String>,
    ) -> Result<i64, InsertEndpointError> {
        conn.execute(
            "INSERT INTO endpoints (created_at) VALUES (strftime('%s', 'now'))",
            params![],
        )?;
        let endpoint_id = conn.last_insert_rowid();
        let hostname = hostname.unwrap_or(ip.clone().unwrap_or_default());
        EndPointAttribute::insert_endpoint_attribute_with_dhcp(
            conn,
            endpoint_id,
            mac,
            ip,
            hostname,
            dhcp_client_id,
            dhcp_vendor_class,
        )?;
        Ok(endpoint_id)
    }

    pub fn get_or_insert_endpoint(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        protocol: Option<String>,
        payload: &[u8],
    ) -> Result<i64, InsertEndpointError> {
        Self::get_or_insert_endpoint_with_dhcp(conn, mac, ip, protocol, payload, None, None, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn get_or_insert_endpoint_with_dhcp(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        protocol: Option<String>,
        payload: &[u8],
        dhcp_client_id: Option<String>,
        dhcp_vendor_class: Option<String>,
        dhcp_hostname: Option<String>,
    ) -> Result<i64, InsertEndpointError> {
        // Filter out IPv6 link-local addresses without EUI-64 format (privacy addresses)
        // These can't be reliably matched to a device and create duplicate endpoints
        if let Some(ref ip_str) = ip
            && is_ipv6_link_local(ip_str)
            && extract_mac_from_ipv6_eui64(ip_str).is_none()
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        // Try to extract MAC from IPv6 EUI-64 address if no MAC provided
        let mac = mac.or_else(|| {
            ip.as_ref()
                .and_then(|ip_str| extract_mac_from_ipv6_eui64(ip_str))
        });

        // Filter out broadcast/multicast MACs - these aren't real endpoints
        if let Some(ref mac_addr) = mac
            && Self::is_broadcast_or_multicast_mac(mac_addr)
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        // For locally administered (randomized/private) MACs:
        // Don't use them for endpoint matching (they change frequently)
        // But still allow endpoint creation based on IP so communications can be recorded
        let is_randomized_mac = mac
            .as_ref()
            .map(|m| is_locally_administered_mac(m))
            .unwrap_or(false);

        // For randomized MACs, don't use the MAC for lookups - use IP or DHCP Client ID instead
        let lookup_mac = if is_randomized_mac { None } else { mac.clone() };

        // Filter out multicast/broadcast IPs - these aren't real endpoints
        if let Some(ref ip_addr) = ip
            && Self::is_multicast_or_broadcast_ip(ip_addr)
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        if (lookup_mac.is_none() || lookup_mac == Some("00:00:00:00:00:00".to_string()))
            && ip.is_none()
            && dhcp_client_id.is_none()
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        // Check if this is a local network IP
        let is_local_ip = ip
            .as_ref()
            .map(|ip| Self::is_on_local_network(ip))
            .unwrap_or(false);
        let has_any_mac = mac.is_some() && mac != Some("00:00:00:00:00:00".to_string());

        // For INTERNET IPs (non-local), record in internet_destinations table instead of creating endpoint
        // This separates external hosts from local network devices
        if let Some(ref ip_str) = ip
            && !Self::is_on_local_network(ip_str)
        {
            // Use hostname if we have one, otherwise use the IP address
            let dest_name = dhcp_hostname
                .clone()
                .or_else(|| {
                    Self::lookup_hostname(ip.clone(), mac.clone(), protocol.clone(), payload)
                })
                .unwrap_or_else(|| ip_str.clone());

            // Record this internet destination (ignore errors - best effort)
            let _ = Self::insert_or_update_internet_destination(conn, &dest_name, 0, true);

            return Err(InsertEndpointError::InternetDestination);
        }

        // Strip .local and other local suffixes from hostnames and normalize to lowercase
        // Prefer DHCP hostname (Option 12) when available - this is the device's actual name
        let hostname = dhcp_hostname
            .clone()
            .or_else(|| Self::lookup_hostname(ip.clone(), mac.clone(), protocol.clone(), payload))
            .map(|h| strip_local_suffix(&h).to_lowercase());
        let endpoint_id = match EndPointAttribute::find_existing_endpoint_id_with_dhcp(
            conn,
            lookup_mac.clone(),
            ip.clone(),
            hostname.clone(),
            dhcp_client_id.clone(),
        ) {
            Some(id) => {
                // Only insert new attributes if we have useful data (MAC or hostname different from IP)
                // Don't insert empty MAC attributes for local IPs (causes bloat)
                let should_insert = if is_local_ip {
                    // For local IPs, only insert if we have a MAC or a real hostname
                    has_any_mac || (ip != hostname && hostname.is_some())
                } else {
                    // For remote IPs, insert if hostname is different from IP
                    ip != hostname && hostname.is_some()
                };

                if should_insert {
                    // Attempt to insert - will be ignored if duplicate due to UNIQUE constraint
                    let _ = EndPointAttribute::insert_endpoint_attribute_with_dhcp(
                        conn,
                        id,
                        lookup_mac,
                        ip.clone(),
                        hostname.clone().unwrap_or(ip.clone().unwrap_or_default()),
                        dhcp_client_id.clone(),
                        dhcp_vendor_class.clone(),
                    );
                }
                // Update DHCP Client ID if we have one and the endpoint doesn't
                if let Some(ref dhcp_id) = dhcp_client_id {
                    let _ = EndPointAttribute::update_dhcp_client_id(conn, id, dhcp_id);
                }
                // Update DHCP Vendor Class if we have one and the endpoint doesn't
                if let Some(ref vendor_class) = dhcp_vendor_class {
                    let _ = EndPointAttribute::update_dhcp_vendor_class(conn, id, vendor_class);
                }
                id
            }
            _ => Self::insert_endpoint_with_dhcp(
                conn,
                lookup_mac.clone(),
                ip.clone(),
                hostname.clone(),
                dhcp_client_id.clone(),
                dhcp_vendor_class.clone(),
            )?,
        };
        Self::check_and_update_endpoint_name(
            conn,
            endpoint_id,
            hostname.clone().unwrap_or_default(),
        )?;

        // If we have an IP but no hostname, spawn a background task to probe for the hostname
        // This is non-blocking and will update the endpoint if a hostname is found
        let hostname_is_ip = hostname
            .as_ref()
            .map(|h| h.parse::<std::net::IpAddr>().is_ok())
            .unwrap_or(true);
        if let Some(ref ip_addr) = ip
            && (hostname.is_none() || hostname_is_ip)
            && Self::is_on_local_network(ip_addr)
        {
            // Only probe for local IPs (remote servers probably won't respond to our mDNS)
            crate::network::mdns_lookup::MDnsLookup::probe_hostname_async(
                ip_addr.clone(),
                endpoint_id,
            );
        }

        Ok(endpoint_id)
    }

    fn check_and_update_endpoint_name(
        conn: &Connection,
        endpoint_id: i64,
        hostname: String,
    ) -> Result<(), InsertEndpointError> {
        // Strip local suffixes like .local, .lan, .home and normalize to lowercase
        let hostname = strip_local_suffix(&hostname).to_lowercase();

        // Only accept valid display names (not empty, not UUID, not IP)
        if !is_valid_display_name(&hostname) {
            return Ok(());
        }

        // Get current name
        let current_name: String = conn.query_row(
            "SELECT COALESCE(name, '') FROM endpoints WHERE id = ?",
            params![endpoint_id],
            |row| row.get(0),
        )?;

        // Update if current name is invalid (empty, UUID, IP) and new name is valid
        let current_is_valid = is_valid_display_name(&current_name);
        let should_update = !current_is_valid;

        if should_update {
            conn.execute(
                "UPDATE endpoints SET name = ? WHERE id = ?",
                params![hostname, endpoint_id],
            )?;
            // When updating to a valid hostname, try to merge other IPv6 endpoints on same prefix
            Self::merge_ipv6_siblings_into_endpoint(conn, endpoint_id);
        }

        Ok(())
    }

    /// Merge other endpoints on the same IPv6 /64 prefix into this endpoint
    /// Called when an endpoint gets a proper hostname, to consolidate IPv6-only duplicates
    fn merge_ipv6_siblings_into_endpoint(conn: &Connection, target_endpoint_id: i64) {
        // Get IPv6 addresses for this endpoint
        let ipv6_addrs: Vec<String> = conn
            .prepare(
                "SELECT ip FROM endpoint_attributes WHERE endpoint_id = ?1 AND ip LIKE '%:%:%:%:%'",
            )
            .and_then(|mut stmt| {
                stmt.query_map([target_endpoint_id], |row| row.get(0))
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
            })
            .unwrap_or_default();

        if ipv6_addrs.is_empty() {
            return;
        }

        // Extract /64 prefixes (first 4 groups)
        let prefixes: Vec<String> = ipv6_addrs
            .iter()
            .filter_map(|ip| {
                let parts: Vec<&str> = ip.split(':').collect();
                if parts.len() >= 4 {
                    Some(format!(
                        "{}:{}:{}:{}",
                        parts[0], parts[1], parts[2], parts[3]
                    ))
                } else {
                    None
                }
            })
            .collect();

        if prefixes.is_empty() {
            return;
        }

        // Find other endpoints with IPv6 addresses on the same prefix that have IP-only names
        for prefix in prefixes {
            // Find endpoints with IPv6-like names (containing colons) on the same prefix
            let siblings: Vec<i64> = conn
                .prepare(
                    "SELECT DISTINCT e.id FROM endpoints e
                     JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                     WHERE ea.ip LIKE ?1 || ':%'
                       AND e.id != ?2
                       AND e.name LIKE '%:%'",
                )
                .and_then(|mut stmt| {
                    stmt.query_map(params![prefix, target_endpoint_id], |row| row.get(0))
                        .map(|rows| rows.filter_map(|r| r.ok()).collect())
                })
                .unwrap_or_default();

            for sibling_id in siblings {
                // Merge sibling into target
                let _ = conn.execute(
                    "UPDATE OR IGNORE endpoint_attributes SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute(
                    "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
                    [sibling_id],
                );
                let _ = conn.execute(
                    "UPDATE OR IGNORE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute(
                    "UPDATE OR IGNORE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute(
                    "DELETE FROM communications WHERE src_endpoint_id = ?1 OR dst_endpoint_id = ?1",
                    [sibling_id],
                );
                let _ = conn.execute(
                    "UPDATE OR IGNORE open_ports SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute(
                    "DELETE FROM open_ports WHERE endpoint_id = ?1",
                    [sibling_id],
                );
                let _ = conn.execute(
                    "UPDATE scan_results SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute("DELETE FROM endpoints WHERE id = ?1", [sibling_id]);
                println!(
                    "Merged IPv6 endpoint {} into {} (same /64 prefix: {})",
                    sibling_id, target_endpoint_id, prefix
                );
            }
        }
    }

    fn parse_windows_gateway(output: &str) -> Option<String> {
        output.lines().find_map(|line| {
            // Look for "0.0.0.0          0.0.0.0     <gateway_ip>"
            if !line.contains("0.0.0.0") || line.split_whitespace().count() < 3 {
                return None;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                Some(parts[2].to_string())
            } else {
                None
            }
        })
    }

    fn parse_macos_gateway(output: &str) -> Option<String> {
        output.lines().find_map(|line| {
            if line.contains("gateway:") {
                line.split_whitespace().nth(1).map(String::from)
            } else {
                None
            }
        })
    }

    fn parse_linux_gateway(output: &str) -> Option<String> {
        // Expected format: "default via <gateway_ip> dev <interface>"
        output
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(2).map(String::from))
    }

    fn parse_linux_route_n(output: &str) -> Option<String> {
        output.lines().find_map(|line| {
            if line.starts_with("0.0.0.0") {
                line.split_whitespace().nth(1).map(String::from)
            } else {
                None
            }
        })
    }

    fn get_default_gateway() -> Option<String> {
        // Check cache first
        if let Ok(cache) = GATEWAY_INFO.lock()
            && let Some((gateway_ip, cached_time)) = cache.as_ref()
            && cached_time.elapsed() < GATEWAY_CACHE_TTL
        {
            return Some(gateway_ip.clone());
        }

        // Get default gateway using system commands
        let gateway_ip = if cfg!(target_os = "windows") {
            std::process::Command::new("route")
                .args(["print", "0.0.0.0"])
                .output()
                .ok()
                .and_then(|output| {
                    Self::parse_windows_gateway(&String::from_utf8_lossy(&output.stdout))
                })
        } else if cfg!(target_os = "macos") {
            std::process::Command::new("route")
                .args(["-n", "get", "default"])
                .output()
                .ok()
                .and_then(|output| {
                    Self::parse_macos_gateway(&String::from_utf8_lossy(&output.stdout))
                })
        } else {
            // Linux: try ip route first, fallback to route -n
            std::process::Command::new("ip")
                .args(["route", "show", "default"])
                .output()
                .ok()
                .and_then(|output| {
                    Self::parse_linux_gateway(&String::from_utf8_lossy(&output.stdout))
                })
                .or_else(|| {
                    std::process::Command::new("route")
                        .args(["-n"])
                        .output()
                        .ok()
                        .and_then(|output| {
                            Self::parse_linux_route_n(&String::from_utf8_lossy(&output.stdout))
                        })
                })
        };

        // Cache the result
        if let Some(ref gw) = gateway_ip
            && let Ok(mut cache) = GATEWAY_INFO.lock()
        {
            *cache = Some((gw.clone(), Instant::now()));
        }

        gateway_ip
    }

    pub fn is_on_local_network(ip: &str) -> bool {
        // Parse the IP address
        let ip_addr: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        // Special case: loopback addresses are always local
        if ip_addr.is_loopback() {
            return true;
        }

        // Check cached local networks (computed once at startup)
        for ip_network in get_local_networks() {
            if ip_network.contains(ip_addr) {
                return true;
            }
        }

        false
    }

    fn lookup_dns(ip: Option<String>, mac: Option<String>) -> Option<String> {
        let ip_str = ip?;
        let mac_str = mac?;
        let ip_addr = ip_str.parse().ok()?;
        let is_local = Self::is_local(ip_str.clone(), mac_str.clone());
        let local_hostname = get_hostname().unwrap_or_default();

        // Check cache first to avoid slow DNS lookups
        if let Ok(cache) = DNS_CACHE.lock()
            && let Some((cached_name, cached_time)) = cache.get(&ip_str)
            && cached_time.elapsed() < DNS_CACHE_TTL
        {
            return Some(cached_name.clone());
        }

        // Get hostname via DNS or fallback to mDNS/IP
        let hostname = match lookup_addr(&ip_addr) {
            Ok(name) if name != ip_str && !is_local => name,
            _ => MDnsLookup::lookup(&ip_str).unwrap_or(ip_str.clone()),
        };

        // Use local hostname for local IPs with different names
        let final_hostname = if is_local && !hostname.eq_ignore_ascii_case(&local_hostname) {
            local_hostname
        } else {
            hostname
        };

        // Cache the result
        if let Ok(mut cache) = DNS_CACHE.lock() {
            cache.insert(ip_str, (final_hostname.clone(), Instant::now()));
            // LRU-style eviction: remove oldest entries instead of clearing all
            if cache.len() > 10000 {
                // Find and remove the 1000 oldest entries
                let mut entries: Vec<_> = cache.iter().map(|(k, (_, t))| (k.clone(), *t)).collect();
                entries.sort_by_key(|(_, t)| *t);
                for (key, _) in entries.into_iter().take(1000) {
                    cache.remove(&key);
                }
            }
        }

        Some(final_hostname)
    }

    fn lookup_hostname(
        ip: Option<String>,
        mac: Option<String>,
        protocol: Option<String>,
        payload: &[u8],
    ) -> Option<String> {
        match protocol.as_deref() {
            Some("HTTP") => Self::get_http_host(payload),
            Some("HTTPS") => Self::find_sni(payload),
            _ => Self::lookup_dns(ip.clone(), mac.clone()),
        }
    }

    fn get_http_host(payload: &[u8]) -> Option<String> {
        let payload_str = String::from_utf8_lossy(payload);

        let mut host = None;

        for line in payload_str.lines() {
            let line = line.to_lowercase();
            if let Some(header_value) = line.strip_prefix("host:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("server:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("location:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("x-host:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("x-forwarded-host:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("x-forwarded-server:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("referer:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("report-uri:") {
                host = Some(header_value.trim().to_string());
                break;
            }
        }
        host.map(|host| Self::remove_all_but_alphanumeric_and_dots(host.as_str()))
    }

    fn remove_all_but_alphanumeric_and_dots(hostname: &str) -> String {
        let mut s = String::new();
        for h in hostname.chars() {
            if h.is_ascii_alphanumeric() || h == '.' || h == '-' {
                s.push(h);
            } else {
                s.clear();
            }
        }
        s
    }

    // Parse TLS ClientHello to extract SNI (Server Name Indication)
    fn find_sni(payload: &[u8]) -> Option<String> {
        // Minimum TLS ClientHello size
        if payload.len() < 44 {
            return None;
        }

        // Check for TLS Handshake (0x16) and version (0x03 0x01, 0x03 0x02, or 0x03 0x03)
        if payload[0] != 0x16 || payload[1] != 0x03 {
            return None;
        }

        // Check for ClientHello (0x01)
        if payload[5] != 0x01 {
            return None;
        }

        // Skip to extensions section
        // TLS record: 5 bytes
        // Handshake header: 4 bytes
        // Client version: 2 bytes
        // Random: 32 bytes
        let mut offset = 43;

        // Session ID length (1 byte) + session ID
        if offset >= payload.len() {
            return None;
        }
        let session_id_len = payload[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suites length (2 bytes) + cipher suites
        if offset + 2 > payload.len() {
            return None;
        }
        let cipher_suites_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
        offset += 2 + cipher_suites_len;

        // Compression methods length (1 byte) + compression methods
        if offset + 1 > payload.len() {
            return None;
        }
        let compression_methods_len = payload[offset] as usize;
        offset += 1 + compression_methods_len;

        // Extensions length (2 bytes)
        if offset + 2 > payload.len() {
            return None;
        }
        let extensions_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
        offset += 2;

        let extensions_end = offset + extensions_len;
        if extensions_end > payload.len() {
            return None;
        }

        // Parse extensions
        while offset + 4 <= extensions_end {
            let ext_type = ((payload[offset] as u16) << 8) | (payload[offset + 1] as u16);
            let ext_len = ((payload[offset + 2] as usize) << 8) | (payload[offset + 3] as usize);
            offset += 4;

            // Server Name extension (0x0000)
            if ext_type == 0x0000 && offset + ext_len <= extensions_end {
                // Server Name List Length (2 bytes)
                if ext_len < 5 || offset + 2 > extensions_end {
                    return None;
                }
                let _list_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
                offset += 2;

                // Server Name Type (1 byte, 0x00 for hostname)
                if payload[offset] != 0x00 {
                    return None;
                }
                offset += 1;

                // Server Name Length (2 bytes)
                if offset + 2 > extensions_end {
                    return None;
                }
                let name_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
                offset += 2;

                // Extract hostname
                if offset + name_len <= extensions_end
                    && let Ok(hostname) =
                        String::from_utf8(payload[offset..offset + name_len].to_vec())
                {
                    let cleaned = Self::remove_all_but_alphanumeric_and_dots(hostname.as_str());
                    if !cleaned.is_empty() {
                        return Some(cleaned);
                    }
                }
                return None;
            }

            offset += ext_len;
        }

        None
    }

    fn is_broadcast_or_multicast_mac(mac: &str) -> bool {
        let mac_lower = mac.to_lowercase();

        // Broadcast address
        if mac_lower == "ff:ff:ff:ff:ff:ff" {
            return true;
        }

        // Check if first octet indicates multicast (LSB of first byte is 1)
        // Multicast MACs: 01:xx:xx:xx:xx:xx, 03:xx:xx:xx:xx:xx, etc.
        if let Some(first_octet) = mac_lower.split(':').next()
            && let Ok(byte) = u8::from_str_radix(first_octet, 16)
        {
            // If LSB of first byte is 1, it's multicast
            if (byte & 0x01) == 0x01 {
                return true;
            }
        }

        false
    }

    fn is_multicast_or_broadcast_ip(ip: &str) -> bool {
        // Try to parse as IP address
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            match addr {
                std::net::IpAddr::V4(ipv4) => {
                    // IPv4 multicast: 224.0.0.0 - 239.255.255.255
                    if ipv4.is_multicast() {
                        return true;
                    }
                    // IPv4 broadcast
                    if ipv4.is_broadcast() {
                        return true;
                    }
                }
                std::net::IpAddr::V6(ipv6) => {
                    // IPv6 multicast: ff00::/8
                    if ipv6.is_multicast() {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn is_local(target_ip: String, mac: String) -> bool {
        // Check definitive loopback addresses first
        if target_ip == "127.0.0.1"
            || target_ip == "::1"
            || target_ip == "localhost"
            || target_ip == "::ffff:"
            || target_ip == "0:0:0:0:0:0:0:1"
        {
            return true; // Loopback addresses are always local
        }

        // For :: (unspecified address), verify MAC matches local interface
        let is_unspecified = target_ip == "::";

        for interface in interfaces() {
            if let Some(iface_mac) = interface.mac {
                if iface_mac.to_string() == mac {
                    return true; // MAC address matches a local interface
                }
            } else if interface
                .ips
                .iter()
                .any(|ip| ip.ip().to_string() == target_ip)
            {
                return true; // IP address matches a local interface
            }
        }

        // Only treat :: as local if we didn't find a matching MAC
        // If MAC didn't match any local interface, :: is NOT local
        if is_unspecified {
            return false;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_test_connection;

    #[test]
    fn test_classify_common_router_ip() {
        // Common router IPs should be classified as gateway
        let classification = EndPoint::classify_endpoint(Some("192.168.1.1".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));

        let classification = EndPoint::classify_endpoint(Some("10.0.0.1".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));
    }

    #[test]
    fn test_classify_router_hostname() {
        // Hostnames with router keywords should be classified as gateway
        let classification = EndPoint::classify_endpoint(None, Some("my-router.local".to_string()));
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));

        let classification =
            EndPoint::classify_endpoint(None, Some("gateway.example.com".to_string()));
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));

        let classification = EndPoint::classify_endpoint(None, Some("pfsense.local".to_string()));
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));
    }

    #[test]
    fn test_classify_internet_endpoint() {
        // Public IPs should be classified as internet
        let classification = EndPoint::classify_endpoint(Some("8.8.8.8".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_INTERNET));

        let classification = EndPoint::classify_endpoint(Some("1.1.1.1".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_INTERNET));
    }

    #[test]
    fn test_classify_local_endpoint() {
        // Loopback should return None as it's not gateway or internet (it's local)
        let classification = EndPoint::classify_endpoint(Some("127.0.0.1".to_string()), None);
        assert_eq!(classification, None);

        // Note: 192.168.x.x may be classified as internet in test environment
        // without configured network interfaces, which is expected behavior
    }

    #[test]
    fn test_classify_none_ip() {
        let classification = EndPoint::classify_endpoint(None, None);
        assert_eq!(classification, None);
    }

    #[test]
    fn test_endpoint_insertion() {
        let conn = new_test_connection();

        // Insert an endpoint - use loopback IP which is always local
        let result = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("00:11:22:33:44:55".to_string()),
            Some("127.0.0.2".to_string()),
            None,
            &[],
        );

        assert!(result.is_ok());
        let endpoint_id = result.unwrap();
        assert!(endpoint_id > 0);

        // Verify endpoint exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM endpoints WHERE id = ?1",
                [endpoint_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_duplicate_endpoint_returns_same_id() {
        let conn = new_test_connection();

        // Insert endpoint first time - use loopback IP which is always local
        let id1 = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("00:11:22:33:44:55".to_string()),
            Some("127.0.0.2".to_string()),
            None,
            &[],
        )
        .unwrap();

        // Insert same endpoint again
        let id2 = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("00:11:22:33:44:55".to_string()),
            Some("127.0.0.2".to_string()),
            None,
            &[],
        )
        .unwrap();

        // Should return the same ID
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_is_multicast_or_broadcast_ip() {
        assert!(EndPoint::is_multicast_or_broadcast_ip("224.0.0.1"));
        assert!(EndPoint::is_multicast_or_broadcast_ip("255.255.255.255"));
        assert!(!EndPoint::is_multicast_or_broadcast_ip("192.168.1.1"));
        assert!(!EndPoint::is_multicast_or_broadcast_ip("8.8.8.8"));
    }

    #[test]
    fn test_is_broadcast_or_multicast_mac() {
        assert!(EndPoint::is_broadcast_or_multicast_mac("ff:ff:ff:ff:ff:ff"));
        assert!(EndPoint::is_broadcast_or_multicast_mac("01:00:5e:00:00:01"));
        assert!(!EndPoint::is_broadcast_or_multicast_mac(
            "00:11:22:33:44:55"
        ));
    }

    #[test]
    fn test_classify_device_type_integration() {
        // Full integration test of classify_device_type
        assert_eq!(
            EndPoint::classify_device_type(Some("hp-laserjet"), &[], &[], &[], None),
            Some("printer")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("roku-ultra"), &[], &[], &[], None),
            Some("tv")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("unknown-device"), &[], &[9100], &[], None),
            Some("printer")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("my-laptop"), &[], &[80, 443], &[], None),
            None
        );
        // SSDP model-based classification
        assert_eq!(
            EndPoint::classify_device_type(Some("samsung-tv"), &[], &[], &[], Some("HW-MS750")),
            Some("soundbar")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("lg-device"), &[], &[], &[], Some("SL8YG")),
            Some("soundbar")
        );
    }

    #[test]
    fn test_classify_by_mac() {
        // Amazon device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                &[],
                &[],
                &["3c:5c:c4:90:a2:93".to_string()],
                None
            ),
            Some("appliance")
        );
        // Google/Nest device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("192.168.1.50"),
                &[],
                &[],
                &["18:d6:c7:12:34:56".to_string()],
                None
            ),
            Some("appliance")
        );
        // Ring device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                &[],
                &[],
                &["34:3e:a4:00:00:00".to_string()],
                None
            ),
            Some("appliance")
        );
        // Apple MAC without desktop services = phone (iPhone/iPad)
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                &[],
                &[],
                &["a4:83:e7:12:34:56".to_string()],
                None
            ),
            Some("phone")
        );
        // Hostname takes precedence over MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("hp-printer"),
                &[],
                &[],
                &["3c:5c:c4:90:a2:93".to_string()],
                None
            ),
            Some("printer")
        );
    }
}
