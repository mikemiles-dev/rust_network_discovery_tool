//! Endpoint CRUD operations. Handles creating, finding, and updating endpoints
//! in the SQLite database, including DHCP-aware insertion and MAC-model naming.

use rusqlite::{Connection, Result, params};

use crate::network::endpoint_attribute::EndPointAttribute;

use super::EndPoint;
use super::constants::{
    extract_mac_from_ipv6_eui64, is_ipv6_link_local, is_locally_administered_mac,
    is_valid_display_name, strip_local_suffix,
};
use super::model::get_model_from_mac;
use super::types::{EndpointData, InsertEndpointError};

impl EndPoint {
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
    ) -> Result<(i64, bool), InsertEndpointError> {
        Self::get_or_insert_endpoint_with_dhcp(
            conn,
            EndpointData {
                mac,
                ip,
                protocol,
                payload,
                dhcp_client_id: None,
                dhcp_vendor_class: None,
                dhcp_hostname: None,
            },
        )
    }

    pub fn get_or_insert_endpoint_with_dhcp(
        conn: &Connection,
        data: EndpointData<'_>,
    ) -> Result<(i64, bool), InsertEndpointError> {
        let EndpointData {
            mac,
            ip,
            protocol,
            payload,
            dhcp_client_id,
            dhcp_vendor_class,
            dhcp_hostname,
        } = data;
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
        let (endpoint_id, is_new) = match EndPointAttribute::find_existing_endpoint_id_with_dhcp(
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
                    // Use original mac (not lookup_mac) so randomized MACs are stored for tracking
                    let _ = EndPointAttribute::insert_endpoint_attribute_with_dhcp(
                        conn,
                        id,
                        mac.clone(),
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
                (id, false)
            }
            _ => {
                // Use original mac (not lookup_mac) so randomized MACs are stored for tracking
                let id = Self::insert_endpoint_with_dhcp(
                    conn,
                    mac.clone(),
                    ip.clone(),
                    hostname.clone(),
                    dhcp_client_id.clone(),
                    dhcp_vendor_class.clone(),
                )?;
                (id, true)
            }
        };
        Self::check_and_update_endpoint_name(
            conn,
            endpoint_id,
            hostname.clone().unwrap_or_default(),
        )?;

        // If endpoint still has no valid name, try to derive one from MAC vendor/model rules
        // e.g. a Nintendo Switch gets named "Nintendo Switch" instead of showing its IP
        if let Some(ref mac_addr) = mac {
            Self::try_set_name_from_mac_model(conn, endpoint_id, mac_addr);
        }

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

        Ok((endpoint_id, is_new))
    }

    /// Try to set endpoint name from MAC vendor/model when no hostname is available.
    /// Gives devices like "Nintendo Switch" a proper name instead of showing their IP.
    /// Appends (2), (3), etc. when another endpoint already has the same model name.
    /// Does NOT trigger hostname-based merging (model names aren't unique identifiers).
    fn try_set_name_from_mac_model(conn: &Connection, endpoint_id: i64, mac: &str) {
        let current_name: String = conn
            .query_row(
                "SELECT COALESCE(name, '') FROM endpoints WHERE id = ?",
                params![endpoint_id],
                |row| row.get(0),
            )
            .unwrap_or_default();

        if is_valid_display_name(&current_name) {
            return; // Already has a good name
        }

        if let Some(model) = get_model_from_mac(mac) {
            let unique = Self::make_unique_endpoint_name(conn, &model, endpoint_id);
            let _ = conn.execute(
                "UPDATE endpoints SET name = ? WHERE id = ?",
                params![unique, endpoint_id],
            );
        }
    }

    /// Generate a unique endpoint name by appending (2), (3), etc. if the base name
    /// is already taken by another endpoint. Used for model-derived names where
    /// multiple devices may share the same model (e.g. two Nintendo Switches).
    pub fn make_unique_endpoint_name(
        conn: &Connection,
        base_name: &str,
        endpoint_id: i64,
    ) -> String {
        // Check if the base name is already taken by another endpoint
        let taken: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM endpoints WHERE LOWER(name) = LOWER(?1) AND id != ?2)",
                params![base_name, endpoint_id],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if !taken {
            return base_name.to_string();
        }

        // Find the next available number
        for n in 2..=99 {
            let candidate = format!("{} ({})", base_name, n);
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM endpoints WHERE LOWER(name) = LOWER(?1) AND id != ?2)",
                    params![candidate, endpoint_id],
                    |row| row.get(0),
                )
                .unwrap_or(false);

            if !exists {
                return candidate;
            }
        }

        format!("{} ({})", base_name, endpoint_id)
    }
}

#[cfg(test)]
mod tests {
    use super::super::EndPoint;
    use crate::db::new_test_connection;

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
        let (endpoint_id, is_new) = result.unwrap();
        assert!(endpoint_id > 0);
        assert!(is_new);

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
        let (id1, new1) = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("00:11:22:33:44:55".to_string()),
            Some("127.0.0.2".to_string()),
            None,
            &[],
        )
        .unwrap();
        assert!(new1);

        // Insert same endpoint again
        let (id2, new2) = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("00:11:22:33:44:55".to_string()),
            Some("127.0.0.2".to_string()),
            None,
            &[],
        )
        .unwrap();
        assert!(!new2);

        // Should return the same ID
        assert_eq!(id1, id2);
    }
}
