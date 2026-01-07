use dns_lookup::{get_hostname, lookup_addr};
use pnet::datalink::interfaces;
use rusqlite::{Connection, Result, params};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::network::endpoint_attribute::EndPointAttribute;
use crate::network::mdns_lookup::MDnsLookup;

// Simple DNS cache to avoid repeated slow lookups
lazy_static::lazy_static! {
    static ref DNS_CACHE: Arc<Mutex<HashMap<String, (String, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
}

const DNS_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

pub enum InsertEndpointError {
    BothMacAndIpNone,
    ConstraintViolation,
    DatabaseError(rusqlite::Error),
}

impl From<rusqlite::Error> for InsertEndpointError {
    fn from(err: rusqlite::Error) -> Self {
        match err {
            rusqlite::Error::SqliteFailure(err, Some(_))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                InsertEndpointError::ConstraintViolation
            }
            _ => InsertEndpointError::DatabaseError(err),
        }
    }
}

#[derive(Default, Debug)]
pub struct EndPoint;

impl EndPoint {
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
        Ok(())
    }

    fn insert_endpoint(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        hostname: Option<String>,
    ) -> Result<i64, InsertEndpointError> {
        conn.execute(
            "INSERT INTO endpoints (created_at) VALUES (strftime('%s', 'now'))",
            params![],
        )?;
        let endpoint_id = conn.last_insert_rowid();
        let hostname = hostname.unwrap_or(ip.clone().unwrap_or_default());
        EndPointAttribute::insert_endpoint_attribute(conn, endpoint_id, mac, ip, hostname)?;
        Ok(endpoint_id)
    }

    pub fn get_or_insert_endpoint(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        protocol: Option<String>,
        payload: &[u8],
    ) -> Result<i64, InsertEndpointError> {
        // Filter out broadcast/multicast MACs - these aren't real endpoints
        if let Some(ref mac_addr) = mac
            && Self::is_broadcast_or_multicast_mac(mac_addr) {
                return Err(InsertEndpointError::BothMacAndIpNone);
            }

        // Filter out multicast/broadcast IPs - these aren't real endpoints
        if let Some(ref ip_addr) = ip
            && Self::is_multicast_or_broadcast_ip(ip_addr) {
                return Err(InsertEndpointError::BothMacAndIpNone);
            }

        if (mac.is_none() || mac == Some("00:00:00:00:00:00".to_string())) && ip.is_none() {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }
        let hostname = Self::lookup_hostname(ip.clone(), mac.clone(), protocol.clone(), payload);
        let endpoint_id = match EndPointAttribute::find_existing_endpoint_id(
            conn,
            mac.clone(),
            ip.clone(),
            hostname.clone(),
        ) {
            Some(id) => {
                // Always try to insert new hostname if it's different from IP
                // This captures all hostnames seen at this endpoint (remote or local)
                if ip != hostname && hostname.is_some() {
                    // Attempt to insert - will be ignored if duplicate due to UNIQUE constraint
                    let _ = EndPointAttribute::insert_endpoint_attribute(
                        conn,
                        id,
                        mac,
                        ip.clone(),
                        hostname.clone().unwrap_or(ip.clone().unwrap_or_default()),
                    );
                }
                id
            }
            _ => Self::insert_endpoint(conn, mac.clone(), ip.clone(), hostname.clone())?,
        };
        Self::check_and_update_endpoint_name(
            conn,
            endpoint_id,
            hostname.clone().unwrap_or_default(),
        )?;
        Ok(endpoint_id)
    }

    fn check_and_update_endpoint_name(
        conn: &Connection,
        endpoint_id: i64,
        hostname: String,
    ) -> Result<(), InsertEndpointError> {
        if hostname.is_empty() {
            return Ok(());
        }
        // Check if endpoint exists with null hostname
        if conn.query_row(
            "SELECT COUNT(*) FROM endpoints WHERE id = ? AND (name IS NULL OR name = '')",
            params![endpoint_id],
            |row| row.get::<_, i64>(0),
        )? > 0
        {
            conn.execute(
                "UPDATE endpoints SET name = ? where id = ?",
                params![hostname, endpoint_id],
            )?;
        } else if hostname.parse::<std::net::IpAddr>().is_err() {
            // Only update if hostname is not an IPv4 or IPv6 address
            // First check if current name is an IP address
            let current_name: String = conn.query_row(
                "SELECT COALESCE(name, '') FROM endpoints WHERE id = ?",
                params![endpoint_id],
                |row| row.get(0),
            )?;

            if current_name.is_empty() || current_name.parse::<std::net::IpAddr>().is_ok() {
                conn.execute(
                    "UPDATE endpoints SET name = ? WHERE id = ?",
                    params![hostname, endpoint_id],
                )?;
            }
        }

        Ok(())
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
            && cached_time.elapsed() < DNS_CACHE_TTL {
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
            // Limit cache size to prevent memory growth
            if cache.len() > 10000 {
                cache.clear();
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
            && let Ok(byte) = u8::from_str_radix(first_octet, 16) {
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
        if target_ip == "127.0.0.1"
            || target_ip == "::1"
            || target_ip == "localhost"
            || target_ip == "::ffff:"
            || target_ip == "0:0:0:0:0:0:0:1"
            || target_ip == "::"
        {
            return true; // Loopback addresses are always local
        }

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

        false
    }
}
