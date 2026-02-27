//! Hostname resolution. Provides DNS lookup, HTTP Host header extraction,
//! and TLS SNI parsing to identify endpoint hostnames from network traffic.

use dns_lookup::{get_hostname, lookup_addr};
use std::time::Instant;

use crate::network::mdns_lookup::MDnsLookup;

use super::EndPoint;
use super::constants::{DNS_CACHE, DNS_CACHE_TTL};

impl EndPoint {
    pub(super) fn lookup_dns(ip: Option<String>, mac: Option<String>) -> Option<String> {
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

    pub(super) fn lookup_hostname(
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

    const HTTP_HOST_HEADERS: &[&str] = &[
        "host:",
        "server:",
        "location:",
        "x-host:",
        "x-forwarded-host:",
        "x-forwarded-server:",
        "referer:",
        "report-uri:",
    ];

    fn get_http_host(payload: &[u8]) -> Option<String> {
        let payload_str = String::from_utf8_lossy(payload);

        for line in payload_str.lines() {
            let line = line.to_lowercase();
            for header in Self::HTTP_HOST_HEADERS {
                if let Some(value) = line.strip_prefix(header) {
                    return Some(Self::remove_all_but_alphanumeric_and_dots(value.trim()));
                }
            }
        }
        None
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
}
