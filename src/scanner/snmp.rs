//! SNMP scanner. Queries devices on UDP port 161 using SNMPv2c GET requests
//! to retrieve system description, name, location, and object ID.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::SnmpResult;

/// Request ID counter for SNMP requests
static REQUEST_ID: AtomicU32 = AtomicU32::new(1);

const SNMP_PORT: u16 = 161;

/// Standard SNMP OIDs for system information
const OID_SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0]; // sysDescr
const OID_SYS_OBJECT_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0]; // sysObjectID
const OID_SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0]; // sysName
const OID_SYS_LOCATION: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 6, 0]; // sysLocation

/// Common SNMP community strings to try
const COMMUNITY_STRINGS: &[&str] = &["public", "private"];

/// SNMP scanner for device identification
/// Queries SNMP-enabled devices for system information (sysDescr, sysName, etc.)
pub struct SnmpScanner {
    timeout_ms: u64,
    communities: Vec<String>,
}

impl SnmpScanner {
    pub fn new() -> Self {
        Self {
            timeout_ms: 2000,
            communities: COMMUNITY_STRINGS.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Encode an OID in BER format
    fn encode_oid(oid: &[u32]) -> Vec<u8> {
        let mut encoded = Vec::new();

        if oid.len() >= 2 {
            // First two components are encoded as: first * 40 + second
            encoded.push((oid[0] * 40 + oid[1]) as u8);

            // Remaining components use variable-length encoding
            for &component in &oid[2..] {
                if component < 128 {
                    encoded.push(component as u8);
                } else {
                    // Multi-byte encoding for values >= 128
                    let mut bytes = Vec::new();
                    let mut val = component;
                    while val > 0 {
                        bytes.push((val & 0x7F) as u8);
                        val >>= 7;
                    }
                    bytes.reverse();
                    for (i, b) in bytes.iter().enumerate() {
                        if i < bytes.len() - 1 {
                            encoded.push(b | 0x80);
                        } else {
                            encoded.push(*b);
                        }
                    }
                }
            }
        }

        encoded
    }

    /// Encode a length in BER format
    fn encode_length(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len < 256 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        }
    }

    /// Build an SNMP v2c GET request for multiple OIDs
    fn build_get_request(community: &str, request_id: u32, oids: &[&[u32]]) -> Vec<u8> {
        // Build varbind list
        let mut varbinds = Vec::new();
        for oid in oids {
            let encoded_oid = Self::encode_oid(oid);
            let mut varbind = Vec::new();
            // OID
            varbind.push(0x06); // OBJECT IDENTIFIER
            varbind.extend(Self::encode_length(encoded_oid.len()));
            varbind.extend(&encoded_oid);
            // NULL value (for GET request)
            varbind.push(0x05); // NULL
            varbind.push(0x00);

            // Wrap in SEQUENCE
            let mut varbind_seq = vec![0x30]; // SEQUENCE
            varbind_seq.extend(Self::encode_length(varbind.len()));
            varbind_seq.extend(varbind);
            varbinds.extend(varbind_seq);
        }

        // Varbind list SEQUENCE
        let mut varbind_list = vec![0x30]; // SEQUENCE
        varbind_list.extend(Self::encode_length(varbinds.len()));
        varbind_list.extend(varbinds);

        // PDU components
        let request_id_bytes = request_id.to_be_bytes();
        let mut pdu_content = Vec::new();

        // Request ID (INTEGER)
        pdu_content.push(0x02); // INTEGER
        pdu_content.push(0x04); // length 4
        pdu_content.extend(&request_id_bytes);

        // Error status (INTEGER 0)
        pdu_content.push(0x02);
        pdu_content.push(0x01);
        pdu_content.push(0x00);

        // Error index (INTEGER 0)
        pdu_content.push(0x02);
        pdu_content.push(0x01);
        pdu_content.push(0x00);

        // Varbind list
        pdu_content.extend(&varbind_list);

        // GetRequest PDU (context-specific [0])
        let mut pdu = vec![0xA0]; // GetRequest-PDU
        pdu.extend(Self::encode_length(pdu_content.len()));
        pdu.extend(pdu_content);

        // Message components
        let mut message_content = Vec::new();

        // Version (INTEGER 1 for SNMPv2c)
        message_content.push(0x02); // INTEGER
        message_content.push(0x01);
        message_content.push(0x01); // version 2c

        // Community string (OCTET STRING)
        let community_bytes = community.as_bytes();
        message_content.push(0x04); // OCTET STRING
        message_content.extend(Self::encode_length(community_bytes.len()));
        message_content.extend(community_bytes);

        // PDU
        message_content.extend(&pdu);

        // Final message SEQUENCE
        let mut message = vec![0x30]; // SEQUENCE
        message.extend(Self::encode_length(message_content.len()));
        message.extend(message_content);

        message
    }

    /// Decode BER length and return (length, bytes_consumed)
    fn decode_length(data: &[u8]) -> Option<(usize, usize)> {
        if data.is_empty() {
            return None;
        }

        if data[0] < 128 {
            Some((data[0] as usize, 1))
        } else {
            let num_bytes = (data[0] & 0x7F) as usize;
            if data.len() < 1 + num_bytes {
                return None;
            }
            let mut len = 0usize;
            for i in 0..num_bytes {
                len = (len << 8) | data[1 + i] as usize;
            }
            Some((len, 1 + num_bytes))
        }
    }

    /// Parse SNMP response and extract varbind values
    fn parse_response(data: &[u8]) -> Option<Vec<(Vec<u32>, String)>> {
        if data.len() < 10 {
            return None;
        }

        // Check SEQUENCE tag
        if data[0] != 0x30 {
            return None;
        }

        let (_, len_bytes) = Self::decode_length(&data[1..])?;
        let mut pos = 1 + len_bytes;

        // Skip version
        if data.get(pos)? != &0x02 {
            return None;
        }
        pos += 1;
        let (ver_len, ver_len_bytes) = Self::decode_length(&data[pos..])?;
        pos += ver_len_bytes + ver_len;

        // Skip community
        if data.get(pos)? != &0x04 {
            return None;
        }
        pos += 1;
        let (comm_len, comm_len_bytes) = Self::decode_length(&data[pos..])?;
        pos += comm_len_bytes + comm_len;

        // Check PDU type (GetResponse = 0xA2)
        if data.get(pos)? != &0xA2 {
            return None;
        }
        pos += 1;
        let (_, pdu_len_bytes) = Self::decode_length(&data[pos..])?;
        pos += pdu_len_bytes;

        // Skip request-id
        if data.get(pos)? != &0x02 {
            return None;
        }
        pos += 1;
        let (rid_len, rid_len_bytes) = Self::decode_length(&data[pos..])?;
        pos += rid_len_bytes + rid_len;

        // Skip error-status
        if data.get(pos)? != &0x02 {
            return None;
        }
        pos += 1;
        let (es_len, es_len_bytes) = Self::decode_length(&data[pos..])?;
        pos += es_len_bytes + es_len;

        // Skip error-index
        if data.get(pos)? != &0x02 {
            return None;
        }
        pos += 1;
        let (ei_len, ei_len_bytes) = Self::decode_length(&data[pos..])?;
        pos += ei_len_bytes + ei_len;

        // Varbind list SEQUENCE
        if data.get(pos)? != &0x30 {
            return None;
        }
        pos += 1;
        let (vbl_len, vbl_len_bytes) = Self::decode_length(&data[pos..])?;
        pos += vbl_len_bytes;

        let vbl_end = pos + vbl_len;
        let mut results = Vec::new();

        // Parse each varbind
        while pos < vbl_end && pos < data.len() {
            // Varbind SEQUENCE
            if data.get(pos)? != &0x30 {
                break;
            }
            pos += 1;
            let (vb_len, vb_len_bytes) = Self::decode_length(&data[pos..])?;
            pos += vb_len_bytes;
            let vb_end = pos + vb_len;

            // OID
            if data.get(pos)? != &0x06 {
                pos = vb_end;
                continue;
            }
            pos += 1;
            let (oid_len, oid_len_bytes) = Self::decode_length(&data[pos..])?;
            pos += oid_len_bytes;

            // Decode OID
            if pos + oid_len > data.len() {
                break;
            }
            let oid_data = &data[pos..pos + oid_len];
            let mut oid = Vec::new();
            if !oid_data.is_empty() {
                oid.push((oid_data[0] / 40) as u32);
                oid.push((oid_data[0] % 40) as u32);
                let mut i = 1;
                while i < oid_data.len() {
                    let mut val = 0u32;
                    while i < oid_data.len() {
                        let b = oid_data[i];
                        i += 1;
                        val = (val << 7) | (b & 0x7F) as u32;
                        if b & 0x80 == 0 {
                            break;
                        }
                    }
                    oid.push(val);
                }
            }
            pos += oid_len;

            // Value
            let value_type = *data.get(pos)?;
            pos += 1;
            let (val_len, val_len_bytes) = Self::decode_length(&data[pos..])?;
            pos += val_len_bytes;

            if pos + val_len > data.len() {
                break;
            }

            let value_str = match value_type {
                0x04 => {
                    // OCTET STRING
                    String::from_utf8_lossy(&data[pos..pos + val_len]).to_string()
                }
                0x06 => {
                    // OID - decode and format as dotted string
                    let oid_bytes = &data[pos..pos + val_len];
                    let mut oid_parts = Vec::new();
                    if !oid_bytes.is_empty() {
                        oid_parts.push((oid_bytes[0] / 40).to_string());
                        oid_parts.push((oid_bytes[0] % 40).to_string());
                        let mut i = 1;
                        while i < oid_bytes.len() {
                            let mut val = 0u32;
                            while i < oid_bytes.len() {
                                let b = oid_bytes[i];
                                i += 1;
                                val = (val << 7) | (b & 0x7F) as u32;
                                if b & 0x80 == 0 {
                                    break;
                                }
                            }
                            oid_parts.push(val.to_string());
                        }
                    }
                    oid_parts.join(".")
                }
                0x02 => {
                    // INTEGER - BER uses two's complement, so handle sign bit
                    if val_len == 0 {
                        "0".to_string()
                    } else {
                        let mut val = if data[pos] & 0x80 != 0 { -1i64 } else { 0i64 };
                        for b in &data[pos..pos + val_len] {
                            val = (val << 8) | *b as i64;
                        }
                        val.to_string()
                    }
                }
                0x40 => {
                    // IpAddress
                    if val_len == 4 {
                        format!(
                            "{}.{}.{}.{}",
                            data[pos],
                            data[pos + 1],
                            data[pos + 2],
                            data[pos + 3]
                        )
                    } else {
                        String::new()
                    }
                }
                _ => {
                    // Other types - skip
                    String::new()
                }
            };

            pos += val_len;

            if !value_str.is_empty() {
                results.push((oid, value_str));
            }

            // Ensure we advance to next varbind
            if pos < vb_end {
                pos = vb_end;
            }
        }

        if results.is_empty() {
            None
        } else {
            Some(results)
        }
    }

    /// Query a single IP for SNMP information
    pub fn query_ip(&self, ip: Ipv4Addr) -> Option<SnmpResult> {
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        socket
            .set_read_timeout(Some(Duration::from_millis(self.timeout_ms)))
            .ok()?;

        let target = SocketAddr::new(IpAddr::V4(ip), SNMP_PORT);
        let oids: Vec<&[u32]> = vec![
            OID_SYS_DESCR,
            OID_SYS_OBJECT_ID,
            OID_SYS_NAME,
            OID_SYS_LOCATION,
        ];

        // Try each community string
        for community in &self.communities {
            let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
            let request = Self::build_get_request(community, request_id, &oids);

            if socket.send_to(&request, target).is_err() {
                continue;
            }

            let mut buf = [0u8; 2048];
            if let Ok((len, src)) = socket.recv_from(&mut buf)
                && src.ip() == IpAddr::V4(ip)
                && let Some(varbinds) = Self::parse_response(&buf[..len])
            {
                let mut sys_descr = None;
                let mut sys_object_id = None;
                let mut sys_name = None;
                let mut sys_location = None;

                for (oid, value) in varbinds {
                    if oid == OID_SYS_DESCR {
                        sys_descr = Some(value);
                    } else if oid == OID_SYS_OBJECT_ID {
                        sys_object_id = Some(value);
                    } else if oid == OID_SYS_NAME {
                        sys_name = Some(value);
                    } else if oid == OID_SYS_LOCATION {
                        sys_location = Some(value);
                    }
                }

                // Only return if we got at least sysDescr or sysName
                if sys_descr.is_some() || sys_name.is_some() {
                    return Some(SnmpResult {
                        ip: IpAddr::V4(ip),
                        community: community.clone(),
                        sys_descr,
                        sys_object_id,
                        sys_name,
                        sys_location,
                    });
                }
            }
        }

        None
    }

    /// Scan a list of IPs for SNMP information
    pub async fn scan_ips(&self, ips: &[IpAddr]) -> Vec<SnmpResult> {
        let timeout_ms = self.timeout_ms;
        let communities = self.communities.clone();
        let ips: Vec<Ipv4Addr> = ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None, // SNMP is typically IPv4
            })
            .collect();

        let mut handles = Vec::new();

        for ip in ips {
            let timeout = timeout_ms;
            let comms = communities.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                let scanner = SnmpScanner {
                    timeout_ms: timeout,
                    communities: comms,
                };
                scanner.query_ip(ip)
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            if let Ok(Some(result)) = handle.await {
                results.push(result);
            }
        }

        results
    }
}

impl Default for SnmpScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_oid() {
        // Test encoding sysDescr OID: 1.3.6.1.2.1.1.1.0
        let encoded = SnmpScanner::encode_oid(OID_SYS_DESCR);
        // 1.3 encodes as 43 (1*40 + 3)
        assert_eq!(encoded[0], 43);
        // Remaining: 6, 1, 2, 1, 1, 1, 0
        assert_eq!(&encoded[1..], &[6, 1, 2, 1, 1, 1, 0]);
    }

    #[test]
    fn test_encode_length() {
        assert_eq!(SnmpScanner::encode_length(10), vec![10]);
        assert_eq!(SnmpScanner::encode_length(127), vec![127]);
        assert_eq!(SnmpScanner::encode_length(128), vec![0x81, 128]);
        assert_eq!(SnmpScanner::encode_length(256), vec![0x82, 1, 0]);
    }

    #[test]
    fn test_decode_length() {
        assert_eq!(SnmpScanner::decode_length(&[10]), Some((10, 1)));
        assert_eq!(SnmpScanner::decode_length(&[127]), Some((127, 1)));
        assert_eq!(SnmpScanner::decode_length(&[0x81, 128]), Some((128, 2)));
        assert_eq!(SnmpScanner::decode_length(&[0x82, 1, 0]), Some((256, 3)));
    }

    #[test]
    fn test_build_get_request() {
        let request = SnmpScanner::build_get_request("public", 1, &[OID_SYS_DESCR]);

        // Should start with SEQUENCE
        assert_eq!(request[0], 0x30);

        // Should contain version 1 (SNMPv2c)
        // After length bytes, version INTEGER should be present
        assert!(request.len() > 10);
    }

    #[test]
    fn test_scanner_default() {
        let scanner = SnmpScanner::default();
        assert_eq!(scanner.timeout_ms, 2000);
        assert_eq!(scanner.communities.len(), 2);
    }

    #[test]
    fn test_scanner_with_timeout() {
        let scanner = SnmpScanner::new().with_timeout(5000);
        assert_eq!(scanner.timeout_ms, 5000);
    }
}
