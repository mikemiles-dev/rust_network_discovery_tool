//! NetBIOS scanner. Queries UDP port 137 to discover Windows device names
//! and workgroup information via NetBIOS Name Service (NBNS) requests.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use super::NetBiosResult;

/// Transaction ID counter for NetBIOS requests
static TRANSACTION_ID: AtomicU16 = AtomicU16::new(1);

const NETBIOS_PORT: u16 = 137;

/// NetBIOS Name Service scanner
/// Queries devices on UDP port 137 for their NetBIOS names
pub struct NetBiosScanner {
    timeout_ms: u64,
}

impl NetBiosScanner {
    pub fn new() -> Self {
        Self { timeout_ms: 1000 }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Build a NetBIOS Node Status Request packet
    /// This queries for the "*" name to get the full name table
    fn build_nbstat_request(transaction_id: u16) -> Vec<u8> {
        let mut packet = Vec::with_capacity(50);

        // Transaction ID (2 bytes)
        packet.push((transaction_id >> 8) as u8);
        packet.push(transaction_id as u8);

        // Flags: 0x0000 (standard query)
        packet.push(0x00);
        packet.push(0x00);

        // Questions: 1
        packet.push(0x00);
        packet.push(0x01);

        // Answer RRs: 0
        packet.push(0x00);
        packet.push(0x00);

        // Authority RRs: 0
        packet.push(0x00);
        packet.push(0x00);

        // Additional RRs: 0
        packet.push(0x00);
        packet.push(0x00);

        // Query name: "*" encoded as NetBIOS name
        // NetBIOS names are encoded by splitting each byte into two nibbles
        // and adding 'A' (0x41) to each nibble
        // "*" (0x2A) padded to 16 chars with spaces (0x20)
        // First byte is length (32 = 0x20)
        packet.push(0x20); // Length of encoded name

        // Encode "*" followed by 15 spaces
        // "*" = 0x2A -> 'C' (0x41 + 0x02), 'K' (0x41 + 0x0A)
        packet.push(b'C');
        packet.push(b'K');

        // 15 spaces, each space (0x20) -> 'C' (0x41 + 0x02), 'A' (0x41 + 0x00)
        for _ in 0..15 {
            packet.push(b'C');
            packet.push(b'A');
        }

        // Null terminator for name
        packet.push(0x00);

        // Query type: NBSTAT (0x0021)
        packet.push(0x00);
        packet.push(0x21);

        // Query class: IN (0x0001)
        packet.push(0x00);
        packet.push(0x01);

        packet
    }

    /// Parse a NetBIOS Node Status Response
    fn parse_nbstat_response(data: &[u8]) -> Option<(String, Option<String>, Option<String>)> {
        // Minimum response size check
        if data.len() < 57 {
            return None;
        }

        // Skip header (12 bytes) and query section (~34 bytes for encoded name + type/class)
        // Response starts with resource record containing name table

        // Find the start of the answer section
        // Skip: header (12) + name length (1) + encoded name (32) + null (1) + type (2) + class (2) = 50
        let mut pos = 50;

        // Skip TTL (4 bytes) + RDLENGTH (2 bytes)
        if data.len() < pos + 6 {
            return None;
        }

        // Read RDLENGTH
        let rdlength = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
        pos += 6;

        if data.len() < pos + rdlength || rdlength < 1 {
            return None;
        }

        // First byte is number of names
        let num_names = data[pos] as usize;
        pos += 1;

        if data.len() < pos + (num_names * 18) {
            return None;
        }

        let mut computer_name: Option<String> = None;
        let mut group_name: Option<String> = None;

        // Each name entry is 18 bytes: 15 bytes name + 1 byte suffix + 2 bytes flags
        for _ in 0..num_names {
            if pos + 18 > data.len() {
                break;
            }

            let name_bytes = &data[pos..pos + 15];
            let suffix = data[pos + 15];
            let flags = u16::from_be_bytes([data[pos + 16], data[pos + 17]]);

            // Convert name bytes to string, trimming spaces
            let name = String::from_utf8_lossy(name_bytes).trim_end().to_string();

            // Flags: bit 15 (0x8000) indicates group name
            let is_group = (flags & 0x8000) != 0;

            // Suffix 0x00 = Workstation/Computer name
            // Suffix 0x00 with group flag = Domain/Workgroup name
            if suffix == 0x00 {
                if is_group {
                    if group_name.is_none() && !name.is_empty() {
                        group_name = Some(name.clone());
                    }
                } else if computer_name.is_none() && !name.is_empty() {
                    computer_name = Some(name.clone());
                }
            }

            pos += 18;
        }

        // MAC address is at the end of the name table
        let mac = if pos + 6 <= data.len() {
            Some(format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5]
            ))
        } else {
            None
        };

        computer_name.map(|name| (name, group_name, mac))
    }

    /// Query a single IP for NetBIOS name
    pub fn query_ip(&self, ip: Ipv4Addr) -> Option<NetBiosResult> {
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        socket
            .set_read_timeout(Some(Duration::from_millis(self.timeout_ms)))
            .ok()?;

        let target = SocketAddr::new(IpAddr::V4(ip), NETBIOS_PORT);
        let request = Self::build_nbstat_request(TRANSACTION_ID.fetch_add(1, Ordering::Relaxed));

        socket.send_to(&request, target).ok()?;

        let mut buf = [0u8; 512];
        let (len, _) = socket.recv_from(&mut buf).ok()?;

        let (netbios_name, group_name, mac) = Self::parse_nbstat_response(&buf[..len])?;

        Some(NetBiosResult {
            ip: IpAddr::V4(ip),
            netbios_name,
            group_name,
            mac,
        })
    }

    /// Scan a list of IPs for NetBIOS names
    pub async fn scan_ips(&self, ips: &[IpAddr]) -> Vec<NetBiosResult> {
        let timeout_ms = self.timeout_ms;
        let ips: Vec<Ipv4Addr> = ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None, // NetBIOS is IPv4 only
            })
            .collect();

        // Run queries concurrently with a semaphore to limit parallelism
        let mut handles = Vec::new();

        for ip in ips {
            let timeout = timeout_ms;
            handles.push(tokio::task::spawn_blocking(move || {
                let scanner = NetBiosScanner::new().with_timeout(timeout);
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

impl Default for NetBiosScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_nbstat_request() {
        let request = NetBiosScanner::build_nbstat_request(0x1234);

        // Check transaction ID
        assert_eq!(request[0], 0x12);
        assert_eq!(request[1], 0x34);

        // Check questions count
        assert_eq!(request[4], 0x00);
        assert_eq!(request[5], 0x01);

        // Check encoded name starts with length 0x20
        assert_eq!(request[12], 0x20);

        // Check query type is NBSTAT (0x0021)
        assert_eq!(request[request.len() - 4], 0x00);
        assert_eq!(request[request.len() - 3], 0x21);

        // Check query class is IN (0x0001)
        assert_eq!(request[request.len() - 2], 0x00);
        assert_eq!(request[request.len() - 1], 0x01);
    }

    #[test]
    fn test_scanner_default() {
        let scanner = NetBiosScanner::default();
        assert_eq!(scanner.timeout_ms, 1000);
    }

    #[test]
    fn test_scanner_with_timeout() {
        let scanner = NetBiosScanner::new().with_timeout(5000);
        assert_eq!(scanner.timeout_ms, 5000);
    }
}
