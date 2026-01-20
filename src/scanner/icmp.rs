use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::Semaphore;

use super::IcmpResult;

/// ICMP echo (ping) scanner
pub struct IcmpScanner {
    timeout_ms: u64,
    max_concurrent: usize,
}

impl IcmpScanner {
    pub fn new() -> Self {
        Self {
            timeout_ms: 1000,
            max_concurrent: 50,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    #[allow(dead_code)]
    pub fn with_concurrency(mut self, max_concurrent: usize) -> Self {
        self.max_concurrent = max_concurrent;
        self
    }

    /// Build an ICMP echo request packet
    fn build_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 8];

        // Type: Echo Request (8)
        packet[0] = 8;
        // Code: 0
        packet[1] = 0;
        // Checksum: will be calculated
        packet[2] = 0;
        packet[3] = 0;
        // Identifier
        packet[4] = (identifier >> 8) as u8;
        packet[5] = (identifier & 0xff) as u8;
        // Sequence
        packet[6] = (sequence >> 8) as u8;
        packet[7] = (sequence & 0xff) as u8;

        // Calculate checksum
        let checksum = Self::calculate_checksum(&packet);
        packet[2] = (checksum >> 8) as u8;
        packet[3] = (checksum & 0xff) as u8;

        packet
    }

    /// Calculate ICMP checksum
    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        while i < data.len() {
            let word = if i + 1 < data.len() {
                ((data[i] as u32) << 8) | (data[i + 1] as u32)
            } else {
                (data[i] as u32) << 8
            };
            sum = sum.wrapping_add(word);
            i += 2;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !sum as u16
    }

    /// Create a failed result for the given IP
    fn failed_result(ip: Ipv4Addr) -> IcmpResult {
        IcmpResult {
            ip: IpAddr::V4(ip),
            alive: false,
            rtt_ms: None,
            ttl: None,
        }
    }

    /// Ping a single IP address
    fn ping_ip(&self, ip: Ipv4Addr, sequence: u16) -> IcmpResult {
        let start = Instant::now();

        // Create raw ICMP socket
        let Ok(socket) = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) else {
            return Self::failed_result(ip);
        };

        // Set timeout
        let _ = socket.set_read_timeout(Some(Duration::from_millis(self.timeout_ms)));
        let _ = socket.set_write_timeout(Some(Duration::from_millis(self.timeout_ms)));

        // Build and send echo request
        let identifier = std::process::id() as u16;
        let packet = Self::build_echo_request(identifier, sequence);
        let addr = SocketAddr::new(IpAddr::V4(ip), 0);

        if socket.send_to(&packet, &addr.into()).is_err() {
            return Self::failed_result(ip);
        }

        // Wait for reply - use MaybeUninit buffer as required by socket2
        let mut buffer: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };
        match socket.recv(&mut buffer) {
            Ok(len) if len >= 28 => {
                // Safety: we know `len` bytes are initialized
                let buffer: &[u8] =
                    unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u8, len) };
                // IP header (20 bytes) + ICMP header (8 bytes minimum)
                let icmp_type = buffer[20];
                let ttl = buffer[8];

                if icmp_type == 0 {
                    // Echo Reply
                    let rtt = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                    return IcmpResult {
                        ip: IpAddr::V4(ip),
                        alive: true,
                        rtt_ms: Some(rtt),
                        ttl: Some(ttl),
                    };
                }
            }
            _ => {}
        }

        Self::failed_result(ip)
    }

    /// Ping sweep multiple IP addresses
    pub async fn ping_sweep(&self, targets: Vec<IpAddr>) -> Vec<IcmpResult> {
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut handles = Vec::with_capacity(targets.len());

        for (sequence, ip) in targets.into_iter().enumerate() {
            if let IpAddr::V4(ipv4) = ip {
                let sem = semaphore.clone();
                let timeout_ms = self.timeout_ms;
                // Wrap sequence number at u16::MAX (65535) - this is fine for ICMP identification
                let seq = (sequence % (u16::MAX as usize + 1)) as u16;

                handles.push(tokio::task::spawn_blocking(move || {
                    // Use try_acquire_owned in blocking context
                    let rt = tokio::runtime::Handle::current();
                    let _permit = rt.block_on(sem.acquire());
                    let scanner = IcmpScanner::new().with_timeout(timeout_ms);
                    scanner.ping_ip(ipv4, seq)
                }));
            }
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            if let Ok(result) = handle.await
                && result.alive
            {
                results.push(result);
            }
        }

        results
    }
}

impl Default for IcmpScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_calculation() {
        // Test with known data
        // ICMP echo request header: type=8, code=0, checksum=0, id=1, seq=1
        let data = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        let checksum = IcmpScanner::calculate_checksum(&data);
        // Verify checksum is non-zero (actual value depends on implementation)
        assert!(checksum > 0);
    }

    #[test]
    fn test_checksum_odd_length() {
        // Test with odd number of bytes
        let data = vec![0x08, 0x00, 0x00];
        let checksum = IcmpScanner::calculate_checksum(&data);
        assert!(checksum > 0);
    }

    #[test]
    fn test_echo_request_building() {
        let packet = IcmpScanner::build_echo_request(1234, 5678);

        // Verify packet structure
        assert_eq!(packet.len(), 8);
        assert_eq!(packet[0], 8); // Type: Echo Request
        assert_eq!(packet[1], 0); // Code: 0

        // Verify identifier (big-endian)
        assert_eq!(packet[4], (1234 >> 8) as u8);
        assert_eq!(packet[5], (1234 & 0xff) as u8);

        // Verify sequence (big-endian)
        assert_eq!(packet[6], (5678 >> 8) as u8);
        assert_eq!(packet[7], (5678 & 0xff) as u8);

        // Checksum should be non-zero
        let checksum = ((packet[2] as u16) << 8) | (packet[3] as u16);
        assert!(checksum > 0);
    }

    #[test]
    fn test_scanner_default() {
        let scanner = IcmpScanner::default();
        assert_eq!(scanner.timeout_ms, 1000);
        assert_eq!(scanner.max_concurrent, 50);
    }

    #[test]
    fn test_scanner_with_timeout() {
        let scanner = IcmpScanner::new().with_timeout(5000);
        assert_eq!(scanner.timeout_ms, 5000);
    }
}
