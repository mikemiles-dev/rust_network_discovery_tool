## Why

Network scans are slower than necessary because scan types run sequentially (ARP → ICMP → Port → SSDP → NetBIOS → SNMP), ARP has artificial per-packet delays, SSDP fetches device descriptions one at a time, and NetBIOS/SNMP lack concurrency limits risking thread exhaustion on large subnets.

## What Changes

- Run independent scan phases concurrently instead of sequentially in `manager.rs`
- Reduce ARP inter-packet delay and scan multiple subnets in parallel
- Parallelize SSDP device description HTTP fetches with a concurrency limit
- Add semaphore-based concurrency limits to NetBIOS and SNMP scanners (matching the pattern already used by ICMP and Port scanners)

## Capabilities

### New Capabilities
- `parallel-scan-phases`: Run independent scan types concurrently in the scan manager, reducing total scan time from the sum of all phases to approximately the duration of the slowest phase
- `arp-speedup`: Reduce ARP inter-packet delay and parallelize multi-subnet ARP scanning
- `ssdp-parallel-fetch`: Fetch SSDP/UPnP device descriptions concurrently instead of sequentially
- `scanner-concurrency-limits`: Add semaphore-based concurrency limits to NetBIOS and SNMP scanners to prevent thread exhaustion

### Modified Capabilities

_(none — no existing spec requirements change)_

## Impact

- **Files:** `src/scanner/manager.rs`, `src/scanner/arp.rs`, `src/scanner/ssdp.rs`, `src/scanner/netbios.rs`, `src/scanner/snmp.rs`
- **Behavior:** Scans complete significantly faster; resource usage becomes bounded and predictable
- **Risk:** Parallel scan phases increase instantaneous network traffic; concurrency limits on NetBIOS/SNMP may slightly slow those individual scanners on very small subnets (negligible)
- **Dependencies:** No new crate dependencies (tokio semaphores and JoinSet already available)
