## Context

Network scans currently run sequentially in `manager.rs`: for each requested scan type, the manager awaits completion before starting the next. A typical full scan (ARP + SSDP + NetBIOS + SNMP) takes the sum of all phase durations. Additionally, ARP has a 10ms inter-packet delay (~2.5s to send all requests for a /24), SSDP fetches device descriptions sequentially, and NetBIOS/SNMP spawn unbounded blocking tasks.

The scan result channel (`mpsc::Sender<ScanResult>`) is already safe for concurrent use — multiple producers can send simultaneously without coordination.

## Goals / Non-Goals

**Goals:**
- Reduce total scan time by running scan phases concurrently
- Reduce ARP send time by lowering inter-packet delay and parallelizing multi-subnet scans
- Parallelize SSDP device description fetches
- Bound NetBIOS and SNMP thread usage with semaphores
- Preserve existing progress reporting, stop signal, and result processing behavior

**Non-Goals:**
- Changing scan result processing logic (`scan_results.rs`)
- Adding new scan types or changing discovery semantics
- Modifying timeouts or ports configuration
- Changing the public API surface

## Decisions

### Decision 1: Run all scan phases concurrently using `JoinSet`

**Choice:** Replace the sequential `for scan_type in &scan_types` loop in `manager.rs` with `tokio::task::JoinSet`, spawning all scan phases concurrently.

**Rationale:** Each scan type sends results independently via `result_tx.clone()`. The result channel already handles concurrent senders. `JoinSet` provides clean tracking of spawned tasks and integrates with the stop signal.

**Alternative considered:** Two-phase approach (ARP/NDP first, then enrichment scanners). Rejected because the result processing layer already handles ordering — ICMP only updates existing endpoints, and the DB retry logic handles concurrent writes. Running everything concurrently is simpler and faster.

**Progress tracking change:** Instead of `completed_phases / total_phases`, each phase completion increments a shared `AtomicU8` counter. Progress is computed as `completed.load() * 100 / total_phases`. The `current_phase` field changes to show all active phases (e.g., "ARP, SSDP, SNMP scan").

### Decision 2: Reduce ARP inter-packet delay from 10ms to 2ms

**Choice:** Change `delay_ms` default from `10` to `2` in `ArpScanner::new()`.

**Rationale:** 10ms is conservative. 2ms is still well within what switches can handle for broadcast traffic on a local subnet. For a /24 (~254 hosts), this reduces send time from ~2.5s to ~0.5s. The ARP timeout window still collects all replies.

**Alternative considered:** Zero delay (fire-and-forget). Rejected because some consumer switches can drop packets under burst broadcast traffic.

### Decision 3: Parallelize multi-subnet ARP scanning

**Choice:** In `manager.rs`, spawn each subnet's ARP scan concurrently using `JoinSet` instead of iterating sequentially.

**Rationale:** Each subnet uses a different network interface, so there's no shared resource contention. A system with 3 subnets now scans all 3 simultaneously.

### Decision 4: Parallelize SSDP device description fetches with semaphore

**Choice:** Replace the sequential `for result in &mut results` loop in `ssdp.rs` with concurrent `tokio::spawn` tasks gated by a semaphore (limit: 10 concurrent HTTP fetches).

**Rationale:** After SSDP multicast discovery, each device's description is fetched via HTTP. Sequential fetches with a 3s timeout mean 50 devices = up to 150s. With 10 concurrent fetches, this drops to ~15s worst case. The semaphore prevents overwhelming a single device or network segment.

**Alternative considered:** `futures::stream::buffer_unordered()`. Viable but a semaphore + JoinSet is more consistent with the pattern used elsewhere in the scanner module.

### Decision 5: Add semaphore limits to NetBIOS and SNMP

**Choice:** Add `Semaphore::new(50)` to both `NetBiosScanner::scan_ips()` and `SnmpScanner::scan_ips()`, matching the pattern in `IcmpScanner::ping_sweep()`.

**Rationale:** Currently both spawn one `spawn_blocking` task per IP with no limit. For a /24, that's 254 blocking threads competing for the thread pool. The ICMP scanner already demonstrates the correct pattern: acquire semaphore permit before work, release on completion. 50 concurrent is enough to keep throughput high while bounding resource usage.

## Risks / Trade-offs

- **Increased instantaneous network traffic** — Running ARP + SSDP + NetBIOS + SNMP simultaneously generates more packets in a shorter window. → Mitigation: Each scanner already has its own pacing (ARP delay, SSDP multicast timeout, per-IP timeouts). On a typical home/office network this is negligible.

- **Progress reporting becomes less granular during parallel execution** — All phases start at once, so early progress jumps are possible (e.g., SSDP finishes fast while Port scan is still running). → Mitigation: The counter-based approach still reports correct completion percentage. UI already handles non-linear progress.

- **NetBIOS/SNMP scans may be slightly slower per-IP on very small subnets** — The semaphore adds acquisition overhead. → Mitigation: Negligible for networks under 50 hosts (semaphore never blocks). For larger subnets it's a net improvement due to bounded thread pool usage.
