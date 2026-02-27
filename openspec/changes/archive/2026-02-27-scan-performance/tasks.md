## 1. Parallel scan phases in manager.rs

- [x] 1.1 Replace the sequential `for scan_type in &scan_types` loop (lines 157-286) with a `tokio::task::JoinSet` that spawns each scan type as a concurrent task, each with its own `result_tx.clone()`
- [x] 1.2 Add a shared `Arc<AtomicU8>` counter for completed phases; each spawned task increments it on completion and updates `status.progress_percent` as `completed * 100 / total_phases`
- [x] 1.3 Update `current_phase` to show all active scan type names at scan start (e.g., "ARP, SSDP, SNMP scan"), then update as phases complete
- [x] 1.4 Track `discovered_ips` using `Arc<Mutex<HashSet<IpAddr>>>` shared across all concurrent phases so `discovered_count` remains accurate
- [x] 1.5 Ensure the stop signal check still works — each spawned phase task reads `stop_signal` before starting its scanner

## 2. ARP speedup

- [x] 2.1 Change `delay_ms` default from `10` to `2` in `ArpScanner::new()` (src/scanner/arp.rs line 28)
- [x] 2.2 In the ARP branch of manager.rs, replace the sequential `for subnet in &subnets` loop with concurrent subnet scanning using `JoinSet` — spawn each subnet's `scanner.scan_subnet()` as a separate task and collect all results

## 3. SSDP parallel fetch

- [x] 3.1 In `SsdpScanner::discover()` (src/scanner/ssdp.rs lines 101-108), replace the sequential `for result in &mut results` loop with concurrent HTTP fetches using `JoinSet` + `Semaphore::new(10)`

## 4. Scanner concurrency limits

- [x] 4.1 In `NetBiosScanner::scan_ips()` (src/scanner/netbios.rs lines 218-224), add `Arc<Semaphore>::new(50)` and acquire a permit in each `spawn_blocking` task before calling `query_ip`, matching the pattern from `IcmpScanner::ping_sweep()`
- [x] 4.2 In `SnmpScanner::scan_ips()` (src/scanner/snmp.rs lines 474-483), add `Arc<Semaphore>::new(50)` and acquire a permit in each `spawn_blocking` task before calling `query_ip`, matching the same pattern

## 5. Validation

- [x] 5.1 Verify `cargo check` succeeds
- [x] 5.2 Verify `cargo clippy` has no new warnings
- [x] 5.3 Verify `cargo test` passes (existing scanner tests)
