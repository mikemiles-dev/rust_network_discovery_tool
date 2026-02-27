## ADDED Requirements

### Requirement: Merge logic extracted to sibling module
`src/db/merge_maintenance.rs` SHALL be created containing: `merge_duplicate_communications`, `merge_duplicate_endpoints_by_hostname`, `merge_endpoints_by_ipv6_prefix`, and `preserve_user_fields`.

#### Scenario: Module compiles after extraction
- **WHEN** `merge_maintenance.rs` exists alongside `maintenance.rs`
- **THEN** `cargo build` SHALL succeed with no new errors

### Requirement: Hotspot merge extracted to sibling module
`src/db/hotspot_merge.rs` SHALL be created containing: `is_hotspot_gateway_candidate`, `find_phone_for_hotspot_gateway`, and `merge_hotspot_gateways_into_phones`.

#### Scenario: Hotspot detection works after split
- **WHEN** the system detects a potential hotspot gateway
- **THEN** `is_hotspot_gateway_candidate` SHALL return the same result as before the split

### Requirement: maintenance.rs retains orchestration
`maintenance.rs` SHALL retain: `cleanup_stale_wal_files`, `WAL_CLEANUP_DONE`, and the `cleanup_old_data` orchestrator function.

#### Scenario: Maintenance orchestration works after split
- **WHEN** `cleanup_old_data` is called
- **THEN** it SHALL invoke all merge and cleanup functions in the same order as before the split

### Requirement: Endpoint merge behavior preserved
Communication deduplication, hostname-based endpoint merging, and IPv6 prefix merging SHALL produce identical results after the split.

#### Scenario: Hostname merge deduplication
- **WHEN** two endpoints share the same hostname (case-insensitive)
- **THEN** `merge_duplicate_endpoints_by_hostname` SHALL merge them identically to before the split

#### Scenario: IPv6 prefix merge
- **WHEN** endpoints share the same /64 IPv6 prefix
- **THEN** `merge_endpoints_by_ipv6_prefix` SHALL merge them identically to before the split

### Requirement: No file exceeds 600 lines
Each resulting file SHALL be under 600 lines.

#### Scenario: Line count check
- **WHEN** the split is complete
- **THEN** `maintenance.rs`, `merge_maintenance.rs`, and `hotspot_merge.rs` SHALL each have fewer than 600 lines
