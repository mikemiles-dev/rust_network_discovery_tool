## ADDED Requirements

### Requirement: Shared merge_endpoint_into helper function
`merge_endpoint_into(conn, keep_id, remove_id)` SHALL be a `pub(super)` function in `src/db/merge_maintenance.rs` that performs the complete endpoint merge sequence: preserve user fields, reassign endpoint_attributes, reassign communications (src and dst), reassign open_ports, reassign scan_results, and delete the source endpoint.

#### Scenario: Full merge sequence executes correctly
- **WHEN** `merge_endpoint_into(conn, keep_id, remove_id)` is called with valid endpoint IDs
- **THEN** it SHALL execute all 6 steps in order: (1) preserve user fields from remove_id to keep_id, (2) UPDATE OR IGNORE endpoint_attributes, DELETE orphaned endpoint_attributes, (3) UPDATE OR IGNORE communications src, UPDATE OR IGNORE communications dst, DELETE orphaned communications, (4) UPDATE OR IGNORE open_ports, DELETE orphaned open_ports, (5) UPDATE scan_results, (6) DELETE endpoint — and return `Ok(())`

#### Scenario: Merge handles unique constraint conflicts
- **WHEN** reassigning rows would violate a unique constraint (e.g., duplicate endpoint_attribute or communication)
- **THEN** the UPDATE OR IGNORE SHALL skip the conflicting row, and the subsequent DELETE SHALL remove the orphaned row from the source endpoint

#### Scenario: Merge returns error on database failure
- **WHEN** any step in the merge sequence fails with a rusqlite error (other than a handled unique constraint)
- **THEN** `merge_endpoint_into` SHALL propagate the error as `Err(rusqlite::Error)`

### Requirement: hostname merge uses shared helper
`merge_duplicate_endpoints_by_hostname` in `merge_maintenance.rs` SHALL call `merge_endpoint_into` instead of inline merge SQL, eliminating the duplicated 6-step sequence (previously lines 152-196).

#### Scenario: Hostname merge produces identical results
- **WHEN** duplicate endpoints are found by hostname and merged
- **THEN** the merge result SHALL be identical to the previous inline implementation — all attributes, communications, open_ports, and scan_results reassigned to the surviving endpoint

### Requirement: IPv6 prefix merge uses shared helper
`merge_endpoints_by_ipv6_prefix` in `merge_maintenance.rs` SHALL call `merge_endpoint_into` instead of inline merge SQL, eliminating the duplicated 6-step sequence (previously lines 302-339).

#### Scenario: IPv6 prefix merge produces identical results
- **WHEN** duplicate endpoints sharing an IPv6 /64 prefix are merged
- **THEN** the merge result SHALL be identical to the previous inline implementation

### Requirement: Hotspot merge uses shared helper
`merge_hotspot_gateways_into_phones` in `hotspot_merge.rs` SHALL call `merge_endpoint_into` instead of inline merge SQL, eliminating the duplicated 6-step sequence (previously lines 128-169).

#### Scenario: Hotspot merge produces identical results
- **WHEN** a hotspot gateway endpoint is merged into a phone endpoint
- **THEN** the merge result SHALL be identical to the previous inline implementation
