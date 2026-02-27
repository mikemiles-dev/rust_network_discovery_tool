## ADDED Requirements

### Requirement: Endpoint operations split into sibling modules
`src/network/endpoint/endpoint_ops.rs` SHALL be split by creating sibling files: `endpoint_crud.rs`, `endpoint_merge.rs`, and `hostname.rs` in `src/network/endpoint/`.

#### Scenario: Module compiles after split
- **WHEN** the new sibling files exist alongside a reduced `endpoint_ops.rs`
- **THEN** `cargo build` SHALL succeed with no new errors

### Requirement: CRUD operations in dedicated module
`endpoint_crud.rs` SHALL contain: `get_or_insert_endpoint` variants, hostname lookup, and IPv6 sibling creation functions.

#### Scenario: Endpoint insertion works after split
- **WHEN** the system processes a new network packet with an unknown endpoint
- **THEN** `get_or_insert_endpoint` SHALL create the endpoint identically to before the split

### Requirement: Merge operations in dedicated module
`endpoint_merge.rs` SHALL contain: `merge_ipv6_siblings_into_endpoint` and `try_merge_by_hostname`.

#### Scenario: IPv6 sibling merge works after split
- **WHEN** the system detects endpoints sharing the same IPv6 /64 prefix
- **THEN** merge behavior SHALL be identical to before the split

### Requirement: Hostname resolution in dedicated module
`hostname.rs` SHALL contain: `lookup_dns`, `lookup_hostname`, `get_http_host`, and `find_sni`.

#### Scenario: DNS and SNI resolution works after split
- **WHEN** the system resolves hostnames from DNS or TLS SNI headers
- **THEN** resolution behavior SHALL be identical to before the split

### Requirement: endpoint_ops.rs retains core classification
`endpoint_ops.rs` SHALL retain: `classify_device_type`, `check_and_update_endpoint_name`, `is_on_local_network`, MAC/IP validation helpers, `is_local`, and gateway classification logic.

#### Scenario: Device classification works after split
- **WHEN** the system classifies a new endpoint's device type
- **THEN** classification behavior SHALL be identical to before the split

### Requirement: Tests move with their functions
Tests SHALL be placed in the module containing the function they test.

#### Scenario: All existing tests pass
- **WHEN** `cargo test` is run after the split
- **THEN** all 72 tests SHALL pass

### Requirement: No file exceeds 600 lines
Each resulting file SHALL be under 600 lines.

#### Scenario: Line count check
- **WHEN** the split is complete
- **THEN** `endpoint_ops.rs`, `endpoint_crud.rs`, `endpoint_merge.rs`, and `hostname.rs` SHALL each have fewer than 600 lines
