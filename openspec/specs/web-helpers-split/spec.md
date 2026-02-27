## ADDED Requirements

### Requirement: Web helpers directory module structure
`src/web/helpers.rs` SHALL be converted to a directory module `src/web/helpers/mod.rs` with sub-modules: `types.rs`, `endpoint_queries.rs`, `protocol_queries.rs`, and `model_queries.rs`.

#### Scenario: Module compiles after split
- **WHEN** `src/web/helpers/` directory exists with all sub-modules
- **THEN** `cargo build` SHALL succeed with no new errors

### Requirement: Types in dedicated module
`types.rs` SHALL contain: `EndpointStats`, `EndpointDetailsResponse`, `NodeQuery`, and endpoint model data tuple types.

#### Scenario: Types importable after split
- **WHEN** other modules import helper types
- **THEN** all previously available types SHALL still be importable

### Requirement: Endpoint queries in dedicated module
`endpoint_queries.rs` SHALL contain: `dropdown_endpoints`, `get_all_endpoint_types`, `get_all_endpoints_last_seen`, `get_all_endpoints_online_status`, `resolve_identifier_to_endpoint_ids`, and `resolve_identifier_to_display_name`.

#### Scenario: Endpoint listing queries work after split
- **WHEN** the web UI requests the endpoint dropdown or type listing
- **THEN** query results SHALL be identical to before the split

### Requirement: Protocol queries in dedicated module
`protocol_queries.rs` SHALL contain: `get_protocols_for_endpoint`, `get_endpoints_for_protocol`, `get_all_protocols`, and `get_ports_for_endpoint`.

#### Scenario: Protocol queries work after split
- **WHEN** the web UI requests protocol or port data
- **THEN** query results SHALL be identical to before the split

### Requirement: Model queries in dedicated module
`model_queries.rs` SHALL contain: `get_endpoint_ips_and_macs`, `get_endpoint_ssdp_models`, `get_endpoint_vendor_classes`, and bytes queries.

#### Scenario: Model and vendor queries work after split
- **WHEN** the web UI requests SSDP models or vendor classes
- **THEN** query results SHALL be identical to before the split

### Requirement: helpers/mod.rs retains shared utilities
`mod.rs` SHALL retain: `DISPLAY_NAME_SQL`, `looks_like_ip`, `probe_hp_printer_model_blocking`, `probe_and_save_hp_printer_model_blocking`, `get_combined_endpoint_stats`, and re-exports from sub-modules.

#### Scenario: Shared utilities accessible after split
- **WHEN** other modules use `DISPLAY_NAME_SQL` or `looks_like_ip`
- **THEN** these items SHALL still be importable from `crate::web::helpers`

### Requirement: No file exceeds 600 lines
Each file in `src/web/helpers/` SHALL be under 600 lines.

#### Scenario: Line count check
- **WHEN** all sub-modules are created
- **THEN** every file in the `helpers/` directory SHALL have fewer than 600 lines
