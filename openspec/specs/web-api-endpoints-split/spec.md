## ADDED Requirements

### Requirement: Endpoints API directory module structure
The `src/web/api/endpoints.rs` file SHALL be converted to a directory module `src/web/api/endpoints/mod.rs` with sub-modules: `probing.rs`, `details.rs`, `crud.rs`, and `table.rs`.

#### Scenario: Module compiles after split
- **WHEN** `src/web/api/endpoints/` directory exists with `mod.rs`, `probing.rs`, `details.rs`, `crud.rs`, and `table.rs`
- **THEN** `cargo build` SHALL succeed with no new errors

### Requirement: Probing handlers in dedicated module
`probing.rs` SHALL contain: `probe_hostname`, `probe_netbios`, `ping_endpoint`, `port_scan_endpoint`, `probe_endpoint`, and `probe_endpoint_model`.

#### Scenario: Probing endpoints accessible after split
- **WHEN** a client calls any probing API endpoint (e.g., `/api/probe_hostname`)
- **THEN** the response SHALL be identical to before the split

### Requirement: Details handler in dedicated module
`details.rs` SHALL contain: `get_endpoint_details` and `get_endpoint_details_blocking`.

#### Scenario: Details endpoint accessible after split
- **WHEN** a client calls the endpoint details API
- **THEN** the response SHALL be identical to before the split

### Requirement: CRUD handlers in dedicated module
`crud.rs` SHALL contain: `set_endpoint_type`, `rename_endpoint`, `set_endpoint_model`, `set_endpoint_vendor`, `delete_endpoint`, and `merge_endpoints`.

#### Scenario: CRUD endpoints accessible after split
- **WHEN** a client calls any endpoint management API (rename, delete, merge, etc.)
- **THEN** the response SHALL be identical to before the split

### Requirement: Table cache in dedicated module
`table.rs` SHALL contain: `EndpointTableCache`, `get_endpoints_table`, and associated cache logic.

#### Scenario: Cached table endpoint accessible after split
- **WHEN** a client calls the endpoints table API
- **THEN** the response SHALL be identical to before the split, including cache behavior

### Requirement: Re-exports preserve external API
`endpoints/mod.rs` SHALL re-export all public items so that existing `use crate::web::api::endpoints::*` paths continue to work. Protocol handlers (`get_protocol_endpoints`, `get_all_protocols_api`) SHALL remain in `mod.rs`.

#### Scenario: No import path changes needed outside endpoints module
- **WHEN** other modules import from `crate::web::api::endpoints`
- **THEN** all previously available items SHALL still be importable without path changes

### Requirement: No file exceeds 600 lines
Each file in `src/web/api/endpoints/` SHALL be under 600 lines.

#### Scenario: Line count check
- **WHEN** all sub-modules are created
- **THEN** every file in the `endpoints/` directory SHALL have fewer than 600 lines
