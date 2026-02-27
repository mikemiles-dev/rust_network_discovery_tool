## ADDED Requirements

### Requirement: Top-level module hierarchy
The `src/` directory SHALL contain exactly these top-level modules: `web/`, `db/`, `network/`, `scanner/`, `device_control/`, plus `main.rs`, `pcap.rs`, and `test_utils.rs`. Each top-level module represents a distinct application concern.

#### Scenario: device_control is a top-level module
- **WHEN** inspecting the `src/` directory
- **THEN** `device_control/` SHALL exist as a direct child of `src/`, not under `network/`

#### Scenario: all crate-level use paths reference top-level modules
- **WHEN** any file uses `crate::device_control`
- **THEN** it SHALL resolve to `src/device_control/`, not `src/network/device_control/`

### Requirement: Web module structure
The `src/web/` module SHALL contain a `mod.rs` for server setup and route registration, a `helpers.rs` for shared database query helpers and types, and an `api/` sub-directory with domain-specific handler modules.

#### Scenario: web/api is a directory with domain modules
- **WHEN** inspecting `src/web/api/`
- **THEN** it SHALL contain separate files for endpoint handlers, device handlers, scanning handlers, settings handlers, DNS handlers, and export handlers

#### Scenario: web/mod.rs contains only server wiring
- **WHEN** inspecting `src/web/mod.rs`
- **THEN** it SHALL contain Actix server setup, route registration, and HTML template rendering
- **THEN** it SHALL NOT contain database query helper functions or SQL constants

#### Scenario: shared helpers are in web/helpers.rs
- **WHEN** any API handler module needs a shared query function or type (e.g., `DISPLAY_NAME_SQL`, `EndpointStats`)
- **THEN** it SHALL import from `web::helpers`, not from `web::mod`

### Requirement: Database module structure
The `src/db/` module SHALL be split into focused sub-modules: `mod.rs` for connection management and re-exports, `schema.rs` for table creation and migrations, `writer.rs` for the `SQLWriter` batch channel, `endpoints.rs` for endpoint/attribute CRUD, `settings.rs` for settings CRUD, and `maintenance.rs` for WAL/SHM cleanup.

#### Scenario: db/mod.rs contains only connection management
- **WHEN** inspecting `src/db/mod.rs`
- **THEN** it SHALL contain `new_connection`, `new_connection_result`, and public re-exports
- **THEN** it SHALL NOT contain table creation DDL, settings logic, or WAL cleanup logic

#### Scenario: SQLWriter is isolated in writer.rs
- **WHEN** inspecting `src/db/writer.rs`
- **THEN** the `SQLWriter` struct and its `mpsc` channel logic SHALL be self-contained in this file

### Requirement: Endpoint classification consolidation
The endpoint classification system SHALL be unified into `classify.rs` as the single entry point for all classification logic (port-based, MAC-based, hostname-based, service-based). Gateway-specific detection SHALL remain in `gateway.rs` as an internal helper called by `classify.rs`.

#### Scenario: classify.rs is the single classification entry point
- **WHEN** `endpoint_ops.rs` needs to classify an endpoint
- **THEN** it SHALL call into `classify.rs`, not directly into `detection.rs` or `classification.rs`

#### Scenario: classification.rs and detection.rs no longer exist as separate files
- **WHEN** inspecting `src/network/endpoint/`
- **THEN** there SHALL be no `classification.rs` or `detection.rs` files — their logic lives in `classify.rs`

#### Scenario: gateway.rs is an internal helper
- **WHEN** `classify.rs` needs gateway/router detection
- **THEN** it SHALL delegate to `gateway.rs` internally
- **THEN** `gateway.rs` SHALL NOT be called directly from outside the classification subsystem

### Requirement: EndPoint impl block consolidation
All `impl EndPoint` blocks SHALL exist in at most two files: `endpoint_ops.rs` for core logic (DNS, classification orchestration, insert/update orchestration) and `db.rs` for database persistence methods.

#### Scenario: no impl EndPoint in gateway.rs or model.rs
- **WHEN** inspecting `src/network/endpoint/gateway.rs` and `src/network/endpoint/model.rs`
- **THEN** neither file SHALL contain `impl EndPoint` blocks — those methods SHALL have been moved to `endpoint_ops.rs`

#### Scenario: endpoint_ops.rs contains core logic methods
- **WHEN** inspecting `src/network/endpoint/endpoint_ops.rs`
- **THEN** it SHALL contain all non-persistence `impl EndPoint` methods (DNS resolution, classification dispatch, model inference delegation)

### Requirement: Model data extraction
Vendor-specific model series data (Samsung TV series maps, LG OLED/NanoCell maps, Sony model prefixes, Roku serial patterns) SHALL be extracted into `model_data.rs`. The `model.rs` file SHALL contain only normalization and inference logic, importing data constants from `model_data.rs`.

#### Scenario: model.rs imports data from model_data.rs
- **WHEN** `model.rs` needs a vendor-specific series map or pattern table
- **THEN** it SHALL import it from `model_data.rs`
- **THEN** `model.rs` SHALL NOT define inline vendor series data

#### Scenario: model_data.rs contains only data constants
- **WHEN** inspecting `model_data.rs`
- **THEN** it SHALL contain only `const` or `static` data definitions (arrays, maps, pattern tables)
- **THEN** it SHALL NOT contain function logic beyond what is needed for `const` initialization

### Requirement: File size guideline
Every non-auto-generated source file SHALL be under 600 lines. Auto-generated files (`mac_vendor_data.rs`, `device_rules_data.rs`) and pure data files (`model_data.rs`) are exempt from this limit.

#### Scenario: large files are split
- **WHEN** a refactored file exceeds 600 lines
- **THEN** it SHALL be further split into smaller focused modules

#### Scenario: auto-generated files are exempt
- **WHEN** measuring file sizes
- **THEN** `mac_vendor_data.rs` and `device_rules_data.rs` SHALL NOT be subject to the 600-line limit

### Requirement: Behavioral preservation
The refactor SHALL produce zero behavioral changes. All existing tests SHALL pass with at most `use` path updates. The web API routes, binary CLI interface, and database schema SHALL remain identical.

#### Scenario: all tests pass after refactor
- **WHEN** running `cargo test` after the refactor is complete
- **THEN** all existing tests SHALL pass (test logic unchanged, only `use` paths may differ)

#### Scenario: web API routes unchanged
- **WHEN** comparing HTTP routes before and after the refactor
- **THEN** every route path, method, request format, and response format SHALL be identical
