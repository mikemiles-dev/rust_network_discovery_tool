## ADDED Requirements

### Requirement: Graph building extracted to sibling module
`src/web/graph.rs` SHALL be created containing: `Node`, `CommunicationRow`, `get_nodes`, `get_endpoints`, `get_endpoint_types`, and `get_ports_from_communications`.

#### Scenario: Module compiles after extraction
- **WHEN** `graph.rs` exists alongside `mod.rs`
- **THEN** `cargo build` SHALL succeed with no new errors

### Requirement: Index handler extracted to sibling module
`src/web/index.rs` SHALL be created containing the `index` handler and its context-building logic.

#### Scenario: Index page renders after extraction
- **WHEN** a client requests the index page
- **THEN** the rendered HTML SHALL be identical to before the split

### Requirement: web/mod.rs retains server setup
`mod.rs` SHALL retain: `start`, `static_files`, `detect_existing_instance`, `get_interfaces`, template loading, and re-exports from `graph`, `index`, `helpers`, and `api`.

#### Scenario: Server startup works after split
- **WHEN** the application starts and binds to a port
- **THEN** all routes SHALL be registered and functional

### Requirement: No file exceeds 600 lines
Each file in `src/web/` (excluding sub-directories) SHALL be under 600 lines.

#### Scenario: Line count check
- **WHEN** the split is complete
- **THEN** `mod.rs`, `graph.rs`, and `index.rs` SHALL each have fewer than 600 lines
