## ADDED Requirements

### Requirement: LG pairing flow extracted to sibling module
`src/device_control/lg_pairing.rs` SHALL be created containing: `get_client_key`, `store_client_key`, `build_handshake`, and `pair`.

#### Scenario: Module compiles after extraction
- **WHEN** `lg_pairing.rs` exists alongside `lg.rs`
- **THEN** `cargo build` SHALL succeed with no new errors

### Requirement: LG command library extracted to sibling module
`src/device_control/lg_commands.rs` SHALL be created containing: `get_commands` and `get_capabilities` with all command constants.

#### Scenario: Command listing works after split
- **WHEN** `get_commands` is called
- **THEN** the returned command list SHALL be identical to before the split

### Requirement: lg.rs retains core operations
`lg.rs` SHALL retain: `is_lg_tv`, `send_command`, `get_device_info`, `get_apps`, and `launch_app`.

#### Scenario: LG TV detection works after split
- **WHEN** the system checks if an endpoint is an LG TV
- **THEN** `is_lg_tv` SHALL return the same result as before the split

#### Scenario: Command execution works after split
- **WHEN** a user sends a command to an LG TV
- **THEN** `send_command` SHALL behave identically to before the split

### Requirement: No file exceeds 600 lines
Each resulting file SHALL be under 600 lines.

#### Scenario: Line count check
- **WHEN** the split is complete
- **THEN** `lg.rs`, `lg_pairing.rs`, and `lg_commands.rs` SHALL each have fewer than 600 lines
