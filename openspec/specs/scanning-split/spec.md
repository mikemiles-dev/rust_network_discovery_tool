## ADDED Requirements

### Requirement: Scan result processing extracted to sibling module
`src/web/api/scan_results.rs` SHALL be created containing: `process_scan_result`, `process_scan_result_inner`, `try_set_endpoint_name_from_discovery`, `find_existing_endpoint_by_ip`, `insert_scan_result`, and `insert_open_port`.

#### Scenario: Module compiles after extraction
- **WHEN** `scan_results.rs` exists alongside `scanning.rs`
- **THEN** `cargo build` SHALL succeed with no new errors

### Requirement: SNMP/SSDP model logic extracted to sibling module
`src/web/api/scan_models.rs` SHALL be created containing: `parse_snmp_sys_descr`, `is_ssdp_model_consistent_with_endpoint`, and `is_more_specific_model`.

#### Scenario: SNMP parsing works after split
- **WHEN** the system receives an SNMP sysDescr string
- **THEN** `parse_snmp_sys_descr` SHALL extract the same vendor/model as before the split

### Requirement: scanning.rs retains scan control handlers
`scanning.rs` SHALL retain: `SCAN_MANAGER`, `start_scan`, `stop_scan`, `get_scan_status`, `get_scan_capabilities`, `get_scan_config`, and `set_scan_config`.

#### Scenario: Scan control API works after split
- **WHEN** a client starts, stops, or queries scan status
- **THEN** behavior SHALL be identical to before the split

### Requirement: Scan result processing preserved
All scan result types (ARP, ICMP, Port, SSDP, NDP, NetBIOS, SNMP) SHALL be processed identically after the split.

#### Scenario: ARP scan result processing
- **WHEN** an ARP scan result is received
- **THEN** endpoint creation and update behavior SHALL be identical to before the split

#### Scenario: SSDP model consistency check
- **WHEN** an SSDP model is received for an existing endpoint
- **THEN** `is_ssdp_model_consistent_with_endpoint` SHALL produce the same consistency verdict as before the split

### Requirement: No file exceeds 600 lines
Each resulting file SHALL be under 600 lines.

#### Scenario: Line count check
- **WHEN** the split is complete
- **THEN** `scanning.rs`, `scan_results.rs`, and `scan_models.rs` SHALL each have fewer than 600 lines
