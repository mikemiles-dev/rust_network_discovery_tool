## ADDED Requirements

### Requirement: COMPONENT_VENDORS constant
A `COMPONENT_VENDORS: &[&str]` constant in `src/web/helpers/types.rs` SHALL replace the inline `component_vendors` arrays in `endpoints/details.rs`, `endpoints/table.rs`, and `export.rs`.

#### Scenario: All three files use the shared constant
- **WHEN** vendor lookup logic in `details.rs`, `table.rs`, or `export.rs` checks against component vendors
- **THEN** it SHALL reference `COMPONENT_VENDORS` from `helpers/types.rs` instead of defining a local array

#### Scenario: Constant contains all vendors
- **WHEN** `COMPONENT_VENDORS` is defined
- **THEN** it SHALL include all vendors present in any of the 3 current arrays: AzureWave, Broadcom, Espressif, Marvell, MediaTek, Murata, Qualcomm, Realtek, Tuya, USI, Wisol

### Requirement: DEFAULT_SCAN_INTERVAL_MINUTES constant
A `DEFAULT_SCAN_INTERVAL_MINUTES: u64 = 525600` constant SHALL replace all hardcoded `525600` values across handlers.

#### Scenario: Table handler uses constant
- **WHEN** `get_endpoints_table` needs the default scan interval
- **THEN** it SHALL use `DEFAULT_SCAN_INTERVAL_MINUTES` instead of the literal `525600`

#### Scenario: Details handler uses constant
- **WHEN** `get_endpoint_details` defaults the `scan_interval` parameter
- **THEN** it SHALL use `DEFAULT_SCAN_INTERVAL_MINUTES`

### Requirement: DEFAULT_ACTIVE_THRESHOLD_SECONDS constant
A `DEFAULT_ACTIVE_THRESHOLD_SECONDS: i64 = 120` constant SHALL replace all hardcoded `120` values for active threshold.

#### Scenario: Table handler uses constant
- **WHEN** `get_endpoints_table` calls `get_setting_i64("active_threshold_seconds", 120)`
- **THEN** the default value SHALL be `DEFAULT_ACTIVE_THRESHOLD_SECONDS`

### Requirement: Named EndpointModelData struct
The `EndpointModelData` type alias (a 6-tuple) in `src/web/helpers/types.rs` SHALL be replaced with a named struct with fields: `custom_model`, `ssdp_model`, `ssdp_friendly_name`, `custom_vendor`, `snmp_vendor`, `snmp_model`.

#### Scenario: Query function returns named struct
- **WHEN** `get_endpoint_ssdp_models` returns model data
- **THEN** it SHALL return `EndpointModelData` as a struct with named fields

#### Scenario: Consumers use named field access
- **WHEN** code destructures `EndpointModelData`
- **THEN** it SHALL use named fields (e.g., `data.custom_model`) instead of positional tuple access (e.g., `data.0`)
