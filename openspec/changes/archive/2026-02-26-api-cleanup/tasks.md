## 1. Add shared types and constants to helpers/types.rs

- [x] 1.1 Add `ApiResponse` struct (`success: bool`, `message: String`) with `Serialize` derive
- [x] 1.2 Add `IpRequest` struct (`ip: String`) with `Deserialize` derive
- [x] 1.3 Add `EndpointNameRequest` struct (`endpoint_name: String`) with `Deserialize` derive
- [x] 1.4 Add `COMPONENT_VENDORS: &[&str]` constant (AzureWave, Broadcom, Espressif, Marvell, MediaTek, Murata, Qualcomm, Realtek, Tuya, USI, Wisol)
- [x] 1.5 Add `DEFAULT_SCAN_INTERVAL_MINUTES: u64 = 525600` constant
- [x] 1.6 Add `DEFAULT_ACTIVE_THRESHOLD_SECONDS: i64 = 120` constant
- [x] 1.7 Replace `EndpointModelData` 6-tuple type alias with named struct (fields: custom_model, ssdp_model, ssdp_friendly_name, custom_vendor, snmp_vendor, snmp_model)
- [x] 1.8 Verify `cargo build` succeeds

## 2. Add endpoint lookup helper to helpers/mod.rs

- [x] 2.1 Add `find_endpoint_ids(conn: &Connection, name: &str) -> Result<Vec<i64>>` function using DISPLAY_NAME_SQL
- [x] 2.2 Add `find_endpoint_id(conn: &Connection, name: &str) -> Result<Option<i64>>` convenience wrapper (returns first match)
- [x] 2.3 Verify `cargo build` succeeds

## 3. Update EndpointModelData consumers

- [x] 3.1 Update `get_endpoint_ssdp_models` in `helpers/model_queries.rs` to return the named struct instead of tuple
- [x] 3.2 Update tuple destructuring in `endpoints/table.rs` (2 sites) to use named field access
- [x] 3.3 Update tuple destructuring in `export.rs` (2 sites) to use named field access
- [x] 3.4 Verify `cargo build` succeeds

## 4. Replace response structs in crud.rs

- [x] 4.1 Remove `ClassifyResponse`, use `ApiResponse` in `set_endpoint_type`
- [x] 4.2 Remove `SetModelResponse`, use `ApiResponse` in `set_endpoint_model`
- [x] 4.3 Remove `SetVendorResponse`, use `ApiResponse` in `set_endpoint_vendor`
- [x] 4.4 Remove `DeleteEndpointResponse`, use `ApiResponse` in `delete_endpoint`
- [x] 4.5 Remove `MergeEndpointsResponse`, use `ApiResponse` in `merge_endpoints`
- [x] 4.6 Replace inline endpoint ID lookup in `delete_endpoint` with `find_endpoint_ids` helper
- [x] 4.7 Replace inline endpoint ID lookups in `merge_endpoints` (target + source) with `find_endpoint_id` helper
- [x] 4.8 Verify `cargo build` succeeds

## 5. Replace response and request structs in probing.rs

- [x] 5.1 Remove `ProbeRequest`, `PingRequest`, `PortScanRequest`, `ProbeModelRequest`; use `IpRequest` for all four handlers
- [x] 5.2 Remove `ProbeEndpointRequest`; use `EndpointNameRequest` for `probe_endpoint`
- [x] 5.3 Verify `cargo build` succeeds

## 6. Replace response structs in scanning.rs and settings.rs

- [x] 6.1 Remove `StartScanResponse`, use `ApiResponse` in `start_scan` and `stop_scan`
- [x] 6.2 Remove `UpdateSettingResponse`, use `ApiResponse` in `update_setting`
- [x] 6.3 Verify `cargo build` succeeds

## 7. Replace hardcoded constants

- [x] 7.1 Replace `525600` in `endpoints/details.rs` with `DEFAULT_SCAN_INTERVAL_MINUTES`
- [x] 7.2 Replace `525600` in `endpoints/table.rs` with `DEFAULT_SCAN_INTERVAL_MINUTES`
- [x] 7.3 Replace `120` in `endpoints/table.rs` with `DEFAULT_ACTIVE_THRESHOLD_SECONDS`
- [x] 7.4 Replace `525600` in `export.rs` with `DEFAULT_SCAN_INTERVAL_MINUTES`
- [x] 7.5 Replace `120` in `export.rs` with `DEFAULT_ACTIVE_THRESHOLD_SECONDS`
- [x] 7.6 Replace `525600` in `endpoints/mod.rs` (2 sites) with `DEFAULT_SCAN_INTERVAL_MINUTES`
- [x] 7.7 Replace inline `component_vendors` array in `endpoints/table.rs` with `COMPONENT_VENDORS`
- [x] 7.8 Replace inline `component_vendors` array in `export.rs` with `COMPONENT_VENDORS`
- [x] 7.9 Verify `cargo build` succeeds

## 8. Fix error handling in devices.rs

- [x] 8.1 Change `.body("...")` error responses to `.json(ApiResponse { ... })` for all 8 InternalServerError sites in devices.rs
- [x] 8.2 Add `eprintln!` logging before each error response in devices.rs
- [x] 8.3 Verify `cargo build` succeeds

## 9. Final validation

- [x] 9.1 Run `cargo test` — all tests pass
- [x] 9.2 Verify no new compiler warnings introduced
- [x] 9.3 Verify no JSON field names changed (grep for `"success"` and `"message"` in response types)
