## 1. Database module split

- [x] 1.1 Create `src/db/schema.rs` — move `create_tables` and all DDL/migration logic from `db/mod.rs`
- [x] 1.2 Create `src/db/writer.rs` — move `SQLWriter` struct, its `mpsc` channel setup, and batch processing logic from `db/mod.rs`
- [x] 1.3 Create `src/db/endpoints.rs` — move `insert_endpoint`, `update_endpoint`, endpoint attribute CRUD, and `insert_notification`/`insert_notification_with_endpoint_id` from `db/mod.rs`
- [x] 1.4 Create `src/db/settings.rs` — move `get_setting`, `get_setting_i64`, `set_setting`, `get_all_settings` from `db/mod.rs`
- [x] 1.5 Create `src/db/maintenance.rs` — move `cleanup_stale_wal_files`, `WAL_CLEANUP_DONE`, and orphan cleanup from `db/mod.rs`
- [x] 1.6 Update `src/db/mod.rs` to retain only `new_connection`, `new_connection_result`, and `pub use` re-exports from sub-modules
- [x] 1.7 Verify `cargo build` succeeds and `cargo test` passes after db split

## 2. Web helpers extraction

- [x] 2.1 Create `src/web/helpers.rs` — move `DISPLAY_NAME_SQL`, `EndpointStats`, `EndpointDetailsResponse`, `NodeQuery`, and all shared query functions (`get_combined_endpoint_stats`, `get_dns_entries`, `dropdown_endpoints`, `get_all_endpoint_types`, `get_all_endpoints_last_seen`, `get_all_endpoints_online_status`, `get_all_ips_macs_and_hostnames_from_single_hostname`, `get_all_protocols`, `get_bytes_for_endpoint`, `get_endpoint_ips_and_macs`, `get_endpoint_ssdp_models`, `get_endpoints_for_protocol`, `get_ports_for_endpoint`, `get_protocols_for_endpoint`, `looks_like_ip`, `probe_and_save_hp_printer_model_blocking`, `probe_hp_printer_model_blocking`) from `web/mod.rs`
- [x] 2.2 Update `src/web/mod.rs` to declare `mod helpers` and retain only Actix server setup, route registration, HTML template rendering, and the `try_db!` macro
- [x] 2.3 Verify `cargo build` succeeds and `cargo test` passes after helpers extraction

## 3. Web API split

- [x] 3.1 Create `src/web/api/` directory and `src/web/api/mod.rs` with re-exports for all handler functions
- [x] 3.2 Create `src/web/api/endpoints.rs` — move endpoint table, details, merge, classification, and reclassification handlers from `web/api.rs`
- [x] 3.3 Create `src/web/api/devices.rs` — move device control handlers (LG, Samsung, Roku) and HP printer probe handlers from `web/api.rs`
- [x] 3.4 Create `src/web/api/scanning.rs` — move scan start/stop/status and PCAP import handlers from `web/api.rs`
- [x] 3.5 Create `src/web/api/settings.rs` — move get/set settings and notification handlers from `web/api.rs`
- [x] 3.6 Create `src/web/api/dns.rs` — move DNS entries CRUD handlers from `web/api.rs`
- [x] 3.7 Create `src/web/api/export.rs` — move Excel export, file upload, and import handlers from `web/api.rs`
- [x] 3.8 Move global state (`PROBING_ENDPOINTS`, `ENDPOINT_TABLE_CACHE`) to the appropriate domain module that uses them
- [x] 3.9 Delete the old `src/web/api.rs` file
- [x] 3.10 Update `src/web/mod.rs` to declare `mod api` pointing to the directory
- [x] 3.11 Verify `cargo build` succeeds and `cargo test` passes after web API split

## 4. Endpoint classification consolidation

- [x] 4.1 Create `src/network/endpoint/classify.rs` — merge logic from `classification.rs` and `detection.rs` into a unified module
- [x] 4.2 Update `gateway.rs` to be an internal helper called only from `classify.rs` (remove any direct external callers)
- [x] 4.3 Update `endpoint_ops.rs` to call `classify.rs` instead of `classification.rs`/`detection.rs` directly
- [x] 4.4 Delete `src/network/endpoint/classification.rs` and `src/network/endpoint/detection.rs`
- [x] 4.5 Update `src/network/endpoint/mod.rs` to declare `mod classify` instead of `mod classification` and `mod detection`
- [x] 4.6 Verify `cargo build` succeeds and `cargo test` passes after classification consolidation

## 5. EndPoint impl block consolidation

- [x] 5.1 Move `impl EndPoint` methods from `gateway.rs` into `endpoint_ops.rs` (classification/inference logic)
- [x] 5.2 Move `impl EndPoint` methods from `model.rs` into `endpoint_ops.rs` (model inference delegation) — N/A: model.rs had no impl EndPoint
- [x] 5.3 Verify that `impl EndPoint` blocks exist only in `endpoint_ops.rs` and `db.rs`
- [x] 5.4 Verify `cargo build` succeeds and `cargo test` passes after impl consolidation

## 6. Model data extraction

- [x] 6.1 Create `src/network/endpoint/model_data.rs` — move all vendor-specific const data (Samsung TV series maps, LG OLED/NanoCell maps, Sony model prefixes, Roku serial patterns) from `model.rs`
- [x] 6.2 Update `model.rs` to import data constants from `model_data.rs` instead of defining them inline
- [x] 6.3 Update `src/network/endpoint/mod.rs` to declare `mod model_data`
- [x] 6.4 Verify `cargo build` succeeds and `cargo test` passes after model data extraction

## 7. Relocate device_control to top-level

- [x] 7.1 Move `src/network/device_control/` to `src/device_control/`
- [x] 7.2 Add `mod device_control;` to `src/main.rs`
- [x] 7.3 Remove `device_control` from `src/network/mod.rs`
- [x] 7.4 Update all `use crate::network::device_control::` paths to `use crate::device_control::` across the codebase
- [x] 7.5 Verify `cargo build` succeeds and `cargo test` passes after relocation

## 8. Final validation

- [x] 8.1 Run full `cargo test` and confirm all tests pass
- [x] 8.2 Verify no non-generated source file exceeds 600 lines (exclude `mac_vendor_data.rs`, `device_rules_data.rs`, `model_data.rs`)
- [x] 8.3 Verify `impl EndPoint` exists only in `endpoint_ops.rs` and `db.rs`
- [x] 8.4 Verify `classification.rs` and `detection.rs` no longer exist
- [x] 8.5 Verify `src/network/device_control/` no longer exists
