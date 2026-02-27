## Context

The `refactor-module-structure` change reorganized the codebase from monolithic files into logical modules. That work established the module hierarchy but left 10 files over 600 lines. This change completes the effort by splitting those files along natural boundaries identified through code analysis.

Current file sizes (non-generated, over 600 lines):

| File | Lines | Primary content |
|------|-------|----------------|
| `web/api/endpoints.rs` | 1834 | API handlers for endpoint CRUD, probing, details, table |
| `network/endpoint/endpoint_ops.rs` | 1378 | EndPoint impl: classification, CRUD, merging, hostname |
| `web/helpers.rs` | 1335 | DB query helpers for web handlers |
| `web/mod.rs` | 1133 | Actix setup, graph building, index handler |
| `network/endpoint/model.rs` | 1054 | Model name normalization, hostname-based detection |
| `web/api/scanning.rs` | 860 | Scan handlers, result processing, SNMP/SSDP logic |
| `db/maintenance.rs` | 780 | WAL cleanup, data dedup, endpoint merging |
| `device_control/lg.rs` | 687 | LG TV WebSocket pairing, commands, info |
| `network/endpoint/classify.rs` | 657 | Device type detection by MAC, hostname, ports |
| `main.rs` | 631 | CLI args, interface selection, packet capture |

## Goals / Non-Goals

**Goals:**
- Every non-generated source file under 600 lines
- Each new module has a single clear responsibility
- All 72 tests pass after each split phase
- No behavior changes — pure code movement
- Preserve existing `pub use` re-export patterns so external callers don't break

**Non-Goals:**
- Refactoring logic within functions (only moving functions between files)
- Adding new tests beyond what exists
- Changing any public API signatures
- Splitting `main.rs` (631 lines, mostly CLI boilerplate that doesn't split cleanly)

## Decisions

### 1. Split order: largest files first, web layer before core

Split in descending size order so the biggest wins come first. Web layer files (`web/api/endpoints.rs`, `web/helpers.rs`, `web/mod.rs`) split before core (`endpoint_ops.rs`, `model.rs`) because web modules have more natural handler-boundary split points.

**Alternative considered**: Split by module depth (core first). Rejected because web files are larger and their handler groupings make splits more obvious.

### 2. Sub-module pattern: sibling files with `mod` + re-exports

For files that are part of an existing directory module (e.g., `web/api/endpoints.rs`), create sibling files in the same directory and add `mod` + `pub use` in the parent. For standalone files (e.g., `web/helpers.rs`), convert to a directory module when needed.

Example for `web/api/endpoints.rs` → keep `endpoints.rs` as a thin re-export hub or convert to `endpoints/mod.rs` with sub-files.

**Decision**: Use sibling files where possible to avoid directory nesting. Only create a directory module if a file needs 4+ sub-modules.

**Alternative considered**: Always create directory modules. Rejected because it adds unnecessary nesting for 2-3 file splits.

### 3. Handling `web/api/endpoints.rs` (1834 lines)

Convert to `web/api/endpoints/mod.rs` with sub-modules:
- `probing.rs` — `probe_hostname`, `probe_netbios`, `ping_endpoint`, `port_scan_endpoint`, `probe_endpoint`, `probe_endpoint_model`
- `details.rs` — `get_endpoint_details`, `get_endpoint_details_blocking`
- `crud.rs` — `set_endpoint_type`, `rename_endpoint`, `set_endpoint_model`, `set_endpoint_vendor`, `delete_endpoint`, `merge_endpoints`
- `table.rs` — `EndpointTableCache`, `get_endpoints_table`, cache logic

`mod.rs` retains protocol handlers (`get_protocol_endpoints`, `get_all_protocols_api`) and re-exports.

### 4. Handling `endpoint_ops.rs` (1378 lines)

Create sibling files in `network/endpoint/`:
- `endpoint_crud.rs` — `get_or_insert_endpoint*`, hostname lookup, IPv6 sibling creation
- `endpoint_merge.rs` — `merge_ipv6_siblings_into_endpoint`, `try_merge_by_hostname`
- `hostname.rs` — `lookup_dns`, `lookup_hostname`, `get_http_host`, `find_sni`

`endpoint_ops.rs` retains: `classify_device_type`, `check_and_update_endpoint_name`, `is_on_local_network`, MAC/IP validation, `is_local`, and gateway classification (which was already consolidated here). Tests stay with their tested functions.

### 5. Handling `web/helpers.rs` (1335 lines)

Convert to `web/helpers/mod.rs` with sub-modules:
- `types.rs` — `EndpointStats`, `EndpointDetailsResponse`, `NodeQuery`, tuple types
- `endpoint_queries.rs` — `dropdown_endpoints`, `get_all_endpoint_types`, `get_all_endpoints_last_seen`, `get_all_endpoints_online_status`, `resolve_identifier_*`
- `protocol_queries.rs` — `get_protocols_for_endpoint`, `get_endpoints_for_protocol`, `get_all_protocols`, `get_ports_for_endpoint`
- `model_queries.rs` — `get_endpoint_ips_and_macs`, `get_endpoint_ssdp_models`, `get_endpoint_vendor_classes`, bytes queries

`mod.rs` retains: `DISPLAY_NAME_SQL`, `looks_like_ip`, `probe_hp_printer_model_blocking`, `get_combined_endpoint_stats`, and re-exports.

### 6. Handling `web/mod.rs` (1133 lines)

Create sibling files in `web/`:
- `graph.rs` — `Node`, `CommunicationRow`, `get_nodes`, `get_endpoints`, `get_endpoint_types`, `get_ports_from_communications`
- `index.rs` — The `index` handler and its context-building logic

`mod.rs` retains: `start`, `static_files`, `detect_existing_instance`, `get_interfaces`, template loading, and re-exports.

### 7. Handling `model.rs` (1054 lines)

Create sibling file in `network/endpoint/`:
- `hostname_model.rs` — `get_model_from_hostname` (the 640-line function) and brand-specific helpers

`model.rs` retains: `normalize_model_name`, `characterize_model`, `infer_model_with_context`, `get_model_from_mac`, `get_model_from_vendor_and_type`, and tests.

### 8. Handling `scanning.rs` (860 lines)

Create sibling files in `web/api/`:
- `scan_results.rs` — `process_scan_result`, `process_scan_result_inner`, `try_set_endpoint_name_from_discovery`, `find_existing_endpoint_by_ip`, `insert_scan_result`, `insert_open_port`
- `scan_models.rs` — `parse_snmp_sys_descr`, `is_ssdp_model_consistent_with_endpoint`, `is_more_specific_model`

`scanning.rs` retains: `SCAN_MANAGER`, scan control handlers (`start_scan`, `stop_scan`, `get_scan_status`, `get_scan_capabilities`, `get_scan_config`, `set_scan_config`).

### 9. Handling `maintenance.rs` (780 lines)

Create sibling files in `db/`:
- `merge_maintenance.rs` — `merge_duplicate_communications`, `merge_duplicate_endpoints_by_hostname`, `merge_endpoints_by_ipv6_prefix`, `preserve_user_fields`
- `hotspot_merge.rs` — `is_hotspot_gateway_candidate`, `find_phone_for_hotspot_gateway`, `merge_hotspot_gateways_into_phones`

`maintenance.rs` retains: `cleanup_stale_wal_files`, `WAL_CLEANUP_DONE`, `cleanup_old_data` orchestrator.

### 10. Handling `lg.rs` (687 lines)

Create sibling files in `device_control/`:
- `lg_commands.rs` — `get_commands`, `get_capabilities`, command constants
- `lg_pairing.rs` — `get_client_key`, `store_client_key`, `build_handshake`, `pair`

`lg.rs` retains: `is_lg_tv`, `send_command`, `get_device_info`, `get_apps`, `launch_app`.

### 11. Handling `classify.rs` (657 lines)

Create sibling files in `network/endpoint/`:
- `classify_hostname.rs` — All `is_*_hostname` functions and hostname pattern matching
- `classify_services.rs` — `classify_by_services`, `is_computer_by_ports`, port/mDNS-based detection

`classify.rs` retains: pattern helpers, `is_*_mac` functions, model/serial detection, phone detection, `is_lg_appliance`.

### 12. `main.rs` (631 lines) — no split

At 631 lines it barely exceeds the threshold and consists of CLI argument parsing, interface filtering, and the capture loop — all tightly coupled. Splitting would create artificial boundaries. Accept as-is.

## Risks / Trade-offs

- **Risk: Circular dependencies between split modules** → Mitigation: Each split moves complete function groups. Shared types/constants stay in the parent module or a `types.rs` sub-module.
- **Risk: Breaking `pub use` re-exports** → Mitigation: After each split, the parent module re-exports everything that was previously public. Callers don't need to change import paths.
- **Risk: Test breakage from moved functions** → Mitigation: Tests move with their functions. Run `cargo test` after each file split. If tests reference items that moved, update the `use` imports in the test module.
- **Trade-off: More files to navigate** → Accepted. Smaller, focused files with clear names are easier to find than scrolling through 1800-line files.
- **Trade-off: `main.rs` stays at 631 lines** → Accepted. Forcing a split would create artificial modules with no clear responsibility boundary.
