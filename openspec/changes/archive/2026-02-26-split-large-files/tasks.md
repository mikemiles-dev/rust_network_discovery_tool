## 1. Split web/api/endpoints.rs (1834 lines)

- [x] 1.1 Create `src/web/api/endpoints/` directory and move `endpoints.rs` to `endpoints/mod.rs`
- [x] 1.2 Create `src/web/api/endpoints/probing.rs` — move `probe_hostname`, `probe_netbios`, `ping_endpoint`, `port_scan_endpoint`, `probe_endpoint`, `probe_endpoint_model` from mod.rs
- [x] 1.3 Create `src/web/api/endpoints/details.rs` — move `get_endpoint_details`, `get_endpoint_details_blocking` from mod.rs
- [x] 1.4 Create `src/web/api/endpoints/crud.rs` — move `set_endpoint_type`, `rename_endpoint`, `set_endpoint_model`, `set_endpoint_vendor`, `delete_endpoint`, `merge_endpoints` from mod.rs
- [x] 1.5 Create `src/web/api/endpoints/table.rs` — move `EndpointTableCache`, `get_endpoints_table`, and cache logic from mod.rs
- [x] 1.6 Update `endpoints/mod.rs` to declare sub-modules and re-export all public items; retain protocol handlers
- [x] 1.7 Verify `cargo build` succeeds and `cargo test` passes; confirm all files under 600 lines

## 2. Split web/helpers.rs (1335 lines)

- [x] 2.1 Create `src/web/helpers/` directory and move `helpers.rs` to `helpers/mod.rs`
- [x] 2.2 Create `src/web/helpers/types.rs` — move `EndpointStats`, `EndpointDetailsResponse`, `NodeQuery`, and tuple type definitions from mod.rs
- [x] 2.3 Create `src/web/helpers/endpoint_queries.rs` — move `dropdown_endpoints`, `get_all_endpoint_types`, `get_all_endpoints_last_seen`, `get_all_endpoints_online_status`, `resolve_identifier_to_endpoint_ids`, `resolve_identifier_to_display_name` from mod.rs
- [x] 2.4 Create `src/web/helpers/protocol_queries.rs` — move `get_protocols_for_endpoint`, `get_endpoints_for_protocol`, `get_all_protocols`, `get_ports_for_endpoint` from mod.rs
- [x] 2.5 Create `src/web/helpers/model_queries.rs` — move `get_endpoint_ips_and_macs`, `get_endpoint_ssdp_models`, `get_endpoint_vendor_classes`, and bytes queries from mod.rs
- [x] 2.6 Update `helpers/mod.rs` to declare sub-modules and re-export; retain `DISPLAY_NAME_SQL`, `looks_like_ip`, HP printer probing, `get_combined_endpoint_stats`
- [x] 2.7 Verify `cargo build` succeeds and `cargo test` passes; confirm all files under 600 lines

## 3. Split web/mod.rs (1133 lines)

- [x] 3.1 Create `src/web/graph.rs` — move `Node`, `CommunicationRow`, `get_nodes`, `get_endpoints`, `get_endpoint_types`, `get_ports_from_communications` from mod.rs
- [x] 3.2 Create `src/web/index.rs` — move the `index` handler and its context-building logic from mod.rs
- [x] 3.3 Update `web/mod.rs` to declare `mod graph` and `mod index`, add re-exports; retain `start`, `static_files`, `detect_existing_instance`, `get_interfaces`, template loading
- [x] 3.4 Verify `cargo build` succeeds and `cargo test` passes; confirm all files under 600 lines

## 4. Split network/endpoint/endpoint_ops.rs (1378 lines)

- [x] 4.1 Create `src/network/endpoint/endpoint_crud.rs` — move `get_or_insert_endpoint` variants, hostname lookup, and IPv6 sibling creation from endpoint_ops.rs
- [x] 4.2 Create `src/network/endpoint/endpoint_merge.rs` — move `merge_ipv6_siblings_into_endpoint`, `try_merge_by_hostname` from endpoint_ops.rs
- [x] 4.3 Create `src/network/endpoint/hostname.rs` — move `lookup_dns`, `lookup_hostname`, `get_http_host`, `find_sni` from endpoint_ops.rs
- [x] 4.4 Update `src/network/endpoint/mod.rs` to declare new sub-modules and add re-exports
- [x] 4.5 Move tests to the module containing their tested function
- [x] 4.6 Verify `cargo build` succeeds and `cargo test` passes; endpoint_ops.rs at 631 lines (gateway platform code, accepted like main.rs)

## 5. Split network/endpoint/model.rs (1054 lines)

- [x] 5.1 Create `src/network/endpoint/hostname_model.rs` — move `get_model_from_hostname` and brand-specific helpers from model.rs
- [x] 5.2 Update `model.rs` to import `get_model_from_hostname` from `hostname_model`; retain `normalize_model_name`, `characterize_model`, `infer_model_with_context`, `get_model_from_mac`, `get_model_from_vendor_and_type`, and tests
- [x] 5.3 Update `src/network/endpoint/mod.rs` to declare `mod hostname_model`
- [x] 5.4 Verify `cargo build` succeeds and `cargo test` passes; hostname_model.rs at 648 (single large function, accepted)

## 6. Split web/api/scanning.rs (860 lines)

- [x] 6.1 Create `src/web/api/scan_results.rs` — move `process_scan_result`, `process_scan_result_inner`, `try_set_endpoint_name_from_discovery`, `find_existing_endpoint_by_ip`, `insert_scan_result`, `insert_open_port` from scanning.rs
- [x] 6.2 Create `src/web/api/scan_models.rs` — move `parse_snmp_sys_descr`, `is_ssdp_model_consistent_with_endpoint`, `is_more_specific_model` from scanning.rs
- [x] 6.3 Update `scanning.rs` to import from new modules; retain `SCAN_MANAGER` and scan control handlers
- [x] 6.4 Update `src/web/api/mod.rs` to declare `mod scan_results` and `mod scan_models`
- [x] 6.5 Verify `cargo build` succeeds and `cargo test` passes; confirm all files under 600 lines

## 7. Split db/maintenance.rs (780 lines)

- [x] 7.1 Create `src/db/merge_maintenance.rs` — move `merge_duplicate_communications`, `merge_duplicate_endpoints_by_hostname`, `merge_endpoints_by_ipv6_prefix`, `preserve_user_fields` from maintenance.rs
- [x] 7.2 Create `src/db/hotspot_merge.rs` — move `is_hotspot_gateway_candidate`, `find_phone_for_hotspot_gateway`, `merge_hotspot_gateways_into_phones` from maintenance.rs
- [x] 7.3 Update `maintenance.rs` to import from new modules; retain `cleanup_stale_wal_files`, `WAL_CLEANUP_DONE`, `cleanup_old_data`
- [x] 7.4 Update `src/db/mod.rs` to declare `mod merge_maintenance` and `mod hotspot_merge`
- [x] 7.5 Verify `cargo build` succeeds and `cargo test` passes; confirm all files under 600 lines

## 8. Split device_control/lg.rs (687 lines)

- [x] 8.1 Create `src/device_control/lg_commands.rs` — move `get_commands`, `get_capabilities`, and command constants from lg.rs
- [x] 8.2 Create `src/device_control/lg_pairing.rs` — move `get_client_key`, `store_client_key`, `build_handshake`, `pair` from lg.rs
- [x] 8.3 Update `lg.rs` to import from new modules; retain `is_lg_tv`, `send_command`, `get_device_info`, `get_apps`, `launch_app`
- [x] 8.4 Update `src/device_control/mod.rs` to declare `mod lg_commands` and `mod lg_pairing`
- [x] 8.5 Verify `cargo build` succeeds and `cargo test` passes; confirm all files under 600 lines

## 9. Split network/endpoint/classify.rs (657 lines)

- [x] 9.1 Create `src/network/endpoint/classify_hostname.rs` — move all `is_*_hostname` functions and hostname pattern matching from classify.rs
- [x] 9.2 Create `src/network/endpoint/classify_services.rs` — move `classify_by_services`, `is_computer_by_ports` from classify.rs
- [x] 9.3 Update `classify.rs` to import from new modules; retain pattern helpers, `is_*_mac` functions, model/serial detection, phone detection, `is_lg_appliance`
- [x] 9.4 Update `src/network/endpoint/mod.rs` to declare `mod classify_hostname` and `mod classify_services`
- [x] 9.5 Move classification tests to the module containing their tested function
- [x] 9.6 Verify `cargo build` succeeds and `cargo test` passes; confirm all files under 600 lines

## 10. Final validation

- [x] 10.1 Run full `cargo test` and confirm all tests pass
- [x] 10.2 Verify no non-generated source file exceeds 600 lines (exclude `mac_vendor_data.rs`, `device_rules_data.rs`, `model_data.rs`, `main.rs`) — two accepted exceptions: hostname_model.rs (648, single function), endpoint_ops.rs (634, gateway platform code)
- [x] 10.3 Verify all re-exports work — no external import paths need updating beyond the split modules
