## 1. Database indexes

- [x] 1.1 In `src/db/schema.rs`, replace the single-column `idx_communications_src` and `idx_communications_dst` indexes with composite indexes: `idx_communications_src_last_seen ON communications(src_endpoint_id, last_seen_at)` and `idx_communications_dst_last_seen ON communications(dst_endpoint_id, last_seen_at)`. Drop the old indexes first with `DROP INDEX IF EXISTS`.
- [x] 1.2 Add a standalone index `idx_communications_last_seen ON communications(last_seen_at)` for time-only filtered queries.

## 2. Connection pool

- [x] 2.1 Add `r2d2` and `r2d2_sqlite` dependencies to `Cargo.toml`
- [x] 2.2 In `src/db/mod.rs`, create a `ConnectionCustomizer` that sets WAL mode, busy_timeout=30000, and synchronous=NORMAL on each connection. Create a `OnceLock<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>` pool with max_size=8, exposed via `pub fn get_pool()`.
- [x] 2.3 Update all web query functions (`dropdown_endpoints`, `get_combined_endpoint_stats`, `get_all_endpoint_types`, `get_endpoint_ips_and_macs`, `get_endpoint_ssdp_models`, `get_endpoint_vendor_classes`, `get_all_endpoints_bytes`, `get_all_endpoints_last_seen`, `get_all_endpoints_online_status`, `get_bytes_for_endpoint`, `get_protocols_for_endpoint`, `get_endpoints_for_protocol`, `get_all_protocols`, `get_ports_for_endpoint`) to use `get_pool().get()` instead of `new_connection_result()`.

## 3. UNION ALL rewrites

- [x] 3.1 In `src/web/helpers/endpoint_queries.rs`, rewrite `get_combined_endpoint_stats()` to use UNION ALL subquery for communications join instead of OR
- [x] 3.2 In `src/web/helpers/endpoint_queries.rs`, rewrite `get_all_endpoints_last_seen()` to use UNION ALL
- [x] 3.3 In `src/web/helpers/endpoint_queries.rs`, rewrite `get_all_endpoints_online_status()` to use UNION ALL
- [x] 3.4 In `src/web/helpers/endpoint_queries.rs`, rewrite `dropdown_endpoints()` to use UNION ALL for the communications join
- [x] 3.5 In `src/web/helpers/model_queries.rs`, rewrite `get_all_endpoints_bytes()` to use UNION ALL

## 4. Batch detail queries

- [x] 4.1 In `src/web/api/endpoints/details.rs`, consolidate the 4 separate endpoint metadata queries (ssdp_model, ssdp_model_for_vendor, dhcp_vendor_class, custom_model/ssdp_model/custom_vendor) into a single query that fetches all fields in one round-trip

## 5. Validation

- [x] 5.1 Verify `cargo check` succeeds
- [x] 5.2 Verify `cargo clippy` has no new warnings
- [x] 5.3 Verify `cargo test` passes
