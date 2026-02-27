## 1. Extract shared merge helper

- [x] 1.1 Add `merge_endpoint_into(conn: &Connection, keep_id: i64, remove_id: i64) -> rusqlite::Result<()>` as a `pub(super)` function in `src/db/merge_maintenance.rs` — implement the full 6-step sequence: preserve_user_fields, reassign endpoint_attributes (UPDATE OR IGNORE + DELETE orphans), reassign communications src+dst (UPDATE OR IGNORE + DELETE orphans), reassign open_ports (UPDATE OR IGNORE + DELETE orphans), reassign scan_results (UPDATE), delete source endpoint
- [x] 1.2 Refactor `merge_duplicate_endpoints_by_hostname` (merge_maintenance.rs) — replace the inline merge sequence (lines 150-196) with a call to `merge_endpoint_into(conn, keep_id, merge_id)?`
- [x] 1.3 Refactor `merge_endpoints_by_ipv6_prefix` (merge_maintenance.rs) — replace the inline merge sequence (lines 301-339) with a call to `merge_endpoint_into(conn, keep_id, merge_id)?`
- [x] 1.4 Refactor `merge_hotspot_gateways_into_phones` (hotspot_merge.rs) — replace the inline merge sequence (lines 125-169) with a call to `super::merge_maintenance::merge_endpoint_into(conn, phone_id, gateway_id)?`, remove the now-unused `use super::merge_maintenance::preserve_user_fields` import

## 2. Fix error handling

- [x] 2.1 Change `preserve_user_fields` signature from returning `()` to returning `rusqlite::Result<()>` — remove the `.ok()` call, return the result directly
- [x] 2.2 In `merge_endpoint_into`, log `preserve_user_fields` errors with `eprintln!` including keep_id and remove_id, then continue with remaining merge steps

## 3. Housekeeping — unused export

- [x] 3.1 Remove `get_setting` from the `pub use settings::{...}` line in `src/db/mod.rs` — keep `get_all_settings`, `get_setting_i64`, `set_setting`

## 4. Housekeeping — file rename

- [x] 4.1 Rename `src/db/endpoints.rs` to `src/db/notifications.rs`
- [x] 4.2 Update `src/db/mod.rs` — change `mod endpoints;` to `mod notifications;` and update the `pub use` line to reference `notifications::` instead of `endpoints::`

## 5. Add missing indexes

- [x] 5.1 Add `CREATE INDEX IF NOT EXISTS idx_endpoint_attributes_endpoint_id ON endpoint_attributes(endpoint_id)` to `initialize_schema` in `src/db/schema.rs`
- [x] 5.2 Add `CREATE INDEX IF NOT EXISTS idx_communications_src ON communications(src_endpoint_id)` to `initialize_schema` in `src/db/schema.rs`
- [x] 5.3 Add `CREATE INDEX IF NOT EXISTS idx_communications_dst ON communications(dst_endpoint_id)` to `initialize_schema` in `src/db/schema.rs`

## 6. Validation

- [x] 6.1 Verify `cargo build` succeeds with no new warnings
- [x] 6.2 Verify `cargo test` passes
