## Why

The `src/db/` layer has accumulated duplication and inconsistencies across its 1,334 lines. The same 6-step endpoint merge sequence (update+delete across 5 tables) is copy-pasted in 3 locations totaling ~120 duplicated lines. Error handling is inconsistent — some merge operations silently swallow failures with `.ok()`, losing data during field preservation. There's also an unused public export (`get_setting`) causing a compiler warning, and the `endpoints.rs` file is misnamed (it contains notification helpers, not endpoint logic).

## What Changes

- Extract the repeated 6-step merge sequence from `hotspot_merge.rs` (lines 129-169), `merge_maintenance.rs` (lines 153-193), and `merge_maintenance.rs` (lines 302-339) into a single `merge_endpoint_into(conn, keep_id, remove_id)` function
- Fix silent error suppression in `preserve_user_fields` (merge_maintenance.rs:361) — log errors instead of `.ok()`
- Fix the unused `get_setting` export: remove from `pub use` in mod.rs, make private in settings.rs
- Rename `src/db/endpoints.rs` to `src/db/notifications.rs` — the file only contains `insert_notification` and `insert_notification_with_endpoint_id`, which are notification helpers, not endpoint logic
- Add missing database indexes on frequently queried columns: `communications(src_endpoint_id)`, `communications(dst_endpoint_id)`, `endpoint_attributes(endpoint_id)`

## Capabilities

### New Capabilities
- `merge-consolidation`: Extract duplicated 6-step endpoint merge pattern into a shared helper function
- `db-error-handling`: Fix silent error suppression and add consistent error logging in merge operations
- `db-housekeeping`: Remove unused export, rename misnamed file, add missing indexes

### Modified Capabilities

## Impact

- `src/db/merge_maintenance.rs` — refactored to use shared merge helper, error handling improved
- `src/db/hotspot_merge.rs` — refactored to use shared merge helper
- `src/db/mod.rs` — updated module declarations and exports
- `src/db/endpoints.rs` → renamed to `src/db/notifications.rs`
- `src/db/settings.rs` — `get_setting` made private
- `src/db/schema.rs` — new indexes added
- No API or template changes
- No dependency changes
