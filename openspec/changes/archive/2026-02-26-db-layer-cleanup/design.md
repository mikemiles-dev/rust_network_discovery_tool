## Context

The `src/db/` module has 8 files totaling ~1,334 lines. Three separate merge functions repeat the same 6-step "reassign related rows then delete endpoint" pattern across `merge_maintenance.rs` (2 locations: lines 148-196 in `merge_duplicate_endpoints_by_hostname`, lines 298-342 in `merge_endpoints_by_ipv6_prefix`) and `hotspot_merge.rs` (lines 128-169 in `merge_hotspot_gateways_into_phones`). Each instance does: UPDATE OR IGNORE endpoint_attributes, DELETE orphaned endpoint_attributes, UPDATE OR IGNORE communications (src), UPDATE OR IGNORE communications (dst), DELETE orphaned communications, UPDATE OR IGNORE open_ports, DELETE orphaned open_ports, UPDATE scan_results, DELETE endpoint — ~40 lines per copy, ~120 lines total.

Error handling is inconsistent: `preserve_user_fields` (merge_maintenance.rs:361) uses `.ok()` to silently swallow rusqlite errors, meaning a failed field preservation produces no log output and no indication of data loss.

`get_setting` is exported publicly in `mod.rs` but only called internally by `get_setting_i64` in `settings.rs`. The unused export produces a compiler warning. The file `endpoints.rs` contains only notification helpers (`insert_notification`, `insert_notification_with_endpoint_id`) — the name is misleading.

No indexes exist on foreign key columns used in merge operations (`endpoint_attributes.endpoint_id`, `communications.src_endpoint_id`, `communications.dst_endpoint_id`), which means every merge's UPDATE and DELETE operations do full table scans on these tables.

## Goals / Non-Goals

**Goals:**
- Eliminate ~80 lines of duplication by extracting the merge pattern into a single shared function
- Make merge error handling consistent and observable (log failures instead of swallowing)
- Remove unused public export to clear compiler warning
- Rename misleadingly-named file to match its actual contents
- Add indexes to speed up merge operations on frequently-joined foreign key columns

**Non-Goals:**
- Refactoring the merge discovery logic (the SQL that finds duplicates to merge stays as-is)
- Changing the merge strategy (UPDATE OR IGNORE + DELETE orphans is the correct approach for unique constraints)
- Adding new merge capabilities or changing which endpoints get merged
- Restructuring the overall `db/` module hierarchy beyond the single rename

## Decisions

### Decision 1: Place `merge_endpoint_into` in `merge_maintenance.rs`

The shared helper `merge_endpoint_into(conn: &Connection, keep_id: i64, remove_id: i64) -> rusqlite::Result<()>` will live in `merge_maintenance.rs` since that file already contains the merge logic and the `preserve_user_fields` function. The function will be `pub(super)` so `hotspot_merge.rs` can call it (it already imports from `merge_maintenance`).

**Alternative considered:** New `merge_helpers.rs` file. Rejected — adding a file for a single function is unnecessary, and `merge_maintenance.rs` is the natural home since it already owns the merge pattern and `preserve_user_fields`.

### Decision 2: `merge_endpoint_into` calls `preserve_user_fields` internally

The shared function will call `preserve_user_fields` as its first step, since every merge site calls it immediately before the 6-step sequence. This simplifies each call site to a single function call. The `preserve_user_fields` function remains `pub(super)` for any callers that need it standalone, but in practice all current callers go through the full merge.

**Alternative considered:** Keep `preserve_user_fields` separate and let callers chain both calls. Rejected — every call site already pairs them, and internalizing it prevents future callers from forgetting the preservation step.

### Decision 3: Change `preserve_user_fields` to return `Result` and log errors

Change the signature from returning `()` (with `.ok()`) to returning `rusqlite::Result<()>`. The caller (`merge_endpoint_into`) will log the error with `eprintln!` and continue — field preservation failure should not abort the merge, but it should be visible. This matches the existing error handling pattern used elsewhere in the module (e.g., `insert_notification` logs with `eprintln!`).

**Alternative considered:** Propagate the error and abort the merge. Rejected — losing user fields is unfortunate but losing the entire merge (and leaving duplicate endpoints) is worse. The merge should complete; the error should be logged.

### Decision 4: `get_setting` stays public but is removed from `pub use` in `mod.rs`

Remove `get_setting` from the `pub use settings::{...}` line in `mod.rs`. The function itself stays `pub` in `settings.rs` since `get_setting_i64` calls it (within the same module, `pub` is fine). This eliminates the unused-import compiler warning without changing any function signatures.

**Alternative considered:** Make `get_setting` `pub(super)`. Either works — but keeping it `pub` is simpler and still resolves the warning since the `pub use` was the only external exposure.

### Decision 5: Rename `endpoints.rs` → `notifications.rs` with module alias

Rename the file and update `mod.rs` to `mod notifications;` with the same `pub use` re-exports. Since the file only contains `insert_notification` and `insert_notification_with_endpoint_id`, the name `notifications` accurately describes its contents. No external API changes — callers still use `crate::db::insert_notification`.

### Decision 6: Add three indexes in `schema.rs` using CREATE INDEX IF NOT EXISTS

Add indexes on:
- `endpoint_attributes(endpoint_id)` — used in every merge to reassign attributes
- `communications(src_endpoint_id)` — used in every merge to reassign outbound communications
- `communications(dst_endpoint_id)` — used in every merge to reassign inbound communications

These use `CREATE INDEX IF NOT EXISTS` so they're idempotent and safe for existing databases. They go in `initialize_schema()` alongside the existing `idx_notifications_created` index.

**Alternative considered:** Adding indexes via a migration system. Rejected — the project uses `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` throughout; there's no migration framework and adding one is out of scope.

## Risks / Trade-offs

- **Merge helper might not cover future merge patterns perfectly** → The 3 existing merge sites are identical in structure. If a future merge needs a different table set, the helper can be extended or the caller can do a custom merge. Low risk.
- **`preserve_user_fields` error logging adds noise** → Only fires on actual SQLite errors (constraint violations, etc.), which should be rare. The current silent suppression hides real problems. Net improvement.
- **Index creation adds startup time for large databases** → `CREATE INDEX IF NOT EXISTS` is a no-op after first run. First-run cost is proportional to table size but is a one-time cost. The ongoing query performance improvement far outweighs it.
- **File rename may confuse git blame** → Git's rename detection handles this well for a 100% content match. The `git log --follow` flag tracks renames. Low risk.
