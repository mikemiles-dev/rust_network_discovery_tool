## ADDED Requirements

### Requirement: get_setting removed from public re-exports
`get_setting` SHALL NOT appear in the `pub use` line in `src/db/mod.rs`. The function SHALL remain accessible within the `db` module (called by `get_setting_i64`) but SHALL NOT be re-exported to the rest of the crate.

#### Scenario: Compiler warning eliminated
- **WHEN** `cargo build` is run
- **THEN** there SHALL be no unused import warning for `get_setting`

#### Scenario: get_setting_i64 still works
- **WHEN** `get_setting_i64` is called from outside the db module
- **THEN** it SHALL function identically to before, internally calling `get_setting`

### Requirement: endpoints.rs renamed to notifications.rs
`src/db/endpoints.rs` SHALL be renamed to `src/db/notifications.rs`. The module declaration in `mod.rs` SHALL change from `mod endpoints` to `mod notifications`. The `pub use` re-exports (`insert_notification`, `insert_notification_with_endpoint_id`) SHALL update to reference `notifications::` instead of `endpoints::`.

#### Scenario: Notification functions still accessible
- **WHEN** other modules call `crate::db::insert_notification` or `crate::db::insert_notification_with_endpoint_id`
- **THEN** the functions SHALL resolve correctly through the updated re-exports

#### Scenario: No file named endpoints.rs exists
- **WHEN** the rename is complete
- **THEN** `src/db/endpoints.rs` SHALL NOT exist and `src/db/notifications.rs` SHALL contain the same two functions

### Requirement: Missing indexes added for merge-heavy columns
`initialize_schema` in `src/db/schema.rs` SHALL create three indexes using `CREATE INDEX IF NOT EXISTS`: `idx_endpoint_attributes_endpoint_id` on `endpoint_attributes(endpoint_id)`, `idx_communications_src` on `communications(src_endpoint_id)`, and `idx_communications_dst` on `communications(dst_endpoint_id)`.

#### Scenario: Indexes created on fresh database
- **WHEN** `initialize_schema` runs on a new database
- **THEN** all three indexes SHALL be created

#### Scenario: Indexes are idempotent on existing database
- **WHEN** `initialize_schema` runs on a database that already has these indexes
- **THEN** `CREATE INDEX IF NOT EXISTS` SHALL be a no-op with no errors

#### Scenario: Merge queries use indexes
- **WHEN** a merge operation runs `UPDATE OR IGNORE endpoint_attributes SET endpoint_id = ?1 WHERE endpoint_id = ?2`
- **THEN** the query SHALL use the `idx_endpoint_attributes_endpoint_id` index instead of a full table scan
