## ADDED Requirements

### Requirement: preserve_user_fields logs errors instead of swallowing them
`preserve_user_fields` in `merge_maintenance.rs` SHALL return `rusqlite::Result<()>` instead of `()`. Callers SHALL log any error with `eprintln!` and continue execution — field preservation failure SHALL NOT abort the merge.

#### Scenario: Successful field preservation
- **WHEN** `preserve_user_fields(conn, target_id, source_id)` succeeds
- **THEN** it SHALL return `Ok(())` and user fields (custom_name, custom_vendor, manual_device_type) SHALL be copied from source to target where target fields are NULL

#### Scenario: Failed field preservation is logged
- **WHEN** `preserve_user_fields(conn, target_id, source_id)` encounters a database error
- **THEN** the error SHALL be returned as `Err(rusqlite::Error)`, and the caller (`merge_endpoint_into`) SHALL log it via `eprintln!` including the target and source endpoint IDs

#### Scenario: Merge continues after field preservation failure
- **WHEN** `preserve_user_fields` returns an error during a merge
- **THEN** `merge_endpoint_into` SHALL continue with the remaining merge steps (reassign attributes, communications, etc.) rather than aborting
