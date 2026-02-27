## ADDED Requirements

### Requirement: Endpoint lookup helper function
A `find_endpoint_ids(conn, name) -> Result<Vec<i64>>` function in `src/web/helpers/mod.rs` SHALL encapsulate the repeated pattern of querying for endpoint IDs by name, hostname, or IP using `DISPLAY_NAME_SQL`.

#### Scenario: Delete endpoint uses helper
- **WHEN** `delete_endpoint` needs to find matching endpoint IDs
- **THEN** it SHALL call `find_endpoint_ids(&conn, &body.endpoint_name)` instead of inline SQL

#### Scenario: Merge endpoint uses helper for both target and source
- **WHEN** `merge_endpoints` needs to find the target and source endpoint IDs
- **THEN** it SHALL call `find_endpoint_ids` for each, replacing the two inline SQL blocks

#### Scenario: Helper returns empty vec for unknown endpoints
- **WHEN** `find_endpoint_ids` is called with a name that matches nothing
- **THEN** it SHALL return `Ok(vec![])` (not an error)

#### Scenario: Helper propagates database errors
- **WHEN** the SQL query fails (connection issue, malformed SQL)
- **THEN** `find_endpoint_ids` SHALL return `Err(rusqlite::Error)`

### Requirement: Single endpoint lookup helper
A `find_endpoint_id(conn, name) -> Result<Option<i64>>` convenience function SHALL return the first matching endpoint ID, for handlers that expect a single result.

#### Scenario: Merge uses single-ID lookup
- **WHEN** `merge_endpoints` looks up the target endpoint
- **THEN** it SHALL use `find_endpoint_id` which returns `Option<i64>` (first match or None)
