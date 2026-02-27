## Context

The web API layer in `src/web/api/` contains 10+ handler files with over 23 response structs, 17 request structs, and inconsistent patterns for error handling, database access, and constant usage. Most response structs are identical (`success: bool, message: String`) and most request structs wrap a single field. Error handling varies between returning HTTP 200 with `success: false`, proper HTTP status codes, or silent failures. The `component_vendors` array is copy-pasted in 3 files, and the `EndpointModelData` type is an opaque 6-tuple.

The API handlers use actix-web with `#[get]`/`#[post]` macros, serde for JSON, and `tokio::task::spawn_blocking` for database access (rusqlite is synchronous). There's no middleware — each handler manages its own error responses.

## Goals / Non-Goals

**Goals:**
- Replace duplicated response structs with a generic `ApiResponse` type
- Consolidate trivial request structs into shared types
- Standardize error handling to use consistent HTTP status codes and response format
- Extract duplicated constants into a single location
- Replace the 6-tuple `EndpointModelData` with a named struct
- Extract repeated endpoint-lookup SQL into helper functions

**Non-Goals:**
- Adding actix-web error middleware or custom extractors (too much architecture for the gain)
- Changing the public API contract (JSON field names, endpoint paths)
- Refactoring handler logic or business rules
- Standardizing `spawn_blocking` vs `web::block` (both work fine; the inconsistency is cosmetic and not worth the churn)
- Moving to a connection pool (rusqlite `new_connection()` per request is the established pattern)

## Decisions

### 1. Generic `ApiResponse` struct replaces per-handler response types

Create a single `ApiResponse` struct in `src/web/helpers/types.rs`:

```rust
#[derive(Serialize)]
pub struct ApiResponse {
    pub success: bool,
    pub message: String,
}
```

This replaces `ClassifyResponse`, `DeleteEndpointResponse`, `MergeEndpointsResponse`, `StartScanResponse`, `UpdateSettingResponse`, and ~8 other identical structs. Handlers that need extra fields (like `RenameResponse.original_name` or `ProbeResponse.hostname`) keep their own struct — only the duplicates are consolidated.

**Alternative considered:** `ApiResponse<T>` with a generic `data: Option<T>` field. Rejected because most handlers only need `success` + `message`. Adding a generic parameter to every response site adds complexity for the few handlers that need extra data — those already have custom structs and should keep them.

### 2. Shared request types for common patterns

Create shared request types in `src/web/helpers/types.rs`:

```rust
#[derive(Deserialize)]
pub struct IpRequest {
    pub ip: String,
}

#[derive(Deserialize)]
pub struct EndpointNameRequest {
    pub endpoint_name: String,
}
```

`IpRequest` replaces `ProbeRequest`, `PingRequest`, `PortScanRequest`, and `ProbeModelRequest` (all identical: `{ ip: String }`). `EndpointNameRequest` replaces `DeleteEndpointRequest` and `ProbeEndpointRequest` (both `{ endpoint_name: String }`).

Request types with additional fields (`ClassifyRequest`, `RenameRequest`, `MergeEndpointsRequest`, `DeviceQuery`, etc.) stay as-is since they're unique.

### 3. Error handling standardization: keep current patterns, fix inconsistencies

Rather than introducing error middleware, fix the specific inconsistencies:
- Probing handlers that return HTTP 200 on failure should continue to do so — these are "soft" failures where the probe ran but found nothing. The `success: false` field is the signal.
- Database errors should consistently return HTTP 500 with `ApiResponse { success: false, message }`.
- "Not found" cases should consistently return HTTP 404.
- Add `eprintln!` logging to the few handlers that silently swallow errors.

**Alternative considered:** Custom actix-web error type with `ResponseError` impl. Rejected because it would change every handler's return type and error flow — high churn for modest benefit. The current pattern of matching on `Result` and returning explicit `HttpResponse` is fine; it just needs consistency.

### 4. Constants in `src/web/helpers/types.rs`

Move shared constants to a single location:

```rust
pub const COMPONENT_VENDORS: &[&str] = &[
    "AzureWave", "Broadcom", "Espressif", "Marvell", "MediaTek",
    "Murata", "Qualcomm", "Realtek", "Tuya", "USI", "Wisol",
];

pub const DEFAULT_SCAN_INTERVAL_MINUTES: u64 = 525600;
pub const DEFAULT_ACTIVE_THRESHOLD_SECONDS: i64 = 120;
```

Replace the 3 inline `component_vendors` arrays (in `details.rs`, `table.rs`, `export.rs`) and the 5+ hardcoded `525600`/`120` values.

### 5. Named struct for `EndpointModelData`

Replace the opaque 6-tuple type alias:

```rust
pub struct EndpointModelData {
    pub custom_model: Option<String>,
    pub ssdp_model: Option<String>,
    pub ssdp_friendly_name: Option<String>,
    pub custom_vendor: Option<String>,
    pub snmp_vendor: Option<String>,
    pub snmp_model: Option<String>,
}
```

All destructuring sites (`let (a, b, c, d, e, f) = ...`) update to use named field access. This is a pure readability improvement.

### 6. Endpoint lookup helper function

Extract the repeated `DISPLAY_NAME_SQL` lookup pattern into a helper in `src/web/helpers/mod.rs`:

```rust
pub fn find_endpoint_ids(conn: &Connection, name: &str) -> Result<Vec<i64>, rusqlite::Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT DISTINCT e.id FROM endpoints e
         LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
         WHERE {} = ?1 COLLATE NOCASE
            OR LOWER(ea.hostname) = LOWER(?1)
            OR LOWER(ea.ip) = LOWER(?1)",
        DISPLAY_NAME_SQL
    ))?;
    let ids = stmt.query_map([name], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(ids)
}
```

This replaces the 3 copy-pasted query blocks in `crud.rs` (delete + merge target + merge source) and 2 in `probing.rs`.

## Risks / Trade-offs

- **Risk: Changing response type names could break downstream consumers** → Mitigation: The JSON field names (`success`, `message`) stay identical. Only the Rust struct names change, which are internal.
- **Risk: Shared `IpRequest` type could diverge if one endpoint needs extra fields later** → Mitigation: It's trivial to replace `IpRequest` with a custom struct for a single handler if needed. The shared type is a convenience, not a lock-in.
- **Trade-off: Not introducing error middleware** → Accepted. Middleware would reduce per-handler boilerplate but requires changing every handler's signature and error flow. The manual approach is more explicit and matches the codebase's style.
- **Trade-off: Keeping probe handlers at HTTP 200 for failures** → Accepted. These are semantically "the request succeeded but found nothing" — changing to 404/500 would break the JS frontend's error handling.
- **Trade-off: `EndpointModelData` struct migration touches many destructuring sites** → Accepted. Named fields are significantly more readable than positional tuple access. The migration is mechanical.
