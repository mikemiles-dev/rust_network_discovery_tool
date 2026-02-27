## Why

The web API layer has accumulated significant boilerplate and inconsistency across 10+ handler files. There are 23+ nearly identical response structs, 17+ request structs (many just wrapping a single `ip: String`), three different patterns for `spawn_blocking`, inconsistent error handling (some return 200 OK on failure, others use proper HTTP status codes), and duplicated constants like the `component_vendors` array appearing in 3 separate files. Cleaning this up will make the API layer easier to maintain and extend.

## What Changes

- Replace 23+ individual response structs (`ClassifyResponse`, `RenameResponse`, `SetModelResponse`, etc.) with a generic `ApiResponse<T>` wrapper
- Consolidate 17+ request structs into a handful of shared types (`IpRequest`, `EndpointNameRequest`, etc.)
- Standardize error handling: consistent HTTP status codes, consistent error response format, consistent error logging
- Extract shared constants: `component_vendors` array (duplicated in 3 files), default values (`DEFAULT_SCAN_INTERVAL_MINUTES = 525600`, `DEFAULT_ACTIVE_THRESHOLD_SECONDS = 120`)
- Replace the 6-tuple `EndpointModelData` type alias with a named struct
- Consolidate duplicated endpoint lookup queries (DISPLAY_NAME_SQL pattern used in 8+ places) into helper functions
- Standardize on `tokio::task::spawn_blocking` (currently mixed with `actix_web::web::block`)

## Capabilities

### New Capabilities
- `unified-response-types`: Generic `ApiResponse<T>` wrapper and consolidated request/response structs to replace 23+ duplicated types
- `error-handling`: Standardized error responses with consistent HTTP status codes, error logging, and nested Result unwrapping
- `db-query-helpers`: Helper functions for common spawn_blocking + DB patterns and endpoint lookup query consolidation
- `shared-constants`: Deduplicated constants (component vendors, default thresholds) and named struct for `EndpointModelData`

### Modified Capabilities

## Impact

- All files under `src/web/api/` (endpoints/crud.rs, endpoints/probing.rs, endpoints/table.rs, endpoints/details.rs, scanning.rs, settings.rs, devices.rs, dns.rs, export.rs)
- `src/web/helpers/types.rs` (new shared types and constants)
- `src/web/helpers/mod.rs` (new helper functions)
- No changes to templates, static JS, or network/db layers
- No public API contract changes (same endpoints, same JSON field names)
- No dependency changes
