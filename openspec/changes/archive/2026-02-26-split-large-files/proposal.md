## Why

The previous `refactor-module-structure` change successfully reorganized the codebase into logical modules, but 10 source files still exceed 600 lines. Several exceed 1000 lines, with `web/api/endpoints.rs` at 1834 lines. Large files are harder to navigate, review, and maintain. Splitting them continues the refactoring effort and brings the codebase to a consistent standard where every non-generated file stays under 600 lines.

## What Changes

- Split `src/web/api/endpoints.rs` (1834 lines) into handler groups: probing, details, CRUD, and table cache
- Split `src/network/endpoint/endpoint_ops.rs` (1378 lines) into classification, CRUD, merging, and hostname resolution
- Split `src/web/helpers.rs` (1335 lines) into query modules by domain: stats, protocols, models, type classification
- Split `src/web/mod.rs` (1133 lines) by extracting graph building and the large index handler
- Split `src/network/endpoint/model.rs` (1054 lines) by extracting hostname-based model detection patterns
- Split `src/web/api/scanning.rs` (860 lines) by extracting SNMP parsing and SSDP validation
- Split `src/db/maintenance.rs` (780 lines) by extracting merge strategies and WAL cleanup
- Split `src/device_control/lg.rs` (687 lines) by extracting pairing and command library
- Split `src/network/endpoint/classify.rs` (657 lines) by extracting detection categories

## Capabilities

### New Capabilities

- `web-api-endpoints-split`: Split the endpoints API handlers into focused sub-modules (probing, details, CRUD, table)
- `endpoint-ops-split`: Split endpoint operations into classification, CRUD, merging, hostname, and validation modules
- `web-helpers-split`: Split web query helpers into domain-specific modules (stats, protocols, models, types)
- `web-mod-split`: Extract graph building and index handler from the web server module
- `model-split`: Extract hostname-based model detection and inference from model.rs
- `scanning-split`: Extract SNMP parsing and SSDP validation from scanning handlers
- `maintenance-split`: Extract merge strategies and WAL cleanup from maintenance module
- `lg-split`: Extract LG TV pairing flow and command library into sub-modules
- `classify-split`: Extract detection categories from the unified classify module

### Modified Capabilities

## Impact

- All changes are internal refactoring — no public API, behavior, or dependency changes
- Every `mod.rs` or parent module for split files will need updated `mod` declarations and re-exports
- Import paths within the crate will change for moved items
- All 72 existing tests must continue to pass after each split
