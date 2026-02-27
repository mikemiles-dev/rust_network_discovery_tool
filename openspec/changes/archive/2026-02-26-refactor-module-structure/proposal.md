## Why

Several core modules have grown beyond maintainable size, with mixed concerns making the codebase harder to navigate and modify. `web/api.rs` (3,700+ lines, 57 handlers), `db/mod.rs` (1,270+ lines), and the endpoint sub-module (scattered `impl EndPoint` blocks across 5+ files) are the worst offenders. Reorganizing now reduces friction for ongoing feature work and makes the codebase approachable for future contributors.

## What Changes

- **Split `web/api.rs`** into domain-specific API modules (endpoints, devices, scanning, settings, import/export) instead of one monolithic file with 57 handlers
- **Split `web/mod.rs`** to extract database query helpers, statistics computation, and cache management from route definitions
- **Split `db/mod.rs`** into focused modules: schema, endpoint writes, settings, and maintenance (WAL cleanup, batch ops)
- **Consolidate endpoint classification**: merge `classification.rs`, `detection.rs`, and `gateway.rs` into a unified classification module with a clear public API, eliminating the scattered three-system approach
- **Consolidate `impl EndPoint` blocks** currently scattered across `endpoint_ops.rs`, `db.rs`, `gateway.rs`, and `model.rs`
- **Split `model.rs`** to extract vendor-specific model knowledge (Samsung series, LG series, Sony, Roku) from generic normalization logic
- **Relocate `device_control/`** from `network/` to a top-level `src/device_control/` module — it's application-level control, not network discovery

## Capabilities

### New Capabilities

- `module-layout`: Defines the target module hierarchy, file size guidelines, and rules for where new code should live

### Modified Capabilities

_(none — no existing specs)_

## Impact

- **All `src/` modules** are touched: `web/`, `db/`, `network/endpoint/`, `network/device_control/`
- **No public API changes** — this is an internal restructure; the web API routes and binary interface remain identical
- **No dependency changes** — no crates added or removed
- **Test files** may need updated `use` paths but test logic stays the same
- **Auto-generated files** (`mac_vendor_data.rs`, `device_rules_data.rs`) stay in place unchanged
