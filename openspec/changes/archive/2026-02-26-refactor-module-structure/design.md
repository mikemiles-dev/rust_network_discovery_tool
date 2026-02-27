## Context

The project is a Rust network discovery tool (~59K lines) with four top-level modules: `web/`, `db/`, `network/`, and `scanner/`. Several files have grown past 1,000 lines with mixed responsibilities. The worst offenders are `web/api.rs` (3,723 lines, 57 handlers), `web/mod.rs` (2,442 lines), `db/mod.rs` (1,273 lines), and `network/endpoint/endpoint_ops.rs` + `model.rs` (~2,400 lines combined). The `EndPoint` struct has `impl` blocks scattered across 5 files.

All changes are internal restructuring — the binary interface, web API routes, and database schema stay the same.

## Goals / Non-Goals

**Goals:**
- Every non-generated source file under 600 lines
- Each file has a single clear responsibility
- `impl EndPoint` consolidated to at most 2 files (core logic + DB persistence)
- New code has an obvious home — the module tree should guide placement
- Zero behavioral changes — all existing tests pass unchanged (only `use` paths may update)

**Non-Goals:**
- Changing the web API routes or HTTP interface
- Adding or removing crate dependencies
- Refactoring scanner/ (already well-organized at ~150–550 lines per file)
- Refactoring auto-generated files (`mac_vendor_data.rs`, `device_rules_data.rs`)
- Introducing traits or abstractions — this is a file/module reorganization, not an API redesign

## Decisions

### 1. Split `web/api.rs` into domain modules

**Decision**: Replace `web/api.rs` with a `web/api/` directory containing domain-specific modules.

**Target layout:**
```
src/web/
├── mod.rs          (routes + server setup only, ~200 lines)
├── helpers.rs      (DB query helpers, stats, DISPLAY_NAME_SQL, shared types)
├── api/
│   ├── mod.rs      (re-exports all handlers)
│   ├── endpoints.rs  (endpoint table, details, merge, classification)
│   ├── devices.rs    (device control — LG, Samsung, Roku, HP probe)
│   ├── scanning.rs   (scan start/stop/status, PCAP import)
│   ├── settings.rs   (get/set settings, notifications)
│   ├── dns.rs        (DNS entries CRUD)
│   └── export.rs     (Excel export, file upload/import)
```

**Rationale**: Domain-based splitting (not alphabetical or size-based) because handlers within a domain share types, query patterns, and state. The `super::` imports from `api.rs → mod.rs` (currently ~20 shared items) move to `helpers.rs`, which all API sub-modules can import.

**Alternative considered**: Keep `api.rs` as a single file but use `#[path]` includes — rejected because it hides module boundaries from the compiler and IDE tooling.

### 2. Extract `web/helpers.rs` from `web/mod.rs`

**Decision**: Move all database query helper functions, the `DISPLAY_NAME_SQL` constant, `EndpointStats`, `EndpointDetailsResponse`, and shared query functions (`get_combined_endpoint_stats`, `get_dns_entries`, `dropdown_endpoints`, etc.) into `web/helpers.rs`. What remains in `mod.rs` is the Actix server setup, route registration, HTML template rendering, and the `try_db!` macro.

**Rationale**: `mod.rs` currently defines ~25 helper functions used by `api.rs` via `super::`. Extracting them lets `mod.rs` focus on server wiring while helpers become importable by all API sub-modules.

### 3. Split `db/mod.rs` into focused modules

**Decision**: Replace the single `db/mod.rs` with:
```
src/db/
├── mod.rs        (re-exports, new_connection, new_connection_result)
├── schema.rs     (create_tables, migration logic)
├── writer.rs     (SQLWriter, channel-based batch writing)
├── endpoints.rs  (insert_endpoint, update_endpoint, endpoint attribute CRUD)
├── settings.rs   (get_setting, set_setting, get_all_settings)
└── maintenance.rs (WAL cleanup, orphan cleanup)
```

**Rationale**: The current file mixes 5 concerns: connection management, schema creation, bulk writes, settings CRUD, and file maintenance. Each concern maps to a module. The `SQLWriter` struct and its `mpsc` channel logic are self-contained and benefit from isolation.

**Alternative considered**: Just splitting into `schema.rs` + `ops.rs` — rejected as `ops.rs` would still be ~800 lines with mixed concerns.

### 4. Consolidate endpoint classification into a single module

**Decision**: Merge `classification.rs`, `detection.rs`, and `gateway.rs` into `classify.rs` with a single public function `classify_endpoint(...)` that orchestrates all classification logic (port-based, MAC-based, hostname-based, gateway detection).

**Rationale**: These three files implement overlapping classification systems with unclear boundaries. `classification.rs` functions are only called from `endpoint_ops.rs`, never from outside. Merging them creates one authoritative classification pipeline. The combined size (~920 lines) is under the 600-line target only if we also extract gateway-specific logic — so `gateway.rs` stays as a separate internal helper called by `classify.rs`.

**Revised layout:**
```
src/network/endpoint/
├── classify.rs    (unified classification: port, MAC, hostname, service → calls gateway.rs)
├── gateway.rs     (gateway/router-specific detection, kept separate due to size)
```

### 5. Consolidate `impl EndPoint` blocks

**Decision**: Move all `impl EndPoint` methods into two files:
- `endpoint_ops.rs` — core logic: DNS resolution, classification orchestration, insert/update orchestration
- `db.rs` — database persistence: all `rusqlite`-touching methods

Currently `impl EndPoint` exists in `endpoint_ops.rs`, `db.rs`, `gateway.rs`, and `model.rs`. The `gateway.rs` and `model.rs` methods move to `endpoint_ops.rs` (they're classification/inference logic, not persistence).

**Rationale**: Scattered `impl` blocks make it hard to find methods. Two files is a pragmatic split — pure DB operations vs. everything else — rather than forcing everything into one 2,000+ line file.

### 6. Extract vendor-specific model data from `model.rs`

**Decision**: Create `model_data.rs` containing the vendor-specific series maps and pattern tables (Samsung TV series, LG OLED/NanoCell maps, Sony model prefixes, Roku serial patterns). `model.rs` retains the normalization and inference logic, importing data from `model_data.rs`.

**Target:**
```
model.rs       (~500 lines) — normalize_model_name, infer_model_with_context, characterize_model
model_data.rs  (~700 lines) — const arrays/maps for Samsung, LG, Sony, Roku, etc.
```

**Rationale**: The data tables change independently from the inference logic (e.g., adding a new Samsung TV series vs. changing how models are matched). Separating them makes both files easier to work with.

### 7. Relocate `device_control/` to top-level

**Decision**: Move `src/network/device_control/` to `src/device_control/`. Update `src/main.rs` (or lib) to declare `mod device_control;`. Update all `use crate::network::device_control::` paths to `use crate::device_control::`.

**Rationale**: Device control (sending commands to LG/Samsung/Roku TVs) is application-level functionality, not network discovery. Placing it under `network/` is misleading. As a top-level module it sits alongside `web/`, `db/`, `scanner/`, and `network/` — all peer-level concerns.

**Internal structure stays the same** — `controller.rs`, `types.rs`, `lg.rs`, `lg_thinq.rs`, `roku.rs`, `samsung.rs` are already well-organized.

## Risks / Trade-offs

- **Large diff, many `use` path changes** → Mitigate by doing the refactor module-by-module (web first, then db, then endpoint, then device_control) so each step compiles and tests pass before moving on.

- **Merge conflicts with in-flight work** → Mitigate by doing the refactor on a dedicated branch and merging quickly. No other feature branches appear active.

- **Scattered `impl EndPoint` consolidation may surface hidden dependencies** → Mitigate by letting the compiler guide: move methods one at a time, fix imports until it compiles.

- **`classify.rs` may exceed 600 lines after merging three files** → Accepted: gateway.rs stays separate as an internal helper, keeping classify.rs under the limit.

- **`model_data.rs` is pure data (~700 lines of const tables)** → Accepted: data files are inherently large but simple; they don't need to meet the same complexity-per-line budget as logic files.
