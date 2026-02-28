## Why

Every web UI page load triggers 4-5 separate database queries (each opening its own connection), many of which use OR-based joins on the communications table that prevent index utilization and duplicate the expensive DISPLAY_NAME_SQL correlated subqueries. The endpoint details view fires 4 separate queries against the same endpoint row. These patterns cause unnecessary latency on every AJAX refresh cycle (every 3 seconds for the table endpoint).

## What Changes

- Add missing database indexes on `communications(last_seen_at)` and a composite covering index for the most common query pattern (communications joined by endpoint ID with last_seen_at filter)
- Replace OR-based joins (`e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id`) with UNION ALL queries that can each use a single-column index efficiently
- Consolidate multiple per-endpoint queries in `get_endpoint_details_blocking` into a single query that fetches ssdp_model, custom_model, custom_vendor, dhcp_vendor_class, and snmp data in one round-trip
- Introduce a shared connection pool (r2d2-sqlite) so the 4-5 parallel `spawn_blocking` queries in the table handler share connections instead of each opening/configuring a new one

## Capabilities

### New Capabilities
- `communications-indexes`: Add covering indexes for the communications table query patterns used in endpoint stats, last_seen, and online status queries
- `union-all-joins`: Replace OR-based communication joins with UNION ALL for index-friendly query plans
- `batch-detail-queries`: Consolidate per-endpoint detail queries into a single round-trip
- `connection-pool`: Replace per-query `new_connection()` calls with an r2d2 connection pool

### Modified Capabilities

## Impact

- `src/db/schema.rs` — new index creation statements
- `src/db/mod.rs` — connection pool setup replacing `new_connection()`/`new_connection_result()`
- `src/web/helpers/endpoint_queries.rs` — UNION ALL rewrites for stats, last_seen, online queries
- `src/web/helpers/model_queries.rs` — UNION ALL rewrite for bytes query
- `src/web/api/endpoints/details.rs` — consolidated single query for endpoint metadata
- `Cargo.toml` — add `r2d2` and `r2d2_sqlite` dependencies
