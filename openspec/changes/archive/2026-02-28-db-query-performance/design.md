## Context

The web UI refreshes endpoint data every 3 seconds via AJAX. Each refresh triggers `get_endpoints_table()` which spawns 4 parallel `spawn_blocking` queries, each opening its own SQLite connection. The most common query pattern joins `endpoints` to `communications` using `e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id` with a `last_seen_at` time filter — this OR condition prevents SQLite from using the existing per-column indexes. The endpoint details panel fires 4 separate queries for the same endpoint's metadata.

Current indexes:
- `idx_communications_src` on `communications(src_endpoint_id)`
- `idx_communications_dst` on `communications(dst_endpoint_id)`
- `idx_endpoint_attributes_endpoint_id` on `endpoint_attributes(endpoint_id)`

No index exists on `communications(last_seen_at)`, which is filtered in every query.

## Goals / Non-Goals

**Goals:**
- Reduce query latency for the main table endpoint (polled every 3s)
- Eliminate redundant connection open/close overhead
- Ensure all communications joins use indexes efficiently
- Reduce round-trips in the endpoint details view

**Non-Goals:**
- Full ORM or query builder (rusqlite raw queries are fine)
- Async SQLite driver (rusqlite is blocking; spawn_blocking is the correct pattern)
- Caching beyond the existing 3-second table cache

## Decisions

### 1. r2d2 connection pool over manual connection management

Use `r2d2` with `r2d2_sqlite` to pool connections. Each pooled connection gets WAL mode, busy_timeout=30s, and synchronous=NORMAL configured via a custom `ConnectionCustomizer`.

- Pool size: 8 connections (sufficient for 4 parallel table queries + details + scanning)
- The pool is stored in a `OnceLock<Pool>` and exposed via `get_pool() -> &'static Pool`
- `new_connection_result()` remains for non-pooled contexts (tests, standalone tools)
- Query functions switch from `new_connection_result()` to `get_pool().get()`

**Alternative**: `deadpool-sqlite` (async pool) — rejected because rusqlite is inherently blocking and we already use `spawn_blocking` correctly.

### 2. UNION ALL instead of OR for communications joins

Replace:
```sql
INNER JOIN communications c ON e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id
```

With:
```sql
INNER JOIN (
    SELECT src_endpoint_id AS endpoint_id, bytes, last_seen_at FROM communications WHERE last_seen_at >= ?
    UNION ALL
    SELECT dst_endpoint_id AS endpoint_id, bytes, last_seen_at FROM communications WHERE last_seen_at >= ?
) c ON e.id = c.endpoint_id
```

This lets each UNION ALL branch use its respective index. The UNION ALL (not UNION) preserves duplicates which are handled by the outer GROUP BY.

### 3. Composite indexes instead of single-column

Replace existing single-column indexes with composite ones that cover both the join column and the most common filter:
- `communications(src_endpoint_id, last_seen_at)` — covers src join + time filter
- `communications(dst_endpoint_id, last_seen_at)` — covers dst join + time filter
- `communications(last_seen_at)` — standalone for queries that filter by time without a specific endpoint

Drop the old single-column indexes since the composites subsume them.

### 4. Consolidated endpoint metadata query

Merge the 4 separate queries in `get_endpoint_details_blocking` into one:
```sql
SELECT e.custom_model, e.ssdp_model, e.custom_vendor, e.ssdp_friendly_name,
       e.snmp_vendor, e.snmp_model, ea.dhcp_vendor_class
FROM endpoints e
LEFT JOIN endpoint_attributes ea ON ea.endpoint_id = e.id
    AND ea.dhcp_vendor_class IS NOT NULL AND ea.dhcp_vendor_class != ''
WHERE (LOWER(e.name) = LOWER(?1) OR LOWER(e.custom_name) = LOWER(?1))
LIMIT 1
```

## Risks / Trade-offs

- [Composite indexes increase write overhead] → Acceptable trade-off; writes happen during scanning (infrequent) while reads happen every 3 seconds.
- [UNION ALL doubles the parameter count] → Parameters must be provided twice (once per branch). Use helper function to duplicate params.
- [Pool exhaustion under heavy load] → Pool size of 8 with 30s busy_timeout is generous. The existing 3-second table cache prevents thundering herd.
- [Dropping old indexes on existing databases] → Use `DROP INDEX IF EXISTS` before creating composites. Safe because schema initialization runs at startup.
