## Context

The application startup path runs several initialization steps sequentially: CLI parsing → interface enumeration → DB creation → mDNS daemon → web server (which internally does instance detection → template loading → port binding). The biggest variable is `detect_existing_instance()` which sequentially checks up to 5 ports with 500ms HTTP timeouts each (worst-case 2.5s when no instance is running). DB init and mDNS startup also run sequentially before the web server spawns.

## Goals / Non-Goals

**Goals:**
- Reduce worst-case instance detection time from ~2.5s to ~500ms by checking ports concurrently
- Overlap independent initialization steps (DB init, mDNS, web server spawn) where safe
- Preserve all existing behavior: instance detection still aborts if another instance found, same port fallback order

**Non-Goals:**
- Changing the template loading mechanism (already uses RustEmbed, fast enough)
- Deferring DB schema creation (required before packet capture starts)
- Changing port fallback behavior or timeout values
- Modifying the initial scan timing (already deferred 500ms after server starts)

## Decisions

### Decision 1: Use std::thread::scope for parallel instance detection

**Choice:** Replace the sequential `for &port in ports` loop in `detect_existing_instance()` with `std::thread::scope` to spawn one thread per port, each making a blocking HTTP request. Return early if any thread finds an instance.

**Rationale:** The function is already in a blocking context (`reqwest::blocking`). Using `std::thread::scope` gives scoped threads that can borrow the client, with automatic join on scope exit. All ports are checked simultaneously, so worst-case is ~500ms (one timeout) instead of ~2.5s (five sequential timeouts).

**Alternative considered:** Using `tokio::spawn` with async reqwest. Rejected because `detect_existing_instance` is called inside a `task::spawn_blocking` context where introducing a new async runtime would add complexity. Scoped threads are simpler and sufficient for 5 concurrent requests.

### Decision 2: Start mDNS daemon before awaiting DB init

**Choice:** In `main()`, call `MDnsLookup::start_daemon()` before `SQLWriter::new().await`, so mDNS service discovery begins while the database schema is being created.

**Rationale:** mDNS daemon uses `OnceLock` for lazy DB connection — it gets its own connection independently when it first needs to write. It doesn't depend on `SQLWriter` being ready. Moving it earlier lets mDNS discovery run during the ~10-100ms DB schema creation window.

**Alternative considered:** Using `tokio::join!` to run DB init, mDNS, and web server concurrently. Rejected because the web server depends on DB being ready (API routes query the database), and mDNS is already non-blocking (spawns background threads immediately). The simple reorder achieves most of the benefit.

### Decision 3: Reduce instance detection timeout from 500ms to 200ms

**Choice:** Lower the `reqwest::blocking::Client` timeout from 500ms to 200ms.

**Rationale:** Instance detection checks localhost only (`127.0.0.1`). A local HTTP server responds in <10ms typically. 200ms is generous for localhost and still handles slow-starting servers. This further reduces worst-case from 500ms to 200ms even with the parallelization.

## Risks / Trade-offs

- **Thread spawning overhead for instance detection** — Spawning 5 scoped threads adds ~1ms overhead. → Mitigation: Negligible compared to the 2+ seconds saved.

- **200ms timeout may miss a very slow instance** — If another instance is under extreme CPU load. → Mitigation: 200ms for localhost is extremely generous; real responses are <10ms. Can be increased if false negatives reported.

- **mDNS starting before DB may attempt writes before schema exists** — The mDNS daemon lazily opens its own DB connection via `OnceLock`. → Mitigation: mDNS uses retry logic for writes, and service discovery takes time before first write. DB schema will be ready well before any mDNS data arrives.
