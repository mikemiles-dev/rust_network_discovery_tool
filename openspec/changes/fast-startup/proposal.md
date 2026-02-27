## Why

The web server startup is slower than necessary because the instance detection check sequentially probes up to 5 ports with 500ms timeouts each (up to 2.5 seconds worst-case), and initialization steps (DB schema, template compilation, instance detection) run sequentially when they could overlap.

## What Changes

- Parallelize instance detection HTTP checks across all candidate ports using concurrent requests instead of sequential iteration
- Overlap DB initialization, mDNS daemon startup, and web server spawning where possible in `main()`

## Capabilities

### New Capabilities
- `parallel-instance-check`: Check all candidate ports concurrently during instance detection, reducing worst-case time from 2.5s to ~500ms
- `parallel-startup-init`: Overlap independent initialization steps (DB schema creation, mDNS daemon, web server template loading) to reduce total startup time

### Modified Capabilities

_(none — no existing spec requirements change)_

## Impact

- **Files:** `src/web/mod.rs` (instance detection), `src/main.rs` (startup sequence)
- **Behavior:** Application reaches "web server accepting connections" state faster; no functional changes
- **Risk:** Minimal — instance detection still checks same ports with same timeout, just concurrently; startup order preserved where dependencies exist
