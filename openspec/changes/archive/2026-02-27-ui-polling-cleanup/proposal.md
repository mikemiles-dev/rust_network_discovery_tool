## Why

The JS frontend has multiple overlapping polling loops hitting the same API endpoints, redundant fetch chains on endpoint selection, and aggressive timers that create unnecessary load. `/api/scan/status` is polled from two separate modules simultaneously (app.js at 2s + scanner.js at 500ms). Notification badge polling runs from both refresh.js and notifications.js. Selecting an HP device can trigger 22 fetches to `/api/endpoint/{name}/details` in 10 seconds. Consolidating these patterns will reduce API load, simplify the code, and make the UI feel less "busy".

## What Changes

- Consolidate scan status polling into a single poller with fast/slow modes (replace dual app.js + scanner.js pollers)
- Unify notification badge polling into notifications.js only (remove overlap from refresh.js)
- Reduce model polling aggressiveness from 500ms/20 polls to 2s/5 polls (same 10s window, 75% fewer requests)
- Deduplicate endpoint details fetching by caching the last result briefly and skipping re-fetch when probe returns no new data
- Throttle scan indicator polling when not on the scanner tab

## Capabilities

### New Capabilities
- `scan-polling-consolidation`: Merge the two scan status pollers (app.js 2s continuous + scanner.js 500ms active) into a single configurable poller
- `notification-polling-unification`: Remove overlapping badge polling from refresh.js, keep single 30s poller in notifications.js
- `model-polling-reduction`: Reduce model discovery polling from 500ms to 2s intervals with fewer max attempts
- `endpoint-fetch-dedup`: Cache endpoint details briefly after selection to avoid redundant re-fetches during probe/model polling

### Modified Capabilities

## Impact

- `static/js/app.js` — Remove scan indicator polling (moved to scanner.js)
- `static/js/scanner.js` — Add unified scan status poller with fast (500ms active) / slow (5s idle) modes
- `static/js/refresh.js` — Remove notification badge polling delegation
- `static/js/notifications.js` — Becomes sole owner of badge polling
- `static/js/endpoints.js` — Reduce model polling frequency; add details cache
- `static/js/endpoints-details.js` — Use cached details when available
- No Rust/backend changes
- No HTML/template changes
- No behavioral changes — pure optimization
