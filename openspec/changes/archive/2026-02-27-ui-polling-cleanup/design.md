## Context

The frontend has 18 JS files using an IIFE + `App` namespace pattern. Several modules independently poll the same backend endpoints on overlapping timers:

- **Scan status** (`/api/scan/status`): `app.js` polls every 2s continuously via `startScanIndicatorPolling`. `scanner.js` polls every 500ms when a scan is active. Both run simultaneously during active scans.
- **Notification badge**: `refresh.js` calls `App.Notifications.poll()` on every refresh cycle (5-60s). `notifications.js` has its own 30s `startBadgePolling` interval. Both run simultaneously.
- **Endpoint details** (`/api/endpoint/{name}/details`): On endpoint selection, the details are fetched once, then a probe triggers a re-fetch, then model polling fetches the same endpoint every 500ms up to 20 times. That's up to 22 fetches of the same URL in 10 seconds.

## Goals / Non-Goals

**Goals:**
- Consolidate scan status polling into a single poller owned by `scanner.js`
- Remove notification badge polling overlap — single owner in `notifications.js`
- Reduce model polling from 500ms/20 attempts to 2s/5 attempts (same 10s window, 75% fewer requests)
- Skip redundant endpoint details re-fetch when probe returns `success: false` (no new data)
- Throttle scan indicator polling when not on the scanner tab (5s idle vs 500ms active)

**Non-Goals:**
- Adding WebSocket or Server-Sent Events (that's a larger architectural change)
- Changing any backend API endpoints
- Modifying the auto-refresh module's core timer logic
- Changing any visual behavior — all changes are internal timing/dedup optimizations

## Decisions

### 1. Unified scan status poller in scanner.js

Remove `App.startScanIndicatorPolling()` from `app.js`. Move the scan indicator update logic into `scanner.js` where the scan poller already lives.

`scanner.js` will expose a `App.Scanner.startIndicatorPolling()` method that polls at two rates:
- **Fast mode** (500ms): When a scan is actively running (current behavior)
- **Slow mode** (5s): When no scan is running, just to keep the indicator updated

The `pollStatus` function already checks `status.running` — it will update the indicator DOM element (same HTML IDs as today) as a side effect. When a scan completes, it switches to slow mode. When a scan starts, it switches to fast mode.

`app.js` line 254 (`App.startScanIndicatorPolling()`) will be replaced with `App.Scanner.startIndicatorPolling()`. The entire `App.startScanIndicatorPolling` function (~30 lines) is deleted from `app.js`.

**Alternative considered:** Keeping two separate pollers but coordinating them with a shared "last fetched" timestamp. Rejected because having one owner is simpler and eliminates the coordination problem entirely.

### 2. Single notification badge owner in notifications.js

Remove the badge polling delegation from `refresh.js`. Currently `refresh.js` lines 120-122 call `App.Notifications.poll()` on every refresh cycle, AND `notifications.js` has its own 30s interval.

The fix: delete lines 120-122 from `refresh.js` (the `if (App.state.activeTab !== 'notifications')` block inside `updateInterval`) and lines 162-164 from the `manual` function. The existing 30s badge poller in `notifications.js` becomes the single owner.

Also delete the same pattern from `refresh.js` `manual()` (lines 162-164) since manual refresh shouldn't also trigger a badge poll.

**Alternative considered:** Moving all badge polling into `refresh.js` and removing it from `notifications.js`. Rejected because `notifications.js` is the natural owner — it understands the badge state, and `refresh.js` is a generic timer that shouldn't know about notification internals.

### 3. Reduced model polling frequency

Change `endpoints.js` model polling from `setInterval(..., 500)` with `maxPolls = 20` to `setInterval(..., 2000)` with `maxPolls = 5`. Same 10-second window, but 75% fewer API calls (5 instead of 20).

This only affects HP devices where the model starts as "HP Device" and gets updated via SNMP probe. A 2s poll interval is still responsive enough — users won't notice a 2s delay vs 500ms for a background model update.

### 4. Skip redundant details re-fetch after probe

In `endpoints.js`, the `probeEndpoint` function always re-fetches details after a probe completes, even when `result.success === false` (meaning no new info was found). The fix: only re-fetch details when `result.success === true`.

Current code (endpoints.js `probeEndpoint`):
```javascript
.then(function(result) {
    if (result.success) {
        // Re-fetch details
        fetch('/api/endpoint/...')
```

This is already correct — the re-fetch only happens on `success: true`. But we can also stop model polling early if the probe already updated the model. Add a check: after the probe's re-fetch, if the model is no longer generic, call `stopModelPolling()`.

### 5. Scan indicator throttling by tab

When the scanner tab is not active, the scan indicator (the small bar on the network tab) only needs to update every 5 seconds since users aren't watching it closely. When on the scanner tab, the detailed progress bar should update at 500ms.

The unified poller in scanner.js will check `App.state.activeTab`:
- `activeTab === 'scanner'`: 500ms polling (fast mode, updates detailed progress)
- Any other tab with scan running: 5s polling (slow mode, updates indicator only)
- No scan running: 5s polling (slow mode, just checks if a scan started)

## Risks / Trade-offs

- **Risk: Model update appears 1.5s slower on average** — Users may notice a slight delay before an HP device model badge updates. Mitigation: 2s is still very responsive for a background discovery feature. The badge gets a highlight animation on change, drawing attention.
- **Risk: Badge count may be up to 30s stale** — Previously badge was updated on every refresh cycle (5-60s) AND every 30s. Now it's only every 30s. Mitigation: 30s is fast enough for notification badges. Users check the notifications tab to see real-time counts.
- **Risk: Scan indicator may be 5s stale on network tab** — Previously polled every 2s. Now 5s when not on scanner tab. Mitigation: The indicator is a small secondary UI element. 5s staleness is acceptable. When user switches to scanner tab, it immediately gets fast polling.
- **Trade-off: scanner.js gains indicator responsibility** — Scanner.js grows slightly (~15 lines for indicator DOM updates). Accepted because it eliminates a whole polling loop from app.js.
