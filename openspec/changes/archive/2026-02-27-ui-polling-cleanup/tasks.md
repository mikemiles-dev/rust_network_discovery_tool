## 1. Consolidate scan status polling

- [x] 1.1 Add `App.Scanner.startIndicatorPolling()` to `static/js/scanner.js` — creates a single `setInterval` that polls `/api/scan/status`, updates both the scanner tab progress UI (`#scan-progress-fill`, `#scan-progress-text`, `#scan-phase`, `#discovered-count`, `#last-scan-time`) AND the network tab indicator (`#scan-indicator`, `#scan-indicator-phase`, `#scan-indicator-progress`), with fast mode (500ms) when scan is active and slow mode (5000ms) when idle
- [x] 1.2 Update `App.Scanner.start()` in `scanner.js` — remove the inline `scanPollInterval = setInterval(App.Scanner.pollStatus, 500)` (line 41) since the unified poller handles fast mode switching; instead call a function to switch to fast mode
- [x] 1.3 Update `App.Scanner.runAutoScan()` in `scanner.js` — remove the inline `scanPollInterval = setInterval(App.Scanner.pollStatus, 500)` (line 251) for the same reason
- [x] 1.4 Delete `App.startScanIndicatorPolling` function from `static/js/app.js` (lines 464-492) and replace the call on line 254 with `App.Scanner.startIndicatorPolling()`

## 2. Unify notification badge polling

- [x] 2.1 Remove badge polling from `refresh.js` `updateInterval` — delete lines 119-122 (`if (App.state.activeTab !== 'notifications' && App.Notifications) { App.Notifications.poll(); }`) inside the `setInterval` callback
- [x] 2.2 Remove badge polling from `refresh.js` `manual` — delete lines 162-164 (same `App.Notifications.poll()` call in the manual refresh function)

## 3. Reduce model polling frequency

- [x] 3.1 Change model polling interval in `static/js/endpoints.js` `startModelPolling` from `500` to `2000` (the `setInterval` delay)
- [x] 3.2 Change `maxPolls` in `startModelPolling` from `20` to `5` (same 10-second total window)

## 4. Endpoint fetch dedup

- [x] 4.1 In `static/js/endpoints.js` `probeEndpoint`, after the probe re-fetches details successfully, check if the model is no longer generic and call `App.Endpoints.stopModelPolling()` if so

## 5. Validation

- [x] 5.1 Verify `cargo check` succeeds (RustEmbed picks up unchanged static files)
- [x] 5.2 Verify only one `setInterval` polls `/api/scan/status` by searching for all `/api/scan/status` fetch calls across JS files
- [x] 5.3 Verify `App.Notifications.poll` is not called from `refresh.js`
