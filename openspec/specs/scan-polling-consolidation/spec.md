## ADDED Requirements

### Requirement: Single scan status poller in scanner.js
`App.Scanner.startIndicatorPolling()` in `static/js/scanner.js` SHALL be the sole poller for `/api/scan/status`. The `App.startScanIndicatorPolling()` function in `static/js/app.js` SHALL be removed.

#### Scenario: Indicator polling starts on page load
- **WHEN** the page loads
- **THEN** `app.js` SHALL call `App.Scanner.startIndicatorPolling()` instead of `App.startScanIndicatorPolling()`

#### Scenario: No duplicate scan status polling
- **WHEN** a scan is running
- **THEN** only one `setInterval` SHALL poll `/api/scan/status` (not two from different modules)

### Requirement: Fast/slow polling modes
The unified poller SHALL adjust its interval based on scan state and active tab.

#### Scenario: Fast mode on scanner tab during active scan
- **WHEN** `App.state.activeTab === 'scanner'` and a scan is running
- **THEN** the poller SHALL run at 500ms intervals

#### Scenario: Slow mode on other tabs during active scan
- **WHEN** a scan is running but the scanner tab is not active
- **THEN** the poller SHALL run at 5000ms intervals and update only the scan indicator element

#### Scenario: Slow mode when idle
- **WHEN** no scan is running
- **THEN** the poller SHALL run at 5000ms intervals to detect when a new scan starts

#### Scenario: Mode switch on scan start
- **WHEN** a scan is started via `App.Scanner.start()`
- **THEN** the poller SHALL immediately switch to fast mode (500ms)

#### Scenario: Mode switch on scan completion
- **WHEN** a running scan completes (`status.running === false`)
- **THEN** the poller SHALL switch to slow mode (5000ms)

### Requirement: Scan indicator DOM updates
The unified poller SHALL update the scan indicator element on the network tab.

#### Scenario: Indicator shows during active scan
- **WHEN** `status.running === true`
- **THEN** the `#scan-indicator` element SHALL display with phase and progress text

#### Scenario: Indicator hides when idle
- **WHEN** `status.running === false`
- **THEN** the `#scan-indicator` element SHALL be hidden
