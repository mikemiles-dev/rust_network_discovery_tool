## ADDED Requirements

### Requirement: Single badge polling owner
`notifications.js` SHALL be the sole owner of notification badge polling. `refresh.js` SHALL NOT call `App.Notifications.poll()`.

#### Scenario: Refresh cycle does not poll badge
- **WHEN** the auto-refresh interval fires in `refresh.js`
- **THEN** it SHALL NOT call `App.Notifications.poll()` (lines 120-122 removed)

#### Scenario: Manual refresh does not poll badge
- **WHEN** `App.Refresh.manual()` is called
- **THEN** it SHALL NOT call `App.Notifications.poll()` (lines 162-164 removed)

#### Scenario: Badge polling continues in notifications.js
- **WHEN** the page is loaded
- **THEN** `App.Notifications.startBadgePolling()` SHALL continue to run its own 30s interval as before

#### Scenario: Badge updates on notifications tab
- **WHEN** the notifications tab is active and `App.Notifications.refresh()` is called
- **THEN** the badge SHALL still update from the full refresh response (existing behavior preserved)
