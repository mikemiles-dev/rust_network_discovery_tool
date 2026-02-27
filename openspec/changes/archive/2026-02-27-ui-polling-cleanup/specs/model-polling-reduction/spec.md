## ADDED Requirements

### Requirement: Reduced model polling frequency
Model polling in `static/js/endpoints.js` SHALL use a 2000ms interval with a maximum of 5 attempts, replacing the current 500ms interval with 20 attempts.

#### Scenario: Model polling interval
- **WHEN** `App.Endpoints.startModelPolling()` is called for a generic-model device
- **THEN** the polling interval SHALL be 2000ms (not 500ms)

#### Scenario: Model polling max attempts
- **WHEN** model polling is active
- **THEN** it SHALL stop after 5 polls (not 20), giving a 10-second total window

#### Scenario: Early stop on model found
- **WHEN** a model change is detected during polling
- **THEN** polling SHALL stop immediately (existing behavior preserved)

#### Scenario: Same devices trigger polling
- **WHEN** an endpoint has a generic model (HP Device, Amazon Device, etc.) and vendor is HP
- **THEN** model polling SHALL start (existing trigger conditions preserved)
