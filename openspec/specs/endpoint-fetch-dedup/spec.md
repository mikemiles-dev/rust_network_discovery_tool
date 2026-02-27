## ADDED Requirements

### Requirement: Stop model polling when probe updates model
After a successful probe re-fetches endpoint details, model polling SHALL stop if the model is no longer generic.

#### Scenario: Probe finds specific model
- **WHEN** `probeEndpoint` re-fetches details and the returned `device_model` is not in the generic list
- **THEN** `App.Endpoints.stopModelPolling()` SHALL be called

#### Scenario: Probe finds no new info
- **WHEN** `probeEndpoint` returns `success: false`
- **THEN** details SHALL NOT be re-fetched (existing behavior — the re-fetch is already gated on `result.success`)

#### Scenario: Model still generic after probe
- **WHEN** the probe re-fetches details but the model is still generic (e.g., "HP Device")
- **THEN** model polling SHALL continue as normal
