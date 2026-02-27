## ADDED Requirements

### Requirement: Concurrent SSDP device description fetches
After SSDP multicast discovery, device description HTTP fetches SHALL run concurrently with a maximum of 10 simultaneous requests.

#### Scenario: Multiple devices discovered
- **WHEN** SSDP discovery finds 20 devices with location URLs
- **THEN** device description HTTP fetches SHALL run concurrently (up to 10 at a time)
- **AND** total fetch time SHALL be approximately ceil(20/10) * timeout instead of 20 * timeout

#### Scenario: Fewer devices than concurrency limit
- **WHEN** SSDP discovery finds 5 devices
- **THEN** all 5 HTTP fetches SHALL run concurrently (no semaphore blocking)

#### Scenario: HTTP fetch timeout
- **WHEN** a device description HTTP fetch times out
- **THEN** that device's friendly_name and model_name SHALL remain None
- **AND** other concurrent fetches SHALL not be affected

#### Scenario: Results preserved
- **WHEN** device description fetches complete (some successful, some failed)
- **THEN** results SHALL contain the same data as the current sequential implementation
