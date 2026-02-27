## ADDED Requirements

### Requirement: Concurrent scan phase execution
The scan manager SHALL run all requested scan types concurrently instead of sequentially, using `tokio::task::JoinSet` to spawn and track each phase.

#### Scenario: Multiple scan types requested
- **WHEN** a scan is started with types [ARP, SSDP, NetBIOS, SNMP]
- **THEN** all four scan types SHALL begin executing concurrently
- **AND** the total scan duration SHALL be approximately the duration of the slowest phase, not the sum of all phases

#### Scenario: Single scan type requested
- **WHEN** a scan is started with only one type (e.g., [ARP])
- **THEN** the behavior SHALL be identical to the current sequential implementation

#### Scenario: Stop signal during concurrent execution
- **WHEN** a stop signal is received while multiple scan phases are running concurrently
- **THEN** all active phases SHALL check the stop signal and terminate

### Requirement: Concurrent progress tracking
The scan manager SHALL track progress across concurrently running phases using an atomic counter.

#### Scenario: Progress updates during concurrent scan
- **WHEN** multiple scan phases are running concurrently and one phase completes
- **THEN** `progress_percent` SHALL reflect the number of completed phases out of total phases (e.g., 1 of 4 = 25%)

#### Scenario: Current phase display during concurrent scan
- **WHEN** multiple scan phases are running concurrently
- **THEN** `current_phase` SHALL display the names of all active scan types (e.g., "ARP, SSDP, SNMP scan")

### Requirement: Concurrent result delivery
Each concurrent scan phase SHALL send results to the shared `result_tx` channel independently.

#### Scenario: Results from concurrent phases
- **WHEN** ARP and SSDP phases both discover devices simultaneously
- **THEN** both SHALL send results to the result channel without blocking each other
