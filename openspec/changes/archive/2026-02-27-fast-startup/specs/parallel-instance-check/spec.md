## ADDED Requirements

### Requirement: Concurrent port checking for instance detection
The `detect_existing_instance` function SHALL check all candidate ports concurrently using scoped threads instead of sequentially iterating.

#### Scenario: No existing instance running
- **WHEN** no other instance is running on any of the candidate ports
- **THEN** the function SHALL return `None` within approximately 200ms (one timeout window), not 1000ms+ (sequential timeouts)

#### Scenario: Existing instance found on first port
- **WHEN** an existing instance is running on the preferred port (e.g., 8080)
- **THEN** the function SHALL return `Some((port, pid))` as soon as any thread detects it
- **AND** the result SHALL be identical to the current sequential implementation

#### Scenario: Existing instance found on fallback port
- **WHEN** an existing instance is running on a non-preferred port (e.g., 8083)
- **THEN** the function SHALL still detect it and return `Some((port, pid))`

### Requirement: Reduced instance detection timeout
The HTTP client timeout for instance detection SHALL be 200ms instead of 500ms.

#### Scenario: Localhost response time
- **WHEN** an instance is running on localhost
- **THEN** a 200ms timeout SHALL be sufficient to detect it (localhost responses are typically <10ms)

#### Scenario: No instance on port
- **WHEN** no instance is running on a given port
- **THEN** the connection SHALL fail or timeout within 200ms
