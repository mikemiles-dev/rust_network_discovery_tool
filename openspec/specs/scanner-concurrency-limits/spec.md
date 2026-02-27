## ADDED Requirements

### Requirement: NetBIOS concurrency limit
The NetBIOS scanner SHALL limit concurrent blocking tasks to 50 using a semaphore.

#### Scenario: Large subnet scan
- **WHEN** NetBIOS scans 254 IPs on a /24 subnet
- **THEN** no more than 50 blocking tasks SHALL run simultaneously
- **AND** all 254 IPs SHALL still be scanned (tasks queue for semaphore permits)

#### Scenario: Small subnet scan
- **WHEN** NetBIOS scans 20 IPs
- **THEN** all 20 tasks SHALL run concurrently without semaphore blocking

#### Scenario: Results unchanged
- **WHEN** NetBIOS scan completes with semaphore limiting
- **THEN** results SHALL be identical to the current unlimited implementation

### Requirement: SNMP concurrency limit
The SNMP scanner SHALL limit concurrent blocking tasks to 50 using a semaphore.

#### Scenario: Large subnet scan
- **WHEN** SNMP scans 254 IPs on a /24 subnet
- **THEN** no more than 50 blocking tasks SHALL run simultaneously
- **AND** all 254 IPs SHALL still be scanned

#### Scenario: Community string iteration preserved
- **WHEN** SNMP queries an IP with community strings ["public", "private"]
- **THEN** community strings SHALL still be tried sequentially within each task
- **AND** the semaphore SHALL gate task-level concurrency, not per-community-string
