## ADDED Requirements

### Requirement: Reduced ARP inter-packet delay
The ARP scanner SHALL use a 2ms default inter-packet delay instead of 10ms.

#### Scenario: ARP scan on /24 subnet
- **WHEN** an ARP scan runs on a /24 subnet (~254 hosts)
- **THEN** ARP request packets SHALL be sent with approximately 2ms between each packet
- **AND** total send time SHALL be approximately 0.5 seconds (not 2.5 seconds)

#### Scenario: ARP responses still collected
- **WHEN** ARP requests are sent with 2ms delay
- **THEN** the receiver SHALL still collect all ARP replies within the timeout window
- **AND** results SHALL be deduplicated by IP as before

### Requirement: Parallel multi-subnet ARP scanning
When multiple subnets are discovered, the ARP scanner SHALL scan all subnets concurrently.

#### Scenario: Multiple subnets present
- **WHEN** the system has 3 active subnets (e.g., 192.168.1.0/24, 192.168.2.0/24, 10.0.0.0/24)
- **THEN** ARP scans for all 3 subnets SHALL run concurrently
- **AND** results from all subnets SHALL be combined into a single result set

#### Scenario: Single subnet present
- **WHEN** the system has only one active subnet
- **THEN** ARP scan behavior SHALL be identical to the current implementation

#### Scenario: Stop signal during multi-subnet scan
- **WHEN** a stop signal is received during parallel subnet scanning
- **THEN** all subnet scans SHALL terminate
