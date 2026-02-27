## ADDED Requirements

### Requirement: Hostname classification extracted to sibling module
`src/network/endpoint/classify_hostname.rs` SHALL be created containing all `is_*_hostname` functions and hostname pattern matching logic.

#### Scenario: Module compiles after extraction
- **WHEN** `classify_hostname.rs` exists alongside `classify.rs`
- **THEN** `cargo build` SHALL succeed with no new errors

### Requirement: Service classification extracted to sibling module
`src/network/endpoint/classify_services.rs` SHALL be created containing: `classify_by_services` and `is_computer_by_ports` (mDNS and port-based detection).

#### Scenario: Service-based classification works after split
- **WHEN** the system classifies an endpoint by its mDNS services or open ports
- **THEN** `classify_by_services` SHALL return the same result as before the split

### Requirement: classify.rs retains MAC and model detection
`classify.rs` SHALL retain: pattern helper functions (`matches_pattern`, `matches_prefix`, `matches_conditional`), all `is_*_mac` functions, model/serial detection functions, phone detection, and `is_lg_appliance`.

#### Scenario: MAC-based classification works after split
- **WHEN** the system classifies an endpoint by its MAC vendor
- **THEN** `is_*_mac` functions SHALL return the same results as before the split

#### Scenario: Roku model detection works after split
- **WHEN** the system checks a Roku serial number or TV model
- **THEN** detection SHALL produce the same result as before the split

### Requirement: All classification tests pass
All existing tests in `classify::tests` SHALL pass after the split, with tests placed in the module containing the function they test.

#### Scenario: Test suite passes
- **WHEN** `cargo test` is run
- **THEN** all classification tests SHALL pass

### Requirement: No file exceeds 600 lines
Each resulting file SHALL be under 600 lines.

#### Scenario: Line count check
- **WHEN** the split is complete
- **THEN** `classify.rs`, `classify_hostname.rs`, and `classify_services.rs` SHALL each have fewer than 600 lines
