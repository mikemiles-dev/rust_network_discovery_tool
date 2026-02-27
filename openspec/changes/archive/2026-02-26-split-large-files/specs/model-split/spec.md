## ADDED Requirements

### Requirement: Hostname model detection extracted to sibling module
`src/network/endpoint/hostname_model.rs` SHALL be created containing `get_model_from_hostname` and its brand-specific helper logic.

#### Scenario: Module compiles after extraction
- **WHEN** `hostname_model.rs` exists alongside `model.rs`
- **THEN** `cargo build` SHALL succeed with no new errors

### Requirement: model.rs retains normalization and inference
`model.rs` SHALL retain: `normalize_model_name`, `characterize_model`, `infer_model_with_context`, `get_model_from_mac`, `get_model_from_vendor_and_type`, and all tests.

#### Scenario: Model normalization works after split
- **WHEN** the system normalizes a model name (e.g., Samsung TV series)
- **THEN** the normalized result SHALL be identical to before the split

### Requirement: Hostname-based model detection preserved
`get_model_from_hostname` in `hostname_model.rs` SHALL detect models from hostnames for all supported brands (Samsung, LG, Sony, Roku, Google/Nest, Amazon, Huawei, Apple, etc.).

#### Scenario: Hostname model detection works after split
- **WHEN** an endpoint has a hostname matching a known brand pattern
- **THEN** `get_model_from_hostname` SHALL return the same model as before the split

### Requirement: No file exceeds 600 lines
Both `model.rs` and `hostname_model.rs` SHALL be under 600 lines.

#### Scenario: Line count check
- **WHEN** the split is complete
- **THEN** both files SHALL have fewer than 600 lines
