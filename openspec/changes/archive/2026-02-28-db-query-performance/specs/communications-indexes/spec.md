## ADDED Requirements

### Requirement: Communications last_seen_at index
The system SHALL create an index on `communications(last_seen_at)` to speed up the time-range filter used in virtually every endpoint query.

#### Scenario: Index exists after schema initialization
- **WHEN** `initialize_schema()` runs
- **THEN** an index `idx_communications_last_seen` on `communications(last_seen_at)` SHALL exist

### Requirement: Communications covering index for endpoint stats
The system SHALL create a composite index on `communications(src_endpoint_id, last_seen_at)` and `communications(dst_endpoint_id, last_seen_at)` to support the most common query pattern: joining communications by endpoint ID with a last_seen_at range filter.

#### Scenario: Covering indexes exist after schema initialization
- **WHEN** `initialize_schema()` runs
- **THEN** indexes `idx_communications_src_last_seen` on `communications(src_endpoint_id, last_seen_at)` and `idx_communications_dst_last_seen` on `communications(dst_endpoint_id, last_seen_at)` SHALL exist
