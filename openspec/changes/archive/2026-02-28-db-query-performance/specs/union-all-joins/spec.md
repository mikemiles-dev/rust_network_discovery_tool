## ADDED Requirements

### Requirement: Replace OR-based communications joins with UNION ALL
All queries that join `endpoints` to `communications` using `e.id = c.src_endpoint_id OR e.id = c.dst_endpoint_id` SHALL be rewritten to use `UNION ALL` of two queries (one for src, one for dst) so that each branch can use a single-column index.

#### Scenario: Combined endpoint stats uses UNION ALL
- **WHEN** `get_combined_endpoint_stats()` is called
- **THEN** the query SHALL use a UNION ALL of src-joined and dst-joined subqueries instead of an OR condition

#### Scenario: Dropdown endpoints uses UNION ALL
- **WHEN** `dropdown_endpoints()` is called
- **THEN** the communications join SHALL use UNION ALL instead of OR

#### Scenario: Last seen query uses UNION ALL
- **WHEN** `get_all_endpoints_last_seen()` is called
- **THEN** the query SHALL use UNION ALL instead of OR-based join

#### Scenario: Online status query uses UNION ALL
- **WHEN** `get_all_endpoints_online_status()` is called
- **THEN** the query SHALL use UNION ALL instead of OR-based join

#### Scenario: Bytes query uses UNION ALL
- **WHEN** `get_all_endpoints_bytes()` is called
- **THEN** the query SHALL use UNION ALL instead of OR-based join
