## ADDED Requirements

### Requirement: Single query for endpoint metadata in details view
The endpoint details handler SHALL fetch ssdp_model, custom_model, custom_vendor, ssdp_friendly_name, snmp_vendor, snmp_model, and dhcp_vendor_class in a single database query instead of multiple separate queries.

#### Scenario: Details view issues one metadata query
- **WHEN** `get_endpoint_details_blocking()` is called for an endpoint
- **THEN** a single query SHALL retrieve all endpoint metadata (custom_model, ssdp_model, custom_vendor, ssdp_friendly_name, snmp_vendor, snmp_model, dhcp_vendor_class) from the endpoints and endpoint_attributes tables

#### Scenario: Existing behavior preserved
- **WHEN** the consolidated query returns results
- **THEN** the same vendor, model, and device type classification logic SHALL apply identically to the current multi-query implementation
