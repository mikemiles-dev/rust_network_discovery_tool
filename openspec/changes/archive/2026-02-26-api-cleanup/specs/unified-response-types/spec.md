## ADDED Requirements

### Requirement: Generic ApiResponse struct
A single `ApiResponse` struct in `src/web/helpers/types.rs` SHALL replace all response structs that only contain `success: bool` and `message: String`.

#### Scenario: ApiResponse replaces ClassifyResponse
- **WHEN** `set_endpoint_type` returns a response
- **THEN** it SHALL use `ApiResponse` instead of `ClassifyResponse`

#### Scenario: ApiResponse replaces DeleteEndpointResponse
- **WHEN** `delete_endpoint` returns a response
- **THEN** it SHALL use `ApiResponse` instead of `DeleteEndpointResponse`

#### Scenario: ApiResponse replaces MergeEndpointsResponse
- **WHEN** `merge_endpoints` returns a response
- **THEN** it SHALL use `ApiResponse` instead of `MergeEndpointsResponse`

#### Scenario: ApiResponse replaces StartScanResponse
- **WHEN** `start_scan` or `stop_scan` returns a response
- **THEN** it SHALL use `ApiResponse` instead of `StartScanResponse`

#### Scenario: ApiResponse replaces UpdateSettingResponse
- **WHEN** `update_setting` returns a response
- **THEN** it SHALL use `ApiResponse` instead of `UpdateSettingResponse`

#### Scenario: ApiResponse replaces SetModelResponse and SetVendorResponse
- **WHEN** `set_endpoint_model` or `set_endpoint_vendor` returns a response
- **THEN** it SHALL use `ApiResponse` instead of the per-handler struct

#### Scenario: Custom response types preserved where needed
- **WHEN** a handler returns extra fields beyond success/message (e.g., `RenameResponse.original_name`, `ProbeResponse.hostname`)
- **THEN** the handler SHALL keep its custom response struct

### Requirement: Shared IpRequest type
A single `IpRequest` struct with field `ip: String` SHALL replace `ProbeRequest`, `PingRequest`, `PortScanRequest`, and `ProbeModelRequest` in `src/web/api/endpoints/probing.rs`.

#### Scenario: Probe handlers use IpRequest
- **WHEN** `probe_hostname`, `ping_endpoint`, `port_scan_endpoint`, or `probe_endpoint_model` receive a request body
- **THEN** the body type SHALL be `Json<IpRequest>`

### Requirement: Shared EndpointNameRequest type
A single `EndpointNameRequest` struct with field `endpoint_name: String` SHALL replace `DeleteEndpointRequest` and `ProbeEndpointRequest`.

#### Scenario: Delete and probe-endpoint handlers use EndpointNameRequest
- **WHEN** `delete_endpoint` or `probe_endpoint` receive a request body
- **THEN** the body type SHALL be `Json<EndpointNameRequest>`

### Requirement: JSON field names unchanged
All JSON field names in API responses SHALL remain identical to before the refactor.

#### Scenario: Frontend compatibility preserved
- **WHEN** the JS frontend parses API responses
- **THEN** it SHALL see the same `success`, `message`, and other field names as before
