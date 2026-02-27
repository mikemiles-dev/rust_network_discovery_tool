## ADDED Requirements

### Requirement: Database errors return HTTP 500
All handlers that encounter a database error (rusqlite error, connection failure) SHALL return `HttpResponse::InternalServerError()` with `ApiResponse { success: false, message }`.

#### Scenario: Consistent 500 on DB error in crud handlers
- **WHEN** a CRUD handler (`set_endpoint_type`, `rename_endpoint`, `set_endpoint_model`, `set_endpoint_vendor`, `delete_endpoint`, `merge_endpoints`) encounters a database error
- **THEN** it SHALL return HTTP 500 with a JSON body containing `success: false`

#### Scenario: Consistent 500 on DB error in settings handlers
- **WHEN** `update_setting` encounters a database error
- **THEN** it SHALL return HTTP 500 with `success: false`

### Requirement: Not-found cases return HTTP 404
All handlers that look up an endpoint by name and find no match SHALL return `HttpResponse::NotFound()`.

#### Scenario: Delete unknown endpoint returns 404
- **WHEN** `delete_endpoint` is called with a name that matches no endpoints
- **THEN** it SHALL return HTTP 404 with `success: false`

#### Scenario: Merge unknown endpoint returns 404
- **WHEN** `merge_endpoints` is called and either target or source is not found
- **THEN** it SHALL return HTTP 404 with `success: false`

### Requirement: Probe "not found" results stay HTTP 200
Probing handlers that successfully execute but find no data SHALL continue returning HTTP 200 with `success: false` in the body, since the probe itself did not error.

#### Scenario: Hostname probe returns no result
- **WHEN** `probe_hostname` runs but DNS lookup returns nothing
- **THEN** it SHALL return HTTP 200 with `success: false`

#### Scenario: NetBIOS probe returns no result
- **WHEN** `probe_netbios` runs but finds no NetBIOS name
- **THEN** it SHALL return HTTP 200 with `success: false`

### Requirement: Database errors logged with eprintln
All handlers that catch a database error SHALL log it with `eprintln!` before returning the error response. Silent error swallowing SHALL be eliminated.

#### Scenario: Devices handler logs errors
- **WHEN** `get_device_capabilities` encounters an error
- **THEN** it SHALL log the error with `eprintln!` before returning HTTP 500
