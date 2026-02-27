## ADDED Requirements

### Requirement: endpoints-details.js contains details panel rendering
`static/js/endpoints-details.js` SHALL contain `getDeviceTypeInfo`, `isControllableDevice`, `updateDetails`, and `showLoading` functions, registered on the `App.Endpoints` namespace.

#### Scenario: Details panel renders endpoint info
- **WHEN** `App.Endpoints.updateDetails(data)` is called after selecting an endpoint
- **THEN** the details panel SHALL render identically to before the split (IPs, MACs, hostnames, ports, protocols, vendor, model, bytes)

#### Scenario: Loading state displays correctly
- **WHEN** `App.Endpoints.showLoading()` is called
- **THEN** the details panel SHALL show loading placeholders in all fields

### Requirement: endpoints-actions.js contains merge/delete operations
`static/js/endpoints-actions.js` SHALL contain `mergeEndpoint`, `renderMergeEndpoints`, `filterMergeEndpoints`, `selectMergeTarget`, `closeMergeModal`, `confirmMerge`, `escapeHtml`, and `deleteEndpoint` functions, plus the DOMContentLoaded merge modal setup, registered on the `App.Endpoints` namespace.

#### Scenario: Merge modal opens and functions
- **WHEN** a user clicks the merge button on an endpoint
- **THEN** the merge modal SHALL appear, list available targets, support search filtering, and execute the merge identically to before

#### Scenario: Delete endpoint works
- **WHEN** a user confirms endpoint deletion
- **THEN** the endpoint SHALL be deleted via the API and the page refreshed

### Requirement: endpoints.js remains as coordinator
`static/js/endpoints.js` SHALL contain selection (`selectNode`, `unselectNode`), polling (`startModelPolling`, `stopModelPolling`), probing (`probeEndpoint`, `probeHostname`), navigation (`scrollToSection`, `handleKeyboardNavigation`), and all `window.*` global exports.

#### Scenario: Node selection works
- **WHEN** a user clicks an endpoint row
- **THEN** `selectNode` SHALL highlight the row, show the details panel, and fetch endpoint details identically to before

#### Scenario: Keyboard navigation works
- **WHEN** a user presses arrow keys with an endpoint selected
- **THEN** navigation SHALL move between rows identically to before

#### Scenario: Global onclick handlers preserved
- **WHEN** HTML onclick attributes reference `selectNode`, `unselectNode`, `scrollToSection`, `mergeEndpoint`, `deleteEndpoint`, `probeHostname`, `getDeviceTypeInfo`, or `updateEndpointDetails`
- **THEN** these functions SHALL be available on `window` scope

### Requirement: Load order is correct
`endpoints-details.js` and `endpoints-actions.js` SHALL load before `endpoints.js` in the script tag order.

#### Scenario: Namespace extension is safe
- **WHEN** `endpoints-details.js` loads before the coordinator
- **THEN** it SHALL use `App.Endpoints = App.Endpoints || {}` to safely extend the namespace
