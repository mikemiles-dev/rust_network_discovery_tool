## ADDED Requirements

### Requirement: filters-search.js contains right-pane search and protocol/port filtering
`static/js/filters-search.js` SHALL contain `filterHostnamesList`, `filterPortsList`, `filterIpsList`, `filterMacsList`, `filterByProtocol`, `showProtocolDropdown`, `hideProtocolDropdown`, `selectEndpointFromDropdown`, `clearProtocolFilter`, `filterByPort`, and `clearPortFilter` functions, registered on the `App.Filters` namespace.

#### Scenario: Right-pane list search works
- **WHEN** a user types in the hostnames/ports/IPs/MACs search inputs
- **THEN** the corresponding list SHALL filter identically to before, and URL state SHALL update

#### Scenario: Protocol filtering works
- **WHEN** a user clicks a protocol badge in the details panel
- **THEN** the protocol dropdown SHALL appear showing endpoints that use that protocol

#### Scenario: Port filtering works
- **WHEN** a user clicks a port in the details panel
- **THEN** the endpoints table SHALL filter to show only endpoints with that port

### Requirement: filters-quick.js contains quick filter buttons and vendor/protocol dropdowns
`static/js/filters-quick.js` SHALL contain `selectAll`, `selectNone`, `selectOnly`, `handleClick`, `showOnlyKnownVendors`, `showOnlyUnknown`, `showOnlyActive`, `showOnlyInactive`, `loadGlobalProtocols`, `filterByGlobalProtocol`, `filterByVendor`, and the `canToggle` helper, registered on the `App.Filters` namespace.

#### Scenario: Quick filter buttons work
- **WHEN** a user clicks All, None, Known, Unknown, Active, or Inactive buttons
- **THEN** the filter checkboxes and endpoint visibility SHALL update identically to before

#### Scenario: Global protocol dropdown works
- **WHEN** a user selects a protocol from the global protocol dropdown
- **THEN** the endpoints table SHALL filter to show only endpoints using that protocol

#### Scenario: Vendor dropdown works
- **WHEN** a user selects a vendor from the vendor dropdown
- **THEN** the endpoints table SHALL filter to show only that vendor's endpoints

### Requirement: filters.js remains as coordinator
`static/js/filters.js` SHALL contain `isLocalIP`, `apply` (the main applyFilters function), `updateFilterButtonStates`, `clearAllFilters`, all `window.*` global exports, and the DOMContentLoaded initialization.

#### Scenario: applyFilters renders correct rows
- **WHEN** `applyFilters()` is called after any filter change
- **THEN** endpoint rows SHALL be shown/hidden based on all active filters identically to before

#### Scenario: Global onclick handlers preserved
- **WHEN** HTML onclick attributes reference `applyFilters`, `selectAllFilters`, `selectNoneFilters`, `selectOnlyFilter`, `handleFilterClick`, `showOnlyKnownVendors`, `showOnlyUnknown`, `showOnlyActive`, `showOnlyInactive`, `filterByProtocol`, `filterByGlobalProtocol`, `filterByVendor`, `filterByPort`, `clearPortFilter`, `clearProtocolFilter`, `clearAllFilters`, `isLocalIP`, `filterHostnamesList`, `filterPortsList`, `filterIpsList`, `filterMacsList`
- **THEN** these functions SHALL be available on `window` scope

### Requirement: Load order is correct
`filters-search.js` and `filters-quick.js` SHALL load before `filters.js` in the script tag order.

#### Scenario: Namespace extension is safe
- **WHEN** sub-module files load before the coordinator
- **THEN** they SHALL use `App.Filters = App.Filters || {}` to safely extend the namespace
