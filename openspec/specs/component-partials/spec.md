## ADDED Requirements

### Requirement: Header extracted into a partial
`templates/partials/header.html` SHALL contain the header section with the logo and tab navigation buttons.

#### Scenario: Header partial renders correctly
- **WHEN** `{% include "partials/header.html" %}` is used in index.html
- **THEN** the tab navigation SHALL render and function identically to before

### Requirement: Filter bar extracted into a partial
`templates/partials/filter-bar.html` SHALL contain the type filter checkboxes, quick filter buttons, and vendor/protocol dropdowns.

#### Scenario: Filter bar partial renders correctly
- **WHEN** `{% include "partials/filter-bar.html" %}` is used in network-tab.html
- **THEN** all filter checkboxes and dropdowns SHALL render with correct IDs for `filters.js`

### Requirement: Search bar extracted into a partial
`templates/partials/search-bar.html` SHALL contain the search input, refresh interval controls, and refresh toggle button.

#### Scenario: Search bar partial renders correctly
- **WHEN** `{% include "partials/search-bar.html" %}` is used in network-tab.html
- **THEN** search and refresh controls SHALL function identically

### Requirement: Endpoints table extracted into a partial
`templates/partials/endpoints-table.html` SHALL contain the table header, the Tera `{% for %}` row loop with all `{% set %}` variable extractions, and the pagination controls.

#### Scenario: Table renders with endpoint data
- **WHEN** the partial is included and `dropdown_endpoints` contains data
- **THEN** the table SHALL render rows with correct endpoint names, types, vendors, models, bandwidth, and online status

#### Scenario: Endpoint row click navigation works
- **WHEN** a user clicks an endpoint row
- **THEN** `endpoints.js` SHALL handle the click identically (DOM IDs and classes preserved)

### Requirement: Endpoint details panel extracted into a partial
`templates/partials/endpoint-details.html` SHALL contain the right-side details panel with all 3 sub-tabs (Details, Network Actions, Controls) and all device-specific remote control UIs (Roku, Samsung, LG ThinQ).

#### Scenario: Details panel shows endpoint information
- **WHEN** an endpoint is selected and the partial is included
- **THEN** the panel SHALL display IPs, MACs, hostnames, ports, protocols, vendor, model, and bandwidth identically to before

#### Scenario: Remote controls render for supported devices
- **WHEN** a Roku/Samsung/LG device is selected
- **THEN** the corresponding remote control UI SHALL render with all buttons and functionality intact

### Requirement: Modals extracted into a partial
`templates/partials/modals.html` SHALL contain the merge endpoint modal overlay and the protocol selection dropdown overlay.

#### Scenario: Merge modal functions correctly
- **WHEN** a user triggers the merge action
- **THEN** the modal SHALL appear and function identically to before

### Requirement: index.html becomes a layout shell
After all extractions, `index.html` SHALL contain only the HTML document structure (`<!DOCTYPE>`, `<html>`, `<head>`, `<body>`), `{% include %}` directives for all partials, external `<script>` imports, and the initialization script.

#### Scenario: Layout shell is concise
- **WHEN** all partials are extracted
- **THEN** `index.html` SHALL be under 100 lines

### Requirement: No Rust code changes
The `RustEmbed` directive and Tera template loading in `src/web/mod.rs` SHALL NOT require any modifications. Partials SHALL be automatically discovered by the existing `Templates::iter()` loop.

#### Scenario: Build succeeds without code changes
- **WHEN** `cargo build` is run after creating partials
- **THEN** compilation SHALL succeed without modifying any `.rs` files
