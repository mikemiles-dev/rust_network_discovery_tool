## ADDED Requirements

### Requirement: Each tab section extracted into a partial
Each of the 7 tab content sections SHALL be extracted into its own partial file under `templates/partials/`. The original index.html SHALL replace each section with a `{% include %}` directive.

#### Scenario: Internet tab partial
- **WHEN** `templates/partials/internet-tab.html` exists
- **THEN** it SHALL contain the complete `#internet-tab` content div and its children

#### Scenario: DNS tab partial
- **WHEN** `templates/partials/dns-tab.html` exists
- **THEN** it SHALL contain the complete `#dns-tab` content div and its children, including the Tera `{% for %}` loop for DNS entries

#### Scenario: Scanner tab partial
- **WHEN** `templates/partials/scanner-tab.html` exists
- **THEN** it SHALL contain the complete `#scanner-tab` content div and its children

#### Scenario: PCAP tab partial
- **WHEN** `templates/partials/pcap-tab.html` exists
- **THEN** it SHALL contain the complete `#pcap-tab` content div and its children

#### Scenario: Notifications tab partial
- **WHEN** `templates/partials/notifications-tab.html` exists
- **THEN** it SHALL contain the complete `#notifications-tab` content div and its children

#### Scenario: Settings tab partial
- **WHEN** `templates/partials/settings-tab.html` exists
- **THEN** it SHALL contain the complete `#settings-tab` content div and its children

#### Scenario: Network tab partial
- **WHEN** `templates/partials/network-tab.html` exists
- **THEN** it SHALL contain the `#network-tab` wrapper div that includes the filter bar, search bar, endpoints table, and endpoint details panel (each of which may themselves be `{% include %}` directives)

### Requirement: Tab sections preserve DOM IDs
Every DOM element with an `id` attribute SHALL retain its exact `id` value after extraction. All `class` attributes SHALL be preserved.

#### Scenario: JS files work without modification
- **WHEN** the partials are included into index.html
- **THEN** all 19 external JS files in `static/js/` SHALL function identically without any changes

### Requirement: Tera template variables work in partials
All Tera variables, loops, and conditionals used within tab sections SHALL continue to resolve correctly since Tera includes inherit the parent template's context.

#### Scenario: DNS entries loop renders
- **WHEN** the dns-tab partial contains `{% for entry in dns_entries %}`
- **THEN** the loop SHALL render identically to when it was inline in index.html
