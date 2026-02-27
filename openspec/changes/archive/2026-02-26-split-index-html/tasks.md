## 1. Setup and CSS extraction

- [x] 1.1 Create `templates/partials/` directory
- [x] 1.2 Extract `<style>...</style>` block (lines 16-1904) into `templates/partials/styles.html`
- [x] 1.3 Replace the style block in `index.html` with `{% include "partials/styles.html" %}`
- [x] 1.4 Verify `cargo build` succeeds and page renders correctly

## 2. Extract header and tab navigation

- [x] 2.1 Extract header section (logo + tab buttons) into `templates/partials/header.html`
- [x] 2.2 Replace in `index.html` with `{% include "partials/header.html" %}`

## 3. Extract secondary tab sections

- [x] 3.1 Extract Internet tab content into `templates/partials/internet-tab.html`
- [x] 3.2 Extract DNS tab content into `templates/partials/dns-tab.html`
- [x] 3.3 Extract Scanner tab content into `templates/partials/scanner-tab.html`
- [x] 3.4 Extract PCAP tab content into `templates/partials/pcap-tab.html`
- [x] 3.5 Extract Notifications tab content into `templates/partials/notifications-tab.html`
- [x] 3.6 Extract Settings tab content into `templates/partials/settings-tab.html`
- [x] 3.7 Replace each section in `index.html` with corresponding `{% include %}` directives
- [x] 3.8 Verify `cargo build` succeeds and all tabs render correctly

## 4. Extract Network tab components

- [x] 4.1 Extract filter bar (type checkboxes + quick buttons + vendor/protocol dropdowns) into `templates/partials/filter-bar.html`
- [x] 4.2 Extract search bar (search input + refresh controls) into `templates/partials/search-bar.html`
- [x] 4.3 Extract endpoints table (table header + Tera row loop + pagination) into `templates/partials/endpoints-table.html`
- [x] 4.4 Extract endpoint details right panel (all 3 sub-tabs + remote controls) into `templates/partials/endpoint-details.html`
- [x] 4.5 Create `templates/partials/network-tab.html` as a wrapper containing `{% include %}` directives for filter-bar, search-bar, endpoints-table, and endpoint-details
- [x] 4.6 Replace Network tab content in `index.html` with `{% include "partials/network-tab.html" %}`
- [x] 4.7 Verify `cargo build` succeeds and Network tab renders correctly with all sub-components

## 5. Extract modals and finalize

- [x] 5.1 Extract merge modal and protocol dropdown overlays into `templates/partials/modals.html`
- [x] 5.2 Replace in `index.html` with `{% include "partials/modals.html" %}`
- [x] 5.3 Verify `index.html` is under 100 lines (layout shell with includes + script tags + init JS)
- [x] 5.4 Verify `cargo build` succeeds with no Rust code changes
- [x] 5.5 Verify all DOM IDs are preserved — no JavaScript files modified
- [x] 5.6 Full functional test: all tabs render, filters work, endpoint selection works, details panel shows, remote controls display
