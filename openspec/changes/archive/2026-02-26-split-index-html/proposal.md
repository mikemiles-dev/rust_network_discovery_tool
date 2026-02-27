## Why

`templates/index.html` is 3,115 lines — a monolithic file containing 1,889 lines of embedded CSS, 7 tab sections, a detail panel with 3 sub-tabs, device remote controls, modals, and initialization JS. Finding and modifying any single component requires scrolling through the entire file. Splitting it into Tera partials makes each section independently editable and easier to understand.

## What Changes

- Extract the 1,889-line embedded `<style>` block into a standalone CSS file served as a static asset
- Extract each of the 7 tab sections (Internet, DNS, Scanner, PCAP, Notifications, Settings, plus the main Network tab content) into Tera `{% include %}` partials
- Extract the endpoint details right panel (with its 3 sub-tabs: Details, Network Actions, Controls) into a partial
- Extract the filter bar and search bar into partials
- Extract modal overlays (merge modal, protocol dropdown) into partials
- Update `index.html` to be a thin layout shell that includes all partials
- Update Tera template loading in `web/mod.rs` to glob partials from subdirectories

## Capabilities

### New Capabilities

- `css-extraction`: Extract embedded CSS into a standalone stylesheet loaded as a static asset
- `tab-partials`: Extract each tab section into a Tera include partial
- `component-partials`: Extract reusable UI components (filter bar, search bar, details panel, modals) into partials

### Modified Capabilities

## Impact

- `templates/index.html` reduced from 3,115 lines to ~100 lines (layout shell)
- New `templates/partials/` directory with ~12-15 partial files
- New `static/css/` file for extracted styles (or embedded in `templates/` as a Tera partial)
- `src/web/mod.rs` may need Tera glob pattern update for subdirectory loading
- No Rust logic changes — all template variables and context remain the same
- All 19 external JS files remain unchanged — they reference DOM IDs which stay the same
- All existing tests continue to pass (no backend changes)
