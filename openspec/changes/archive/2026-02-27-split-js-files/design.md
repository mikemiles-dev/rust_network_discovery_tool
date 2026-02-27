## Context

The `static/js/` directory has 18 files using an IIFE + `App` namespace pattern. Files are loaded as `<script>` tags in order — no bundler. All modules communicate through the global `App` namespace and expose onclick handlers via `window`. The two largest files — `endpoints.js` (876 lines) and `filters.js` (855 lines) — each contain 3-4 distinct functional areas. Additionally, `getPageNumbers()` is copy-pasted identically in `pagination.js`, `notifications.js`, and `internet.js`.

## Goals / Non-Goals

**Goals:**
- Split `endpoints.js` into 3 focused files, each under 400 lines
- Split `filters.js` into 3 focused files, each under 400 lines
- Eliminate duplicated `getPageNumbers()` from `notifications.js` and `internet.js`
- Add a shared `renderPaginationUI()` helper to `pagination.js`
- Preserve all `window.*` global function exports for HTML onclick handlers
- Preserve the `App.Endpoints` and `App.Filters` namespace interfaces

**Non-Goals:**
- Introducing a JS module bundler (ES modules, webpack, etc.)
- Refactoring the App namespace pattern itself
- Splitting files that are already under 500 lines
- Changing any HTML, Tera templates, or DOM IDs
- Modifying any behavior

## Decisions

### 1. Split endpoints.js into 3 files

**endpoints-details.js** (~250 lines): Details panel rendering
- `getDeviceTypeInfo` (lines 88-102)
- `isControllableDevice` (lines 107-122)
- `updateDetails` (lines 127-317)
- `showLoading` (lines 322-359)
- Registers on `App.Endpoints` namespace

**endpoints-actions.js** (~220 lines): Merge/delete actions
- `mergeEndpoint` (lines 598-627)
- `renderMergeEndpoints` (lines 632-657)
- `filterMergeEndpoints` (lines 662-678)
- `selectMergeTarget` (lines 683-697)
- `closeMergeModal` (lines 702-706)
- `confirmMerge` (lines 711-743)
- `escapeHtml` (lines 748-752)
- `deleteEndpoint` (lines 757-781)
- DOMContentLoaded merge modal setup (lines 841-864)
- Registers on `App.Endpoints` namespace

**endpoints.js** (~400 lines): Selection, navigation, probing + coordinator
- `startModelPolling` / `stopModelPolling` (lines 20-84)
- `selectNode` (lines 364-431)
- `probeEndpoint` (lines 437-459)
- `unselectNode` (lines 464-550)
- `scrollToSection` (lines 555-560)
- `probeHostname` (lines 565-593)
- `handleKeyboardNavigation` (lines 787-838)
- All `window.*` global exports (lines 867-874)

Load order: `endpoints-details.js` → `endpoints-actions.js` → `endpoints.js`

The coordinator (`endpoints.js`) loads last and wires up the global exports. The details and actions files extend the `App.Endpoints` namespace that the coordinator owns.

**Alternative considered:** 4-file split separating polling from selection. Rejected because polling is tightly coupled to selection (model polling starts when a node is selected) — splitting them would create circular dependencies.

### 2. Split filters.js into 3 files

**filters-search.js** (~200 lines): Right-pane search + protocol/port/vendor filtering
- `filterHostnamesList` (lines 414-436)
- `filterPortsList` (lines 441-463)
- `filterIpsList` (lines 468-490)
- `filterMacsList` (lines 495-517)
- `filterByProtocol` (lines 522-540)
- `showProtocolDropdown` (lines 545-597)
- `hideProtocolDropdown` (lines 602-607)
- `selectEndpointFromDropdown` (lines 612-617)
- `clearProtocolFilter` (lines 622-630)
- `filterByPort` (lines 706-736)
- `clearPortFilter` (lines 741-756)
- Registers on `App.Filters` namespace

**filters-quick.js** (~220 lines): Quick filter buttons + vendor/protocol dropdowns
- `selectAll` (lines 59-78)
- `selectNone` (lines 159-171)
- `selectOnly` (lines 176-196)
- `handleClick` (lines 201-208)
- `showOnlyKnownVendors` (lines 83-98)
- `showOnlyUnknown` (lines 103-118)
- `showOnlyActive` (lines 123-136)
- `showOnlyInactive` (lines 141-154)
- `loadGlobalProtocols` (lines 635-657)
- `filterByGlobalProtocol` (lines 663-701)
- `filterByVendor` (lines 761-775)
- `canToggle` helper (lines 11-18)
- Registers on `App.Filters` namespace

**filters.js** (~400 lines): Core filtering + coordinator
- `isLocalIP` (lines 24-54)
- `apply` (lines 213-358) — the main applyFilters function
- `updateFilterButtonStates` (lines 363-409)
- `clearAllFilters` (lines 803-848)
- All `window.*` global exports (lines 779-798)
- DOMContentLoaded initialization

Load order: `filters-search.js` → `filters-quick.js` → `filters.js`

The coordinator loads last, calls `loadGlobalProtocols()` on init, and exposes all global functions. Sub-modules extend the `App.Filters` namespace.

### 3. Extend pagination.js with shared helpers

Expose `getPageNumbers` as `App.Pagination.getPageNumbers` (it's currently a local function).

Add a `renderPaginationUI(config)` shared helper:
```javascript
App.Pagination.renderPaginationUI = function(config) {
    // config: { controlsId, currentPage, totalPages, onPageClick, btnClass, ellipsisClass }
};
```

Then replace the inline implementations:
- `notifications.js` lines 168-213 + 443-454: Remove local `getPageNumbers`, call `App.Pagination.getPageNumbers` and `App.Pagination.renderPaginationUI`
- `internet.js` lines 126-159 + 164-184: Remove local `getPageNumbers` method, call shared helpers

### 4. Script tag load order in index.html

New load order (new files marked with `+`):
```
theme.js → utils.js → formatting.js → pagination.js → tabs.js →
scanner.js → pcap.js →
+ endpoints-details.js → + endpoints-actions.js → endpoints.js →
+ filters-search.js → + filters-quick.js → filters.js →
classification.js → refresh.js →
device-control.js → lg-thinq.js → internet.js →
settings.js → network-actions.js → notifications.js → app.js
```

Sub-module files load before their coordinator to ensure namespace extensions are registered before the coordinator wires up global exports.

### 5. Namespace extension pattern

Each sub-module extends its parent namespace without recreating it:
```javascript
(function() {
    // Ensure parent namespace exists (coordinator may not have loaded yet)
    App.Endpoints = App.Endpoints || {};

    App.Endpoints.updateDetails = function(data) { ... };
    App.Endpoints.showLoading = function() { ... };
})();
```

The coordinator file initializes the namespace fresh, but sub-modules use `= App.X || {}` to be safe regardless of load order during development.

## Risks / Trade-offs

- **Risk: Load order sensitivity** → Mitigation: Sub-modules use `App.X = App.X || {}` pattern. Coordinator loads last and sets up global exports. Load order documented in the design.
- **Risk: Cross-file function calls break** → Mitigation: All functions stay on the same `App.Endpoints` / `App.Filters` namespace. Only the file location changes, not the access path.
- **Risk: More HTTP requests (4 new script tags)** → Accepted. These are small files loaded from RustEmbed (no network latency in production — everything is served from the binary). The maintainability gain outweighs the negligible overhead.
- **Trade-off: URL state management stays scattered across filters files** → Accepted. Moving URL param management into a separate helper would require passing too much context. Each filter function manages its own URL param inline.
- **Trade-off: Not consolidating renderPagination fully** → The notification and internet pagination renderers have slight differences (CSS classes, info text). The shared `renderPaginationUI` helper handles the common controls rendering, but each module keeps its own info text formatting.
