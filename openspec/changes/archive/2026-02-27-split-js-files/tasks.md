## 1. Split endpoints.js

- [x] 1.1 Create `static/js/endpoints-details.js` — extract `getDeviceTypeInfo` (lines 88-102), `isControllableDevice` (lines 107-122), `updateDetails` (lines 127-317), `showLoading` (lines 322-359) into IIFE with `App.Endpoints = App.Endpoints || {}` namespace
- [x] 1.2 Create `static/js/endpoints-actions.js` — extract `mergeEndpoint` (lines 598-627), `renderMergeEndpoints` (lines 632-657), `filterMergeEndpoints` (lines 662-678), `selectMergeTarget` (lines 683-697), `closeMergeModal` (lines 702-706), `confirmMerge` (lines 711-743), `escapeHtml` (lines 748-752), `deleteEndpoint` (lines 757-781), and DOMContentLoaded merge modal setup (lines 841-864) into IIFE with `App.Endpoints = App.Endpoints || {}` namespace
- [x] 1.3 Update `static/js/endpoints.js` — remove extracted functions, keep `startModelPolling`, `stopModelPolling`, `selectNode`, `probeEndpoint`, `unselectNode`, `scrollToSection`, `probeHostname`, `handleKeyboardNavigation`, and all `window.*` global exports
- [x] 1.4 Verify all three files use consistent `App.Endpoints` namespace and no function references are broken

## 2. Split filters.js

- [x] 2.1 Create `static/js/filters-search.js` — extract `filterHostnamesList` (lines 414-436), `filterPortsList` (lines 441-463), `filterIpsList` (lines 468-490), `filterMacsList` (lines 495-517), `filterByProtocol` (lines 522-540), `showProtocolDropdown` (lines 545-597), `hideProtocolDropdown` (lines 602-607), `selectEndpointFromDropdown` (lines 612-617), `clearProtocolFilter` (lines 622-630), `filterByPort` (lines 706-736), `clearPortFilter` (lines 741-756) into IIFE with `App.Filters = App.Filters || {}` namespace
- [x] 2.2 Create `static/js/filters-quick.js` — extract `canToggle` (lines 11-18), `selectAll` (lines 59-78), `showOnlyKnownVendors` (lines 83-98), `showOnlyUnknown` (lines 103-118), `showOnlyActive` (lines 123-136), `showOnlyInactive` (lines 141-154), `selectNone` (lines 159-171), `selectOnly` (lines 176-196), `handleClick` (lines 201-208), `loadGlobalProtocols` (lines 635-657), `filterByGlobalProtocol` (lines 663-701), `filterByVendor` (lines 761-775) into IIFE with `App.Filters = App.Filters || {}` namespace
- [x] 2.3 Update `static/js/filters.js` — remove extracted functions, keep `isLocalIP`, `apply`, `updateFilterButtonStates`, `clearAllFilters`, all `window.*` global exports, and DOMContentLoaded initialization
- [x] 2.4 Verify all three files use consistent `App.Filters` namespace and no function references are broken

## 3. Pagination deduplication

- [x] 3.1 Expose `getPageNumbers` as `App.Pagination.getPageNumbers` in `static/js/pagination.js` (currently a local function)
- [x] 3.2 Add `App.Pagination.renderPaginationUI(config)` shared helper to `pagination.js` — accepts `{ controlsId, currentPage, totalPages, onPageClick, btnClass, ellipsisClass }`
- [x] 3.3 Update `static/js/notifications.js` — remove local `getPageNumbers` (lines 443-454), refactor `renderPagination` (lines 168-213) to use `App.Pagination.getPageNumbers` and `App.Pagination.renderPaginationUI`
- [x] 3.4 Update `static/js/internet.js` — remove local `getPageNumbers` method (lines 164-184), refactor `updatePaginationControls` (lines 126-159) to use `App.Pagination.getPageNumbers` and `App.Pagination.renderPaginationUI`

## 4. Update script tags

- [x] 4.1 Add `<script src="/static/js/endpoints-details.js"></script>` and `<script src="/static/js/endpoints-actions.js"></script>` before the existing `endpoints.js` tag in `templates/index.html`
- [x] 4.2 Add `<script src="/static/js/filters-search.js"></script>` and `<script src="/static/js/filters-quick.js"></script>` before the existing `filters.js` tag in `templates/index.html`

## 5. Validation

- [x] 5.1 Verify `cargo build` succeeds (RustEmbed picks up new files)
- [x] 5.2 Verify all original `endpoints.js` functions are accessible via `App.Endpoints.*` and `window.*`
- [x] 5.3 Verify all original `filters.js` functions are accessible via `App.Filters.*` and `window.*`
- [x] 5.4 Verify no file exceeds 450 lines
- [x] 5.5 Verify `cargo test` passes
