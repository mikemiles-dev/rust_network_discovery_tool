## Why

The `static/js/` directory has 18 files totaling 6,341 lines. Two files significantly exceed 500 lines — `endpoints.js` (876 lines) and `filters.js` (855 lines) — each mixing 3-4 distinct responsibilities. Additionally, pagination logic (`getPageNumbers` + pagination control HTML rendering) is duplicated across `pagination.js`, `notifications.js`, and `internet.js`. Splitting the large files and extracting shared pagination utilities will make the JS layer easier to maintain.

## What Changes

- Split `endpoints.js` (876 lines) into focused modules: details panel rendering, merge/delete actions, and row selection/keyboard navigation
- Split `filters.js` (855 lines) into focused modules: device type checkbox filters, special filters (known/active/vendor), and right-pane list search helpers
- Extract duplicated `getPageNumbers()` and pagination UI rendering from `notifications.js` and `internet.js` into the existing `pagination.js`
- Update `templates/partials/network-tab.html` and `templates/index.html` script tags for new files
- All DOM IDs and global function names preserved — no Tera or HTML changes beyond script imports

## Capabilities

### New Capabilities
- `endpoints-split`: Split endpoints.js into focused modules while preserving the App.Endpoints namespace and all global onclick handlers
- `filters-split`: Split filters.js into focused modules while preserving the App.Filters namespace and all global onclick handlers
- `pagination-dedup`: Consolidate duplicated pagination logic from notifications.js and internet.js into shared helpers in pagination.js

### Modified Capabilities

## Impact

- `static/js/endpoints.js` split into 3-4 files
- `static/js/filters.js` split into 3 files
- `static/js/pagination.js` gains shared helper functions
- `static/js/notifications.js` and `static/js/internet.js` use shared pagination helpers instead of inline implementations
- `templates/index.html` updated with new `<script>` tags (load order matters)
- No Rust code changes
- No template variable or DOM ID changes
- No behavioral changes — pure refactoring
