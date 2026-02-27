## ADDED Requirements

### Requirement: getPageNumbers exposed as shared helper
`App.Pagination.getPageNumbers(current, total)` SHALL be exposed as a public method on the `App.Pagination` namespace in `static/js/pagination.js`, returning an array of page numbers with ellipsis-friendly gaps.

#### Scenario: Shared helper returns correct page numbers
- **WHEN** `App.Pagination.getPageNumbers(5, 10)` is called
- **THEN** it SHALL return `[1, 3, 4, 5, 6, 7, 10]` (current page +/- 2 delta, with first and last)

### Requirement: renderPaginationUI shared helper
`App.Pagination.renderPaginationUI(config)` SHALL be a shared helper in `pagination.js` that renders pagination controls (Previous, page numbers with ellipsis, Next) into a target element.

#### Scenario: Helper renders controls for notifications
- **WHEN** `notifications.js` calls `App.Pagination.renderPaginationUI` with its config
- **THEN** pagination controls SHALL render identically to the current inline implementation

#### Scenario: Helper renders controls for internet table
- **WHEN** `internet.js` calls `App.Pagination.renderPaginationUI` with its config
- **THEN** pagination controls SHALL render identically to the current inline implementation

### Requirement: notifications.js uses shared pagination
`notifications.js` SHALL remove its local `getPageNumbers` function (lines 443-454) and its inline pagination control rendering (lines 168-213), replacing them with calls to `App.Pagination.getPageNumbers` and `App.Pagination.renderPaginationUI`.

#### Scenario: Notification pagination works identically
- **WHEN** notifications are paginated
- **THEN** pagination SHALL function identically to before (page numbers, Previous/Next, info text)

### Requirement: internet.js uses shared pagination
`internet.js` SHALL remove its local `getPageNumbers` method (lines 164-184) and its inline `updatePaginationControls` (lines 126-159), replacing them with calls to `App.Pagination.getPageNumbers` and `App.Pagination.renderPaginationUI`.

#### Scenario: Internet table pagination works identically
- **WHEN** internet destinations are paginated
- **THEN** pagination SHALL function identically to before (page numbers, Previous/Next)
