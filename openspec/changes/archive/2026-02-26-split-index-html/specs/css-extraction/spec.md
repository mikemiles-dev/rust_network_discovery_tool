## ADDED Requirements

### Requirement: CSS extracted into a Tera partial
The embedded `<style>...</style>` block (lines 16-1904 of index.html) SHALL be moved verbatim into `templates/partials/styles.html`. The original index.html SHALL replace the style block with `{% include "partials/styles.html" %}`.

#### Scenario: Styles partial contains complete CSS
- **WHEN** `templates/partials/styles.html` is created
- **THEN** it SHALL contain the entire `<style>` opening tag, all CSS rules, and the `</style>` closing tag exactly as they appeared in the original file

#### Scenario: Page renders with identical styling
- **WHEN** the application serves the index page after extraction
- **THEN** the rendered HTML SHALL contain the same CSS as before, producing identical visual output

### Requirement: No CSS modifications
The CSS content SHALL be moved as-is with no additions, removals, or reformatting.

#### Scenario: Byte-equivalent CSS content
- **WHEN** comparing the CSS in the partial to the original embedded CSS
- **THEN** the content SHALL be identical (whitespace-preserving move)
