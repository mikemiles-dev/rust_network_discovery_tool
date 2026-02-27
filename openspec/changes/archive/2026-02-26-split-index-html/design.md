## Context

`templates/index.html` is a 3,115-line monolithic Tera template containing:
- 1,889 lines of embedded CSS (lines 16-1904)
- 7 tab sections (Network, Internet, DNS, Scanner, PCAP, Notifications, Settings)
- An endpoint details right panel with 3 sub-tabs (Details, Network Actions, Controls)
- Device-specific remote control UIs (Roku, Samsung, LG ThinQ)
- Modal overlays (merge, protocol dropdown)
- 19 external JS file imports (already modularized in `static/js/`)

Templates are loaded via `RustEmbed` from the `templates/` folder. The `Templates::iter()` loop registers every file under `templates/` with Tera using its relative path (e.g., `partials/header.html`). Tera's `{% include "partials/header.html" %}` will resolve against these registered names automatically — no code changes needed for subdirectory support.

Static assets are similarly embedded from `static/`. There is no `static/css/` directory currently.

## Goals / Non-Goals

**Goals:**
- Split `index.html` from 3,115 lines into a ~60-line layout shell plus partials
- Each partial under 500 lines (CSS partial excepted — it's a single stylesheet)
- Preserve all DOM IDs so existing JS files continue to work unchanged
- All Tera template variables and context remain the same
- No Rust code changes needed (RustEmbed already loads subdirectories)

**Non-Goals:**
- Refactoring the CSS itself (just extracting it as-is)
- Moving CSS to a separate static file (keeping it as a Tera partial avoids cache issues and keeps the single-page-load pattern)
- Modifying any JavaScript files
- Changing the visual appearance or behavior of the UI
- Splitting the CSS into per-component stylesheets

## Decisions

### 1. Use Tera `{% include %}` partials, not `{% block %}`/`{% extends %}`

Tera supports both inheritance (`{% extends "base.html" %}`) and includes (`{% include "partial.html" %}`). Since index.html is the only template and there's no base layout to inherit from, simple includes are the right choice. Each partial is a fragment that gets inlined at the include point.

**Alternative considered**: Tera block inheritance. Rejected because there's only one page — blocks add abstraction without benefit.

### 2. Keep CSS as a Tera partial, not a static CSS file

Extract the `<style>` block into `templates/partials/styles.html` (containing just the `<style>...</style>` block). This keeps it embedded in the HTML response, matching the current behavior where everything loads in a single request.

**Alternative considered**: Move CSS to `static/css/styles.css` and link it. Rejected because:
- The current design embeds everything for a single-request load
- CSS theming uses Tera-compatible patterns (CSS variables, not Tera variables) so no templating is needed, but keeping it in templates keeps the build simple
- Avoids adding a new HTTP request and cache-busting concern

### 3. Partition by visual section, not by Tera feature

Group partials by UI section (each tab, the filter bar, the details panel) rather than by template feature (all loops in one file, all conditionals in another). This matches how developers think about the UI.

### 4. Partial file structure

```
templates/
├── index.html                      (~60 lines - HTML shell with includes)
└── partials/
    ├── styles.html                 (~1,890 lines - full <style> block)
    ├── header.html                 (~15 lines - logo + tab buttons)
    ├── network-tab.html            (~35 lines - wrapper for filter/table/details)
    ├── filter-bar.html             (~80 lines - type checkboxes + quick buttons)
    ├── search-bar.html             (~25 lines - search input + refresh controls)
    ├── endpoints-table.html        (~80 lines - table header + Tera row loop)
    ├── endpoint-details.html       (~500 lines - right panel with 3 sub-tabs)
    ├── internet-tab.html           (~50 lines)
    ├── dns-tab.html                (~50 lines)
    ├── scanner-tab.html            (~120 lines)
    ├── pcap-tab.html               (~95 lines)
    ├── notifications-tab.html      (~20 lines)
    ├── settings-tab.html           (~100 lines)
    └── modals.html                 (~30 lines - merge modal + protocol dropdown)
```

The endpoint-details partial is the largest non-CSS partial (~500 lines) because it contains the details tab, network actions tab, and control tab (with 3 device-specific remote UIs). Further splitting the remote controls into sub-partials would add complexity for minimal gain since each remote is ~50 lines.

### 5. Tera include syntax

Each include passes all context implicitly (Tera includes inherit the parent template's context). No explicit variable passing needed.

```html
{# index.html #}
{% include "partials/header.html" %}
{% include "partials/network-tab.html" %}
```

### 6. No changes to `src/web/mod.rs`

The `RustEmbed` `#[folder = "templates/"]` directive already recursively includes subdirectories. The `Templates::iter()` loop registers all files. Tera will find partials by their registered path (`partials/header.html`). No Rust code changes required.

## Risks / Trade-offs

- **Risk: Tera include path resolution** → Mitigation: RustEmbed registers files with relative paths from the `templates/` root. Verify with `cargo build` that includes resolve correctly.
- **Risk: Breaking DOM structure by splitting mid-element** → Mitigation: Each partial is a complete HTML fragment. Split points are between sibling elements (between tabs, between sections), never inside an element.
- **Risk: Template variable scope in includes** → Mitigation: Tera includes inherit all variables from the including template. No variables need to be passed explicitly.
- **Trade-off: CSS stays as one large file** → Accepted. Splitting CSS by component would require careful dependency analysis and adds risk of broken styles. The CSS is self-contained with CSS variables for theming.
- **Trade-off: endpoint-details.html is ~500 lines** → Accepted. The details panel's 3 sub-tabs and 3 remote controls are tightly coupled and splitting further adds include overhead without meaningful maintainability gain.
