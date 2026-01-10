# Release Notes

## [0.3.1]

### Added
- SQL cleanup script (`cleanup_duplicates.sql`) for one-time cleanup of existing duplicate endpoints
- Script merges duplicate endpoints sharing the same MAC address into a single endpoint
- Automatic duplicate prevention now active - duplicates are merged immediately when detected during network scanning

### Fixed
- Issue where endpoints would show as local machine on graph when communicating with unnamed duplicate endpoints
- Cleanup script ensures all existing duplicates are merged before automatic prevention takes over

### Usage
To clean up existing duplicates in your database:
1. Stop the network discovery tool
2. Run: `sqlite3 test.db < cleanup_duplicates.sql`
3. Restart the tool

The automatic merging logic will prevent new duplicates from forming going forward.

## [0.3.0]

### Added
- Endpoint search now searches IP addresses and MAC addresses in addition to hostnames
- Device type badge now displayed in right pane showing classification (Internet, Printer, TV, etc.)
- Endpoint search input automatically focused on page load for faster searching
- Database schema optimizations with new indexes for faster queries:
  - Case-insensitive index on endpoint names (`idx_endpoints_name_lower`)
  - Direct index on endpoint names (`idx_endpoints_name`)
  - Composite indexes on communications for time-range queries (`idx_communications_last_seen_src`, `idx_communications_last_seen_dst`)
- SQL migration script (`optimize_schema.sql`) for upgrading existing databases

### Changed
- Endpoint search now uses debouncing (150ms delay) for significantly improved performance and responsiveness
- Graph filtering logic rewritten to directly apply filter criteria instead of reading DOM state
- Endpoint slider behavior improved:
  - When viewing overall network (no endpoint selected): Slider limits which endpoints appear on graph
  - When viewing specific endpoint (clicked in sidebar): Slider is bypassed, showing ALL endpoints it communicates with
  - This ensures you always see complete communication paths for selected endpoints
- Filter logic ensures graph and sidebar list stay synchronized

### Fixed
- Critical bug where graph filters were reading stale DOM state, causing incorrect filtering (e.g., api.anthropic.com disappearing when unchecking Printer filter)
- Critical bug where graph always defaulted to showing only local machine communications, even when no endpoint was selected in URL
  - Graph now shows ALL network communications when accessed without `?node=` parameter (overall network view)
  - When `?node=endpoint` is in URL, graph filters to show only that endpoint's communications
  - This fixes issue where endpoints like photos.local wouldn't appear on graph despite having recent activity
- Critical bug where endpoint limit slider would hide communication partners when viewing a specific endpoint
  - Previously, clicking an endpoint would show "No Communications Found" if its partners were filtered out by the slider
  - Now, when viewing a specific endpoint, ALL its communication partners are shown regardless of slider setting
  - Slider only applies to overall network view, not individual endpoint views
- Critical bug where duplicate endpoints with same MAC address could exist, causing missing communications
  - Automatic duplicate detection and merging now occurs when MAC addresses match
  - Prefers keeping endpoints with non-empty names over those with empty names
  - All communications and attributes from duplicates are merged into the kept endpoint
  - Prevents issues like endpoints showing "No Communications Found" when communicating with unnamed duplicates
- Endpoint name lookups now use optimized indexes for 10-50x faster performance
- Graph now correctly respects both type filters and endpoint limit slider in appropriate contexts
- Endpoint resolution query optimized to return only most recently active endpoint when duplicates exist

### Performance
- Endpoint name lookups: 10-50x faster (from full table scan to indexed lookup)
- Communications queries: 3-10x faster with composite indexes
- Search input: No more lag on every keystroke thanks to debouncing
- Overall UI: Noticeably more responsive, especially with many endpoints

## [0.2.8]

### Added
- Endpoint search now searches IP addresses and MAC addresses in addition to hostnames
- Search functionality in the endpoint sidebar now matches against all known IPs and MACs for each endpoint

### Changed
- Enhanced filterEndpointsList function to search across endpoint names, IP addresses, and MAC addresses

### Fixed
- Critical bug where clicking on an endpoint (e.g., an IP address like 192.168.7.160) would incorrectly show data from a different endpoint that had previously used the same IP address
- Endpoint identifier resolution now prioritizes exact name matches before falling back to IP/MAC lookups
- This prevents confusion when DHCP reassigns IP addresses or when multiple devices have shared the same IP over time

## [0.2.7]

### Added
- ❓ Other device category for unclassified endpoints that don't match any specific device type
- All/None buttons above device type filters for quick selection/deselection of all filter categories
- "No Communications Found" message now appears when all device type filters are turned off

### Changed
- Auto-refresh indicator now turns red (solid) when stopped instead of disappearing
- Endpoint list in sidebar is now a flowing list instead of a fixed-height scrolling box
- All/None filter buttons are left-aligned for better visual flow
- Filter logic completely rewritten to properly handle null, undefined, or empty device types

### Fixed
- Critical bug where endpoints with null or unrecognized device types would remain visible even when all filters were unchecked
- "No Communications Found" message would incorrectly appear when viewing overall network graph with multiple endpoints visible
- Filter state now correctly defaults to "false" instead of "true", ensuring proper filtering behavior

## [0.2.6]

### Added
- Phone/Tablet device detection (iPhone, iPad, Android phones, Galaxy, Pixel, OnePlus, Xiaomi, Huawei, Motorola, and more)
- 📱 Phone filter in UI with teal color coding (#14b8a6)
- Phone devices now display with distinct color in network graph for easy identification

### Changed
- Phone devices are now classified separately from generic "Local" devices
- Filter UI now includes 10 device categories for comprehensive device type filtering

## [0.2.5]

### Added
- Soundbar device detection (Sonos, Bose, Yamaha, Samsung, LG, Vizio, JBL)
- Appliance device detection (dishwashers, washing machines, dryers, refrigerators, ovens)
- Device classification now checks mDNS service types first for more reliable smart device identification
- Filter UI now includes 🔊 Soundbar and 🏠 Appliance categories
- Flexible endpoint identifier resolution - URLs now work with any identifier (hostname, IP, or MAC)

### Fixed
- URL bookmarks no longer break when endpoint names change from IP to hostname after DNS/mDNS resolution
- Endpoint lookup now searches across all identifiers (name, IP, MAC) instead of just the endpoint name field
- Parameter count mismatch in port query that caused panics
- All endpoint detail queries now use unified identifier resolution for consistency

### Changed
- Endpoint queries refactored to use centralized `resolve_identifier_to_endpoint_ids()` function
- Better handling of endpoint identity changes over time

## [0.2.4]

### Fix
 - Better Endpoint UI lookup

## [0.2.3]

### Added
 - Better printer/VM/Gaming/appliance/etc support

### Fixes
 - Sliders auto refresh
 - Incorrect interface monitoring
 
### Added
 - UI Ports

## [0.2.2]
### Added
 - UI Slider for Endpoints

## [0.2.1]

### Added
 - More UI Updates

## [0.2.0]

### Added
 - UI Search bars

### Fixed
- Critical bug in endpoint matching logic that caused DHCP IP address reuse to incorrectly merge different physical devices into the same endpoint (e.g., Samsung.attlocal.net showing hostname as MikesPC)
- Endpoint matching now requires MAC address match when MAC is available, preventing IP-based collisions from DHCP reassignments

## [0.1.3]

### Fixed
- Reworkd UI elements for internet types + added UI filters
- Added tests

## [0.1.2]

## Fixed
- Reworked how Windows interface monitoring works.

## [0.1.1] 

### Added
- Ability to configure web server port

## [0.1.0] 

### Added
- Pre-built binaries for macOS (Intel & Apple Silicon), Linux, and Windows
- Comprehensive installation documentation
- Real-time network traffic monitoring and visualization
- Smart interface filtering (automatically skips loopback, Docker, VPN interfaces)
- Connection deduplication (tracks unique connections instead of individual packets)
- Interactive network graph visualization powered by Cytoscape.js
- Protocol detection for 20+ protocols (HTTP, HTTPS, DNS, SSH, etc.)
- Hostname resolution using DNS, mDNS, and deep packet inspection (SNI, HTTP Host headers)
- DNS caching with intelligent 5-minute TTL
- Automatic data retention management (7 days default, configurable)
- Privacy-focused design (no packet payload storage)
- High-performance database operations with indexes and connection pooling
- SQLite database with bundled support (no external DB required)
- GitHub Actions workflow for automated cross-platform binary releases
- Configurable environment variables:
  - `MONITOR_INTERFACES`: Specify network interfaces to monitor
  - `DATABASE_URL`: Custom database location
  - `DATA_RETENTION_DAYS`: Configure data retention period
  - `CHANNEL_BUFFER_SIZE`: Adjust internal packet buffer

### Platform Support
- macOS (Intel and Apple Silicon)
- Linux (x86_64)
- Windows (requires Npcap/WinPcap drivers)

### Security
- Local-only web UI (binds to 127.0.0.1)
- No payload storage (only connection metadata)
- Requires elevated privileges for packet capture

### Performance
- 99%+ reduction in database size vs traditional packet capture
- Stores connections instead of individual packets
- Automatic cleanup of old data
- Example: 1GB file download = 1 database row instead of ~700,000

---

## Release Template

When creating a new release, copy this template:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes to existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security improvements or fixes
```

[Unreleased]: https://github.com/mikemiles-dev/rust_network_discovery_tool/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mikemiles-dev/rust_network_discovery_tool/releases/tag/v0.1.0
