# Release Notes

## [0.5.2]

### Added
- **Settings Tab** - New UI tab for configuring application settings
  - Cleanup Interval (seconds) - How often to run merge/cleanup tasks (default: 30s)
  - Data Retention (days) - How long to keep communication records (default: 7 days)
  - Settings stored in SQLite database and persist across restarts
  - API endpoints: `GET /api/settings`, `POST /api/settings`
- **Automatic IPv6 Endpoint Merging** - Devices with multiple IPv6 addresses now automatically merged
  - Merges endpoints sharing the same /64 prefix when one gets a hostname
  - Runs immediately when hostname is discovered via mDNS/DNS
  - Also runs periodically as part of cleanup task
  - Prefers endpoints with proper hostnames over IPv6-address-named endpoints

### Changed
- **Delete Endpoint Behavior** - Now preserves communication history for other endpoints
  - Previously deleted all communications involving the endpoint
  - Now sets endpoint ID to NULL in communications, preserving records for other devices
  - Prevents "disappearing endpoints" when deleting a gateway or hub device
- **Endpoint Details Panel** - Hidden when no endpoint is selected
  - Previously showed local machine details by default
  - Now shows clean UI until user selects an endpoint
- **Cleanup Task Interval** - Now configurable via Settings (was hardcoded to 30s)
- **Data Retention** - Now configurable via Settings (previously only via environment variable)

### Fixed
- **Delete Endpoint API** - Fixed wrong column names (`source_endpoint_id`/`destination_endpoint_id` → `src_endpoint_id`/`dst_endpoint_id`)
- **Delete Endpoint Error Handling** - Now returns proper error messages instead of silently failing
- **Endpoint Details Loading** - Fixed 15+ second delay caused by hidden overlay panel
  - JavaScript now properly shows overlay when selecting endpoint via AJAX
- **Endpoint Details API** - Moved blocking DB operations to `spawn_blocking` for better async performance

---

## [0.5.1]

### Added
- **Internet Destinations Tab** - Track external domains your network connects to
  - Shows domain names (not raw IPs) for better readability
  - Filters out IPv4 addresses, IPv6 addresses, and mDNS (.local) names
  - Sortable columns: Domain, Packets, First Seen, Last Seen
  - Searchable domain list

### Changed
- **Internet Destinations UI** - Renamed "Hostname" column to "Domain" for clarity
- **Internet Destinations UI** - Removed Traffic column for cleaner display
- **Endpoint Rename** - URL filters (vendor, protocol, page, etc.) now preserved when renaming endpoints
- **Auto-refresh** - Pauses during rename, vendor edit, and model edit operations to prevent input focus loss

### Fixed
- **Special Characters in Names** - Endpoint names with apostrophes now work correctly in URLs and UI
- **Device Type Saving** - Manual device type overrides now save and display correctly
- **Vendor/Model Display** - Custom vendor and model names now show properly in endpoint table
- **Template Rendering** - Fixed HashMap lookup errors when endpoint not found in type/vendor/model maps

---

## [0.5.0]

### Added
- **IPv6 Neighbor Discovery (NDP) Scanner** - Discover IPv6 devices on the local network
  - Sends ICMPv6 Neighbor Solicitation to all-nodes multicast (ff02::1)
  - Parses Neighbor Advertisement responses to extract IPv6/MAC pairs
  - Enabled by default alongside ARP and SSDP scans
- **IPv6 EUI-64 MAC Extraction** - Extract MAC addresses from IPv6 link-local addresses
  - Automatically detects EUI-64 format addresses (with ff:fe pattern)
  - Saves extracted MAC to endpoint for better device tracking
- **SSDP/UPnP Device Description Fetching** - Get detailed device info from UPnP XML
  - Fetches `friendlyName` and `modelName` from device description URLs
  - Stored in database as `ssdp_friendly_name` and `ssdp_model`
  - Model info used for device classification and display
- **TV Model Normalization** - Convert cryptic model numbers to friendly names
  - Samsung: QN43LS03TAFXZA → "Samsung The Frame", QN65Q80CAFXZA → "Samsung QLED Q8"
  - Samsung lifestyle TVs: The Frame, The Serif, The Sero, The Terrace
  - Samsung series: Neo QLED, QLED Q6-Q9, OLED S85-S95, Crystal UHD
  - LG: OLED55C3PUA → "LG OLED C3", QNED, NanoCell series
  - Sony: XR55A90J → "Sony Bravia XR A90"
- **Soundbar Model Detection & Normalization** - Identify soundbars by model number
  - Samsung: HW-* (HW-MS750 → "Samsung Soundbar MS750"), SPK-*, WAM*
  - LG: SL*, SN*, SP*, SC9* series
  - JBL: Bar-* series
  - Soundbars now properly classified instead of as TVs
- **Filter Persistence** - Vendor and protocol filters preserved across page refreshes
  - Vendor selection saved to URL query parameter
  - Protocol selection saved to URL query parameter
  - Scroll position (window, table, details pane) saved to sessionStorage
- **Clickable Logo** - Click "Rust Network Discovery Tool" to navigate to / and clear all filters
- **Manual Model Override** - Set custom model names for any device via API
  - `/api/endpoint/model` endpoint to set or clear custom models
  - Custom models take priority over auto-detected models
  - Useful for devices that can't be auto-detected (e.g., smart plugs, sensors)
- **Heuristic-Based Model Detection** - Infer device models from context when not discoverable
  - Amazon devices: Echo (no SSDP/mDNS/ports), Fire TV (specific ports), Ring
  - Google/Nest devices: Chromecast, Nest/Google speakers
  - Uses MAC vendor + network behavior to identify devices
- **Automatic HP Printer Model Detection** - Probes HP printer web interfaces for model info
  - Triggers automatically when viewing HP device details or via ARP scan
  - Extracts model from web page title (LaserJet, OfficeJet, DeskJet, ENVY)
  - UI auto-polls and updates when model is discovered (no manual refresh needed)
  - Manual probe via `/api/endpoint/probe` endpoint
- **Tab Persistence** - Selected tab preserved across page refreshes
  - Tab state saved to URL query parameter
  - Switching between Network, mDNS, and Scanner tabs now persists

### Fixed
- **MacBook Classified as Phone** - Mac computers advertising `_companion-link._tcp` (Handoff/AirDrop) were incorrectly classified as phones
  - Now checks hostname for Mac patterns before applying phone classification from mDNS services
- **IPv6 Privacy Addresses** - Link-local IPv6 addresses with randomized interface IDs (RFC 4941) no longer saved as endpoints
  - Only EUI-64 format addresses (with extractable MAC) are saved
  - Prevents cluttering database with temporary privacy addresses

---

## [0.4.0]

### Added
- **Pagination** - Both endpoints table and mDNS entries table now have pagination
  - Configurable page sizes (10, 25, 50, 100 items per page)
  - Page navigation controls with current/total page display
  - Pagination state preserved in URL for bookmarking
- **Sticky Table Headers** - Endpoints table headers stay visible while scrolling
  - Column headers and pagination controls always visible
  - Improved usability for large endpoint lists
- **Sort & Selection Persistence** - Auto-refresh now preserves UI state
  - Sort column and direction saved to URL before refresh
  - Current page number preserved across refreshes
  - No more losing your place when the page auto-refreshes
- **New MAC Vendors**
  - Texas Instruments (28:ec:9a) - IoT devices
  - Samjin (28:6d:97) - SmartThings sensors
  - Intel device detection improvements
- **Expanded mDNS Service Discovery** - Now browsing 50+ service types including:
  - Gaming consoles: Xbox, PlayStation, Nintendo
  - Media servers/speakers: Sonos, Plex, iTunes/DAAP
  - Smart home: Philips Hue, Nanoleaf, Wemo, TP-Link Kasa/Tapo, Tuya, Ecobee, Ring
  - NAS devices: Synology, QNAP, Apple Time Machine
  - Network equipment: Ubiquiti
  - Remote access: VNC/RFB
  - Apple services: AirDrop, Continuity
  - Android: ADB (when debugging enabled)
  - Samsung: Smart View screen mirroring

### Changed
- **Filter Bar Reorganization**
  - Quick filter buttons (All, Local, Home, None) moved above filter checkboxes
  - Time Range dropdown moved from header to filter bar (next to All Protocols)
  - Cleaner, more compact layout
- **Header Layout**
  - Tabs now on the left, aligned with bottom border
  - Logo moved to right side of header
  - More compact header design

### Fixed
- **mDNS Invalid IP Bug** - mDNS no longer creates entries with 0.0.0.0 or :: addresses
  - Added `is_unspecified()` check to skip invalid addresses from mdns-sd library
  - Prevents ghost devices with invalid IPs appearing in the database
- **mDNS Hostname Propagation** - Discovered hostnames now update the UI properly
  - Previously only updated `endpoint_attributes.hostname`
  - Now also updates `endpoints.name` so friendly names appear in the endpoints list
  - Only updates if current name is an IP address and no custom name is set
- **UI Scrolling Issues** - Fixed various layout issues with table scrolling and sticky positioning

---

## [0.3.6]

### Added
- **Stop Scan Button** - Cancel running network scans from the UI
  - Red "Stop Scan" button appears when a scan is in progress
  - Gracefully stops the current scan phase
- **Interface-Based Database Naming** - Database automatically named after the monitored interface
  - Single interface `en0` → `en0.db`
  - Single interface `Wi-Fi` → `Wi-Fi.db`
  - Multiple interfaces → `network.db`
  - `DATABASE_URL` environment variable still overrides this behavior
- **MAC Vendor Detection** - Displays device manufacturer next to Type in endpoint details
  - 500+ MAC OUI prefixes for major vendors (Apple, Samsung, Amazon, Google, Sony, Microsoft, Nintendo, Roku, etc.)
  - Hostname-based vendor detection as fallback (for devices with locally administered MACs like LG ThinQ)
  - Detects LG, eero, HP, Canon, Epson, Brother, Sonos, and more from hostname patterns
  - Vendor badge shown next to device type classification
  - Vendor also shown in endpoint list (left of bytes count)
- **Device Model Detection** - Extracts and displays model information from hostnames
  - Roku: Ultra, Express, Streaming Stick, etc.
  - PlayStation: PS4 → "PlayStation 4", PS5 → "PlayStation 5"
  - Xbox: Xbox One, Xbox Series X/S
  - Apple: iPhone (with version), iPad Pro/Air, MacBook Pro/Air
  - Samsung/LG TVs: Model numbers like QN65Q80B, OLED55C1
  - LG Appliances: Dishwasher, Washing Machine, Dryer, Refrigerator
  - Google/Nest: Chromecast, Nest Hub, Nest Mini, Google Home
  - Amazon Echo: Echo, Echo Dot, Echo Show, Echo Studio
  - Sonos: One, Beam, Arc, Move, Roam, Sub, Play:1/3/5
  - Ring: Doorbell, Camera, Stick Up Cam
  - HP Printers: LaserJet, OfficeJet, DeskJet, ENVY
  - Model badge shown in purple next to vendor badge
- **Smart Device Classification** - Automatically classifies devices based on MAC vendor
  - **Gaming**: Nintendo devices automatically classified as 🎮 Gaming
  - **TV**: Roku devices automatically classified as 📺 TV
  - **Appliances**: Amazon Echo/Ring, Google Nest/Chromecast, Philips Hue, TP-Link/Kasa, Wyze, iRobot, Tuya
  - Works even when device hostname is just an IP address
- **mDNS Local Filter** - Filters out local machine's own mDNS entries from the mDNS tab
  - Reduces clutter by hiding services advertised by your own machine
- **Automatic Scan on Startup** - Runs initial network scan when the application launches
  - Uses default scan types (ARP and SSDP) for immediate device discovery
  - No manual intervention required to discover devices
- **LG Device Control** - Full control for LG TVs and ThinQ appliances
  - **LG webOS TV Control**: Volume, playback, channels, power, input switching, and app launching via local WebSocket
  - **LG ThinQ Cloud Integration**: Uses official LG ThinQ Connect API (opened December 2024)
    - Supports dishwashers, washing machines, dryers, refrigerators, and air conditioners
    - Get device status, start/stop cycles, and control appliance modes
    - Uses Personal Access Token (PAT) from [LG ThinQ Developer Site](https://smartsolution.developer.lge.com/en/apiManage/thinq_connect)
    - **In-app PAT setup**: Enter your PAT token directly in the Control tab for ThinQ devices
    - Token stored in database for automatic use on future sessions
    - Disconnect option to clear stored credentials
    - API endpoints: `/api/thinq/setup`, `/api/thinq/status`, `/api/thinq/devices`, `/api/thinq/disconnect`
  - Automatic appliance detection from hostname patterns (lma*, lmw*, wm*, wf*, ref*, ac*)
- **PlayStation/Xbox Detection** - Gaming consoles now detected by hostname patterns (ps4-*, ps5-*, xbox-*) and classified as gaming devices
  - Sony added to gaming vendors for MAC-based classification

### Changed
- Scanner moved to dedicated "Scanner" tab in the header (previously in sidebar)
- Scanner tab now stays active during auto-refresh (no longer redirects to network tab)
- Selected endpoint indicator moved to above the search bar in the sidebar
- **Cleaner hostnames** - Common local suffixes stripped when saving endpoints
  - Removes `.local`, `.lan`, `.home`, `.internal`, `.localdomain`, `.localhost`
  - Example: `Roku-Ultra-1234.local` → `Roku-Ultra-1234`

### Fixed
- **Database locking issues during scanning** - Multiple improvements:
  - Tables for scan results now created at startup instead of on every insert (eliminates schema lock contention)
  - Added comprehensive retry logic with exponential backoff for database operations
  - SQLWriter batch processing now properly retries on lock errors instead of failing
- Auto-refresh no longer causes redirect away from Scanner tab
- **Critical bug where public IPs were misclassified as "local"**
  - Virtual network adapters (Hyper-V, Docker, WSL, VPN) with 0.0.0.0/0 routing caused every IP to match as "local"
  - Internet endpoints (e.g., valve.net, Cloudflare IPs) were incorrectly shown as 🖥️ Local instead of 🌐 Internet
  - Now filters out catch-all networks (0.0.0.0/0 and ::/0) from local network detection
  - Added IP extraction from hostnames in pattern "xxx-xxx-xxx-xxx.domain" when IP not found in database

### Performance
- Removed redundant `CREATE TABLE IF NOT EXISTS` calls from hot paths (was causing exclusive locks on every scan result insert)

---

## [0.3.5]

### Added
- **Active Network Scanning** - Discover devices that aren't actively communicating
  - **ARP Scanning**: Discover all devices on local subnet by MAC address (requires root/admin)
  - **ICMP Ping Sweep**: Find responsive hosts via ping (requires root/admin)
  - **TCP Port Scanning**: Probe common ports (22, 80, 443, 8080, etc.) to identify services
  - **SSDP/UPnP Discovery**: Find smart devices, media servers, and IoT devices
  - UI controls in sidebar with scan type selection and progress indicator
  - Scan results create new endpoints in the graph
  - Open ports stored in database for discovered devices
  - API endpoints: `/api/scan/start`, `/api/scan/stop`, `/api/scan/status`, `/api/scan/capabilities`
- Manual refresh button (🔄) next to auto-refresh stop button for on-demand data refresh
- Clicking an endpoint now clears the search filter for cleaner navigation
- Selected node indicator in sidebar showing "Selected: [node]" with unselect (X) button
- **Device Remote Control** - Control compatible devices directly from the UI
  - New "Control" tab in endpoint details panel (next to "Details")
  - **Roku TV/streaming device support** via External Control Protocol (ECP):
    - Navigation controls (D-pad: Up/Down/Left/Right/OK, Back, Home)
    - Playback controls (Play/Pause, Rewind, Fast Forward)
    - Volume controls (Up/Down/Mute)
    - Power control (Power Off)
    - App launcher with icons for installed apps
    - Device info display (model, name, software version)
  - **Samsung Smart TV support** via WebSocket API:
    - One-time pairing with approval on TV screen (token stored for future use)
    - Navigation controls (D-pad, Back, Home, Exit)
    - Playback controls (Play, Pause, Stop, Rewind, Fast Forward)
    - Volume and channel controls
    - Power, Source, and Menu buttons
    - Automatic token storage in database for seamless reconnection
  - API endpoints: `/api/device/capabilities`, `/api/device/command`, `/api/device/launch`, `/api/device/pair`
  - Automatic device detection - shows "No remote control available" for non-supported devices

### Performance
- **Database query optimization**: Reduced from 8+ connections per page load to 3 (with explicit drops to avoid lock contention)
- **N+1 query elimination**: Batch queries for endpoint types, IPs, MACs, and bytes instead of per-endpoint queries
  - Reduced from 100+ queries to 2-4 queries per page load
- **O(n²) to O(1)**: Replaced `Vec::contains()` with `HashSet` for deduplication
- **Scalar subquery elimination**: Replaced per-row subqueries with JOINs in communications query
- **Optimized identifier resolution**: Removed expensive GROUP BY with JOIN on communications table
- **Network interface caching**: Local network CIDR blocks computed once at startup instead of per-packet
- **LRU DNS cache eviction**: Removes oldest 1,000 entries instead of clearing all 10,000
- **Bounded mDNS entries**: Circular buffer (10,000 max) prevents unbounded memory growth
- **DocumentFragment batching**: DNS table refresh uses single DOM operation instead of per-row appends

### Changed
- Hostname lookup cached globally to avoid repeated system calls
- Local device is now always classified as "Local" type regardless of other detection

### Fixed
- Database locking issues with concurrent read/write access
  - Enabled WAL (Write-Ahead Logging) mode for concurrent reads during writes
  - Added 5-second busy timeout to wait for locks instead of failing
  - Set synchronous mode to NORMAL for better performance
- Endpoint list now filters to only show nodes visible in the graph when a node is selected
- Ports list now only shows ports from communications visible in the graph (prevents port filter from showing hidden edges)
- Port and protocol filters now respect device type filters (e.g., filtering by port 443 no longer shows Internet devices when Internet filter is unchecked)
- Ports list now dynamically updates based on visible edges when device type filters change

## [0.3.4]

### Added
- Manual device reclassification - click the device type badge in endpoint details to change classification
  - Dropdown with all device types: Local, Printer, TV, Gaming, Phone, VM, Soundbar, Appliance, Other
  - Select "Auto" to revert to automatic detection
  - Manual overrides persist in database and are indicated with "(manually set)" label
  - Manual overrides shown with purple highlight
- LG ThinQ smart appliance detection for dishwashers, washers, dryers, and refrigerators
  - Detects model number patterns: LMA, LMW, LDF, LDT, LDP, WM, DLE, DLEX, LRMV
  - Prevents misclassification as TV when appliances advertise AirPlay
- API endpoint `/api/dns-entries` for fetching mDNS entries as JSON
- API endpoint `/api/endpoint/classify` for setting manual device types

### Changed
- Auto-refresh now works on mDNS Entries tab - updates DNS table without page reload
- Auto-refresh and time range controls remain visible on both tabs
- Graph re-layouts automatically after filtering to prevent flower/disjointed patterns
- Removed Gateway and Internet from manual classification options (network-level, not device types)

### Fixed
- Device type display now respects manual overrides instead of always showing auto-detected type
- Local machine no longer forced to show as "Local" when manually reclassified

## [0.3.3]

### Added
- mDNS Entries tab in the header for viewing discovered mDNS/DNS entries
  - Displays timestamp, IP address, hostname, and services for each discovery
  - Tab-based navigation between Network view and mDNS Entries table
  - Tabs styled as buttons positioned under the logo
- Zoom controls on network graph (zoom in, zoom out, fit to view)
- Total bytes indicator on endpoints list showing traffic volume per endpoint
- Clickable stat badges in endpoint details that scroll to corresponding sections
- Endpoint name now displayed in endpoint details panel
- More robust protocol identification - only falls back to source port when destination is in ephemeral range (>=32768)

### Changed
- Auto-refresh and time range controls now hide when viewing mDNS Entries tab
- Auto-refresh is disabled when on the mDNS Entries tab to prevent unwanted page reloads
- Removed mDNS console log messages for cleaner output
- Increased node size and font on network graph for better visibility

### Fixed
- Protocol identification could incorrectly identify against ephemeral source ports

## [0.3.2]

### Added
- Port filtering functionality to match protocol filtering behavior
  - Click on any port badge to filter the graph to show only communications using that port
  - Port data now included on graph edges for filtering
  - Clear button to remove port filter
  - Filtered ports highlighted with visual feedback

### Changed
- Hostnames, IP addresses, MAC addresses, and ports in the right pane are now plain text displays
  - No longer clickable buttons with hover effects
  - Text can be selected and copied normally
  - Cleaner, simpler display that focuses on readability
  - Removed confusing interactive styling
  - Text items indented slightly to the right for better visual hierarchy
- Endpoint limit slider now applies consistently in all views
  - Previously bypassed when viewing a specific endpoint
  - Now limits the number of visible endpoints in both overall and specific endpoint views
- Ports now display as clickable badges matching protocol styling
  - Ports appear as styled badges that can be clicked to filter the graph
  - Port filtering shows only endpoints and communications using the selected port
  - Visual feedback with highlighting and dimming for better UX
- Protocol and port filters now work together instead of overriding each other
  - Selecting both a protocol and a port shows only communications that match BOTH filters (intersection)
  - Clearing one filter preserves the other filter
  - Previously, selecting a second filter would completely replace the first filter

### Fixed
- Critical bug where isolated endpoints (endpoints with no recent communications) were not visible on the graph
  - Backend was assigning type "device" to unclassified endpoints, but frontend only recognized specific types
  - Changed default endpoint type from "device" to "other" to match frontend filter system
  - Isolated endpoints now properly appear on the graph with the ❓ Other classification
  - This fixes issue where endpoints like 192.168.7.219 would not display even when explicitly selected
- Issue where local network devices (with private IP addresses) were classified as "Other" instead of "Local"
  - Endpoints with local IPs (192.168.x.x, 10.x.x.x, etc.) that don't match specific device types (printer, TV, etc.) are now properly classified as 🖥️ Local
  - Only truly unclassified endpoints (no IP or hostname) remain as ❓ Other
- Critical bug where clicking some ports in the ports list would show no endpoints on the graph
  - Previously only the first port for each communication pair was stored on graph edges
  - Now all ports are stored as comma-separated strings on edges (matching protocol behavior)
  - Port filtering now correctly shows all communications using the selected port
  - Added string conversion and trimming to ensure robust port comparisons
- Issue where "No Communications Found" message would not appear when port filtering resulted in no visible nodes
  - Added `checkForCommunications()` calls to port filtering functions
- Critical bug where ports list would show ports that don't appear on any graph edges
  - Ports from communications with unnamed endpoints would appear in the list but clicking them showed nothing
  - Added endpoint name filters to `get_ports_for_endpoint` query to match graph edge filters
  - Ports list now only shows ports that are actually visible on the graph

## [0.3.1]

### Added
- Automatic duplicate prevention now active - duplicates are merged immediately when detected during network scanning

### Fixed
- Issue where endpoints would show as local machine on graph when communicating with unnamed duplicate endpoints
- Cleanup script ensures all existing duplicates are merged before automatic prevention takes over
- Issue where selecting an endpoint with no recent communications would show an empty graph
  - Selected endpoint now always appears on the graph, even if it has no communications within the time range
  - Displays as an isolated node with no edges
  - This includes endpoints identified by IP address (e.g., 192.168.7.219) that have communications filtered out due to unnamed communication partners

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
