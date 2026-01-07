# Release Notes

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions workflow for automated cross-platform binary releases
- Pre-built binaries for macOS (Intel & Apple Silicon), Linux, and Windows
- Comprehensive installation documentation

### Changed
- Updated README with detailed installation instructions for all platforms
- Clarified Windows Npcap requirements with direct download links

## [0.1.0] - TBD

### Added
- Modern dark UI with responsive web interface
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
