## ADDED Requirements

### Requirement: mDNS daemon starts before DB initialization completes
The mDNS daemon SHALL be started before awaiting `SQLWriter::new()` so that service discovery begins during database schema creation.

#### Scenario: Normal startup sequence
- **WHEN** the application starts
- **THEN** `MDnsLookup::start_daemon()` SHALL be called before `SQLWriter::new().await`
- **AND** mDNS service discovery SHALL begin while the database schema is being created

#### Scenario: mDNS writes before schema ready
- **WHEN** mDNS discovers a service before the database schema is fully created
- **THEN** the mDNS daemon's lazy DB connection (via `OnceLock`) SHALL handle this gracefully using its existing retry logic

#### Scenario: DB init completes normally
- **WHEN** database schema creation completes
- **THEN** subsequent mDNS daemon writes SHALL succeed normally
- **AND** the web server SHALL start after DB init as before
