## ADDED Requirements

### Requirement: Connection pool replaces per-query connection creation
The system SHALL use an r2d2 connection pool for database access instead of opening a new connection per query via `new_connection()` / `new_connection_result()`.

#### Scenario: Pool initialized at startup
- **WHEN** the application starts
- **THEN** a connection pool SHALL be initialized with WAL mode, busy_timeout, and synchronous=NORMAL pragmas applied to each connection

#### Scenario: Query functions use pooled connections
- **WHEN** any web handler query function (e.g., `dropdown_endpoints`, `get_combined_endpoint_stats`) needs a database connection
- **THEN** it SHALL obtain the connection from the pool instead of calling `new_connection_result()`

#### Scenario: Pool size limits concurrent connections
- **WHEN** multiple queries run in parallel (e.g., 4 spawn_blocking tasks in the table handler)
- **THEN** the pool SHALL manage connections with a configurable max size (default 8) to prevent connection storms
