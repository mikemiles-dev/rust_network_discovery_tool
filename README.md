Rust Network Discovery Tool

A lightweight network traffic monitoring tool that captures and visualizes network connections on your local network. Shows "what's talking to what" in an easy-to-use web interface.

## Features

- **Smart Interface Filtering**: Automatically monitors only real network interfaces (skips loopback, Docker, VPN)
- **Connection Deduplication**: Tracks unique connections instead of individual packets (reduces DB size by 99%+)
- **Automatic Data Retention**: Keeps data for 7 days by default (configurable)
- **Privacy-Focused**: Doesn't store packet payloads, only connection metadata
- **Real-time Web UI**: View network graph at http://127.0.0.1:8080
- **Protocol Detection**: Identifies HTTP, HTTPS, DNS, SSH, and 20+ other protocols
- **Hostname Resolution**: Uses DNS, mDNS, and deep packet inspection (SNI, HTTP Host headers)

## Usage

Basic:
```bash
cargo run
```

With configuration:
```bash
# Monitor specific interface(s)
MONITOR_INTERFACES="en0" cargo run

# Multiple interfaces
MONITOR_INTERFACES="en0,eth0" cargo run

# Custom database location
DATABASE_URL="my_network.db" cargo run

# Custom data retention (in days)
DATA_RETENTION_DAYS=30 cargo run

# Combine options
MONITOR_INTERFACES="en0" DATA_RETENTION_DAYS=14 DATABASE_URL="network.db" cargo run
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MONITOR_INTERFACES` | Auto-detect | Comma-separated list of interfaces to monitor (e.g., "en0,eth0") |
| `DATABASE_URL` | `test.db` | Path to SQLite database file |
| `DATA_RETENTION_DAYS` | `7` | Number of days to keep historical data |
| `CHANNEL_BUFFER_SIZE` | `10000000` | Internal packet buffer size |

## How It Works

1. **Captures packets** on selected network interfaces using libpnet
2. **Deduplicates connections**: Only stores unique (source, destination, protocol) tuples
3. **Updates last_seen_at** and packet_count for existing connections
4. **Resolves hostnames** using DNS, mDNS, and packet inspection
5. **Displays in web UI** with interactive graph visualization
6. **Cleans up old data** automatically based on retention policy

## Performance Optimizations

Unlike traditional packet capture tools that store every packet, this tool:
- ✅ Stores connections, not packets (1 row per connection instead of millions)
- ✅ Monitors only real network interfaces (not loopback/docker)
- ✅ Doesn't store packet payloads (privacy + storage savings)
- ✅ Auto-cleans old data (prevents unbounded growth)
- ✅ Uses database indexes for fast queries

**Example**: Downloading a 1GB file creates **1 database row** instead of **~700,000 rows**.

## Platform Support

- **macOS/Linux**: Full support
- **Windows**: Requires WinPcap/Npcap (see [libpnet docs](https://github.com/libpnet/libpnet))

## Screenshot

![Screenshot](screenshot.png)

## Privacy & Security

- **No payload storage**: Only connection metadata is stored
- **Local-only web UI**: Binds to 127.0.0.1 (not exposed to network)
- **No authentication**: Intended for personal use on trusted machines
- **Root/Admin required**: Packet capture requires elevated privileges