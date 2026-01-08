Rust Network Discovery Tool

![Screenshot](screenshot.png)

A lightweight network traffic monitoring tool that captures and visualizes network connections on your local network. Shows "what's talking to what" in an easy-to-use web interface.

## Features

- **Smart Interface Filtering**: Automatically monitors only real network interfaces (skips loopback, Docker, VPN)
- **Connection Deduplication**: Tracks unique connections instead of individual packets 
- **Automatic Data Retention**: Keeps data for 7 days by default (configurable)
- **Privacy-Focused**: Doesn't store packet payloads, only connection metadata
- **Interactive Network Graph**: Click-to-navigate network visualization powered by Cytoscape.js
- **Protocol Detection**: Identifies HTTP, HTTPS, DNS, SSH, and 20+ other protocols
- **Hostname Resolution**: Uses DNS, mDNS, and deep packet inspection (SNI, HTTP Host headers)
- **DNS Caching**: Prevents slow lookups with DNS cache
- **High Performance**: Optimized with database indexes, transaction batching, and connection pooling

## Installation

### Pre-built Binaries

Download the latest release for your platform from the [Releases page](https://github.com/mikemiles-dev/rust_network_discovery_tool/releases/latest):

- **macOS (Apple Silicon)**: `awareness-macos-aarch64.tar.gz`
- **macOS (Intel)**: `awareness-macos-x86_64.tar.gz`
- **Linux**: `awareness-linux-x86_64.tar.gz`
- **Windows**: `awareness-windows-x86_64.zip`

#### macOS/Linux Installation

```bash
# Download and extract (adjust filename for your platform)
tar -xzf awareness-macos-aarch64.tar.gz

# Make executable
chmod +x awareness

# Move to PATH (optional)
sudo mv awareness /usr/local/bin/

# Run with sudo (required for packet capture)
sudo awareness
```

Then open http://localhost:8080 in your browser (or the port you configured with `WEB_PORT`).

#### Windows Installation

1. Download and extract the ZIP file from the releases page
2. **Install Npcap** (required for packet capture):
   - Download from: https://npcap.com/#download
   - Run the installer with default options
   - Npcap provides the packet capture drivers that `awareness.exe` needs to monitor network traffic
   - Alternative: WinPcap also works but Npcap is recommended and actively maintained
3. Run PowerShell or Command Prompt as Administrator
4. Navigate to the extracted folder and run `awareness.exe`

Then open http://localhost:8080 in your browser (or the port you configured with `WEB_PORT`).

**Important for Windows users**: While the `awareness.exe` binary is fully statically linked (no DLL dependencies for Rust code), it still requires Npcap/WinPcap drivers to be installed on your system. These are kernel-mode drivers that enable packet capture on Windows and cannot be bundled with the application.

### Build from Source

Requirements:
- Rust
- libpcap (Linux/macOS) or Npcap (Windows)

```bash
git clone https://github.com/mikemiles-dev/rust_network_discovery_tool.git
cd rust_network_discovery_tool
cargo build --release
```

The binary will be in `target/release/awareness`.

## Usage

### Command Line Options

```bash
# Show help
awareness --help

# List all available network interfaces (recommended first step)
awareness --list-interfaces

# Monitor a specific interface by index number (easiest)
awareness --interface 1

# Monitor a specific interface by name
awareness --interface "Wi-Fi"
# On Windows: awareness --interface "\Device\NPF_{...}"

# Monitor multiple interfaces
awareness --interface "en0,eth0"

# Use custom web server port
awareness --port 9000

# Combine options
awareness --interface 1 --port 3000
```

### Windows-Specific Interface Selection

On Windows, network interfaces have technical names like `\Device\NPF_{GUID}` which are hard to work with. We recommend using the index-based selection:

1. First, list available interfaces:
   ```powershell
   awareness --list-interfaces
   ```

2. Find the interface with IP addresses assigned (usually your Ethernet or Wi-Fi adapter)
   - **Note**: The status (UP/DOWN) may be unreliable on Windows due to limitations in the underlying `pnet` library
   - Look for interfaces that have IP addresses assigned instead

3. Use the index number in brackets:
   ```powershell
   awareness --interface 1
   ```

**Multiple Interface Warning**: If you run `awareness` without specifying an interface on Windows, it will monitor ALL interfaces that have IP addresses. This may include virtual adapters (VPN, Hyper-V, VMware, etc.). You'll see a warning like:

```
⚠️  Warning: Monitoring 3 interfaces simultaneously.
   This may include virtual adapters (VPN, Hyper-V, VMware, etc.)
   To monitor a specific interface, use: awareness --list-interfaces
   Then select one with: awareness --interface <number>
```

To avoid monitoring unwanted virtual adapters, use `--list-interfaces` first and select your primary network adapter explicitly.

### Environment Variables

You can also configure the tool using environment variables:

```bash
# Monitor specific interface(s) - supports index numbers or names
MONITOR_INTERFACES="1" cargo run

# Multiple interfaces
MONITOR_INTERFACES="en0,eth0" cargo run

# Custom database location
DATABASE_URL="my_network.db" cargo run

# Custom data retention (in days)
DATA_RETENTION_DAYS=30 cargo run

# Custom web server port (CLI --port flag takes precedence)
WEB_PORT=9000 cargo run

# Combine options
MONITOR_INTERFACES="1" DATA_RETENTION_DAYS=14 DATABASE_URL="network.db" WEB_PORT=3000 cargo run
```

### Configuration Reference

| CLI Option | Environment Variable | Default | Description |
|------------|---------------------|---------|-------------|
| `--interface` / `-i` | `MONITOR_INTERFACES` | Auto-detect | Interface(s) to monitor (supports index numbers or names, comma-separated) |
| `--port` / `-p` | `WEB_PORT` | `8080` | Web server port (CLI option takes precedence) |
| `--list-interfaces` / `-l` | - | - | List all available interfaces and exit |
| - | `DATABASE_URL` | `test.db` | Path to SQLite database file |
| - | `DATA_RETENTION_DAYS` | `7` | Number of days to keep historical data |
| - | `CHANNEL_BUFFER_SIZE` | `10000000` | Internal packet buffer size |

## How It Works

1. **Captures packets** on selected network interfaces using libpnet
2. **Deduplicates connections**: Only stores unique (source, destination, protocol) tuples
3. **Updates last_seen_at** and packet_count for existing connections
4. **Resolves hostnames** using DNS, mDNS, and packet inspection
5. **Displays in web UI** with interactive graph visualization
6. **Cleans up old data** automatically based on retention policy

## Platform Support

- **macOS**: Full support (Intel and Apple Silicon)
- **Linux**: Full support (x86_64)
- **Windows**: Full support - requires [Npcap](https://npcap.com/#download) drivers to be installed (see Installation section above)

## Troubleshooting

### Windows: "No suitable network interfaces found"

If you see this error on Windows, try these steps:

1. **Verify Npcap is installed and running:**
   - Download from https://npcap.com/#download
   - Install with default options
   - Restart your computer after installation

2. **Run as Administrator:**
   - Right-click on PowerShell or Command Prompt
   - Select "Run as Administrator"
   - Navigate to the folder and run `awareness.exe`

3. **Manually select your interface:**
   ```powershell
   # First, list all interfaces
   awareness --list-interfaces

   # Find your active network adapter (look for interfaces with IP addresses)
   # Note: Status (UP/DOWN) may be unreliable on Windows
   # Then use the index number:
   awareness --interface 1
   ```

4. **Check your network adapter:**
   - Open Network Connections (Windows Settings → Network & Internet)
   - Ensure your Ethernet or Wi-Fi adapter is connected and has an IP address
   - Disable and re-enable the adapter if needed

### Windows: Monitoring Too Many Interfaces

If you see a warning about monitoring multiple interfaces simultaneously:

```
⚠️  Warning: Monitoring 3 interfaces simultaneously.
   This may include virtual adapters (VPN, Hyper-V, VMware, etc.)
```

**This is expected behavior** on Windows. The tool cannot reliably determine interface status due to `pnet` library limitations, so it monitors all interfaces with IP addresses. This may include:
- VPN adapters
- Hyper-V virtual switches
- VMware network adapters
- Docker adapters (though these are filtered out)

**Solution**: Use `--list-interfaces` to see all available interfaces, then select your primary network adapter:
```powershell
awareness --interface 1
```

### macOS/Linux: Permission Denied

Packet capture requires elevated privileges:

```bash
# Run with sudo
sudo awareness

# Or set capabilities (Linux only)
sudo setcap cap_net_raw,cap_net_admin=eip ./awareness
```

## Privacy & Security

- **No payload storage**: Only connection metadata is stored
- **Local-only web UI**: Binds to 127.0.0.1 (not exposed to network)
- **No authentication**: Intended for personal use on trusted machines
- **Root/Admin required**: Packet capture requires elevated privileges