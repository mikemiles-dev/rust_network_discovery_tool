mod db;
mod network;
mod web;

#[cfg(test)]
mod test_utils;

use clap::Parser;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;
use std::env;
use std::path::Path;
use tokio::{io, task};

use db::SQLWriter;
use {network::communication::Communication, network::mdns_lookup::MDnsLookup};

/// Network discovery tool that monitors network interfaces and captures traffic
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Specific network interface(s) to monitor (comma-separated, or use index number from --list-interfaces)
    #[arg(short, long, value_delimiter = ',')]
    interface: Option<Vec<String>>,

    /// List all available network interfaces and exit
    #[arg(short, long)]
    list_interfaces: bool,

    /// Web server port
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Import pcap file(s) instead of live capture
    #[arg(long, value_name = "FILE")]
    import: Option<Vec<String>>,

    /// Label/source name for imported pcap files
    #[arg(long, requires = "import")]
    label: Option<String>,

    /// Batch mode: import pcap and exit (don't start web server)
    #[arg(long, requires = "import")]
    batch: bool,
}

fn process_pcap_file(
    file_path: &str,
    label: Option<String>,
    sender: &tokio::sync::mpsc::Sender<Communication>,
) -> io::Result<usize> {
    use pcap::Capture;

    println!("Processing pcap file: {}", file_path);

    let source_label = label.unwrap_or_else(|| {
        Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(file_path)
            .to_string()
    });

    let mut cap = Capture::from_file(file_path)
        .map_err(|e| io::Error::other(format!("Failed to open pcap file {}: {}", file_path, e)))?;

    let mut packet_count = 0;
    while let Ok(packet) = cap.next_packet() {
        if let Some(ethernet_packet) = EthernetPacket::new(packet.data) {
            let communication =
                Communication::new_with_source(ethernet_packet, Some(source_label.clone()));

            if sender.blocking_send(communication).is_err() {
                eprintln!("Warning: Failed to send packet to database writer");
                break;
            }
            packet_count += 1;

            if packet_count % 1000 == 0 {
                print!("\rProcessed {} packets...", packet_count);
                use std::io::Write;
                std::io::stdout().flush().ok();
            }
        }
    }

    println!("\rProcessed {} packets from {}", packet_count, file_path);
    Ok(packet_count)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    // Handle pcap import mode
    if let Some(ref pcap_files) = args.import {
        println!("Running in pcap import mode");

        let sql_writer = SQLWriter::new().await;

        let mut total_packets = 0;
        for pcap_file in pcap_files {
            match process_pcap_file(pcap_file, args.label.clone(), &sql_writer.sender) {
                Ok(count) => total_packets += count,
                Err(e) => {
                    eprintln!("Error processing {}: {}", pcap_file, e);
                    if !args.batch {
                        eprintln!("Continuing with remaining files...");
                    }
                }
            }
        }

        println!(
            "\nImport complete: {} total packets processed",
            total_packets
        );

        // In batch mode, wait a moment for DB writes to complete, then exit
        if args.batch {
            println!("Batch mode: waiting for database writes to complete...");
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            println!("Done.");
            return Ok(());
        }

        // Otherwise, start web server for analysis
        println!("\nStarting web server for analysis...");
        let web_port = if args.port != 8080 {
            args.port
        } else {
            env::var("WEB_PORT")
                .ok()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(args.port)
        };

        web::start(web_port);

        // Keep main thread alive indefinitely (Ctrl+C will exit)
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    // Get all network interfaces
    let interfaces = datalink::interfaces();

    // If --list-interfaces flag is set, display all interfaces and exit
    if args.list_interfaces {
        println!("Available network interfaces:");
        println!("{:=<100}", "");

        #[cfg(target_os = "windows")]
        println!("Note: On Windows, interface names are technical device paths.");
        #[cfg(target_os = "windows")]
        println!("Look for interfaces with IP addresses assigned (Status may be unreliable).\n");

        for (idx, iface) in interfaces.iter().enumerate() {
            println!("[{}] {}", idx + 1, iface.name);

            // Show description on Windows if available
            #[cfg(target_os = "windows")]
            if !iface.description.is_empty() {
                println!("    Description: {}", iface.description);
            }

            println!(
                "    Status: {}",
                if iface.is_up() { "UP ✓" } else { "DOWN" }
            );

            let ip_info = if iface.ips.is_empty() {
                "None".to_string()
            } else {
                iface
                    .ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            println!("    IP Addresses: {}", ip_info);

            if let Some(mac) = iface.mac {
                println!("    MAC: {}", mac);
            }

            println!("{:-<100}", "");
        }

        println!("\nTo monitor a specific interface:");

        #[cfg(target_os = "windows")]
        {
            println!("  Option 1 (Easier): Use the index number");
            println!("    awareness --interface 1");
            println!("\n  Option 2: Use the full device path");
            println!("    awareness --interface \"\\Device\\NPF_{{...}}\"");
            println!("\nTip: Use the index number [1], [2], etc. shown above.");
            println!("     Look for interfaces with IP addresses assigned.");
        }

        #[cfg(not(target_os = "windows"))]
        {
            println!("  Option 1 (Easier): Use the index number");
            println!("    awareness --interface 1");
            println!("\n  Option 2: Use the interface name");
            println!("    awareness --interface \"<interface-name>\"");
            println!("\nExample: awareness --interface \"Wi-Fi\"");
        }

        return Ok(());
    }

    let sql_writer = SQLWriter::new().await;

    // Setup Ctrl+C handler for immediate shutdown
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl+C, shutting down...");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");

    MDnsLookup::start_daemon();

    // Check for port from CLI args, then env variable, then default
    let web_port = if args.port != 8080 {
        // CLI arg was explicitly set (not default)
        args.port
    } else {
        // Try env variable, fall back to CLI default (8080)
        env::var("WEB_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(args.port)
    };

    web::start(web_port);

    // Check for interface selection from CLI args, then env variable
    let selected_interfaces = args
        .interface
        .or_else(|| {
            env::var("MONITOR_INTERFACES").ok().map(|s| {
                s.split(',')
                    .map(|i| i.trim().to_string())
                    .collect::<Vec<String>>()
            })
        })
        .map(|selections| {
            // Support selecting by index number (e.g., "1" or "2") in addition to name
            selections
                .iter()
                .filter_map(|s| {
                    // Try parsing as index first
                    if let Ok(idx) = s.parse::<usize>() {
                        // Index is 1-based for user friendliness
                        if idx > 0 && idx <= interfaces.len() {
                            Some(interfaces[idx - 1].name.clone())
                        } else {
                            eprintln!(
                                "Warning: Interface index {} is out of range (1-{})",
                                idx,
                                interfaces.len()
                            );
                            None
                        }
                    } else {
                        // Otherwise use as interface name
                        Some(s.clone())
                    }
                })
                .collect::<Vec<String>>()
        });

    // Filter interfaces to only monitor real network interfaces
    let filtered_interfaces: Vec<NetworkInterface> = interfaces
        .into_iter()
        .filter(|iface| {
            // If specific interfaces are configured, only monitor those
            if let Some(ref selected) = selected_interfaces
                && !selected.contains(&iface.name)
            {
                return false;
            }

            let name = iface.name.to_lowercase();

            // On Windows, be more permissive with interface selection
            #[cfg(target_os = "windows")]
            {
                // On Windows, skip obvious loopback and virtual interfaces but be less strict
                // Windows interfaces often have names like "Ethernet", "Wi-Fi", "Local Area Connection"
                // Don't filter out interfaces with "virtual" in the name on Windows,
                // as valid adapters like Hyper-V or VPN connections may contain this
                // Note: is_up() is unreliable on Windows with pnet, so we check for IP addresses instead
                !name.contains("loopback") && !name.starts_with("docker") && !iface.ips.is_empty() // Must have an IP address (more reliable than is_up on Windows)
            }

            // On Unix/Linux/macOS, use stricter filtering
            #[cfg(not(target_os = "windows"))]
            {
                // Skip loopback, docker, virtual interfaces, etc.
                !name.starts_with("lo")
                    && !name.starts_with("docker")
                    && !name.starts_with("veth")
                    && !name.starts_with("br-")
                    && !name.starts_with("vmnet")
                    && !name.starts_with("vbox")
                    && !name.contains("virtual")
                    && iface.is_up()
                    && !iface.ips.is_empty() // Must have an IP address
            }
        })
        .collect();

    if filtered_interfaces.is_empty() {
        eprintln!("No suitable network interfaces found!");
        eprintln!("\nAvailable interfaces:");
        for (idx, iface) in datalink::interfaces().iter().enumerate() {
            eprintln!(
                "  [{}] {} (up: {}, ips: {})",
                idx + 1,
                iface.name,
                iface.is_up(),
                iface.ips.len()
            );
        }

        #[cfg(target_os = "windows")]
        {
            eprintln!("\nNote: On Windows, you may need to manually select your interface.");
            eprintln!("Common causes:");
            eprintln!("  - Npcap/WinPcap not installed or not running");
            eprintln!("  - No network adapter is active with an IP address");
            eprintln!("  - Running without Administrator privileges");
        }

        eprintln!("\nTo use a specific interface:");
        eprintln!("  1. Use index number (easier):");
        eprintln!("     awareness --interface 1");
        eprintln!("\n  2. Use full interface name:");

        #[cfg(target_os = "windows")]
        eprintln!("     awareness --interface \"\\Device\\NPF_{{...}}\"");

        #[cfg(not(target_os = "windows"))]
        eprintln!("     awareness --interface \"<interface-name>\"");

        eprintln!("\n  3. Set environment variable:");
        eprintln!("     MONITOR_INTERFACES=1 awareness");
        eprintln!("     WEB_PORT=3000 awareness");
        eprintln!("\nFor more details, use: awareness --list-interfaces");
        return Ok(());
    }

    println!("Monitoring interfaces:");
    for iface in &filtered_interfaces {
        println!("  - {}", iface.name);
    }

    // Warn on Windows if monitoring multiple interfaces
    #[cfg(target_os = "windows")]
    if filtered_interfaces.len() > 1 && selected_interfaces.is_none() {
        println!(
            "\n⚠️  Warning: Monitoring {} interfaces simultaneously.",
            filtered_interfaces.len()
        );
        println!("   This may include virtual adapters (VPN, Hyper-V, VMware, etc.)");
        println!("   To monitor a specific interface, use: awareness --list-interfaces");
        println!("   Then select one with: awareness --interface <number>\n");
    }

    for interface in filtered_interfaces.into_iter() {
        let sender = sql_writer.sender.clone();
        task::spawn_blocking(move || capture_packets(interface, sender));
    }

    // Keep main thread alive indefinitely (Ctrl+C will exit)
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}

fn capture_packets(
    interface: NetworkInterface,
    sender: tokio::sync::mpsc::Sender<Communication>,
) -> io::Result<()> {
    println!("Starting packet capture on interface: {}", interface.name);

    // Create a new channel, dealing with layer 2 packets
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("Unsupported channel type for interface: {}", interface.name);
            return Ok(()); // Skip this interface
        }
        Err(e) => {
            eprintln!(
                "Failed to create datalink channel for interface {}: {}",
                interface.name, e
            );
            eprintln!("Hint: Try running with sudo/administrator privileges");
            return Ok(()); // Skip this interface
        }
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                // Parse ethernet packet
                let ethernet_packet = match EthernetPacket::new(packet) {
                    Some(pkt) => pkt,
                    None => {
                        // Malformed packet, skip it
                        continue;
                    }
                };

                let communication: Communication = Communication::new(ethernet_packet);
                if let Err(e) = sender.blocking_send(communication) {
                    eprintln!("Failed to send communication to SQL writer: {}", e);
                    break; // Channel closed, exit loop
                }
            }
            Err(e) => {
                eprintln!("Error reading packet on {}: {}", interface.name, e);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_test_connection;
    use crate::test_utils::{PacketBuilder, create_test_pcap};
    use pnet::packet::ethernet::EthernetPacket;

    #[test]
    fn test_communication_from_synthetic_packet() {
        let packet_data = PacketBuilder::https_packet("192.168.1.100", "1.1.1.1");
        let eth_packet = EthernetPacket::new(&packet_data).unwrap();

        let comm = Communication::new(eth_packet);

        assert_eq!(comm.source_ip, Some("192.168.1.100".to_string()));
        assert_eq!(comm.destination_ip, Some("1.1.1.1".to_string()));
        assert_eq!(comm.destination_port, Some(443));
        assert_eq!(comm.ip_header_protocol, Some("Tcp".to_string()));
    }

    #[test]
    fn test_communication_insertion_to_db() {
        let conn = new_test_connection();
        let packet_data = PacketBuilder::https_packet("192.168.1.100", "8.8.8.8");
        let eth_packet = EthernetPacket::new(&packet_data).unwrap();

        let comm = Communication::new_with_source(eth_packet, Some("test".to_string()));
        let result = comm.insert_communication(&conn);

        assert!(result.is_ok());

        // Verify communication was inserted
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM communications", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);

        // Verify source was stored
        let source: String = conn
            .query_row(
                "SELECT source FROM communications WHERE source IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source, "test");
    }

    #[test]
    fn test_pcap_file_creation_and_reading() {
        // Create synthetic packets
        let packets = vec![
            PacketBuilder::https_packet("192.168.1.100", "1.1.1.1"),
            PacketBuilder::http_packet("192.168.1.100", "8.8.8.8"),
            PacketBuilder::dns_packet("192.168.1.100", "8.8.4.4"),
        ];

        // Create pcap file
        let pcap_file = create_test_pcap(packets.clone()).unwrap();
        let path = pcap_file.path().to_str().unwrap();

        // Verify file exists
        assert!(std::path::Path::new(path).exists());

        // Read it back using pcap crate
        use pcap::Capture;
        let mut cap = Capture::from_file(path).unwrap();

        let mut packet_count = 0;
        while cap.next_packet().is_ok() {
            packet_count += 1;
        }

        assert_eq!(packet_count, 3);
    }

    #[tokio::test]
    async fn test_integration_pcap_import_to_db() {
        // Create synthetic packets representing different types of traffic
        let packets = vec![
            PacketBuilder::https_packet("192.168.1.100", "1.1.1.1"), // Cloudflare
            PacketBuilder::https_packet("192.168.1.100", "8.8.8.8"), // Google DNS
            PacketBuilder::http_packet("192.168.1.100", "142.250.185.46"), // Google
            PacketBuilder::dns_packet("192.168.1.100", "8.8.4.4"),   // Google DNS
            PacketBuilder::https_packet("192.168.1.101", "1.1.1.1"), // Different local IP
        ];

        // Create pcap file
        let pcap_file = create_test_pcap(packets).unwrap();
        let path = pcap_file.path().to_str().unwrap().to_string();

        // Use in-memory DB for testing
        unsafe {
            std::env::set_var("DATABASE_URL", ":memory:");
        }

        // Create SQL writer
        let sql_writer = db::SQLWriter::new().await;

        // Process the pcap file in a blocking task
        let sender = sql_writer.sender.clone();
        let result = tokio::task::spawn_blocking(move || {
            process_pcap_file(&path, Some("integration_test".to_string()), &sender)
        })
        .await
        .unwrap();

        assert!(result.is_ok());
        let packet_count = result.unwrap();
        assert_eq!(packet_count, 5);

        // Give the SQL writer time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

        // Verify data in database (Note: won't work with different in-memory DB)
        // This test verifies that pcap files can be processed without errors
        println!(
            "Successfully processed {} packets from pcap file",
            packet_count
        );
    }

    #[test]
    fn test_different_protocol_packets() {
        let conn = new_test_connection();

        // Test TCP packet (use unicast MACs - LSB of first octet must be 0)
        let tcp_packet = PacketBuilder::tcp_packet(
            "aa:bb:cc:dd:ee:ff", // 0xAA = 0b10101010, LSB=0, unicast ✓
            "00:22:33:44:55:66", // 0x00 = 0b00000000, LSB=0, unicast ✓
            "192.168.1.100",
            "8.8.8.8",
            12345,
            443,
        );
        let eth = EthernetPacket::new(&tcp_packet).unwrap();
        let comm_tcp = Communication::new(eth);
        assert_eq!(comm_tcp.ip_header_protocol, Some("Tcp".to_string()));
        assert!(comm_tcp.insert_communication(&conn).is_ok());

        // Test UDP packet
        let udp_packet = PacketBuilder::udp_packet(
            "aa:bb:cc:dd:ee:ff",
            "00:22:33:44:55:66",
            "192.168.1.100",
            "8.8.8.8",
            54321,
            53,
        );
        let eth = EthernetPacket::new(&udp_packet).unwrap();
        let comm_udp = Communication::new(eth);
        assert_eq!(comm_udp.ip_header_protocol, Some("Udp".to_string()));
        assert!(comm_udp.insert_communication(&conn).is_ok());

        // Verify both were inserted
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM communications", [], |row| row.get(0))
            .unwrap();

        assert_eq!(count, 2);
    }
}
