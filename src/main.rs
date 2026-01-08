mod db;
mod network;
mod web;

use clap::Parser;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;
use std::env;
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
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

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
            if let Some(desc) = &iface.description {
                println!("    Description: {}", desc);
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
