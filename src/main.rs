mod db;
mod network;
mod web;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;
use std::env;
use tokio::{io, task};

use db::SQLWriter;
use {network::communication::Communication, network::mdns_lookup::MDnsLookup};

#[tokio::main]
async fn main() -> io::Result<()> {
    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();

    let sql_writer = SQLWriter::new().await;

    // Setup Ctrl+C handler for immediate shutdown
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl+C, shutting down...");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");

    MDnsLookup::start_daemon();

    // Read web server port from environment variable, default to 8080
    let web_port = env::var("WEB_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);

    web::start(web_port);

    // Check for specific interface selection via environment variable
    let selected_interfaces = env::var("MONITOR_INTERFACES").ok().map(|s| {
        s.split(',')
            .map(|i| i.trim().to_string())
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
        })
        .collect();

    if filtered_interfaces.is_empty() {
        eprintln!("No suitable network interfaces found!");
        eprintln!("Available interfaces:");
        for iface in datalink::interfaces() {
            eprintln!(
                "  - {} (up: {}, ips: {})",
                iface.name,
                iface.is_up(),
                iface.ips.len()
            );
        }
        return Ok(());
    }

    println!("Monitoring interfaces:");
    for iface in &filtered_interfaces {
        println!("  - {}", iface.name);
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
