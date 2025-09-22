mod db;
mod network;
mod web;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;
use tokio::{io, task};

use db::SQLWriter;
use {network::communication::Communication, network::mdns_lookup::MDnsLookup};

#[tokio::main]
async fn main() -> io::Result<()> {
    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();

    let mut handles = vec![];

    let sql_writer = SQLWriter::new().await;

    // Setup Ctrl+C handler
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl+C, shutting down...");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");

    MDnsLookup::start_daemon();
    web::start();

    for interface in interfaces.into_iter() {
        let sender = sql_writer.sender.clone();
        let result = task::spawn_blocking(move || capture_packets(interface, sender));
        handles.push(result);
    }

    Ok(())
}

fn capture_packets(
    interface: NetworkInterface,
    sender: tokio::sync::mpsc::Sender<Communication>,
) -> io::Result<()> {
    println!("Starting packet capture on interface: {}", interface.name);
    // Create a new channel, dealing with layer 2 packets
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_packet: EthernetPacket<'_> = EthernetPacket::new(packet).unwrap();
                let communication: Communication =
                    Communication::new(ethernet_packet, interface.name.clone());
                if let Err(e) = sender.blocking_send(communication) {
                    eprintln!("Failed to send communication to SQL writer: {}", e);
                }
            }
            Err(e) => {
                println!("An error occurred while reading: {}", e);
            }
        }
    }
}
