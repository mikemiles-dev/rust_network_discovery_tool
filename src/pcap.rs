//! PCAP file processing. Reads captured packet files, extracts Ethernet frames,
//! and sends them to the database writer with progress tracking.

use pcap::Capture;
use pnet::packet::ethernet::EthernetPacket;
use std::io::{self, Write};
use std::path::Path;

use crate::network::communication::Communication;

/// Process a PCAP file and send packets to the database writer.
///
/// Returns the number of packets successfully processed.
pub fn process_pcap_file(
    file_path: &str,
    label: Option<String>,
    sender: &tokio::sync::mpsc::Sender<Communication>,
) -> io::Result<usize> {
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
                io::stdout().flush().ok();
            }
        }
    }

    println!("\rProcessed {} packets from {}", packet_count, file_path);
    Ok(packet_count)
}
