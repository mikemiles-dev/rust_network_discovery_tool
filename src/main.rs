pub mod network;
pub mod writer;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;

use tokio::{io, task};

use network::communication::Communication;
use writer::SQLWriter;

#[tokio::main]
async fn main() -> io::Result<()> {
    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();

    let mut handles = vec![];

    let sql_writer = SQLWriter::new().await;

    for interface in interfaces.into_iter() {
        let sql_writer_clone = sql_writer.clone();
        let result = task::spawn_blocking(move || capture_packets(interface, sql_writer_clone));
        handles.push(result);
    }

    futures::future::join_all(handles).await;

    Ok(())
}

fn capture_packets(interface: NetworkInterface, sql_writer: SQLWriter) -> io::Result<()> {
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
                communication.write(sql_writer.clone());
            }
            Err(e) => {
                println!("An error occurred while reading: {}", e);
            }
        }
    }
}
