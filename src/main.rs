pub mod packet;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::EthernetPacket;

use tokio::io;

use packet::communication::Communication;

#[tokio::main]
async fn main() -> io::Result<()> {
    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();

    let mut results = vec![];

    for interface in interfaces.into_iter() {
        println!("Capturing on interface: {}", interface.name);
        let result = tokio::spawn(async { capture_packets(interface).await });
        results.push(result);
    }

    for result in results {
        let _ = result.await;
    }

    Ok(())
}

async fn capture_packets(interface: NetworkInterface) -> io::Result<()> {
    // Create a new channel, dealing with layer 2 packets
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };
    let mut communications = vec![];
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_packet: EthernetPacket<'_> = EthernetPacket::new(packet).unwrap();
                let mut communication: Communication = ethernet_packet.into();
                communication.interface = interface.name.clone();
                println!("Detected communication: {:?}", communication);
                communications.push(communication);
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                println!("An error occurred while reading: {}", e);
            }
        }
    }
}
