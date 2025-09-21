use num_derive::FromPrimitive;

// Macro to define all protocol ports and implementations at once
macro_rules! define_protocol_ports {
    ($(($variant:ident, $port:expr, $display:expr)),* $(,)?) => {
        #[derive(Debug, FromPrimitive)]
        pub enum ProtocolPort {
            $(
                $variant = $port,
            )*
        }

        impl ProtocolPort {
            pub fn get_all_protocols() -> Vec<String> {
                vec![
                    $(
                        Self::$variant.to_string(),
                    )*
                ]
            }
        }

        impl std::fmt::Display for ProtocolPort {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(
                        Self::$variant => write!(f, $display),
                    )*
                }
            }
        }
    };
}

// Use the macro to define everything in one place
define_protocol_ports! {
    // Web protocols
    (HTTP, 80, "HTTP"),
    (HTTPS, 443, "HTTPS"),
    // File transfer
    (FTP, 21, "FTP"),
    (FTPS, 990, "FTPS"),
    // Email
    (SMTP, 25, "SMTP"),
    (POP3, 110, "POP3"),
    (IMAP, 143, "IMAP"),
    // Domain and network services
    (DNS, 53, "DNS"),
    (DhcpServer, 67, "DHCP Server"),
    (DhcpClient, 68, "DHCP Client"),
    (NTP, 123, "NTP"),
    // Remote access
    (SSH, 22, "SSH"),
    (Telnet, 23, "Telnet"),
    (RDP, 3389, "RDP"),
    // Windows networking
    (SMB, 445, "SMB"),
    (NBNS, 137, "NetBIOS Name Service"),
    (NBDG, 138, "NetBIOS Datagram Service"),
    (NBSS, 139, "NetBIOS Session Service"),
    (MDNS, 5353, "mDNS"),
    (Valve, 27020, "Valve"),
    (Dota2, 27015, "Dota 2"),
    (AppleXServerAid, 3722, "Apple X Server AID"),
    (OAS, 58726, "OAS"),
    (WMI, 59632, "Windows Management Instrumentation"),
}
