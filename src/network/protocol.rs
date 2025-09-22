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
    (Http, 80, "HTTP"),
    (Https, 443, "HTTPS"),
    // File transfer
    (Ftp, 21, "FTP"),
    (Ftps, 990, "FTPS"),
    // Email
    (Smtp, 25, "SMTP"),
    (Pop3, 110, "POP3"),
    (Imap, 143, "IMAP"),
    // Domain and network services
    (Dns, 53, "DNS"),
    (DhcpServer, 67, "DHCP Server"),
    (DhcpClient, 68, "DHCP Client"),
    (Ntp, 123, "NTP"),
    // Remote access
    (Ssh, 22, "SSH"),
    (Telnet, 23, "Telnet"),
    (Rdp, 3389, "RDP"),
    // Windows networking
    (Smb, 445, "SMB"),
    (Nbns, 137, "NetBIOS Name Service"),
    (Nbdg, 138, "NetBIOS Datagram Service"),
    (Nbss, 139, "NetBIOS Session Service"),
    (Immich, 2238, "Immich"),
    (Mdns, 5353, "mDNS"),
    (Valve, 27020, "Valve"),
    (Dota2, 27015, "Dota 2"),
    (AppleXServerAid, 3722, "Apple X Server AID"),
    (Oas, 58726, "OAS"),
    (Wmi, 59632, "WMI"),
}
