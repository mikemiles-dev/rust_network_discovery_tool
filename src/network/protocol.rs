use num_derive::FromPrimitive;

#[derive(Debug, FromPrimitive)]
pub enum ProtocolPort {
    // Web protocols
    HTTP = 80,
    HTTPS = 443,
    // File transfer
    FTP = 21,
    FTPS = 990,
    // Email
    SMTP = 25,
    POP3 = 110,
    IMAP = 143,
    // Domain and network services
    DNS = 53,
    DhcpServer = 67,
    DhcpClient = 68,
    NTP = 123,
    // Remote access
    SSH = 22,
    Telnet = 23,
    RDP = 3389,
    // Windows networking
    SMB = 445,
    NBNS = 137,
    NBDG = 138,
    NBSS = 139,
    MDNS = 5353,
    Valve = 27020,
    Dota2 = 27015,
    AppleXServerAid = 3722,
}

impl std::fmt::Display for ProtocolPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolPort::HTTP => write!(f, "HTTP"),
            ProtocolPort::HTTPS => write!(f, "HTTPS"),
            ProtocolPort::FTP => write!(f, "FTP"),
            ProtocolPort::FTPS => write!(f, "FTPS"),
            ProtocolPort::SMTP => write!(f, "SMTP"),
            ProtocolPort::POP3 => write!(f, "POP3"),
            ProtocolPort::IMAP => write!(f, "IMAP"),
            ProtocolPort::DNS => write!(f, "DNS"),
            ProtocolPort::DhcpServer => write!(f, "DHCP Server"),
            ProtocolPort::DhcpClient => write!(f, "DHCP Client"),
            ProtocolPort::NTP => write!(f, "NTP"),
            ProtocolPort::SSH => write!(f, "SSH"),
            ProtocolPort::Telnet => write!(f, "Telnet"),
            ProtocolPort::RDP => write!(f, "RDP"),
            ProtocolPort::SMB => write!(f, "SMB"),
            ProtocolPort::NBNS => write!(f, "NetBIOS Name Service"),
            ProtocolPort::NBDG => write!(f, "NetBIOS Datagram Service"),
            ProtocolPort::NBSS => write!(f, "NetBIOS Session Service"),
            ProtocolPort::MDNS => write!(f, "mDNS"),
            ProtocolPort::Valve => write!(f, "Valve"),
            ProtocolPort::Dota2 => write!(f, "Dota 2"),
            ProtocolPort::AppleXServerAid => write!(f, "Apple X Server AID"),
        }
    }
}
