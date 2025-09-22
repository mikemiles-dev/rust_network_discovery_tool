pub enum ProtocolPort {
    // Web protocols
    Http,
    Https,
    // File transfer
    Ftp,
    Ftps,
    // Email
    Smtp,
    Pop3,
    Imap,
    // Domain and network services
    Dns,
    DhcpServer,
    DhcpClient,
    Ntp,
    // Remote access
    Ssh,
    Telnet,
    Rdp,
    // Windows networking
    Smb,
    Nbns,
    Nbdg,
    Nbss,
    Immich,
    Mdns,
    Valve,
    Dota2,
    Dota2Workshop,
    Steam,
    AppleXServerAid,
    Oas,
    Wmi,
    Llmnr,
    Unknown(u16),
}

impl ProtocolPort {
    pub fn get_supported_protocols() -> Vec<String> {
        vec![
            ProtocolPort::Http,
            ProtocolPort::Https,
            ProtocolPort::Ftp,
            ProtocolPort::Ftps,
            ProtocolPort::Smtp,
            ProtocolPort::Pop3,
            ProtocolPort::Imap,
            ProtocolPort::Dns,
            ProtocolPort::DhcpServer,
            ProtocolPort::DhcpClient,
            ProtocolPort::Ntp,
            ProtocolPort::Ssh,
            ProtocolPort::Telnet,
            ProtocolPort::Rdp,
            ProtocolPort::Smb,
            ProtocolPort::Nbns,
            ProtocolPort::Nbdg,
            ProtocolPort::Nbss,
            ProtocolPort::Immich,
            ProtocolPort::Mdns,
            ProtocolPort::Valve,
            ProtocolPort::Dota2,
            ProtocolPort::Dota2Workshop,
            ProtocolPort::Steam,
            ProtocolPort::AppleXServerAid,
            ProtocolPort::Oas,
            ProtocolPort::Wmi,
            ProtocolPort::Llmnr,
            ProtocolPort::Unknown(0),
        ]
        .into_iter()
        .map(|protocol| format!("{}", protocol))
        .collect()
    }
}

impl From<u16> for ProtocolPort {
    fn from(port: u16) -> Self {
        match port {
            21 => ProtocolPort::Ftp,
            22 => ProtocolPort::Ssh,
            23 => ProtocolPort::Telnet,
            25 => ProtocolPort::Smtp,
            53 => ProtocolPort::Dns,
            67 => ProtocolPort::DhcpServer,
            68 => ProtocolPort::DhcpClient,
            80 => ProtocolPort::Http,
            110 => ProtocolPort::Pop3,
            123 => ProtocolPort::Ntp,
            137 => ProtocolPort::Nbns,
            138 => ProtocolPort::Nbdg,
            139 => ProtocolPort::Nbss,
            143 => ProtocolPort::Imap,
            443 => ProtocolPort::Https,
            445 => ProtocolPort::Smb,
            5353 => ProtocolPort::Mdns,
            5355 => ProtocolPort::Llmnr,
            3389 => ProtocolPort::Rdp,
            3722 => ProtocolPort::AppleXServerAid,
            59632 => ProtocolPort::Wmi,
            58726 => ProtocolPort::Oas,
            27005 => ProtocolPort::Dota2,
            27014 => ProtocolPort::Steam,
            27015 => ProtocolPort::Dota2,
            27020 => ProtocolPort::Dota2,
            27036 => ProtocolPort::Dota2,
            27042 => ProtocolPort::Dota2,
            27050 => ProtocolPort::Dota2,
            _ => ProtocolPort::Unknown(port),
        }
    }
}

impl std::fmt::Display for ProtocolPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let protocol_name = match self {
            ProtocolPort::Http => "HTTP",
            ProtocolPort::Https => "HTTPS",
            ProtocolPort::Ftp => "FTP",
            ProtocolPort::Ftps => "FTPS",
            ProtocolPort::Smtp => "SMTP",
            ProtocolPort::Pop3 => "POP3",
            ProtocolPort::Imap => "IMAP",
            ProtocolPort::Dns => "DNS",
            ProtocolPort::DhcpServer => "DHCP Server",
            ProtocolPort::DhcpClient => "DHCP Client",
            ProtocolPort::Ntp => "NTP",
            ProtocolPort::Ssh => "SSH",
            ProtocolPort::Telnet => "Telnet",
            ProtocolPort::Rdp => "RDP",
            ProtocolPort::Smb => "SMB",
            ProtocolPort::Nbns => "NBNS",
            ProtocolPort::Nbdg => "NBDG",
            ProtocolPort::Nbss => "NBSS",
            ProtocolPort::Immich => "Immich",
            ProtocolPort::Mdns => "mDNS",
            ProtocolPort::Valve => "Valve",
            ProtocolPort::Dota2 => "Dota 2",
            ProtocolPort::Dota2Workshop => "Dota 2 Workshop",
            ProtocolPort::Steam => "Steam",
            ProtocolPort::AppleXServerAid => "Apple Xserve Aid",
            ProtocolPort::Oas => "OAS",
            ProtocolPort::Wmi => "WMI",
            ProtocolPort::Llmnr => "LLMNR",
            ProtocolPort::Unknown(port) => return write!(f, "Unknown ({})", port),
        };
        write!(f, "{}", protocol_name)
    }
}
