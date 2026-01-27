pub enum ProtocolPort {
    // Web protocols
    Http,
    Https,
    HttpAlt,
    HttpProxy,

    // File transfer
    Ftp,
    FtpData,
    Ftps,
    Sftp,
    Tftp,

    // Email
    Smtp,
    SmtpSecure,
    Pop3,
    Pop3Secure,
    Imap,
    ImapSecure,

    // Domain and network services
    Dns,
    DhcpServer,
    DhcpClient,
    Ntp,
    Snmp,
    SnmpTrap,
    Ldap,
    LdapSecure,

    // Remote access
    Ssh,
    Telnet,
    Rdp,
    Vnc,

    // Windows networking
    Smb,
    Nbns,
    Nbdg,
    Nbss,
    Wmi,
    ActiveDirectory,
    Kerberos,

    // Database
    Mysql,
    PostgreSql,
    MongoDB,
    Redis,
    Cassandra,
    Elasticsearch,
    Memcached,
    MsSql,
    Oracle,
    CouchDb,
    InfluxDb,

    // Messaging & Queues
    Mqtt,
    MqttSecure,
    Amqp,
    AmqpSecure,
    Kafka,
    RabbitMq,
    Nats,

    // VoIP & Media
    Sip,
    SipTls,
    Rtsp,

    // VPN
    OpenVpn,
    WireGuard,
    IpSecIke,
    IpSecNat,
    Pptp,
    L2tp,

    // Container & Orchestration
    Docker,
    DockerSwarm,
    Kubernetes,
    KubernetesApi,
    Etcd,
    Consul,

    // Version Control
    Git,
    Svn,

    // Monitoring & Logging
    Prometheus,
    Grafana,
    Syslog,
    SyslogSecure,
    Zabbix,
    Nagios,
    Splunk,

    // Development
    Webpack,
    Vite,
    NodeDebug,

    // Gaming
    Minecraft,
    MinecraftRcon,
    Valve,
    TeamSpeak,
    Mumble,

    // Apple Services
    Mdns,
    AppleXServerAid,
    Airplay,

    // Streaming & CDN
    Rtmp,

    // IoT
    CoAp,
    HomeAssistant,

    // Backup & Storage
    Rsync,
    Nfs,

    // Misc
    Llmnr,
    Oas,
    Immich,
    Plex,
    Jellyfin,
    Sonarr,
    Radarr,
    Transmission,
    Qbittorrent,

    Unknown(u16),
}

impl ProtocolPort {
    pub fn get_supported_protocols() -> Vec<String> {
        vec![
            ProtocolPort::Http,
            ProtocolPort::Https,
            ProtocolPort::Ftp,
            ProtocolPort::Ssh,
            ProtocolPort::Smtp,
            ProtocolPort::Dns,
            ProtocolPort::Mysql,
            ProtocolPort::PostgreSql,
            ProtocolPort::MongoDB,
            ProtocolPort::Redis,
            ProtocolPort::Mqtt,
            ProtocolPort::Docker,
            ProtocolPort::Kubernetes,
            ProtocolPort::Prometheus,
            ProtocolPort::Grafana,
            ProtocolPort::Minecraft,
            ProtocolPort::Rdp,
            ProtocolPort::Vnc,
        ]
        .into_iter()
        .map(|protocol| format!("{}", protocol))
        .collect()
    }
}

impl From<u16> for ProtocolPort {
    fn from(port: u16) -> Self {
        match port {
            // Web
            80 => ProtocolPort::Http,
            443 => ProtocolPort::Https,
            8080 => ProtocolPort::HttpAlt,
            8443 => ProtocolPort::Https,
            3128 => ProtocolPort::HttpProxy,

            // File Transfer
            20 => ProtocolPort::FtpData,
            21 => ProtocolPort::Ftp,
            22 => ProtocolPort::Ssh,
            69 => ProtocolPort::Tftp,
            989 => ProtocolPort::Ftps,
            990 => ProtocolPort::Ftps,
            115 => ProtocolPort::Sftp,

            // Email
            25 => ProtocolPort::Smtp,
            465 => ProtocolPort::SmtpSecure,
            587 => ProtocolPort::SmtpSecure,
            110 => ProtocolPort::Pop3,
            995 => ProtocolPort::Pop3Secure,
            143 => ProtocolPort::Imap,
            993 => ProtocolPort::ImapSecure,

            // Network Services
            53 => ProtocolPort::Dns,
            67 => ProtocolPort::DhcpServer,
            68 => ProtocolPort::DhcpClient,
            123 => ProtocolPort::Ntp,
            161 => ProtocolPort::Snmp,
            162 => ProtocolPort::SnmpTrap,
            389 => ProtocolPort::Ldap,
            636 => ProtocolPort::LdapSecure,

            // Remote Access
            23 => ProtocolPort::Telnet,
            3389 => ProtocolPort::Rdp,
            5900 => ProtocolPort::Vnc,
            5901 => ProtocolPort::Vnc,

            // Windows
            137 => ProtocolPort::Nbns,
            138 => ProtocolPort::Nbdg,
            139 => ProtocolPort::Nbss,
            445 => ProtocolPort::Smb,
            88 => ProtocolPort::Kerberos,
            464 => ProtocolPort::Kerberos,
            3268 => ProtocolPort::ActiveDirectory,
            3269 => ProtocolPort::ActiveDirectory,
            59632 => ProtocolPort::Wmi,

            // Databases
            3306 => ProtocolPort::Mysql,
            5432 => ProtocolPort::PostgreSql,
            27017 => ProtocolPort::MongoDB,
            6379 => ProtocolPort::Redis,
            9042 => ProtocolPort::Cassandra,
            9200 => ProtocolPort::Elasticsearch,
            9300 => ProtocolPort::Elasticsearch,
            11211 => ProtocolPort::Memcached,
            1433 => ProtocolPort::MsSql,
            1521 => ProtocolPort::Oracle,
            5984 => ProtocolPort::CouchDb,
            8086 => ProtocolPort::InfluxDb,

            // Messaging
            1883 => ProtocolPort::Mqtt,
            8883 => ProtocolPort::MqttSecure,
            5672 => ProtocolPort::Amqp,
            5671 => ProtocolPort::AmqpSecure,
            9092 => ProtocolPort::Kafka,
            15672 => ProtocolPort::RabbitMq,
            4222 => ProtocolPort::Nats,

            // VoIP
            5060 => ProtocolPort::Sip,
            5061 => ProtocolPort::SipTls,
            554 => ProtocolPort::Rtsp,

            // VPN
            1194 => ProtocolPort::OpenVpn,
            51820 => ProtocolPort::WireGuard,
            500 => ProtocolPort::IpSecIke,
            4500 => ProtocolPort::IpSecNat,
            1723 => ProtocolPort::Pptp,
            1701 => ProtocolPort::L2tp,

            // Containers
            2375 => ProtocolPort::Docker,
            2376 => ProtocolPort::Docker,
            2377 => ProtocolPort::DockerSwarm,
            6443 => ProtocolPort::KubernetesApi,
            8001 => ProtocolPort::Kubernetes,
            2379 => ProtocolPort::Etcd,
            2380 => ProtocolPort::Etcd,
            8500 => ProtocolPort::Consul,

            // Version Control
            9418 => ProtocolPort::Git,
            3690 => ProtocolPort::Svn,

            // Monitoring
            9090 => ProtocolPort::Prometheus,
            3000 => ProtocolPort::Grafana,
            514 => ProtocolPort::Syslog,
            6514 => ProtocolPort::SyslogSecure,
            10050 => ProtocolPort::Zabbix,
            10051 => ProtocolPort::Zabbix,
            5666 => ProtocolPort::Nagios,
            8089 => ProtocolPort::Splunk,

            // Proxies
            // Note: 3128 already mapped to HttpProxy above

            // Development
            8081 => ProtocolPort::Webpack,
            5173 => ProtocolPort::Vite,
            9229 => ProtocolPort::NodeDebug,

            // Gaming
            25565 => ProtocolPort::Minecraft,
            25575 => ProtocolPort::MinecraftRcon,
            27005 => ProtocolPort::Valve,
            27014 => ProtocolPort::Valve,
            27015 => ProtocolPort::Valve,
            27020 => ProtocolPort::Valve,
            27036 => ProtocolPort::Valve,
            27042 => ProtocolPort::Valve,
            27050 => ProtocolPort::Valve,
            9987 => ProtocolPort::TeamSpeak,
            64738 => ProtocolPort::Mumble,

            // Apple
            5353 => ProtocolPort::Mdns,
            3722 => ProtocolPort::AppleXServerAid,
            7000 => ProtocolPort::Airplay,

            // Streaming
            1935 => ProtocolPort::Rtmp,

            // IoT
            5683 => ProtocolPort::CoAp,
            8123 => ProtocolPort::HomeAssistant,

            // Backup & Storage
            873 => ProtocolPort::Rsync,
            2049 => ProtocolPort::Nfs,

            // Misc Services
            5355 => ProtocolPort::Llmnr,
            58726 => ProtocolPort::Oas,
            2283 => ProtocolPort::Immich,
            32400 => ProtocolPort::Plex,
            8096 => ProtocolPort::Jellyfin,
            8989 => ProtocolPort::Sonarr,
            7878 => ProtocolPort::Radarr,
            9091 => ProtocolPort::Transmission,
            8112 => ProtocolPort::Qbittorrent,

            _ => ProtocolPort::Unknown(port),
        }
    }
}

impl std::fmt::Display for ProtocolPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let protocol_name = match self {
            // Web
            ProtocolPort::Http => "HTTP",
            ProtocolPort::Https => "HTTPS",
            ProtocolPort::HttpAlt => "HTTP (Alt)",
            ProtocolPort::HttpProxy => "HTTP Proxy",

            // File Transfer
            ProtocolPort::Ftp => "FTP",
            ProtocolPort::FtpData => "FTP Data",
            ProtocolPort::Ftps => "FTPS",
            ProtocolPort::Sftp => "SFTP",
            ProtocolPort::Tftp => "TFTP",

            // Email
            ProtocolPort::Smtp => "SMTP",
            ProtocolPort::SmtpSecure => "SMTP/S",
            ProtocolPort::Pop3 => "POP3",
            ProtocolPort::Pop3Secure => "POP3/S",
            ProtocolPort::Imap => "IMAP",
            ProtocolPort::ImapSecure => "IMAP/S",

            // Network
            ProtocolPort::Dns => "DNS",
            ProtocolPort::DhcpServer => "DHCP Server",
            ProtocolPort::DhcpClient => "DHCP Client",
            ProtocolPort::Ntp => "NTP",
            ProtocolPort::Snmp => "SNMP",
            ProtocolPort::SnmpTrap => "SNMP Trap",
            ProtocolPort::Ldap => "LDAP",
            ProtocolPort::LdapSecure => "LDAPS",

            // Remote Access
            ProtocolPort::Ssh => "SSH",
            ProtocolPort::Telnet => "Telnet",
            ProtocolPort::Rdp => "RDP",
            ProtocolPort::Vnc => "VNC",

            // Windows
            ProtocolPort::Smb => "SMB",
            ProtocolPort::Nbns => "NetBIOS-NS",
            ProtocolPort::Nbdg => "NetBIOS-DG",
            ProtocolPort::Nbss => "NetBIOS-SS",
            ProtocolPort::Wmi => "WMI",
            ProtocolPort::ActiveDirectory => "Active Directory",
            ProtocolPort::Kerberos => "Kerberos",

            // Databases
            ProtocolPort::Mysql => "MySQL",
            ProtocolPort::PostgreSql => "PostgreSQL",
            ProtocolPort::MongoDB => "MongoDB",
            ProtocolPort::Redis => "Redis",
            ProtocolPort::Cassandra => "Cassandra",
            ProtocolPort::Elasticsearch => "Elasticsearch",
            ProtocolPort::Memcached => "Memcached",
            ProtocolPort::MsSql => "MS SQL Server",
            ProtocolPort::Oracle => "Oracle DB",
            ProtocolPort::CouchDb => "CouchDB",
            ProtocolPort::InfluxDb => "InfluxDB",

            // Messaging
            ProtocolPort::Mqtt => "MQTT",
            ProtocolPort::MqttSecure => "MQTT/S",
            ProtocolPort::Amqp => "AMQP",
            ProtocolPort::AmqpSecure => "AMQP/S",
            ProtocolPort::Kafka => "Kafka",
            ProtocolPort::RabbitMq => "RabbitMQ",
            ProtocolPort::Nats => "NATS",

            // VoIP
            ProtocolPort::Sip => "SIP",
            ProtocolPort::SipTls => "SIP/TLS",
            ProtocolPort::Rtsp => "RTSP",

            // VPN
            ProtocolPort::OpenVpn => "OpenVPN",
            ProtocolPort::WireGuard => "WireGuard",
            ProtocolPort::IpSecIke => "IPSec IKE",
            ProtocolPort::IpSecNat => "IPSec NAT-T",
            ProtocolPort::Pptp => "PPTP",
            ProtocolPort::L2tp => "L2TP",

            // Containers
            ProtocolPort::Docker => "Docker",
            ProtocolPort::DockerSwarm => "Docker Swarm",
            ProtocolPort::Kubernetes => "Kubernetes",
            ProtocolPort::KubernetesApi => "Kubernetes API",
            ProtocolPort::Etcd => "etcd",
            ProtocolPort::Consul => "Consul",

            // Version Control
            ProtocolPort::Git => "Git",
            ProtocolPort::Svn => "SVN",

            // Monitoring
            ProtocolPort::Prometheus => "Prometheus",
            ProtocolPort::Grafana => "Grafana",
            ProtocolPort::Syslog => "Syslog",
            ProtocolPort::SyslogSecure => "Syslog/TLS",
            ProtocolPort::Zabbix => "Zabbix",
            ProtocolPort::Nagios => "Nagios",
            ProtocolPort::Splunk => "Splunk",

            // Development
            ProtocolPort::Webpack => "Webpack Dev",
            ProtocolPort::Vite => "Vite",
            ProtocolPort::NodeDebug => "Node Debug",

            // Gaming
            ProtocolPort::Minecraft => "Minecraft",
            ProtocolPort::MinecraftRcon => "Minecraft RCON",
            ProtocolPort::Valve => "Valve/Steam",
            ProtocolPort::TeamSpeak => "TeamSpeak",
            ProtocolPort::Mumble => "Mumble",

            // Apple
            ProtocolPort::Mdns => "mDNS",
            ProtocolPort::AppleXServerAid => "Apple Xserve",
            ProtocolPort::Airplay => "AirPlay",

            // Streaming
            ProtocolPort::Rtmp => "RTMP",

            // IoT
            ProtocolPort::CoAp => "CoAP",
            ProtocolPort::HomeAssistant => "Home Assistant",

            // Backup & Storage
            ProtocolPort::Rsync => "Rsync",
            ProtocolPort::Nfs => "NFS",

            // Misc
            ProtocolPort::Llmnr => "LLMNR",
            ProtocolPort::Oas => "OAS",
            ProtocolPort::Immich => "Immich",
            ProtocolPort::Plex => "Plex",
            ProtocolPort::Jellyfin => "Jellyfin",
            ProtocolPort::Sonarr => "Sonarr",
            ProtocolPort::Radarr => "Radarr",
            ProtocolPort::Transmission => "Transmission",
            ProtocolPort::Qbittorrent => "qBittorrent",

            ProtocolPort::Unknown(_port) => "Unknown",
        };
        write!(f, "{}", protocol_name)
    }
}
