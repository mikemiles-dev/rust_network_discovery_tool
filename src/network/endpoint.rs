use dns_lookup::{get_hostname, lookup_addr};
use pnet::datalink::interfaces;
use pnet::ipnetwork::IpNetwork;
use rusqlite::{Connection, Result, params};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::network::endpoint_attribute::EndPointAttribute;
use crate::network::mdns_lookup::MDnsLookup;

// Simple DNS cache to avoid repeated slow lookups
lazy_static::lazy_static! {
    static ref DNS_CACHE: Arc<Mutex<HashMap<String, (String, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref GATEWAY_INFO: Arc<Mutex<Option<(String, Instant)>>> = Arc::new(Mutex::new(None));
}

// Cache for local network CIDR blocks (computed once at startup)
static LOCAL_NETWORKS: OnceLock<Vec<IpNetwork>> = OnceLock::new();

/// Common local network hostname suffixes to strip
const LOCAL_SUFFIXES: &[&str] = &[".local", ".lan", ".home", ".internal", ".localdomain", ".localhost"];

/// Strip common local network suffixes from a hostname
pub fn strip_local_suffix(hostname: &str) -> String {
    let lower = hostname.to_lowercase();
    for suffix in LOCAL_SUFFIXES {
        if lower.ends_with(suffix) {
            return hostname[..hostname.len() - suffix.len()].to_string();
        }
    }
    hostname.to_string()
}

fn get_local_networks() -> &'static Vec<IpNetwork> {
    LOCAL_NETWORKS.get_or_init(|| {
        interfaces()
            .into_iter()
            .flat_map(|iface| iface.ips)
            .filter(|network| {
                // Filter out catch-all networks (0.0.0.0/0 and ::/0) that match everything
                // These are not actual local networks
                let is_catch_all = match network.ip() {
                    IpAddr::V4(ipv4) => ipv4.is_unspecified() && network.prefix() == 0,
                    IpAddr::V6(ipv6) => ipv6.is_unspecified() && network.prefix() == 0,
                };
                !is_catch_all
            })
            .collect()
    })
}

const DNS_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes
const GATEWAY_CACHE_TTL: Duration = Duration::from_secs(60); // 1 minute

// Classification type constants
const CLASSIFICATION_GATEWAY: &str = "gateway";
const CLASSIFICATION_INTERNET: &str = "internet";
const CLASSIFICATION_PRINTER: &str = "printer";
const CLASSIFICATION_TV: &str = "tv";
const CLASSIFICATION_GAMING: &str = "gaming";
const CLASSIFICATION_VIRTUALIZATION: &str = "virtualization";
const CLASSIFICATION_SOUNDBAR: &str = "soundbar";
const CLASSIFICATION_APPLIANCE: &str = "appliance";
const CLASSIFICATION_PHONE: &str = "phone";

// Device detection patterns
const PRINTER_PATTERNS: &[&str] = &[
    "printer",
    "print",
    "hp-",
    "canon",
    "epson",
    "brother",
    "lexmark",
    "xerox",
    "ricoh",
    "laserjet",
    "officejet",
    "pixma",
    "mfc-",
    "dcp-",
    "hpcolor",
    "hplaserjet",
    "designjet",
    "colorjet",
    "scanjet",
];
const PRINTER_PREFIXES: &[&str] = &["hp", "npi", "np", "brn", "brw", "epson"];

const TV_PATTERNS: &[&str] = &[
    "tv",
    "samsung",
    "lg-",
    "sony",
    "vizio",
    "roku",
    "chromecast",
    "appletv",
    "apple-tv",
    "firetv",
    "fire-tv",
    "shield",
    "androidtv",
];
const TV_PREFIXES: &[&str] = &["lg"];

const GAMING_PATTERNS: &[&str] = &[
    "xbox",
    "playstation",
    "ps4",
    "ps5",
    "nintendo",
    "switch",
    "steamdeck",
    "steam-deck",
];

const PHONE_PATTERNS: &[&str] = &[
    "iphone", "ipad", "ipod", "oneplus", "motorola", "oppo", "vivo", "realme", "redmi", "poco",
];
const PHONE_PREFIXES: &[&str] = &["sm-", "moto"];
const PHONE_CONDITIONAL: &[(&str, &str)] = &[
    ("galaxy", "tv"),
    ("pixel", "tv"),
    ("xiaomi", "tv"),
    ("huawei", "tv"),
    ("nokia", "tv"),
];

const VM_PATTERNS: &[&str] = &[
    "vmware",
    "esxi",
    "vcenter",
    "proxmox",
    "hyper-v",
    "hyperv",
    "virtualbox",
    "vbox",
    "kvm",
    "qemu",
    "xen",
    "docker",
    "container",
    "k8s",
    "kubernetes",
    "rancher",
    "portainer",
];

const SOUNDBAR_PATTERNS: &[&str] = &[
    "soundbar",
    "sound-bar",
    "sonos",
    "bose",
    "playbar",
    "playbase",
    "beam",
];

const APPLIANCE_PATTERNS: &[&str] = &[
    "dishwasher",
    "washer",
    "dryer",
    "washing",
    "laundry",
    "refrigerator",
    "fridge",
    "oven",
    "range",
    "microwave",
    "maytag",
    "miele",
    "electrolux",
    "kenmore",
    "kitchenaid",
    "echo",
    "alexa",
    "amazon-",
    "ring-",
    "nest-",
    "google-home",
    "homepod",
];
const LG_APPLIANCE_PREFIXES: &[&str] = &["lma", "lmw", "ldf", "ldt", "ldp", "dle", "dlex", "lrmv"];

// MAC OUI prefixes mapped to vendor names (first 3 bytes, lowercase, colon-separated)
// Used for both appliance classification and vendor display
const MAC_VENDOR_MAP: &[(&str, &str)] = &[
    // Amazon (Echo, Fire TV Stick, Ring, etc.)
    ("00:fc:8b", "Amazon"),
    ("0c:47:c9", "Amazon"),
    ("10:2c:6b", "Amazon"),
    ("14:91:82", "Amazon"),
    ("18:74:2e", "Amazon"),
    ("24:4c:e3", "Amazon"),
    ("34:d2:70", "Amazon"),
    ("38:f7:3d", "Amazon"),
    ("3c:5c:c4", "Amazon"),
    ("40:a2:db", "Amazon"),
    ("44:65:0d", "Amazon"),
    ("48:e6:c0", "Amazon"),
    ("4c:ef:c0", "Amazon"),
    ("50:dc:e7", "Amazon"),
    ("50:f5:da", "Amazon"),
    ("54:c8:0f", "Amazon"),
    ("68:37:e9", "Amazon"),
    ("68:54:fd", "Amazon"),
    ("6c:56:97", "Amazon"),
    ("74:c2:46", "Amazon"),
    ("78:e1:03", "Amazon"),
    ("7c:61:66", "Amazon"),
    ("84:d6:d0", "Amazon"),
    ("88:71:b1", "Amazon"),
    ("8c:85:80", "Amazon"),
    ("94:e3:6d", "Amazon"),
    ("a4:08:ea", "Amazon"),
    ("ac:63:be", "Amazon"),
    ("b0:fc:0d", "Amazon"),
    ("b4:7c:9c", "Amazon"),
    ("c8:f7:33", "Amazon"),
    ("cc:9e:a2", "Amazon"),
    ("dc:54:75", "Amazon"),
    ("f0:27:2d", "Amazon"),
    ("f0:81:73", "Amazon"),
    ("f0:f0:a4", "Amazon"),
    ("fc:65:de", "Amazon"),
    // Google/Nest (Nest thermostat, Home, Chromecast, etc.)
    ("18:d6:c7", "Google"),
    ("1c:f2:9a", "Google"),
    ("20:df:b9", "Google"),
    ("30:fd:38", "Google"),
    ("48:d6:d5", "Google"),
    ("54:60:09", "Google"),
    ("5c:e9:31", "Google"),
    ("64:16:7f", "Google"),
    ("6c:ad:f8", "Google"),
    ("94:94:26", "Google"),
    ("a4:77:33", "Google"),
    ("cc:47:40", "Google"),
    ("d4:f5:47", "Google"),
    ("e4:f0:42", "Google"),
    ("f4:f5:d8", "Google"),
    ("f4:f5:e8", "Google"),
    // Ring (doorbells, cameras)
    ("34:3e:a4", "Ring"),
    ("90:48:9a", "Ring"),
    // Philips Hue
    ("00:17:88", "Philips Hue"),
    ("ec:b5:fa", "Philips Hue"),
    // Ecobee (thermostats)
    ("44:61:32", "Ecobee"),
    // TP-Link/Kasa smart plugs
    ("50:c7:bf", "TP-Link"),
    ("60:32:b1", "TP-Link"),
    ("68:ff:7b", "TP-Link"),
    ("98:da:c4", "TP-Link"),
    ("b0:be:76", "TP-Link"),
    // Wemo (Belkin smart plugs)
    ("08:86:3b", "Belkin"),
    ("14:91:38", "Belkin"),
    ("24:f5:a2", "Belkin"),
    ("58:ef:68", "Belkin"),
    ("94:10:3e", "Belkin"),
    ("b4:75:0e", "Belkin"),
    ("c4:41:1e", "Belkin"),
    ("ec:1a:59", "Belkin"),
    // Wyze (cameras, plugs)
    ("2c:aa:8e", "Wyze"),
    ("7c:78:b2", "Wyze"),
    ("d0:3f:27", "Wyze"),
    // iRobot (Roomba)
    ("50:14:79", "iRobot"),
    ("80:c5:f2", "iRobot"),
    // Tuya (generic IoT devices)
    ("10:d5:61", "Tuya"),
    ("48:e1:e9", "Tuya"),
    ("50:8a:06", "Tuya"),
    ("68:57:2d", "Tuya"),
    ("7c:f6:66", "Tuya"),
    ("84:e3:42", "Tuya"),
    ("a4:cf:12", "Tuya"),
    ("cc:8d:a2", "Tuya"),
    ("d4:a6:51", "Tuya"),
    ("dc:23:4e", "Tuya"),
    // Apple devices
    ("00:03:93", "Apple"),
    ("00:05:02", "Apple"),
    ("00:0a:27", "Apple"),
    ("00:0a:95", "Apple"),
    ("00:0d:93", "Apple"),
    ("00:10:fa", "Apple"),
    ("00:11:24", "Apple"),
    ("00:14:51", "Apple"),
    ("00:16:cb", "Apple"),
    ("00:17:f2", "Apple"),
    ("00:19:e3", "Apple"),
    ("00:1b:63", "Apple"),
    ("00:1c:b3", "Apple"),
    ("00:1d:4f", "Apple"),
    ("00:1e:52", "Apple"),
    ("00:1e:c2", "Apple"),
    ("00:1f:5b", "Apple"),
    ("00:1f:f3", "Apple"),
    ("00:21:e9", "Apple"),
    ("00:22:41", "Apple"),
    ("00:23:12", "Apple"),
    ("00:23:32", "Apple"),
    ("00:23:6c", "Apple"),
    ("00:23:df", "Apple"),
    ("00:24:36", "Apple"),
    ("00:25:00", "Apple"),
    ("00:25:4b", "Apple"),
    ("00:25:bc", "Apple"),
    ("00:26:08", "Apple"),
    ("00:26:4a", "Apple"),
    ("00:26:b0", "Apple"),
    ("00:26:bb", "Apple"),
    ("04:0c:ce", "Apple"),
    ("04:15:52", "Apple"),
    ("04:1e:64", "Apple"),
    ("04:26:65", "Apple"),
    ("04:48:9a", "Apple"),
    ("04:4b:ed", "Apple"),
    ("04:52:f3", "Apple"),
    ("04:54:53", "Apple"),
    ("04:69:f8", "Apple"),
    ("04:d3:cf", "Apple"),
    ("04:db:56", "Apple"),
    ("04:e5:36", "Apple"),
    ("04:f1:3e", "Apple"),
    ("04:f7:e4", "Apple"),
    ("08:00:07", "Apple"),
    ("08:66:98", "Apple"),
    ("08:6d:41", "Apple"),
    ("0c:74:c2", "Apple"),
    ("10:40:f3", "Apple"),
    ("14:10:9f", "Apple"),
    ("18:af:61", "Apple"),
    ("1c:36:bb", "Apple"),
    ("20:78:f0", "Apple"),
    ("24:a0:74", "Apple"),
    ("28:cf:da", "Apple"),
    ("2c:be:08", "Apple"),
    ("34:c0:59", "Apple"),
    ("38:c9:86", "Apple"),
    ("3c:06:30", "Apple"),
    ("40:33:1a", "Apple"),
    ("40:a6:d9", "Apple"),
    ("44:2a:60", "Apple"),
    ("48:60:bc", "Apple"),
    ("4c:32:75", "Apple"),
    ("4c:57:ca", "Apple"),
    ("50:32:37", "Apple"),
    ("54:26:96", "Apple"),
    ("54:72:4f", "Apple"),
    ("54:ae:27", "Apple"),
    ("58:55:ca", "Apple"),
    ("5c:59:48", "Apple"),
    ("5c:96:9d", "Apple"),
    ("5c:f7:e6", "Apple"),
    ("60:03:08", "Apple"),
    ("60:69:44", "Apple"),
    ("60:c5:47", "Apple"),
    ("60:d9:c7", "Apple"),
    ("60:f8:1d", "Apple"),
    ("60:fa:cd", "Apple"),
    ("64:20:0c", "Apple"),
    ("64:76:ba", "Apple"),
    ("64:a3:cb", "Apple"),
    ("64:b9:e8", "Apple"),
    ("64:e6:82", "Apple"),
    ("68:5b:35", "Apple"),
    ("68:64:4b", "Apple"),
    ("68:96:7b", "Apple"),
    ("68:9c:70", "Apple"),
    ("68:a8:6d", "Apple"),
    ("68:ab:1e", "Apple"),
    ("68:d9:3c", "Apple"),
    ("68:db:ca", "Apple"),
    ("68:fe:f7", "Apple"),
    ("6c:3e:6d", "Apple"),
    ("6c:70:9f", "Apple"),
    ("6c:94:f8", "Apple"),
    ("6c:c2:6b", "Apple"),
    ("70:11:24", "Apple"),
    ("70:3e:ac", "Apple"),
    ("70:56:81", "Apple"),
    ("70:cd:60", "Apple"),
    ("70:de:e2", "Apple"),
    ("70:ec:e4", "Apple"),
    ("74:1b:b2", "Apple"),
    ("78:31:c1", "Apple"),
    ("78:3a:84", "Apple"),
    ("78:4f:43", "Apple"),
    ("78:6c:1c", "Apple"),
    ("78:7e:61", "Apple"),
    ("78:88:6d", "Apple"),
    ("78:9f:70", "Apple"),
    ("78:a3:e4", "Apple"),
    ("78:ca:39", "Apple"),
    ("78:d7:5f", "Apple"),
    ("78:fd:94", "Apple"),
    ("7c:04:d0", "Apple"),
    ("7c:11:be", "Apple"),
    ("7c:5c:f8", "Apple"),
    ("7c:6d:62", "Apple"),
    ("7c:6d:f8", "Apple"),
    ("7c:c3:a1", "Apple"),
    ("7c:d1:c3", "Apple"),
    ("7c:f0:5f", "Apple"),
    ("7c:fa:df", "Apple"),
    ("80:00:6e", "Apple"),
    ("80:49:71", "Apple"),
    ("80:82:23", "Apple"),
    ("80:92:9f", "Apple"),
    ("80:be:05", "Apple"),
    ("80:e6:50", "Apple"),
    ("80:ed:2c", "Apple"),
    ("84:29:99", "Apple"),
    ("84:38:35", "Apple"),
    ("84:78:8b", "Apple"),
    ("84:85:06", "Apple"),
    ("84:89:ad", "Apple"),
    ("84:8e:0c", "Apple"),
    ("84:a1:34", "Apple"),
    ("84:b1:53", "Apple"),
    ("84:fc:ac", "Apple"),
    ("84:fc:fe", "Apple"),
    ("88:1f:a1", "Apple"),
    ("88:53:95", "Apple"),
    ("88:63:df", "Apple"),
    ("88:66:5a", "Apple"),
    ("88:c6:63", "Apple"),
    ("88:cb:87", "Apple"),
    ("88:e8:7f", "Apple"),
    ("8c:00:6d", "Apple"),
    ("8c:29:37", "Apple"),
    ("8c:2d:aa", "Apple"),
    ("8c:58:77", "Apple"),
    ("8c:7b:9d", "Apple"),
    ("8c:7c:92", "Apple"),
    ("8c:85:90", "Apple"),
    ("8c:fa:ba", "Apple"),
    ("90:27:e4", "Apple"),
    ("90:3c:92", "Apple"),
    ("90:72:40", "Apple"),
    ("90:84:0d", "Apple"),
    ("90:8d:6c", "Apple"),
    ("90:b0:ed", "Apple"),
    ("90:b2:1f", "Apple"),
    ("90:b6:bf", "Apple"),
    ("90:c1:c6", "Apple"),
    ("90:fd:61", "Apple"),
    ("94:94:26", "Apple"),
    ("94:e9:6a", "Apple"),
    ("94:f6:a3", "Apple"),
    ("98:01:a7", "Apple"),
    ("98:03:d8", "Apple"),
    ("98:10:e8", "Apple"),
    ("98:5a:eb", "Apple"),
    ("98:b8:e3", "Apple"),
    ("98:d6:bb", "Apple"),
    ("98:e0:d9", "Apple"),
    ("98:f0:ab", "Apple"),
    ("98:fe:94", "Apple"),
    ("9c:04:eb", "Apple"),
    ("9c:20:7b", "Apple"),
    ("9c:35:eb", "Apple"),
    ("9c:4f:da", "Apple"),
    ("9c:8b:a0", "Apple"),
    ("9c:f3:87", "Apple"),
    ("a0:18:28", "Apple"),
    ("a0:99:9b", "Apple"),
    ("a0:d7:95", "Apple"),
    ("a0:ed:cd", "Apple"),
    ("a4:5e:60", "Apple"),
    ("a4:67:06", "Apple"),
    ("a4:83:e7", "Apple"),
    ("a4:b1:97", "Apple"),
    ("a4:b8:05", "Apple"),
    ("a4:c3:61", "Apple"),
    ("a4:d1:8c", "Apple"),
    ("a4:d1:d2", "Apple"),
    ("a8:20:66", "Apple"),
    ("a8:5c:2c", "Apple"),
    ("a8:66:7f", "Apple"),
    ("a8:86:dd", "Apple"),
    ("a8:88:08", "Apple"),
    ("a8:8e:24", "Apple"),
    ("a8:96:8a", "Apple"),
    ("a8:bb:cf", "Apple"),
    ("a8:fa:d8", "Apple"),
    ("ac:29:3a", "Apple"),
    ("ac:3c:0b", "Apple"),
    ("ac:61:ea", "Apple"),
    ("ac:7f:3e", "Apple"),
    ("ac:87:a3", "Apple"),
    ("ac:bc:32", "Apple"),
    ("ac:cf:5c", "Apple"),
    ("ac:e4:b5", "Apple"),
    ("ac:fd:ec", "Apple"),
    ("b0:19:c6", "Apple"),
    ("b0:34:95", "Apple"),
    ("b0:65:bd", "Apple"),
    ("b0:70:2d", "Apple"),
    ("b0:9f:ba", "Apple"),
    ("b4:18:d1", "Apple"),
    ("b4:8b:19", "Apple"),
    ("b4:f0:ab", "Apple"),
    ("b4:f6:1c", "Apple"),
    ("b8:09:8a", "Apple"),
    ("b8:17:c2", "Apple"),
    ("b8:41:a4", "Apple"),
    ("b8:44:d9", "Apple"),
    ("b8:53:ac", "Apple"),
    ("b8:63:4d", "Apple"),
    ("b8:78:2e", "Apple"),
    ("b8:8d:12", "Apple"),
    ("b8:c1:11", "Apple"),
    ("b8:c7:5d", "Apple"),
    ("b8:e8:56", "Apple"),
    ("b8:f6:b1", "Apple"),
    ("b8:ff:61", "Apple"),
    ("bc:3b:af", "Apple"),
    ("bc:4c:c4", "Apple"),
    ("bc:52:b7", "Apple"),
    ("bc:54:36", "Apple"),
    ("bc:67:78", "Apple"),
    ("bc:6c:21", "Apple"),
    ("bc:92:6b", "Apple"),
    ("bc:9f:ef", "Apple"),
    ("bc:a9:20", "Apple"),
    ("bc:ec:5d", "Apple"),
    ("bc:fe:d9", "Apple"),
    ("c0:1a:da", "Apple"),
    ("c0:63:94", "Apple"),
    ("c0:84:7a", "Apple"),
    ("c0:9f:42", "Apple"),
    ("c0:a5:3e", "Apple"),
    ("c0:cc:f8", "Apple"),
    ("c0:ce:cd", "Apple"),
    ("c0:d0:12", "Apple"),
    ("c0:f2:fb", "Apple"),
    ("c4:2c:03", "Apple"),
    ("c8:1e:e7", "Apple"),
    ("c8:2a:14", "Apple"),
    ("c8:33:4b", "Apple"),
    ("c8:69:cd", "Apple"),
    ("c8:6f:1d", "Apple"),
    ("c8:85:50", "Apple"),
    ("c8:b5:b7", "Apple"),
    ("c8:bc:c8", "Apple"),
    ("c8:e0:eb", "Apple"),
    ("c8:f6:50", "Apple"),
    ("cc:08:8d", "Apple"),
    ("cc:20:e8", "Apple"),
    ("cc:25:ef", "Apple"),
    ("cc:29:f5", "Apple"),
    ("cc:44:63", "Apple"),
    ("cc:78:5f", "Apple"),
    ("cc:c7:60", "Apple"),
    ("d0:03:4b", "Apple"),
    ("d0:23:db", "Apple"),
    ("d0:25:98", "Apple"),
    ("d0:33:11", "Apple"),
    ("d0:4f:7e", "Apple"),
    ("d0:a6:37", "Apple"),
    ("d0:c5:f3", "Apple"),
    ("d0:d2:b0", "Apple"),
    ("d0:e1:40", "Apple"),
    ("d4:61:9d", "Apple"),
    ("d4:9a:20", "Apple"),
    ("d4:dc:cd", "Apple"),
    ("d4:f4:6f", "Apple"),
    ("d8:00:4d", "Apple"),
    ("d8:1d:72", "Apple"),
    ("d8:30:62", "Apple"),
    ("d8:8f:76", "Apple"),
    ("d8:96:95", "Apple"),
    ("d8:9e:3f", "Apple"),
    ("d8:a2:5e", "Apple"),
    ("d8:bb:2c", "Apple"),
    ("d8:cf:9c", "Apple"),
    ("d8:d1:cb", "Apple"),
    ("dc:0c:5c", "Apple"),
    ("dc:2b:2a", "Apple"),
    ("dc:2b:61", "Apple"),
    ("dc:37:14", "Apple"),
    ("dc:41:5f", "Apple"),
    ("dc:56:e7", "Apple"),
    ("dc:86:d8", "Apple"),
    ("dc:9b:9c", "Apple"),
    ("dc:a4:ca", "Apple"),
    ("dc:a9:04", "Apple"),
    ("e0:5f:45", "Apple"),
    ("e0:66:78", "Apple"),
    ("e0:ac:cb", "Apple"),
    ("e0:b5:2d", "Apple"),
    ("e0:b9:ba", "Apple"),
    ("e0:c7:67", "Apple"),
    ("e0:c9:7a", "Apple"),
    ("e0:f5:c6", "Apple"),
    ("e0:f8:47", "Apple"),
    ("e4:25:e7", "Apple"),
    ("e4:8b:7f", "Apple"),
    ("e4:98:d6", "Apple"),
    ("e4:9a:dc", "Apple"),
    ("e4:c6:3d", "Apple"),
    ("e4:ce:8f", "Apple"),
    ("e4:e4:ab", "Apple"),
    ("e8:04:0b", "Apple"),
    ("e8:06:88", "Apple"),
    ("e8:80:2e", "Apple"),
    ("e8:8d:28", "Apple"),
    ("ec:35:86", "Apple"),
    ("ec:85:2f", "Apple"),
    ("f0:18:98", "Apple"),
    ("f0:24:75", "Apple"),
    ("f0:79:60", "Apple"),
    ("f0:99:b6", "Apple"),
    ("f0:b0:e7", "Apple"),
    ("f0:c1:f1", "Apple"),
    ("f0:cb:a1", "Apple"),
    ("f0:d1:a9", "Apple"),
    ("f0:db:e2", "Apple"),
    ("f0:dc:e2", "Apple"),
    ("f0:f6:1c", "Apple"),
    ("f4:0f:24", "Apple"),
    ("f4:1b:a1", "Apple"),
    ("f4:31:c3", "Apple"),
    ("f4:37:b7", "Apple"),
    ("f4:5c:89", "Apple"),
    ("f8:1e:df", "Apple"),
    ("f8:27:93", "Apple"),
    ("f8:38:80", "Apple"),
    ("f8:62:14", "Apple"),
    ("fc:25:3f", "Apple"),
    ("fc:d8:48", "Apple"),
    ("fc:e9:98", "Apple"),
    // Samsung devices
    ("00:02:78", "Samsung"),
    ("00:07:ab", "Samsung"),
    ("00:09:18", "Samsung"),
    ("00:0d:ae", "Samsung"),
    ("00:12:47", "Samsung"),
    ("00:12:fb", "Samsung"),
    ("00:13:77", "Samsung"),
    ("00:15:99", "Samsung"),
    ("00:15:b9", "Samsung"),
    ("00:16:32", "Samsung"),
    ("00:16:6b", "Samsung"),
    ("00:16:6c", "Samsung"),
    ("00:17:c9", "Samsung"),
    ("00:17:d5", "Samsung"),
    ("00:18:af", "Samsung"),
    ("00:1a:8a", "Samsung"),
    ("00:1b:98", "Samsung"),
    ("00:1c:43", "Samsung"),
    ("00:1d:25", "Samsung"),
    ("00:1d:f6", "Samsung"),
    ("00:1e:7d", "Samsung"),
    ("00:1f:cc", "Samsung"),
    ("00:1f:cd", "Samsung"),
    ("00:21:19", "Samsung"),
    ("00:21:4c", "Samsung"),
    ("00:21:d1", "Samsung"),
    ("00:21:d2", "Samsung"),
    ("00:23:39", "Samsung"),
    ("00:23:3a", "Samsung"),
    ("00:23:99", "Samsung"),
    ("00:23:d6", "Samsung"),
    ("00:23:d7", "Samsung"),
    ("00:24:54", "Samsung"),
    ("00:24:90", "Samsung"),
    ("00:24:91", "Samsung"),
    ("00:24:e9", "Samsung"),
    ("00:25:66", "Samsung"),
    ("00:25:67", "Samsung"),
    ("00:26:37", "Samsung"),
    ("00:26:5d", "Samsung"),
    ("00:26:5f", "Samsung"),
    ("04:18:0f", "Samsung"),
    ("04:1b:ba", "Samsung"),
    ("08:08:c2", "Samsung"),
    ("08:37:3d", "Samsung"),
    ("08:d4:2b", "Samsung"),
    ("08:ec:a9", "Samsung"),
    ("0c:14:20", "Samsung"),
    ("0c:71:5d", "Samsung"),
    ("0c:89:10", "Samsung"),
    ("10:1d:c0", "Samsung"),
    ("10:30:47", "Samsung"),
    ("14:49:e0", "Samsung"),
    ("14:89:fd", "Samsung"),
    ("14:a3:64", "Samsung"),
    ("18:22:7e", "Samsung"),
    ("18:3a:2d", "Samsung"),
    ("18:67:b0", "Samsung"),
    ("18:89:5b", "Samsung"),
    ("1c:5a:3e", "Samsung"),
    ("1c:62:b8", "Samsung"),
    ("1c:66:aa", "Samsung"),
    ("20:13:e0", "Samsung"),
    ("20:55:31", "Samsung"),
    ("20:64:32", "Samsung"),
    ("24:4b:03", "Samsung"),
    ("24:c6:96", "Samsung"),
    ("28:27:bf", "Samsung"),
    ("28:98:7b", "Samsung"),
    ("28:ba:b5", "Samsung"),
    ("28:cc:01", "Samsung"),
    ("2c:44:01", "Samsung"),
    ("2c:ae:2b", "Samsung"),
    ("30:19:66", "Samsung"),
    ("30:96:fb", "Samsung"),
    ("30:c7:ae", "Samsung"),
    ("30:cd:a7", "Samsung"),
    ("34:14:5f", "Samsung"),
    ("34:23:ba", "Samsung"),
    ("34:aa:8b", "Samsung"),
    ("34:c3:ac", "Samsung"),
    ("38:01:97", "Samsung"),
    ("38:0a:94", "Samsung"),
    ("38:16:d1", "Samsung"),
    ("38:2d:d1", "Samsung"),
    ("38:aa:3c", "Samsung"),
    ("38:d4:0b", "Samsung"),
    ("3c:5a:37", "Samsung"),
    ("3c:62:00", "Samsung"),
    ("3c:8b:fe", "Samsung"),
    ("3c:a1:0d", "Samsung"),
    ("40:0e:85", "Samsung"),
    ("44:4e:1a", "Samsung"),
    ("44:6d:6c", "Samsung"),
    ("44:78:3e", "Samsung"),
    ("48:44:f7", "Samsung"),
    ("4c:3c:16", "Samsung"),
    ("4c:bc:a5", "Samsung"),
    ("50:01:bb", "Samsung"),
    ("50:a4:c8", "Samsung"),
    ("50:b7:c3", "Samsung"),
    ("50:c8:e5", "Samsung"),
    ("50:cc:f8", "Samsung"),
    ("50:f0:d3", "Samsung"),
    ("54:40:ad", "Samsung"),
    ("54:88:0e", "Samsung"),
    ("54:92:be", "Samsung"),
    ("54:9b:12", "Samsung"),
    ("58:c3:8b", "Samsung"),
    ("5c:2e:59", "Samsung"),
    ("5c:3c:27", "Samsung"),
    ("5c:a3:9d", "Samsung"),
    ("60:6b:bd", "Samsung"),
    ("60:a1:0a", "Samsung"),
    ("60:af:6d", "Samsung"),
    ("64:1c:ae", "Samsung"),
    ("64:77:91", "Samsung"),
    ("64:b3:10", "Samsung"),
    ("68:48:98", "Samsung"),
    ("68:eb:ae", "Samsung"),
    ("6c:2f:2c", "Samsung"),
    ("6c:83:36", "Samsung"),
    ("70:28:8b", "Samsung"),
    ("70:f9:27", "Samsung"),
    ("74:45:ce", "Samsung"),
    ("74:9e:af", "Samsung"),
    ("78:1f:db", "Samsung"),
    ("78:25:ad", "Samsung"),
    ("78:40:e4", "Samsung"),
    ("78:47:1d", "Samsung"),
    ("78:52:1a", "Samsung"),
    ("78:9e:d0", "Samsung"),
    ("78:ab:bb", "Samsung"),
    ("78:bd:bc", "Samsung"),
    ("78:c3:e9", "Samsung"),
    ("78:d6:f0", "Samsung"),
    ("7c:0a:3f", "Samsung"),
    ("7c:78:7e", "Samsung"),
    ("7c:f8:54", "Samsung"),
    ("80:18:a7", "Samsung"),
    ("80:57:19", "Samsung"),
    ("80:65:6d", "Samsung"),
    ("84:25:19", "Samsung"),
    ("84:38:38", "Samsung"),
    ("84:55:a5", "Samsung"),
    ("84:a4:66", "Samsung"),
    ("84:b8:02", "Samsung"),
    ("88:32:9b", "Samsung"),
    ("88:9b:39", "Samsung"),
    ("88:ad:d2", "Samsung"),
    ("8c:77:12", "Samsung"),
    ("8c:f5:a3", "Samsung"),
    ("90:00:4e", "Samsung"),
    ("90:18:7c", "Samsung"),
    ("94:01:c2", "Samsung"),
    ("94:35:0a", "Samsung"),
    ("94:51:03", "Samsung"),
    ("94:b1:0a", "Samsung"),
    ("94:d7:71", "Samsung"),
    ("98:0c:82", "Samsung"),
    ("98:52:b1", "Samsung"),
    ("98:83:89", "Samsung"),
    ("9c:02:98", "Samsung"),
    ("9c:3a:af", "Samsung"),
    ("9c:e6:e7", "Samsung"),
    ("a0:0b:ba", "Samsung"),
    ("a0:21:95", "Samsung"),
    ("a0:82:1f", "Samsung"),
    ("a4:07:b6", "Samsung"),
    ("a4:e5:97", "Samsung"),
    ("a8:06:00", "Samsung"),
    ("a8:7c:01", "Samsung"),
    ("ac:36:13", "Samsung"),
    ("ac:5a:14", "Samsung"),
    ("b0:47:bf", "Samsung"),
    ("b0:72:bf", "Samsung"),
    ("b0:c4:e7", "Samsung"),
    ("b0:df:3a", "Samsung"),
    ("b0:ec:71", "Samsung"),
    ("b4:07:f9", "Samsung"),
    ("b4:3a:28", "Samsung"),
    ("b4:79:a7", "Samsung"),
    ("b4:ef:39", "Samsung"),
    ("b8:5a:73", "Samsung"),
    ("b8:bb:af", "Samsung"),
    ("b8:c6:8e", "Samsung"),
    ("bc:14:01", "Samsung"),
    ("bc:20:a4", "Samsung"),
    ("bc:44:86", "Samsung"),
    ("bc:47:60", "Samsung"),
    ("bc:72:b1", "Samsung"),
    ("bc:79:ad", "Samsung"),
    ("bc:85:1f", "Samsung"),
    ("bc:8c:cd", "Samsung"),
    ("bc:b1:f3", "Samsung"),
    ("c0:19:7c", "Samsung"),
    ("c0:65:99", "Samsung"),
    ("c0:97:27", "Samsung"),
    ("c0:bd:d1", "Samsung"),
    ("c4:42:02", "Samsung"),
    ("c4:50:06", "Samsung"),
    ("c4:73:1e", "Samsung"),
    ("c8:19:f7", "Samsung"),
    ("c8:3d:dc", "Samsung"),
    ("cc:07:ab", "Samsung"),
    ("cc:3a:61", "Samsung"),
    ("d0:22:be", "Samsung"),
    ("d0:59:e4", "Samsung"),
    ("d0:66:7b", "Samsung"),
    ("d0:87:e2", "Samsung"),
    ("d4:87:d8", "Samsung"),
    ("d4:88:90", "Samsung"),
    ("d8:57:ef", "Samsung"),
    ("d8:90:e8", "Samsung"),
    ("dc:71:96", "Samsung"),
    ("e4:12:1d", "Samsung"),
    ("e4:32:cb", "Samsung"),
    ("e4:58:b8", "Samsung"),
    ("e4:7c:f9", "Samsung"),
    ("e4:e0:c5", "Samsung"),
    ("e8:03:9a", "Samsung"),
    ("e8:50:8b", "Samsung"),
    ("ec:1f:72", "Samsung"),
    ("ec:9b:f3", "Samsung"),
    ("f0:25:b7", "Samsung"),
    ("f0:5a:09", "Samsung"),
    ("f0:72:8c", "Samsung"),
    ("f4:7b:5e", "Samsung"),
    ("f4:9f:54", "Samsung"),
    ("f8:04:2e", "Samsung"),
    ("f8:3f:51", "Samsung"),
    ("f8:d0:ac", "Samsung"),
    ("fc:a1:3e", "Samsung"),
    ("fc:f1:36", "Samsung"),
    // Roku
    ("08:05:81", "Roku"),
    ("10:59:32", "Roku"),
    ("20:ef:bd", "Roku"),
    ("2c:e4:12", "Roku"),
    ("ac:3a:7a", "Roku"),
    ("b0:a7:37", "Roku"),
    ("b8:3e:59", "Roku"),
    ("c8:3a:6b", "Roku"),
    ("d4:e2:2f", "Roku"),
    ("d8:31:34", "Roku"),
    ("dc:3a:5e", "Roku"),
    // Sony (PlayStation, TVs)
    ("00:01:4a", "Sony"),
    ("00:04:1f", "Sony"),
    ("00:13:a9", "Sony"),
    ("00:15:c1", "Sony"),
    ("00:19:63", "Sony"),
    ("00:1a:80", "Sony"),
    ("00:1d:ba", "Sony"),
    ("00:1e:a4", "Sony"),
    ("00:24:be", "Sony"),
    ("00:eb:2d", "Sony"),
    ("04:5d:4b", "Sony"),
    ("04:76:6e", "Sony"),
    ("28:0d:fc", "Sony"),
    ("2c:33:61", "Sony"),
    ("30:39:26", "Sony"),
    ("40:b8:37", "Sony"),
    ("54:42:49", "Sony"),
    ("78:84:3c", "Sony"),
    ("84:00:d2", "Sony"),
    ("a8:e3:ee", "Sony"),
    ("ac:9b:0a", "Sony"),
    ("b4:52:7e", "Sony"),
    ("c8:63:14", "Sony"),
    ("f8:46:1c", "Sony"),
    ("fc:0f:e6", "Sony"),
    ("fc:f1:52", "Sony"),
    // Microsoft (Xbox, Surface)
    ("00:03:ff", "Microsoft"),
    ("00:0d:3a", "Microsoft"),
    ("00:12:5a", "Microsoft"),
    ("00:15:5d", "Microsoft"),
    ("00:17:fa", "Microsoft"),
    ("00:1d:d8", "Microsoft"),
    ("00:22:48", "Microsoft"),
    ("00:25:ae", "Microsoft"),
    ("00:50:f2", "Microsoft"),
    ("28:18:78", "Microsoft"),
    ("30:59:b7", "Microsoft"),
    ("50:1a:c5", "Microsoft"),
    ("58:82:a8", "Microsoft"),
    ("60:45:bd", "Microsoft"),
    ("7c:1e:52", "Microsoft"),
    ("7c:ed:8d", "Microsoft"),
    ("98:5f:d3", "Microsoft"),
    ("b4:0e:de", "Microsoft"),
    ("c8:3f:26", "Microsoft"),
    ("dc:53:7c", "Microsoft"),
    // Nintendo (Switch, Wii)
    ("00:09:bf", "Nintendo"),
    ("00:16:56", "Nintendo"),
    ("00:17:ab", "Nintendo"),
    ("00:19:1d", "Nintendo"),
    ("00:19:fd", "Nintendo"),
    ("00:1a:e9", "Nintendo"),
    ("00:1b:7a", "Nintendo"),
    ("00:1b:ea", "Nintendo"),
    ("00:1c:be", "Nintendo"),
    ("00:1d:bc", "Nintendo"),
    ("00:1e:35", "Nintendo"),
    ("00:1f:32", "Nintendo"),
    ("00:1f:c5", "Nintendo"),
    ("00:21:47", "Nintendo"),
    ("00:21:bd", "Nintendo"),
    ("00:22:4c", "Nintendo"),
    ("00:22:aa", "Nintendo"),
    ("00:23:31", "Nintendo"),
    ("00:23:cc", "Nintendo"),
    ("00:24:1e", "Nintendo"),
    ("00:24:44", "Nintendo"),
    ("00:24:f3", "Nintendo"),
    ("00:25:a0", "Nintendo"),
    ("00:26:59", "Nintendo"),
    ("00:27:09", "Nintendo"),
    ("04:03:d6", "Nintendo"),
    ("2c:10:c1", "Nintendo"),
    ("34:af:2c", "Nintendo"),
    ("40:d2:8a", "Nintendo"),
    ("40:f4:07", "Nintendo"),
    ("58:2f:40", "Nintendo"),
    ("58:bd:a3", "Nintendo"),
    ("5c:52:1e", "Nintendo"),
    ("7c:bb:8a", "Nintendo"),
    ("8c:56:c5", "Nintendo"),
    ("98:41:5c", "Nintendo"),
    ("98:b6:e9", "Nintendo"),
    ("a4:5c:27", "Nintendo"),
    ("a4:c0:e1", "Nintendo"),
    ("b8:ae:6e", "Nintendo"),
    ("cc:9e:00", "Nintendo"),
    ("d8:6b:f7", "Nintendo"),
    ("dc:68:eb", "Nintendo"),
    ("e0:0c:7f", "Nintendo"),
    ("e0:e7:51", "Nintendo"),
    ("e8:4e:ce", "Nintendo"),
    ("e8:96:3a", "Nintendo"),
];

// mDNS service types for device classification
const TV_SERVICES: &[&str] = &[
    "_googlecast._tcp",
    "_airplay._tcp",
    "_raop._tcp",
    "_roku._tcp",
    "_spotify-connect._tcp",
];
const PRINTER_SERVICES: &[&str] = &["_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp"];

/// Check if hostname matches any pattern in list
fn matches_pattern(hostname: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| hostname.contains(p))
}

/// Check if hostname starts with any prefix in list
fn matches_prefix(hostname: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| hostname.starts_with(p))
}

/// Check if hostname matches pattern but not exclusion
fn matches_conditional(hostname: &str, conditionals: &[(&str, &str)]) -> bool {
    conditionals
        .iter()
        .any(|(pattern, exclude)| hostname.contains(pattern) && !hostname.contains(exclude))
}

/// Check if hostname indicates a printer
fn is_printer_hostname(hostname: &str) -> bool {
    matches_pattern(hostname, PRINTER_PATTERNS) || matches_prefix(hostname, PRINTER_PREFIXES)
}

/// Check if hostname indicates a TV/streaming device
fn is_tv_hostname(hostname: &str) -> bool {
    matches_pattern(hostname, TV_PATTERNS) || matches_prefix(hostname, TV_PREFIXES)
}

/// Check if hostname indicates a gaming console
fn is_gaming_hostname(hostname: &str) -> bool {
    matches_pattern(hostname, GAMING_PATTERNS)
}

/// Check if hostname indicates a phone/tablet
fn is_phone_hostname(hostname: &str) -> bool {
    if matches_pattern(hostname, PHONE_PATTERNS) || matches_prefix(hostname, PHONE_PREFIXES) {
        return true;
    }
    if matches_conditional(hostname, PHONE_CONDITIONAL) {
        return true;
    }
    // Special case: android but not androidtv
    if hostname.contains("android") && !hostname.contains("androidtv") && !hostname.contains("tv") {
        return true;
    }
    // Special case: asus phone
    if hostname.contains("asus") && (hostname.contains("phone") || hostname.contains("zenfone")) {
        return true;
    }
    false
}

/// Check if hostname indicates a VM/container
fn is_vm_hostname(hostname: &str) -> bool {
    matches_pattern(hostname, VM_PATTERNS)
        || hostname.starts_with("vm-")
        || hostname.ends_with("-vm")
}

/// Check if hostname indicates a soundbar
fn is_soundbar_hostname(hostname: &str) -> bool {
    if matches_pattern(hostname, SOUNDBAR_PATTERNS) {
        return true;
    }
    // Sonos Arc special case
    if hostname.contains("arc") && (hostname.contains("sonos") || hostname.contains("sound")) {
        return true;
    }
    // Brand + sound combinations
    let sound_brands = ["yamaha", "samsung", "lg", "vizio"];
    if sound_brands.iter().any(|b| hostname.contains(b)) && hostname.contains("sound") {
        return true;
    }
    // JBL bar
    if hostname.contains("jbl") && hostname.contains("bar") {
        return true;
    }
    false
}

/// Check if hostname indicates an appliance
fn is_appliance_hostname(hostname: &str) -> bool {
    if matches_pattern(hostname, APPLIANCE_PATTERNS) {
        return true;
    }
    // Whirlpool (but not router)
    if hostname.contains("whirlpool") && !hostname.contains("router") {
        return true;
    }
    // GE appliance
    if hostname.contains("ge-") && hostname.contains("appliance") {
        return true;
    }
    // Bosch washer/dishwasher
    if hostname.contains("bosch") && (hostname.contains("wash") || hostname.contains("dish")) {
        return true;
    }
    false
}

// IoT vendors that should be classified as appliances (not general computing devices)
const APPLIANCE_VENDORS: &[&str] = &[
    "Amazon",
    "Google",
    "Ring",
    "Philips Hue",
    "Ecobee",
    "TP-Link",
    "Belkin",
    "Wyze",
    "iRobot",
    "Tuya",
];

// Gaming vendors that should be classified as gaming devices
const GAMING_VENDORS: &[&str] = &["Nintendo", "Sony"];

// TV/streaming vendors that should be classified as TV
const TV_VENDORS: &[&str] = &["Roku"];

/// Get vendor name from MAC address OUI
pub fn get_mac_vendor(mac: &str) -> Option<&'static str> {
    let mac_lower = mac.to_lowercase();
    if mac_lower.len() >= 8 {
        let oui = &mac_lower[..8];
        for (prefix, vendor) in MAC_VENDOR_MAP {
            if oui == *prefix {
                return Some(vendor);
            }
        }
    }
    None
}

/// Get vendor name from hostname patterns (fallback when MAC is locally administered)
pub fn get_hostname_vendor(hostname: &str) -> Option<&'static str> {
    let lower = hostname.to_lowercase();

    // LG ThinQ appliances (lma, lmw, wm, etc.)
    if matches_prefix(&lower, LG_APPLIANCE_PREFIXES)
        || (lower.starts_with("wm")
            && lower
                .chars()
                .nth(2)
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false))
    {
        return Some("LG");
    }
    // Samsung SmartThings
    if lower.contains("samsung") || lower.contains("smartthings") {
        return Some("Samsung");
    }
    // Amazon Echo/Alexa
    if lower.contains("echo") || lower.contains("alexa") || lower.contains("amazon") {
        return Some("Amazon");
    }
    // Google/Nest
    if lower.contains("google") || lower.contains("nest-") || lower.contains("chromecast") {
        return Some("Google");
    }
    // Apple
    if lower.contains("apple")
        || lower.contains("homepod")
        || lower.contains("macbook")
        || lower.contains("iphone")
        || lower.contains("ipad")
    {
        return Some("Apple");
    }
    // Roku
    if lower.contains("roku") {
        return Some("Roku");
    }
    // Sonos
    if lower.contains("sonos") {
        return Some("Sonos");
    }
    // Philips Hue
    if lower.contains("philips") || lower.contains("hue") {
        return Some("Philips Hue");
    }
    // Ring
    if lower.contains("ring-") || lower.starts_with("ring") {
        return Some("Ring");
    }
    // Ecobee
    if lower.contains("ecobee") {
        return Some("Ecobee");
    }
    // iRobot Roomba
    if lower.contains("irobot") || lower.contains("roomba") {
        return Some("iRobot");
    }
    // Wyze
    if lower.contains("wyze") {
        return Some("Wyze");
    }
    // eero routers
    if lower.contains("eero") {
        return Some("eero");
    }
    // Sony PlayStation
    if lower.starts_with("ps4") || lower.starts_with("ps5") || lower.contains("playstation") {
        return Some("Sony");
    }
    // Xbox
    if lower.starts_with("xbox") {
        return Some("Microsoft");
    }
    // HP printers
    if lower.starts_with("hp") || lower.starts_with("npi") {
        return Some("HP");
    }
    // Canon printers
    if lower.contains("canon") {
        return Some("Canon");
    }
    // Epson printers
    if lower.contains("epson") {
        return Some("Epson");
    }
    // Brother printers
    if lower.starts_with("brn") || lower.starts_with("brw") || lower.contains("brother") {
        return Some("Brother");
    }

    None
}

/// Extract model name from hostname patterns
pub fn get_model_from_hostname(hostname: &str) -> Option<String> {
    let lower = hostname.to_lowercase();

    // Roku devices: Roku-Ultra-XXXXX, Roku-Express-XXXXX, etc.
    if lower.starts_with("roku-") || lower.starts_with("roku_") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        if parts.len() >= 2 {
            // Model is typically the second part
            let model = parts[1];
            if !model.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(model.to_string());
            }
        }
    }

    // PlayStation: PS4-XXXXX, PS5-XXXXX
    if lower.starts_with("ps4") {
        return Some("PlayStation 4".to_string());
    }
    if lower.starts_with("ps5") {
        return Some("PlayStation 5".to_string());
    }

    // Xbox: Xbox-One-XXXXX, Xbox-Series-X-XXXXX
    if lower.starts_with("xbox") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        if parts.len() >= 2 {
            // Combine model parts (e.g., "Series-X" -> "Series X")
            let model_parts: Vec<&str> = parts[1..]
                .iter()
                .take_while(|p| !p.chars().all(|c| c.is_ascii_hexdigit()))
                .copied()
                .collect();
            if !model_parts.is_empty() {
                return Some(format!("Xbox {}", model_parts.join(" ")));
            }
        }
        return Some("Xbox".to_string());
    }

    // iPhone: iPhone-14-Pro, iPhone15Pro, etc.
    if lower.contains("iphone") {
        // Try to extract version number
        let after_iphone = lower.split("iphone").nth(1).unwrap_or("");
        let model_str: String = after_iphone
            .chars()
            .skip_while(|c| *c == '-' || *c == '_')
            .take_while(|c| c.is_ascii_digit() || *c == '-' || *c == '_' || c.is_ascii_alphabetic())
            .collect();
        if !model_str.is_empty() {
            let cleaned: String = model_str
                .replace(['-', '_'], " ")
                .split_whitespace()
                .take_while(|p| !p.chars().all(|c| c.is_ascii_hexdigit() || c == 's'))
                .collect::<Vec<_>>()
                .join(" ");
            if !cleaned.is_empty() {
                return Some(format!("iPhone {}", cleaned));
            }
        }
        return Some("iPhone".to_string());
    }

    // iPad: iPad-Pro, iPad-Air, etc.
    if lower.contains("ipad") {
        let after_ipad = lower.split("ipad").nth(1).unwrap_or("");
        let model_str: String = after_ipad
            .chars()
            .skip_while(|c| *c == '-' || *c == '_')
            .take_while(|c| c.is_ascii_alphabetic() || *c == '-' || *c == '_')
            .collect();
        if !model_str.is_empty() && !model_str.chars().all(|c| c.is_ascii_hexdigit()) {
            let cleaned = model_str.replace(['-', '_'], " ");
            return Some(format!("iPad {}", cleaned.trim()));
        }
        return Some("iPad".to_string());
    }

    // MacBook: MacBook-Pro, MacBook-Air, etc.
    if lower.contains("macbook") {
        if lower.contains("pro") {
            return Some("MacBook Pro".to_string());
        }
        if lower.contains("air") {
            return Some("MacBook Air".to_string());
        }
        return Some("MacBook".to_string());
    }

    // Samsung TVs: often have model numbers like QN65Q80B, UN55NU8000
    if lower.contains("samsung") {
        let parts: Vec<&str> = hostname.split(['-', '_', ' ']).collect();
        for part in parts {
            // Samsung TV model numbers start with QN, UN, or similar
            let upper = part.to_uppercase();
            if (upper.starts_with("QN") || upper.starts_with("UN") || upper.starts_with("UA"))
                && upper.len() >= 6
            {
                return Some(upper);
            }
        }
    }

    // LG TVs: often have model numbers like OLED55C1, 65UP8000
    if lower.starts_with("lg") || lower.contains("[lg]") {
        let parts: Vec<&str> = hostname.split(['-', '_', ' ']).collect();
        for part in parts {
            let upper = part.to_uppercase();
            if upper.starts_with("OLED") || upper.starts_with("NANO") {
                return Some(upper);
            }
            // Model like 65UP8000
            if upper.len() >= 6
                && upper.chars().take(2).all(|c| c.is_ascii_digit())
                && upper
                    .chars()
                    .skip(2)
                    .take(2)
                    .all(|c| c.is_ascii_uppercase())
            {
                return Some(upper);
            }
        }
    }

    // LG ThinQ appliances: LMA749755 (dishwasher), WM3600HWA (washer), etc.
    if lower.starts_with("lma") || lower.starts_with("ldp") || lower.starts_with("ldf") {
        return Some("Dishwasher".to_string());
    }
    if lower.starts_with("wm")
        && lower
            .chars()
            .nth(2)
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
    {
        return Some("Washing Machine".to_string());
    }
    if lower.starts_with("dlex") || lower.starts_with("dle") || lower.starts_with("dlg") {
        return Some("Dryer".to_string());
    }
    if lower.starts_with("lrm") || lower.starts_with("lrf") || lower.starts_with("lrs") {
        return Some("Refrigerator".to_string());
    }

    // Google/Nest devices
    if lower.contains("chromecast") {
        if lower.contains("ultra") {
            return Some("Chromecast Ultra".to_string());
        }
        if lower.contains("4k") || lower.contains("google-tv") {
            return Some("Chromecast with Google TV".to_string());
        }
        return Some("Chromecast".to_string());
    }
    if lower.contains("nest-hub") || lower.contains("nesthub") {
        if lower.contains("max") {
            return Some("Nest Hub Max".to_string());
        }
        return Some("Nest Hub".to_string());
    }
    if lower.contains("nest-mini") || lower.contains("google-home-mini") {
        return Some("Nest Mini".to_string());
    }
    if lower.contains("google-home") {
        return Some("Google Home".to_string());
    }

    // Amazon Echo devices
    if lower.contains("echo") {
        if lower.contains("dot") {
            return Some("Echo Dot".to_string());
        }
        if lower.contains("show") {
            return Some("Echo Show".to_string());
        }
        if lower.contains("studio") {
            return Some("Echo Studio".to_string());
        }
        if lower.contains("plus") {
            return Some("Echo Plus".to_string());
        }
        return Some("Echo".to_string());
    }

    // Sonos speakers
    if lower.contains("sonos") {
        if lower.contains("one") {
            return Some("Sonos One".to_string());
        }
        if lower.contains("beam") {
            return Some("Sonos Beam".to_string());
        }
        if lower.contains("arc") {
            return Some("Sonos Arc".to_string());
        }
        if lower.contains("move") {
            return Some("Sonos Move".to_string());
        }
        if lower.contains("roam") {
            return Some("Sonos Roam".to_string());
        }
        if lower.contains("sub") {
            return Some("Sonos Sub".to_string());
        }
        if lower.contains("play:1") || lower.contains("play1") {
            return Some("Sonos Play:1".to_string());
        }
        if lower.contains("play:3") || lower.contains("play3") {
            return Some("Sonos Play:3".to_string());
        }
        if lower.contains("play:5") || lower.contains("play5") {
            return Some("Sonos Play:5".to_string());
        }
    }

    // Ring doorbells/cameras
    if lower.contains("ring") {
        if lower.contains("doorbell") {
            return Some("Ring Doorbell".to_string());
        }
        if lower.contains("cam") || lower.contains("camera") {
            return Some("Ring Camera".to_string());
        }
        if lower.contains("stick") {
            return Some("Ring Stick Up Cam".to_string());
        }
    }

    // HP Printers - try to extract model
    if lower.starts_with("hp") || lower.starts_with("npi") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in parts {
            // HP model patterns like LaserJet, OfficeJet, DeskJet, ENVY
            let upper = part.to_uppercase();
            if upper.contains("LASERJET")
                || upper.contains("OFFICEJET")
                || upper.contains("DESKJET")
                || upper.contains("ENVY")
                || upper.contains("PHOTOSMART")
            {
                return Some(upper);
            }
        }
    }

    None
}

/// Check if any MAC address matches known IoT/appliance vendor OUIs
fn is_appliance_mac(macs: &[String]) -> bool {
    macs.iter()
        .any(|mac| get_mac_vendor(mac).is_some_and(|v| APPLIANCE_VENDORS.contains(&v)))
}

/// Check if any MAC address matches known gaming vendor OUIs
fn is_gaming_mac(macs: &[String]) -> bool {
    macs.iter()
        .any(|mac| get_mac_vendor(mac).is_some_and(|v| GAMING_VENDORS.contains(&v)))
}

/// Check if any MAC address matches known TV/streaming vendor OUIs
fn is_tv_mac(macs: &[String]) -> bool {
    macs.iter()
        .any(|mac| get_mac_vendor(mac).is_some_and(|v| TV_VENDORS.contains(&v)))
}

/// Check if hostname indicates an LG ThinQ appliance
fn is_lg_appliance(hostname: &str) -> bool {
    if matches_prefix(hostname, LG_APPLIANCE_PREFIXES) {
        return true;
    }
    // WM with digit as third character (washer model)
    if hostname.starts_with("wm")
        && let Some(c) = hostname.chars().nth(2)
        && c.is_ascii_digit()
    {
        return true;
    }
    false
}

/// Check mDNS services for device type
fn classify_by_services(services: &[String]) -> Option<&'static str> {
    for service in services {
        if TV_SERVICES.contains(&service.as_str()) {
            return Some(CLASSIFICATION_TV);
        }
        if PRINTER_SERVICES.contains(&service.as_str()) {
            return Some(CLASSIFICATION_PRINTER);
        }
    }
    None
}

/// Classify by port number
fn classify_by_port(port: u16) -> Option<&'static str> {
    match port {
        // Printer ports
        9100 | 631 | 515 => Some(CLASSIFICATION_PRINTER),
        // TV/Streaming ports
        8008 | 8009 => Some(CLASSIFICATION_TV), // Chromecast
        7000 | 7001 | 8001 | 8002 => Some(CLASSIFICATION_TV), // Samsung TV
        3000 | 3001 => Some(CLASSIFICATION_TV), // LG WebOS
        6467 | 6466 => Some(CLASSIFICATION_TV), // Roku
        // VM/Container ports
        902 | 903 => Some(CLASSIFICATION_VIRTUALIZATION), // VMware ESXi
        8006 => Some(CLASSIFICATION_VIRTUALIZATION),      // Proxmox
        2179 => Some(CLASSIFICATION_VIRTUALIZATION),      // Hyper-V
        2375 | 2376 => Some(CLASSIFICATION_VIRTUALIZATION), // Docker API
        6443 => Some(CLASSIFICATION_VIRTUALIZATION),      // Kubernetes API
        10250 => Some(CLASSIFICATION_VIRTUALIZATION),     // Kubelet
        9000 => Some(CLASSIFICATION_VIRTUALIZATION),      // Portainer
        _ => None,
    }
}

#[derive(Debug)]
pub enum InsertEndpointError {
    BothMacAndIpNone,
    ConstraintViolation,
    DatabaseError(rusqlite::Error),
}

impl From<rusqlite::Error> for InsertEndpointError {
    fn from(err: rusqlite::Error) -> Self {
        match err {
            rusqlite::Error::SqliteFailure(err, Some(_))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                InsertEndpointError::ConstraintViolation
            }
            _ => InsertEndpointError::DatabaseError(err),
        }
    }
}

#[derive(Default, Debug)]
pub struct EndPoint;

impl EndPoint {
    /// Classify an endpoint as Gateway, Internet, or LocalNetwork based on IP address and hostname
    pub fn classify_endpoint(ip: Option<String>, hostname: Option<String>) -> Option<&'static str> {
        // Check if it's the default gateway
        if let Some(ref ip_str) = ip {
            if let Some(gateway_ip) = Self::get_default_gateway()
                && gateway_ip == *ip_str
            {
                return Some(CLASSIFICATION_GATEWAY);
            }

            // Check if it's a common router IP
            if Self::is_common_router_ip(ip_str) {
                return Some(CLASSIFICATION_GATEWAY);
            }

            // Check if it's on the local network
            if !Self::is_on_local_network(ip_str) {
                return Some(CLASSIFICATION_INTERNET);
            }
        }

        // Check if hostname indicates a router/gateway
        if let Some(ref hostname_str) = hostname
            && Self::is_router_hostname(hostname_str)
        {
            return Some(CLASSIFICATION_GATEWAY);
        }

        // Local network device, no special classification
        None
    }

    /// Check if IP is a common router/gateway address
    fn is_common_router_ip(ip: &str) -> bool {
        matches!(
            ip,
            "192.168.0.1"
                | "192.168.1.1"
                | "192.168.2.1"
                | "192.168.1.254"
                | "10.0.0.1"
                | "10.0.1.1"
                | "10.1.1.1"
                | "10.10.1.1"
                | "172.16.0.1"
                | "172.16.1.1"
                | "192.168.0.254"
                | "192.168.1.253"
                | "192.168.100.1"
                | "192.168.254.254"
        )
    }

    /// Check if hostname indicates a router or gateway
    fn is_router_hostname(hostname: &str) -> bool {
        let lower = hostname.to_lowercase();
        lower.contains("router")
            || lower.contains("gateway")
            || lower.contains("-gw")
            || lower.starts_with("gw-")
            || lower.starts_with("gw.")
            || lower == "gw"
            || lower.contains(".gateway.")
            || lower.contains(".gw.")
            || lower.contains("firewall")
            || lower.contains("pfsense")
            || lower.contains("opnsense")
            || lower.contains("ubiquiti")
            || lower.contains("unifi")
            || lower.contains("edgerouter")
            || lower.contains("mikrotik")
    }

    /// Classify device type based on hostname, ports, MACs, and mDNS services
    /// Returns device-specific classification (printer, tv, gaming) or None
    /// This is separate from network-level classification (gateway, internet)
    pub fn classify_device_type(
        hostname: Option<&str>,
        ip: Option<&str>,
        ports: &[u16],
        macs: &[String],
    ) -> Option<&'static str> {
        // Pre-compute lowercase hostname once
        let lower_hostname = hostname.map(|h| h.to_lowercase());
        let lower = lower_hostname.as_deref();

        // Check for LG ThinQ appliances FIRST (they advertise AirPlay but aren't TVs)
        if let Some(h) = lower
            && is_lg_appliance(h)
        {
            return Some(CLASSIFICATION_APPLIANCE);
        }

        // Check mDNS service advertisements (most reliable for smart devices)
        if let Some(ip_str) = ip {
            let services = crate::network::mdns_lookup::MDnsLookup::get_services(ip_str);
            if let Some(classification) = classify_by_services(&services) {
                return Some(classification);
            }
        }

        // Check hostname patterns
        if let Some(h) = lower {
            // Order matters: check more specific patterns first
            if is_printer_hostname(h) {
                return Some(CLASSIFICATION_PRINTER);
            }
            if is_tv_hostname(h) {
                return Some(CLASSIFICATION_TV);
            }
            if is_gaming_hostname(h) {
                return Some(CLASSIFICATION_GAMING);
            }
            if is_phone_hostname(h) {
                return Some(CLASSIFICATION_PHONE);
            }
            if is_vm_hostname(h) {
                return Some(CLASSIFICATION_VIRTUALIZATION);
            }
            if is_soundbar_hostname(h) {
                return Some(CLASSIFICATION_SOUNDBAR);
            }
            if is_appliance_hostname(h) {
                return Some(CLASSIFICATION_APPLIANCE);
            }
        }

        // MAC-based detection (identifies devices by vendor OUI)
        if is_gaming_mac(macs) {
            return Some(CLASSIFICATION_GAMING);
        }
        if is_tv_mac(macs) {
            return Some(CLASSIFICATION_TV);
        }
        if is_appliance_mac(macs) {
            return Some(CLASSIFICATION_APPLIANCE);
        }

        // Port-based detection (less reliable, fallback)
        for &port in ports {
            if let Some(classification) = classify_by_port(port) {
                return Some(classification);
            }
        }

        None
    }

    pub fn create_table_if_not_exists(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL,
                name TEXT
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_created_at ON endpoints (created_at);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_name ON endpoints (name);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_endpoints_name_lower ON endpoints (LOWER(name));",
            [],
        )?;
        // Migration: Add manual_device_type column if it doesn't exist
        let has_column: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'manual_device_type'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_column {
            conn.execute(
                "ALTER TABLE endpoints ADD COLUMN manual_device_type TEXT",
                [],
            )?;
        }
        Ok(())
    }

    /// Set the manual device type for an endpoint by name
    /// Pass None to clear the manual override and revert to automatic classification
    pub fn set_manual_device_type(
        conn: &Connection,
        endpoint_name: &str,
        device_type: Option<&str>,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET manual_device_type = ? WHERE LOWER(name) = LOWER(?)",
            params![device_type, endpoint_name],
        )
    }

    /// Get all manual device types as a HashMap
    pub fn get_all_manual_device_types(conn: &Connection) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT name, manual_device_type FROM endpoints WHERE manual_device_type IS NOT NULL AND name IS NOT NULL",
        ) && let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                map.insert(row.0, row.1);
            }
        }
        map
    }

    fn insert_endpoint(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        hostname: Option<String>,
    ) -> Result<i64, InsertEndpointError> {
        conn.execute(
            "INSERT INTO endpoints (created_at) VALUES (strftime('%s', 'now'))",
            params![],
        )?;
        let endpoint_id = conn.last_insert_rowid();
        let hostname = hostname.unwrap_or(ip.clone().unwrap_or_default());
        EndPointAttribute::insert_endpoint_attribute(conn, endpoint_id, mac, ip, hostname)?;
        Ok(endpoint_id)
    }

    pub fn get_or_insert_endpoint(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        protocol: Option<String>,
        payload: &[u8],
    ) -> Result<i64, InsertEndpointError> {
        // Filter out broadcast/multicast MACs - these aren't real endpoints
        if let Some(ref mac_addr) = mac
            && Self::is_broadcast_or_multicast_mac(mac_addr)
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        // Filter out multicast/broadcast IPs - these aren't real endpoints
        if let Some(ref ip_addr) = ip
            && Self::is_multicast_or_broadcast_ip(ip_addr)
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        if (mac.is_none() || mac == Some("00:00:00:00:00:00".to_string())) && ip.is_none() {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }
        let hostname = Self::lookup_hostname(ip.clone(), mac.clone(), protocol.clone(), payload);
        let endpoint_id = match EndPointAttribute::find_existing_endpoint_id(
            conn,
            mac.clone(),
            ip.clone(),
            hostname.clone(),
        ) {
            Some(id) => {
                // Always try to insert new hostname if it's different from IP
                // This captures all hostnames seen at this endpoint (remote or local)
                if ip != hostname && hostname.is_some() {
                    // Attempt to insert - will be ignored if duplicate due to UNIQUE constraint
                    let _ = EndPointAttribute::insert_endpoint_attribute(
                        conn,
                        id,
                        mac,
                        ip.clone(),
                        hostname.clone().unwrap_or(ip.clone().unwrap_or_default()),
                    );
                }
                id
            }
            _ => Self::insert_endpoint(conn, mac.clone(), ip.clone(), hostname.clone())?,
        };
        Self::check_and_update_endpoint_name(
            conn,
            endpoint_id,
            hostname.clone().unwrap_or_default(),
        )?;
        Ok(endpoint_id)
    }

    fn check_and_update_endpoint_name(
        conn: &Connection,
        endpoint_id: i64,
        hostname: String,
    ) -> Result<(), InsertEndpointError> {
        if hostname.is_empty() {
            return Ok(());
        }
        // Strip local suffixes like .local, .lan, .home
        let hostname = strip_local_suffix(&hostname);

        // Check if endpoint exists with null hostname
        if conn.query_row(
            "SELECT COUNT(*) FROM endpoints WHERE id = ? AND (name IS NULL OR name = '')",
            params![endpoint_id],
            |row| row.get::<_, i64>(0),
        )? > 0
        {
            conn.execute(
                "UPDATE endpoints SET name = ? where id = ?",
                params![hostname, endpoint_id],
            )?;
        } else if hostname.parse::<std::net::IpAddr>().is_err() {
            // Only update if hostname is not an IPv4 or IPv6 address
            // First check if current name is an IP address
            let current_name: String = conn.query_row(
                "SELECT COALESCE(name, '') FROM endpoints WHERE id = ?",
                params![endpoint_id],
                |row| row.get(0),
            )?;

            if current_name.is_empty() || current_name.parse::<std::net::IpAddr>().is_ok() {
                conn.execute(
                    "UPDATE endpoints SET name = ? WHERE id = ?",
                    params![hostname, endpoint_id],
                )?;
            }
        }

        Ok(())
    }

    fn parse_windows_gateway(output: &str) -> Option<String> {
        output.lines().find_map(|line| {
            // Look for "0.0.0.0          0.0.0.0     <gateway_ip>"
            if !line.contains("0.0.0.0") || line.split_whitespace().count() < 3 {
                return None;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                Some(parts[2].to_string())
            } else {
                None
            }
        })
    }

    fn parse_macos_gateway(output: &str) -> Option<String> {
        output.lines().find_map(|line| {
            if line.contains("gateway:") {
                line.split_whitespace().nth(1).map(String::from)
            } else {
                None
            }
        })
    }

    fn parse_linux_gateway(output: &str) -> Option<String> {
        // Expected format: "default via <gateway_ip> dev <interface>"
        output
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(2).map(String::from))
    }

    fn parse_linux_route_n(output: &str) -> Option<String> {
        output.lines().find_map(|line| {
            if line.starts_with("0.0.0.0") {
                line.split_whitespace().nth(1).map(String::from)
            } else {
                None
            }
        })
    }

    fn get_default_gateway() -> Option<String> {
        // Check cache first
        if let Ok(cache) = GATEWAY_INFO.lock()
            && let Some((gateway_ip, cached_time)) = cache.as_ref()
            && cached_time.elapsed() < GATEWAY_CACHE_TTL
        {
            return Some(gateway_ip.clone());
        }

        // Get default gateway using system commands
        let gateway_ip = if cfg!(target_os = "windows") {
            std::process::Command::new("route")
                .args(["print", "0.0.0.0"])
                .output()
                .ok()
                .and_then(|output| {
                    Self::parse_windows_gateway(&String::from_utf8_lossy(&output.stdout))
                })
        } else if cfg!(target_os = "macos") {
            std::process::Command::new("route")
                .args(["-n", "get", "default"])
                .output()
                .ok()
                .and_then(|output| {
                    Self::parse_macos_gateway(&String::from_utf8_lossy(&output.stdout))
                })
        } else {
            // Linux: try ip route first, fallback to route -n
            std::process::Command::new("ip")
                .args(["route", "show", "default"])
                .output()
                .ok()
                .and_then(|output| {
                    Self::parse_linux_gateway(&String::from_utf8_lossy(&output.stdout))
                })
                .or_else(|| {
                    std::process::Command::new("route")
                        .args(["-n"])
                        .output()
                        .ok()
                        .and_then(|output| {
                            Self::parse_linux_route_n(&String::from_utf8_lossy(&output.stdout))
                        })
                })
        };

        // Cache the result
        if let Some(ref gw) = gateway_ip
            && let Ok(mut cache) = GATEWAY_INFO.lock()
        {
            *cache = Some((gw.clone(), Instant::now()));
        }

        gateway_ip
    }

    pub fn is_on_local_network(ip: &str) -> bool {
        // Parse the IP address
        let ip_addr: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        // Special case: loopback addresses are always local
        if ip_addr.is_loopback() {
            return true;
        }

        // Check cached local networks (computed once at startup)
        for ip_network in get_local_networks() {
            if ip_network.contains(ip_addr) {
                return true;
            }
        }

        false
    }

    fn lookup_dns(ip: Option<String>, mac: Option<String>) -> Option<String> {
        let ip_str = ip?;
        let mac_str = mac?;
        let ip_addr = ip_str.parse().ok()?;
        let is_local = Self::is_local(ip_str.clone(), mac_str.clone());
        let local_hostname = get_hostname().unwrap_or_default();

        // Check cache first to avoid slow DNS lookups
        if let Ok(cache) = DNS_CACHE.lock()
            && let Some((cached_name, cached_time)) = cache.get(&ip_str)
            && cached_time.elapsed() < DNS_CACHE_TTL
        {
            return Some(cached_name.clone());
        }

        // Get hostname via DNS or fallback to mDNS/IP
        let hostname = match lookup_addr(&ip_addr) {
            Ok(name) if name != ip_str && !is_local => name,
            _ => MDnsLookup::lookup(&ip_str).unwrap_or(ip_str.clone()),
        };

        // Use local hostname for local IPs with different names
        let final_hostname = if is_local && !hostname.eq_ignore_ascii_case(&local_hostname) {
            local_hostname
        } else {
            hostname
        };

        // Cache the result
        if let Ok(mut cache) = DNS_CACHE.lock() {
            cache.insert(ip_str, (final_hostname.clone(), Instant::now()));
            // LRU-style eviction: remove oldest entries instead of clearing all
            if cache.len() > 10000 {
                // Find and remove the 1000 oldest entries
                let mut entries: Vec<_> = cache.iter().map(|(k, (_, t))| (k.clone(), *t)).collect();
                entries.sort_by_key(|(_, t)| *t);
                for (key, _) in entries.into_iter().take(1000) {
                    cache.remove(&key);
                }
            }
        }

        Some(final_hostname)
    }

    fn lookup_hostname(
        ip: Option<String>,
        mac: Option<String>,
        protocol: Option<String>,
        payload: &[u8],
    ) -> Option<String> {
        match protocol.as_deref() {
            Some("HTTP") => Self::get_http_host(payload),
            Some("HTTPS") => Self::find_sni(payload),
            _ => Self::lookup_dns(ip.clone(), mac.clone()),
        }
    }

    fn get_http_host(payload: &[u8]) -> Option<String> {
        let payload_str = String::from_utf8_lossy(payload);

        let mut host = None;

        for line in payload_str.lines() {
            let line = line.to_lowercase();
            if let Some(header_value) = line.strip_prefix("host:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("server:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("location:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("x-host:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("x-forwarded-host:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("x-forwarded-server:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("referer:") {
                host = Some(header_value.trim().to_string());
                break;
            } else if let Some(header_value) = line.strip_prefix("report-uri:") {
                host = Some(header_value.trim().to_string());
                break;
            }
        }
        host.map(|host| Self::remove_all_but_alphanumeric_and_dots(host.as_str()))
    }

    fn remove_all_but_alphanumeric_and_dots(hostname: &str) -> String {
        let mut s = String::new();
        for h in hostname.chars() {
            if h.is_ascii_alphanumeric() || h == '.' || h == '-' {
                s.push(h);
            } else {
                s.clear();
            }
        }
        s
    }

    // Parse TLS ClientHello to extract SNI (Server Name Indication)
    fn find_sni(payload: &[u8]) -> Option<String> {
        // Minimum TLS ClientHello size
        if payload.len() < 44 {
            return None;
        }

        // Check for TLS Handshake (0x16) and version (0x03 0x01, 0x03 0x02, or 0x03 0x03)
        if payload[0] != 0x16 || payload[1] != 0x03 {
            return None;
        }

        // Check for ClientHello (0x01)
        if payload[5] != 0x01 {
            return None;
        }

        // Skip to extensions section
        // TLS record: 5 bytes
        // Handshake header: 4 bytes
        // Client version: 2 bytes
        // Random: 32 bytes
        let mut offset = 43;

        // Session ID length (1 byte) + session ID
        if offset >= payload.len() {
            return None;
        }
        let session_id_len = payload[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suites length (2 bytes) + cipher suites
        if offset + 2 > payload.len() {
            return None;
        }
        let cipher_suites_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
        offset += 2 + cipher_suites_len;

        // Compression methods length (1 byte) + compression methods
        if offset + 1 > payload.len() {
            return None;
        }
        let compression_methods_len = payload[offset] as usize;
        offset += 1 + compression_methods_len;

        // Extensions length (2 bytes)
        if offset + 2 > payload.len() {
            return None;
        }
        let extensions_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
        offset += 2;

        let extensions_end = offset + extensions_len;
        if extensions_end > payload.len() {
            return None;
        }

        // Parse extensions
        while offset + 4 <= extensions_end {
            let ext_type = ((payload[offset] as u16) << 8) | (payload[offset + 1] as u16);
            let ext_len = ((payload[offset + 2] as usize) << 8) | (payload[offset + 3] as usize);
            offset += 4;

            // Server Name extension (0x0000)
            if ext_type == 0x0000 && offset + ext_len <= extensions_end {
                // Server Name List Length (2 bytes)
                if ext_len < 5 || offset + 2 > extensions_end {
                    return None;
                }
                let _list_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
                offset += 2;

                // Server Name Type (1 byte, 0x00 for hostname)
                if payload[offset] != 0x00 {
                    return None;
                }
                offset += 1;

                // Server Name Length (2 bytes)
                if offset + 2 > extensions_end {
                    return None;
                }
                let name_len = ((payload[offset] as usize) << 8) | (payload[offset + 1] as usize);
                offset += 2;

                // Extract hostname
                if offset + name_len <= extensions_end
                    && let Ok(hostname) =
                        String::from_utf8(payload[offset..offset + name_len].to_vec())
                {
                    let cleaned = Self::remove_all_but_alphanumeric_and_dots(hostname.as_str());
                    if !cleaned.is_empty() {
                        return Some(cleaned);
                    }
                }
                return None;
            }

            offset += ext_len;
        }

        None
    }

    fn is_broadcast_or_multicast_mac(mac: &str) -> bool {
        let mac_lower = mac.to_lowercase();

        // Broadcast address
        if mac_lower == "ff:ff:ff:ff:ff:ff" {
            return true;
        }

        // Check if first octet indicates multicast (LSB of first byte is 1)
        // Multicast MACs: 01:xx:xx:xx:xx:xx, 03:xx:xx:xx:xx:xx, etc.
        if let Some(first_octet) = mac_lower.split(':').next()
            && let Ok(byte) = u8::from_str_radix(first_octet, 16)
        {
            // If LSB of first byte is 1, it's multicast
            if (byte & 0x01) == 0x01 {
                return true;
            }
        }

        false
    }

    fn is_multicast_or_broadcast_ip(ip: &str) -> bool {
        // Try to parse as IP address
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            match addr {
                std::net::IpAddr::V4(ipv4) => {
                    // IPv4 multicast: 224.0.0.0 - 239.255.255.255
                    if ipv4.is_multicast() {
                        return true;
                    }
                    // IPv4 broadcast
                    if ipv4.is_broadcast() {
                        return true;
                    }
                }
                std::net::IpAddr::V6(ipv6) => {
                    // IPv6 multicast: ff00::/8
                    if ipv6.is_multicast() {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn is_local(target_ip: String, mac: String) -> bool {
        // Check definitive loopback addresses first
        if target_ip == "127.0.0.1"
            || target_ip == "::1"
            || target_ip == "localhost"
            || target_ip == "::ffff:"
            || target_ip == "0:0:0:0:0:0:0:1"
        {
            return true; // Loopback addresses are always local
        }

        // For :: (unspecified address), verify MAC matches local interface
        let is_unspecified = target_ip == "::";

        for interface in interfaces() {
            if let Some(iface_mac) = interface.mac {
                if iface_mac.to_string() == mac {
                    return true; // MAC address matches a local interface
                }
            } else if interface
                .ips
                .iter()
                .any(|ip| ip.ip().to_string() == target_ip)
            {
                return true; // IP address matches a local interface
            }
        }

        // Only treat :: as local if we didn't find a matching MAC
        // If MAC didn't match any local interface, :: is NOT local
        if is_unspecified {
            return false;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_test_connection;

    #[test]
    fn test_classify_common_router_ip() {
        // Common router IPs should be classified as gateway
        let classification = EndPoint::classify_endpoint(Some("192.168.1.1".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));

        let classification = EndPoint::classify_endpoint(Some("10.0.0.1".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));
    }

    #[test]
    fn test_classify_router_hostname() {
        // Hostnames with router keywords should be classified as gateway
        let classification = EndPoint::classify_endpoint(None, Some("my-router.local".to_string()));
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));

        let classification =
            EndPoint::classify_endpoint(None, Some("gateway.example.com".to_string()));
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));

        let classification = EndPoint::classify_endpoint(None, Some("pfsense.local".to_string()));
        assert_eq!(classification, Some(CLASSIFICATION_GATEWAY));
    }

    #[test]
    fn test_classify_internet_endpoint() {
        // Public IPs should be classified as internet
        let classification = EndPoint::classify_endpoint(Some("8.8.8.8".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_INTERNET));

        let classification = EndPoint::classify_endpoint(Some("1.1.1.1".to_string()), None);
        assert_eq!(classification, Some(CLASSIFICATION_INTERNET));
    }

    #[test]
    fn test_classify_local_endpoint() {
        // Loopback should return None as it's not gateway or internet (it's local)
        let classification = EndPoint::classify_endpoint(Some("127.0.0.1".to_string()), None);
        assert_eq!(classification, None);

        // Note: 192.168.x.x may be classified as internet in test environment
        // without configured network interfaces, which is expected behavior
    }

    #[test]
    fn test_classify_none_ip() {
        let classification = EndPoint::classify_endpoint(None, None);
        assert_eq!(classification, None);
    }

    #[test]
    fn test_endpoint_insertion() {
        let conn = new_test_connection();

        // Insert an endpoint
        let result = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            Some("192.168.1.100".to_string()),
            None,
            &[],
        );

        assert!(result.is_ok());
        let endpoint_id = result.unwrap();
        assert!(endpoint_id > 0);

        // Verify endpoint exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM endpoints WHERE id = ?1",
                [endpoint_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_duplicate_endpoint_returns_same_id() {
        let conn = new_test_connection();

        // Insert endpoint first time
        let id1 = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            Some("192.168.1.100".to_string()),
            None,
            &[],
        )
        .unwrap();

        // Insert same endpoint again
        let id2 = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            Some("192.168.1.100".to_string()),
            None,
            &[],
        )
        .unwrap();

        // Should return the same ID
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_is_multicast_or_broadcast_ip() {
        assert!(EndPoint::is_multicast_or_broadcast_ip("224.0.0.1"));
        assert!(EndPoint::is_multicast_or_broadcast_ip("255.255.255.255"));
        assert!(!EndPoint::is_multicast_or_broadcast_ip("192.168.1.1"));
        assert!(!EndPoint::is_multicast_or_broadcast_ip("8.8.8.8"));
    }

    #[test]
    fn test_is_broadcast_or_multicast_mac() {
        assert!(EndPoint::is_broadcast_or_multicast_mac("ff:ff:ff:ff:ff:ff"));
        assert!(EndPoint::is_broadcast_or_multicast_mac("01:00:5e:00:00:01"));
        assert!(!EndPoint::is_broadcast_or_multicast_mac(
            "00:11:22:33:44:55"
        ));
    }

    // Device classification tests
    #[test]
    fn test_classify_printer() {
        use super::*;

        // Hostname patterns
        assert_eq!(is_printer_hostname("hp-laserjet-pro"), true);
        assert_eq!(is_printer_hostname("canon-mx920"), true);
        assert_eq!(is_printer_hostname("epson-wf-7720"), true);
        assert_eq!(is_printer_hostname("brother-mfc-9340cdw"), true);
        assert_eq!(is_printer_hostname("npi123456"), true);
        assert_eq!(is_printer_hostname("brn001122334455"), true);

        // Non-printers
        assert_eq!(is_printer_hostname("my-laptop"), false);
        assert_eq!(is_printer_hostname("iphone"), false);
    }

    #[test]
    fn test_classify_tv() {
        use super::*;

        // Hostname patterns
        assert_eq!(is_tv_hostname("samsung-tv"), true);
        assert_eq!(is_tv_hostname("roku-ultra"), true);
        assert_eq!(is_tv_hostname("chromecast-living-room"), true);
        assert_eq!(is_tv_hostname("appletv"), true);
        assert_eq!(is_tv_hostname("lg-oled55"), true);
        assert_eq!(is_tv_hostname("firetv-stick"), true);

        // Non-TVs
        assert_eq!(is_tv_hostname("my-laptop"), false);
        assert_eq!(is_tv_hostname("printer"), false);
    }

    #[test]
    fn test_classify_gaming() {
        use super::*;

        assert_eq!(is_gaming_hostname("xbox-series-x"), true);
        assert_eq!(is_gaming_hostname("playstation-5"), true);
        assert_eq!(is_gaming_hostname("nintendo-switch"), true);
        assert_eq!(is_gaming_hostname("steamdeck"), true);

        assert_eq!(is_gaming_hostname("my-pc"), false);
    }

    #[test]
    fn test_classify_phone() {
        use super::*;

        assert_eq!(is_phone_hostname("iphone-14-pro"), true);
        assert_eq!(is_phone_hostname("ipad-mini"), true);
        assert_eq!(is_phone_hostname("galaxy-s23"), true);
        assert_eq!(is_phone_hostname("pixel-7"), true);
        assert_eq!(is_phone_hostname("sm-g991u"), true);
        assert_eq!(is_phone_hostname("oneplus-11"), true);
        assert_eq!(is_phone_hostname("moto-g-power"), true);

        // Should NOT match TV variants
        assert_eq!(is_phone_hostname("galaxy-tv"), false);
        assert_eq!(is_phone_hostname("androidtv"), false);
    }

    #[test]
    fn test_classify_vm() {
        use super::*;

        assert_eq!(is_vm_hostname("vmware-esxi-01"), true);
        assert_eq!(is_vm_hostname("proxmox-server"), true);
        assert_eq!(is_vm_hostname("docker-host"), true);
        assert_eq!(is_vm_hostname("kubernetes-node-1"), true);
        assert_eq!(is_vm_hostname("vm-ubuntu-22"), true);
        assert_eq!(is_vm_hostname("webserver-vm"), true);

        assert_eq!(is_vm_hostname("my-laptop"), false);
    }

    #[test]
    fn test_classify_soundbar() {
        use super::*;

        assert_eq!(is_soundbar_hostname("sonos-beam"), true);
        assert_eq!(is_soundbar_hostname("bose-soundbar-700"), true);
        assert_eq!(is_soundbar_hostname("samsung-sound-plus"), true);
        assert_eq!(is_soundbar_hostname("jbl-bar-5.1"), true);

        assert_eq!(is_soundbar_hostname("samsung-tv"), false);
    }

    #[test]
    fn test_classify_appliance() {
        use super::*;

        assert_eq!(is_appliance_hostname("lg-dishwasher"), true);
        assert_eq!(is_appliance_hostname("samsung-washer"), true);
        assert_eq!(is_appliance_hostname("whirlpool-dryer"), true);
        assert_eq!(is_appliance_hostname("bosch-dishwasher-500"), true);

        // LG ThinQ appliances
        assert_eq!(is_lg_appliance("ldf7774st"), true);
        assert_eq!(is_lg_appliance("wm3900hwa"), true);
        assert_eq!(is_lg_appliance("dlex3900w"), true);

        assert_eq!(is_appliance_hostname("my-laptop"), false);
    }

    #[test]
    fn test_classify_by_port() {
        use super::*;

        // Printer ports
        assert_eq!(classify_by_port(9100), Some(CLASSIFICATION_PRINTER));
        assert_eq!(classify_by_port(631), Some(CLASSIFICATION_PRINTER));

        // TV ports
        assert_eq!(classify_by_port(8008), Some(CLASSIFICATION_TV)); // Chromecast
        assert_eq!(classify_by_port(8001), Some(CLASSIFICATION_TV)); // Samsung
        assert_eq!(classify_by_port(6467), Some(CLASSIFICATION_TV)); // Roku

        // VM ports
        assert_eq!(classify_by_port(8006), Some(CLASSIFICATION_VIRTUALIZATION)); // Proxmox
        assert_eq!(classify_by_port(2375), Some(CLASSIFICATION_VIRTUALIZATION)); // Docker

        // Unknown
        assert_eq!(classify_by_port(80), None);
        assert_eq!(classify_by_port(443), None);
    }

    #[test]
    fn test_classify_device_type_integration() {
        // Full integration test of classify_device_type
        assert_eq!(
            EndPoint::classify_device_type(Some("hp-laserjet"), None, &[], &[]),
            Some("printer")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("roku-ultra"), None, &[], &[]),
            Some("tv")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("unknown-device"), None, &[9100], &[]),
            Some("printer")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("my-laptop"), None, &[80, 443], &[]),
            None
        );
    }

    #[test]
    fn test_classify_by_mac() {
        // Amazon device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                None,
                &[],
                &["3c:5c:c4:90:a2:93".to_string()]
            ),
            Some("appliance")
        );
        // Google/Nest device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("192.168.1.50"),
                None,
                &[],
                &["18:d6:c7:12:34:56".to_string()]
            ),
            Some("appliance")
        );
        // Ring device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                None,
                &[],
                &["34:3e:a4:00:00:00".to_string()]
            ),
            Some("appliance")
        );
        // Unknown MAC (Apple)
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                None,
                &[],
                &["a4:83:e7:12:34:56".to_string()]
            ),
            None
        );
        // Hostname takes precedence over MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("hp-printer"),
                None,
                &[],
                &["3c:5c:c4:90:a2:93".to_string()]
            ),
            Some("printer")
        );
    }
}
