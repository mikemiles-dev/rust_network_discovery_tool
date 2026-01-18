use dns_lookup::{get_hostname, lookup_addr};
use pnet::datalink::interfaces;
use pnet::ipnetwork::IpNetwork;
use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};
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
const LOCAL_SUFFIXES: &[&str] = &[
    ".local",
    ".lan",
    ".home",
    ".internal",
    ".localdomain",
    ".localhost",
];

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
    "bravia", // Sony TVs (not "sony" - that would match PlayStation too)
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

/// Soundbar model number prefixes (for SSDP model detection)
const SOUNDBAR_MODEL_PREFIXES: &[&str] = &[
    "hw-",  // Samsung soundbars (HW-MS750, HW-Q990B, etc.)
    "spk-", // Samsung speakers (SPK-WAM750, etc.)
    "wam",  // Samsung Wireless Audio Multiroom (WAM750, etc.)
    "sl",   // LG soundbars (SL8YG, SL10YG, etc.) - no dash in LG models
    "sn",   // LG soundbars (SN11RG, etc.)
    "sp",   // LG soundbars (SP9YA, etc.)
    "sc9",  // LG soundbars (SC9S, etc.) - sc9 to avoid matching other "sc" models
    "bar-", // JBL soundbars (Bar 5.1, etc.)
];

/// Samsung TV model series patterns mapped to friendly names
/// Model format: [Panel][Size][Series][Variant] e.g., QN43LS03TAFXZA
/// - QN = QLED, UN = UHD LED
/// - 43 = screen size
/// - LS03 = The Frame series
/// - TAFXZA = year/region variant
const SAMSUNG_TV_SERIES: &[(&str, &str)] = &[
    // Lifestyle TVs
    ("ls03", "The Frame"),
    ("ls01", "The Serif"),
    ("ls05", "The Sero"),
    ("lst7", "The Terrace"),
    // OLED series
    ("s95", "OLED S95"),
    ("s90", "OLED S90"),
    ("s85", "OLED S85"),
    // Neo QLED series (highest to lowest)
    ("qn9", "Neo QLED QN9"),
    ("qn8", "Neo QLED QN8"),
    ("qn7", "Neo QLED QN7"),
    // QLED series
    ("q8", "QLED Q8"),
    ("q7", "QLED Q7"),
    ("q6", "QLED Q6"),
    // Crystal UHD series
    ("cu8", "Crystal UHD CU8"),
    ("cu7", "Crystal UHD CU7"),
    ("bu8", "Crystal UHD BU8"),
    ("au8", "Crystal UHD AU8"),
    ("tu8", "Crystal UHD TU8"),
    ("tu7", "Crystal UHD TU7"),
];

/// LG TV model series patterns mapped to friendly names
/// Model format: OLED[Size][Series][Year][Variant] e.g., OLED55C3PUA
const LG_TV_SERIES: &[(&str, &str)] = &[
    // OLED series (premium to standard)
    ("oled", "OLED"),
    ("g3", "OLED G3"),
    ("g2", "OLED G2"),
    ("c3", "OLED C3"),
    ("c2", "OLED C2"),
    ("c1", "OLED C1"),
    ("b3", "OLED B3"),
    ("b2", "OLED B2"),
    // QNED series
    ("qned", "QNED"),
    // NanoCell series
    ("nano", "NanoCell"),
    // UHD series
    ("uq", "UHD"),
    ("up", "UHD"),
];

/// Sony TV model series patterns
const SONY_TV_SERIES: &[(&str, &str)] = &[
    ("a95", "Bravia XR A95"),
    ("a90", "Bravia XR A90"),
    ("a80", "Bravia XR A80"),
    ("x95", "Bravia XR X95"),
    ("x90", "Bravia XR X90"),
    ("x85", "Bravia X85"),
    ("x80", "Bravia X80"),
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
    // Smart home hubs
    "smartthings",
    "hubv2",
    "hubv3",
    "hue-bridge",
    "homebridge",
    "home-assistant",
    "homeassistant",
];
const LG_APPLIANCE_PREFIXES: &[&str] = &["lma", "lmw", "ldf", "ldt", "ldp", "dle", "dlex", "lrmv"];

// MAC OUI prefixes mapped to vendor names (first 3 bytes, lowercase, colon-separated)
// Used for both appliance classification and vendor display
const MAC_VENDOR_MAP: &[(&str, &str)] = &[
    // Amazon (Echo, Fire TV Stick, Ring, etc.)
    ("00:fc:8b", "Amazon"),
    ("0c:47:c9", "Amazon"),
    ("10:2c:6b", "Amazon"),
    ("14:91:38", "Amazon"),
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
    // eero mesh routers (Amazon subsidiary)
    ("00:ab:48", "eero"),
    ("08:9b:f1", "eero"),
    ("08:f0:1e", "eero"),
    ("0c:1c:1a", "eero"),
    ("0c:93:a5", "eero"),
    ("0c:c7:63", "eero"),
    ("14:22:db", "eero"),
    ("18:90:88", "eero"),
    ("18:a9:ed", "eero"),
    ("20:3a:0c", "eero"),
    ("20:be:cd", "eero"),
    ("20:e6:df", "eero"),
    ("24:2d:6c", "eero"),
    ("24:f3:e3", "eero"),
    ("28:ec:22", "eero"),
    ("2c:2f:f4", "eero"),
    ("30:29:2b", "eero"),
    ("30:34:22", "eero"),
    ("30:3a:4a", "eero"),
    ("30:57:8e", "eero"),
    ("34:bc:5e", "eero"),
    ("3c:5c:f1", "eero"),
    ("40:47:5e", "eero"),
    ("40:49:7c", "eero"),
    ("44:ac:85", "eero"),
    ("48:b4:24", "eero"),
    ("48:dd:0c", "eero"),
    ("4c:01:43", "eero"),
    ("50:27:a9", "eero"),
    ("50:61:3f", "eero"),
    ("5c:a5:bc", "eero"),
    ("60:57:7d", "eero"),
    ("60:5f:8d", "eero"),
    ("60:f4:19", "eero"),
    ("64:97:14", "eero"),
    ("64:c2:69", "eero"),
    ("64:d9:c2", "eero"),
    ("64:da:ed", "eero"),
    ("68:4a:76", "eero"),
    ("6c:ae:f6", "eero"),
    ("70:93:c1", "eero"),
    ("74:b6:b6", "eero"),
    ("78:68:29", "eero"),
    ("78:76:89", "eero"),
    ("78:d6:d6", "eero"),
    ("7c:49:cf", "eero"),
    ("7c:5e:98", "eero"),
    ("7c:7e:f9", "eero"),
    ("80:af:9f", "eero"),
    ("80:b9:7a", "eero"),
    ("80:da:13", "eero"),
    ("84:70:d7", "eero"),
    ("84:d9:e0", "eero"),
    ("88:67:46", "eero"),
    ("8c:dd:0b", "eero"),
    ("94:cd:fd", "eero"),
    ("98:ed:7e", "eero"),
    ("9c:0b:05", "eero"),
    ("9c:57:bc", "eero"),
    ("9c:a5:70", "eero"),
    ("a0:8e:24", "eero"),
    ("a4:6b:1f", "eero"),
    ("a4:99:a8", "eero"),
    ("a8:13:0b", "eero"),
    ("a8:b0:88", "eero"),
    ("ac:39:3d", "eero"),
    ("ac:ec:85", "eero"),
    ("b0:f1:ae", "eero"),
    ("b4:20:46", "eero"),
    ("b4:b9:e6", "eero"),
    ("b8:32:8f", "eero"),
    ("c0:36:53", "eero"),
    ("c0:6f:98", "eero"),
    ("c4:a8:16", "eero"),
    ("c4:f1:74", "eero"),
    ("c8:b8:2f", "eero"),
    ("c8:c6:fe", "eero"),
    ("c8:cc:21", "eero"),
    ("c8:e3:06", "eero"),
    ("d0:16:7c", "eero"),
    ("d0:68:27", "eero"),
    ("d0:cb:dd", "eero"),
    ("d4:05:de", "eero"),
    ("d4:3f:32", "eero"),
    ("d8:8e:d4", "eero"),
    ("dc:69:b5", "eero"),
    ("e4:19:7f", "eero"),
    ("e8:d3:eb", "eero"),
    ("ec:30:dd", "eero"),
    ("ec:74:27", "eero"),
    ("f0:21:e0", "eero"),
    ("f0:b6:61", "eero"),
    ("f8:bb:bf", "eero"),
    ("f8:bc:0e", "eero"),
    ("fc:3d:73", "eero"),
    ("fc:3f:a6", "eero"),
    // HP/Hewlett-Packard (printers, computers, etc.)
    ("00:01:e6", "HP"),
    ("00:01:e7", "HP"),
    ("00:02:a5", "HP"),
    ("00:04:ea", "HP"),
    ("00:08:02", "HP"),
    ("00:08:83", "HP"),
    ("00:0a:57", "HP"),
    ("00:0b:cd", "HP"),
    ("00:0d:9d", "HP"),
    ("00:0e:7f", "HP"),
    ("00:0f:20", "HP"),
    ("00:10:83", "HP"),
    ("00:10:e3", "HP"),
    ("00:11:0a", "HP"),
    ("00:11:85", "HP"),
    ("00:12:79", "HP"),
    ("00:13:21", "HP"),
    ("00:14:c2", "HP"),
    ("00:15:60", "HP"),
    ("00:16:35", "HP"),
    ("00:17:08", "HP"),
    ("00:17:a4", "HP"),
    ("00:18:71", "HP"),
    ("00:18:fe", "HP"),
    ("00:19:bb", "HP"),
    ("00:1a:4b", "HP"),
    ("00:1b:78", "HP"),
    ("00:1c:c4", "HP"),
    ("00:1e:0b", "HP"),
    ("00:1f:29", "HP"),
    ("00:21:5a", "HP"),
    ("00:22:64", "HP"),
    ("00:23:7d", "HP"),
    ("00:24:81", "HP"),
    ("00:25:b3", "HP"),
    ("00:26:55", "HP"),
    ("00:30:6e", "HP"),
    ("00:30:c1", "HP"),
    ("00:50:8b", "HP"),
    ("00:60:b0", "HP"),
    ("00:80:5f", "HP"),
    ("00:80:a0", "HP"),
    ("08:00:09", "HP"),
    ("08:2e:5f", "HP"),
    ("10:1f:74", "HP"),
    ("10:60:4b", "HP"),
    ("10:62:e5", "HP"),
    ("10:e7:c6", "HP"),
    ("14:58:d0", "HP"),
    ("18:60:24", "HP"),
    ("18:a9:05", "HP"),
    ("1c:c1:de", "HP"),
    ("24:be:05", "HP"),
    ("28:80:23", "HP"),
    ("28:92:4a", "HP"),
    ("2c:23:3a", "HP"),
    ("2c:27:d7", "HP"),
    ("2c:41:38", "HP"),
    ("2c:44:fd", "HP"),
    ("2c:59:e5", "HP"),
    ("2c:76:8a", "HP"),
    ("30:8d:99", "HP"),
    ("30:e1:71", "HP"),
    ("34:64:a9", "HP"),
    ("38:63:bb", "HP"),
    ("38:ea:a7", "HP"),
    ("3c:4a:92", "HP"),
    ("3c:52:82", "HP"),
    ("3c:a8:2a", "HP"),
    ("3c:d9:2b", "HP"),
    ("40:a8:f0", "HP"),
    ("40:b0:34", "HP"),
    ("44:1e:a1", "HP"),
    ("44:31:92", "HP"),
    ("48:0f:cf", "HP"),
    ("48:ba:4e", "HP"),
    ("50:65:f3", "HP"),
    ("58:20:b1", "HP"),
    ("5c:8a:38", "HP"),
    ("5c:b9:01", "HP"),
    ("5c:ba:ef", "HP"), // Foxconn-manufactured HP devices
    ("64:31:50", "HP"),
    ("64:51:06", "HP"),
    ("68:b5:99", "HP"),
    ("6c:3b:e5", "HP"),
    ("6c:c2:17", "HP"),
    ("70:5a:0f", "HP"),
    ("74:46:a0", "HP"),
    ("78:48:59", "HP"),
    ("78:ac:c0", "HP"),
    ("78:e3:b5", "HP"),
    ("78:e7:d1", "HP"),
    ("80:c1:6e", "HP"),
    ("80:ce:62", "HP"),
    ("80:e8:2c", "HP"),
    ("84:34:97", "HP"),
    ("84:a9:3e", "HP"),
    ("88:51:fb", "HP"),
    ("8c:dc:d4", "HP"),
    ("94:57:a5", "HP"),
    ("98:4b:e1", "HP"),
    ("98:e7:f4", "HP"),
    ("9c:7b:ef", "HP"),
    ("9c:8e:99", "HP"),
    ("9c:b6:54", "HP"),
    ("a0:1d:48", "HP"),
    ("a0:2b:b8", "HP"),
    ("a0:48:1c", "HP"),
    ("a0:8c:fd", "HP"),
    ("a0:b3:cc", "HP"),
    ("a0:d3:c1", "HP"),
    ("a4:5d:36", "HP"),
    ("ac:16:2d", "HP"),
    ("ac:e2:d3", "HP"),
    ("b0:0c:d1", "HP"),
    ("b0:5a:da", "HP"),
    ("b4:99:ba", "HP"),
    ("b4:b5:2f", "HP"),
    ("b4:b6:86", "HP"),
    ("b8:af:67", "HP"),
    ("bc:ea:fa", "HP"),
    ("c4:34:6b", "HP"),
    ("c4:65:16", "HP"),
    ("c8:cb:b8", "HP"),
    ("c8:d3:ff", "HP"),
    ("c8:d9:d2", "HP"),
    ("cc:3e:5f", "HP"),
    ("d0:7e:28", "HP"),
    ("d0:bf:9c", "HP"),
    ("d4:85:64", "HP"),
    ("d4:c9:ef", "HP"),
    ("d8:9d:67", "HP"),
    ("d8:d3:85", "HP"),
    ("dc:4a:3e", "HP"),
    ("e4:11:5b", "HP"),
    ("e4:e7:49", "HP"),
    ("e8:39:35", "HP"),
    ("ec:8e:b5", "HP"),
    ("ec:9a:74", "HP"),
    ("ec:b1:d7", "HP"),
    ("f0:92:1c", "HP"),
    ("f4:30:b9", "HP"),
    ("f4:39:09", "HP"),
    ("f4:ce:46", "HP"),
    ("f8:b4:6a", "HP"),
    ("fc:15:b4", "HP"),
    ("fc:3f:db", "HP"),
    // Huawei (phones, tablets, routers, smart devices)
    ("00:18:82", "Huawei"),
    ("00:1e:10", "Huawei"),
    ("00:25:68", "Huawei"),
    ("00:25:9e", "Huawei"),
    ("00:46:4b", "Huawei"),
    ("00:e0:fc", "Huawei"),
    ("04:02:1f", "Huawei"),
    ("04:25:c5", "Huawei"),
    ("04:4a:6c", "Huawei"),
    ("04:b0:e7", "Huawei"),
    ("04:f9:38", "Huawei"),
    ("08:19:a6", "Huawei"),
    ("08:63:61", "Huawei"),
    ("0c:37:dc", "Huawei"),
    ("10:44:00", "Huawei"),
    ("10:47:80", "Huawei"),
    ("14:30:04", "Huawei"),
    ("14:b9:68", "Huawei"),
    ("18:de:d7", "Huawei"),
    ("1c:1d:67", "Huawei"),
    ("20:08:ed", "Huawei"),
    ("20:0b:c7", "Huawei"),
    ("24:09:95", "Huawei"),
    ("24:69:a5", "Huawei"),
    ("28:31:52", "Huawei"),
    ("28:6e:d4", "Huawei"),
    ("2c:55:d3", "Huawei"),
    ("30:74:96", "Huawei"),
    ("34:00:a3", "Huawei"),
    ("38:f8:89", "Huawei"),
    ("40:4d:8e", "Huawei"),
    ("44:55:b1", "Huawei"),
    ("48:00:31", "Huawei"),
    ("48:3c:0c", "Huawei"),
    ("4c:1f:cc", "Huawei"),
    ("4c:b1:6c", "Huawei"),
    ("50:01:6b", "Huawei"),
    ("54:25:ea", "Huawei"),
    ("58:2a:f7", "Huawei"),
    ("5c:7d:5e", "Huawei"),
    ("60:de:44", "Huawei"),
    ("64:16:f0", "Huawei"),
    ("68:a0:f6", "Huawei"),
    ("6c:b7:49", "Huawei"),
    ("70:72:3c", "Huawei"),
    ("70:8a:09", "Huawei"),
    ("74:88:2a", "Huawei"),
    ("78:f5:57", "Huawei"),
    ("7c:11:cb", "Huawei"),
    ("80:b6:86", "Huawei"),
    ("80:d0:9b", "Huawei"),
    ("84:5b:12", "Huawei"),
    ("88:28:b3", "Huawei"),
    ("88:53:d4", "Huawei"),
    ("8c:34:fd", "Huawei"),
    ("94:04:9c", "Huawei"),
    ("94:77:2b", "Huawei"),
    ("9c:28:ef", "Huawei"),
    ("a4:4b:d5", "Huawei"),
    ("a4:be:2b", "Huawei"),
    ("a8:ca:7b", "Huawei"),
    ("ac:4e:91", "Huawei"),
    ("ac:e8:7b", "Huawei"),
    ("b4:15:13", "Huawei"),
    ("b4:30:52", "Huawei"),
    ("bc:25:e0", "Huawei"),
    ("bc:76:70", "Huawei"),
    ("c0:70:09", "Huawei"),
    ("c4:07:2f", "Huawei"),
    ("c8:d1:5e", "Huawei"),
    ("cc:53:b5", "Huawei"),
    ("cc:a2:23", "Huawei"),
    ("d0:2d:b3", "Huawei"),
    ("d4:6a:a8", "Huawei"),
    ("d4:6e:5c", "Huawei"),
    ("d8:49:0b", "Huawei"),
    ("dc:d2:fc", "Huawei"),
    ("e0:19:1d", "Huawei"),
    ("e0:24:7f", "Huawei"),
    ("e4:68:a3", "Huawei"),
    ("e8:08:8b", "Huawei"),
    ("e8:cd:2d", "Huawei"),
    ("ec:23:3d", "Huawei"),
    ("f0:43:47", "Huawei"),
    ("f4:4c:7f", "Huawei"),
    ("f4:63:1f", "Huawei"),
    ("f8:01:13", "Huawei"),
    ("fc:48:ef", "Huawei"),
    // AzureWave Technology (WiFi/Bluetooth modules in laptops, tablets, etc.)
    ("2c:dc:d7", "AzureWave"),
    // Intel (WiFi/Ethernet adapters in laptops, desktops, etc.)
    ("4c:03:4f", "Intel"),
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
    // Texas Instruments (IoT chips, sensors, CC3xxx WiFi modules)
    ("28:ec:9a", "Texas Instruments"),
    // TP-Link/Kasa smart plugs
    ("50:c7:bf", "TP-Link"),
    ("60:32:b1", "TP-Link"),
    ("68:ff:7b", "TP-Link"),
    ("98:da:c4", "TP-Link"),
    ("b0:be:76", "TP-Link"),
    // Wemo (Belkin smart plugs)
    ("08:86:3b", "Belkin"),
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
    // Dyson (air purifiers, fans, vacuums)
    ("c8:ff:77", "Dyson"),
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
    // USI (Universal Global Scientific Industrial - ODM/contract manufacturer)
    ("e0:4f:43", "USI"),
    // Wisol (Korean IoT/RF modules - sensors, trackers)
    ("70:2c:1f", "Wisol"),
    // Espressif (ESP32/ESP8266 IoT WiFi modules - used in many smart devices)
    ("94:3c:c6", "Espressif"),
    ("24:62:ab", "Espressif"),
    ("30:ae:a4", "Espressif"),
    ("60:01:94", "Espressif"),
    ("84:cc:a8", "Espressif"),
    ("ac:67:b2", "Espressif"),
    ("cc:50:e3", "Espressif"),
    ("5c:cf:7f", "Espressif"),
    ("d8:bf:c0", "Espressif"),
    ("98:f4:ab", "Espressif"),
    ("a0:20:a6", "Espressif"),
    ("dc:4f:22", "Espressif"),
    ("48:3f:da", "Espressif"),
    ("c4:4f:33", "Espressif"),
    ("70:03:9f", "Espressif"),
    // LG Electronics (used for some smart appliances)
    ("00:1e:75", "LG Electronics"),
    ("10:68:3f", "LG Electronics"),
    ("20:3d:bd", "LG Electronics"),
    ("34:4d:f7", "LG Electronics"),
    ("40:b0:fa", "LG Electronics"),
    ("5c:f9:38", "LG Electronics"),
    ("64:99:5d", "LG Electronics"),
    ("74:a7:22", "LG Electronics"),
    ("88:c9:d0", "LG Electronics"),
    ("a8:16:d0", "LG Electronics"),
    ("c4:36:6c", "LG Electronics"),
    ("cc:2d:8c", "LG Electronics"),
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
    ("9c:da:a8", "Apple"),
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
    ("4c:c9:5e", "Samsung"),
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
    ("80:47:86", "Samsung"),
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
    ("cc:6e:a4", "Samsung"),
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
    // Samjin (SmartThings sensors, IoT devices for Samsung)
    ("28:6d:97", "Samjin"),
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
    "_roku._tcp",
    "_webos._tcp", // LG WebOS TVs
                   // Note: _raop._tcp removed - too generic (MacBooks, iPhones, HomePods advertise it)
                   // Note: _spotify-connect._tcp removed - too generic (phones, speakers, consoles all use it)
                   // Note: _airplay._tcp removed - too generic (iPhones, MacBooks also advertise it)
];
const PRINTER_SERVICES: &[&str] = &["_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp"];

const PHONE_SERVICES: &[&str] = &[
    "_apple-mobdev2._tcp",  // Apple mobile device service (iPhones/iPads)
    "_companion-link._tcp", // iOS companion link (AirDrop, Handoff)
    "_rdlink._tcp",         // Remote desktop link (iOS)
];

const APPLIANCE_SERVICES: &[&str] = &[
    "_lge._tcp",        // LG ThinQ appliances
    "_xbcs._tcp",       // LG ThinQ appliances (dishwashers, etc.)
    "_dyson_mqtt._tcp", // Dyson devices (fans, purifiers)
];

const SOUNDBAR_SERVICES: &[&str] = &[
    "_sonos._tcp", // Sonos speakers/soundbars
];

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
    if matches_pattern(hostname, TV_PATTERNS) || matches_prefix(hostname, TV_PREFIXES) {
        return true;
    }
    // Roku serial number as hostname (e.g., YN00NJ468680)
    let hostname_upper = hostname.to_uppercase();
    is_roku_serial_number(&hostname_upper)
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

/// Check if SSDP/UPnP model indicates a soundbar
fn is_soundbar_model(model: &str) -> bool {
    let model_lower = model.to_lowercase();
    SOUNDBAR_MODEL_PREFIXES
        .iter()
        .any(|prefix| model_lower.starts_with(prefix))
}

/// Check if a model name indicates a TV
fn is_tv_model(model: &str) -> bool {
    let model_lower = model.to_lowercase();
    let model_upper = model.to_uppercase();

    // Check for known TV model patterns
    // Samsung TV model patterns
    if model_upper.starts_with("QN")
        || model_upper.starts_with("UN")
        || model_upper.starts_with("UA")
    {
        // QN = QLED, UN/UA = LED TVs
        // e.g., QN43LS03TAFXZA (The Frame), UN55TU8000FXZA
        return true;
    }

    // Samsung Frame TVs (LS series)
    if model_upper.contains("LS03") || model_upper.contains("LS01") {
        return true;
    }

    // LG TV model patterns
    if model_upper.starts_with("OLED") || model_upper.starts_with("NANO") {
        return true;
    }

    // Sony Bravia
    if model_lower.contains("bravia")
        || model_upper.starts_with("XR")
        || model_upper.starts_with("KD-")
    {
        return true;
    }

    // Vizio
    if model_lower.contains("vizio") {
        return true;
    }

    // Roku TV platform identifiers (TCL, Hisense, etc. running Roku OS)
    // Format: 4 digits followed by optional X (e.g., 7105X, 7000X, 6500X, 3800X)
    // 7XXX series = TCL TVs, 6XXX = mid-range, 3XXX = budget models
    if is_roku_tv_model(&model_upper) {
        return true;
    }

    // Check for generic TV indicators in model name
    if model_lower.contains("the frame") || model_lower.contains("samsung tv") {
        return true;
    }

    false
}

/// Check if a string is a Roku serial number
/// Roku serial numbers follow the pattern: 2 letters + 2 digits + 2 letters + 6 digits (12 chars total)
/// Examples: YN00NJ468680, YK00KM123456
fn is_roku_serial_number(s: &str) -> bool {
    if s.len() != 12 {
        return false;
    }
    let chars: Vec<char> = s.chars().collect();
    // First 2 chars: letters
    chars[0].is_ascii_alphabetic()
        && chars[1].is_ascii_alphabetic()
        // Next 2 chars: digits
        && chars[2].is_ascii_digit()
        && chars[3].is_ascii_digit()
        // Next 2 chars: letters
        && chars[4].is_ascii_alphabetic()
        && chars[5].is_ascii_alphabetic()
        // Last 6 chars: digits
        && chars[6..12].iter().all(|c| c.is_ascii_digit())
}

/// Check if model is a Roku TV platform identifier
/// Roku TV models follow patterns like 7105X, 7000X, 6500X, 3800X
fn is_roku_tv_model(model: &str) -> bool {
    let model_upper = model.to_uppercase();
    // Pattern: 4 digits, optionally followed by X
    if model_upper.len() >= 4 && model_upper.len() <= 5 {
        let chars: Vec<char> = model_upper.chars().collect();
        // First 4 chars must be digits
        if chars[0..4].iter().all(|c| c.is_ascii_digit()) {
            // 5th char (if present) must be X
            if chars.len() == 4 || chars[4] == 'X' {
                // Roku TV models typically start with 3, 4, 5, 6, or 7
                let first_digit = chars[0];
                return matches!(first_digit, '3' | '4' | '5' | '6' | '7' | '8' | '9');
            }
        }
    }

    // Roku serial number format used as hostname (e.g., YN00NJ468680)
    // Pattern: 2 letters + 2 digits + 2 letters + 6 digits (12 chars total)
    if is_roku_serial_number(&model_upper) {
        return true;
    }
    false
}

/// Normalize a TV/device model number to a friendly name
/// e.g., "QN43LS03TAFXZA" -> "Samsung The Frame"
/// e.g., "OLED55C3PUA" -> "LG OLED C3"
/// e.g., "HW-MS750" -> "Samsung Soundbar"
pub fn normalize_model_name(model: &str, vendor: Option<&str>) -> Option<String> {
    let model_upper = model.to_uppercase();
    let model_lower = model.to_lowercase();

    // Check for soundbar models first
    if model_lower.starts_with("hw-") || model_lower.starts_with("spk-") {
        // Samsung soundbar - extract series
        // HW-MS750 -> Soundbar MS750
        // HW-Q990B -> Soundbar Q990B
        let series = if model_lower.starts_with("hw-") {
            &model_upper[3..]
        } else {
            &model_upper[4..]
        };
        return Some(format!("Samsung Soundbar {}", series));
    }
    if model_lower.starts_with("wam") {
        // Samsung Wireless Audio Multiroom
        return Some(format!("Samsung Wireless Speaker {}", &model_upper[3..]));
    }
    // LG soundbar models
    if (model_lower.starts_with("sl")
        || model_lower.starts_with("sn")
        || model_lower.starts_with("sp"))
        && model_lower
            .chars()
            .nth(2)
            .is_some_and(|c| c.is_ascii_digit())
    {
        return Some(format!("LG Soundbar {}", model_upper));
    }
    if model_lower.starts_with("sc9") {
        return Some(format!("LG Soundbar {}", model_upper));
    }
    // JBL soundbar
    if model_lower.starts_with("bar-") || model_lower.starts_with("bar ") {
        return Some(format!("JBL {}", model_upper));
    }

    // Determine vendor from model prefix or provided vendor
    let is_samsung = model_upper.starts_with("QN")
        || model_upper.starts_with("UN")
        || vendor.is_some_and(|v| v.to_lowercase().contains("samsung"));
    let is_lg = model_upper.starts_with("OLED")
        || model_upper.contains("NANO")
        || model_upper.contains("QNED")
        || vendor.is_some_and(|v| v.to_lowercase().contains("lg"));
    let is_sony = model_upper.starts_with("XR")
        || model_upper.starts_with("KD")
        || vendor.is_some_and(|v| v.to_lowercase().contains("sony"));

    // Samsung TV models
    if is_samsung {
        // Skip screen size digits to find series identifier
        // Format: [QN|UN][Size][Series][Variant]
        let series_part = if model_upper.starts_with("QN") || model_upper.starts_with("UN") {
            // Skip panel type (2 chars) and size (2-3 digits)
            let after_panel = &model_lower[2..];
            after_panel.trim_start_matches(|c: char| c.is_ascii_digit())
        } else {
            &model_lower[..]
        };

        for (pattern, name) in SAMSUNG_TV_SERIES {
            if series_part.starts_with(pattern) {
                return Some(format!("Samsung {}", name));
            }
        }
    }

    // LG TV models
    if is_lg {
        for (pattern, name) in LG_TV_SERIES {
            if model_lower.contains(pattern) {
                return Some(format!("LG {}", name));
            }
        }
    }

    // Sony TV models
    if is_sony {
        // Skip prefix like XR or KD and size
        let series_part = model_lower
            .trim_start_matches("xr")
            .trim_start_matches("kd")
            .trim_start_matches(|c: char| c.is_ascii_digit() || c == '-');

        for (pattern, name) in SONY_TV_SERIES {
            if series_part.starts_with(pattern) {
                return Some(format!("Sony {}", name));
            }
        }
    }

    // Roku TV platform identifiers (TCL, Hisense TVs running Roku OS)
    // Models like 7105X, 7000X, 6500X are typically TCL Roku TVs
    // Vendor is set separately to TCL, so just return "Roku TV" as model
    if is_roku_tv_model(&model_upper) {
        return Some("Roku TV".to_string());
    }

    None
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
    "Wisol",
    "Dyson",
];

// Gaming vendors that should be classified as gaming devices
const GAMING_VENDORS: &[&str] = &["Nintendo", "Sony"];

// TV/streaming vendors that should be classified as TV
const TV_VENDORS: &[&str] = &["Roku"];

// Services that indicate a Mac (desktop/laptop) vs mobile device
// Macs typically advertise file sharing services; iPhones/iPads don't
const MAC_DESKTOP_SERVICES: &[&str] = &[
    "_afpovertcp._tcp", // Apple Filing Protocol
    "_smb._tcp",        // SMB file sharing
    "_ssh._tcp",        // SSH access (typically enabled on Macs)
    "_sftp-ssh._tcp",   // SFTP
];

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
    // Roku serial number as hostname (e.g., YN00NJ468680) - typically TCL Roku TVs
    if is_roku_serial_number(&hostname.to_uppercase()) {
        return Some("TCL");
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

/// Get vendor name from model number patterns
/// This helps identify vendor when MAC OUI and hostname don't provide info
pub fn get_vendor_from_model(model: &str) -> Option<&'static str> {
    let model_upper = model.to_uppercase();
    let model_lower = model.to_lowercase();

    // Samsung TV models: QN/UN/UA prefix
    if model_upper.starts_with("QN")
        || model_upper.starts_with("UN")
        || model_upper.starts_with("UA")
    {
        return Some("Samsung");
    }

    // Samsung soundbars: HW- prefix
    if model_lower.starts_with("hw-") || model_lower.starts_with("spk-") {
        return Some("Samsung");
    }

    // LG TV models: OLED/NANO prefix
    if model_upper.starts_with("OLED") || model_upper.starts_with("NANO") {
        return Some("LG");
    }

    // LG soundbars: SL/SN/SP prefix (without dash)
    if model_lower.starts_with("sl")
        || model_lower.starts_with("sn")
        || model_lower.starts_with("sp")
    {
        // Make sure it's followed by a digit (to avoid false positives)
        if model.len() > 2
            && model
                .chars()
                .nth(2)
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        {
            return Some("LG");
        }
    }

    // Sony Bravia TVs: XR/KD- prefix
    if model_upper.starts_with("XR") || model_upper.starts_with("KD-") {
        return Some("Sony");
    }

    // Roku TV platform identifiers (TCL, Hisense TVs running Roku OS)
    // Models like 7105X, 7000X, 6500X are TCL Roku TVs
    if is_roku_tv_model(&model_upper) {
        return Some("TCL");
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

    // Roku serial number as hostname (e.g., YN00NJ468680) - typically TCL Roku TVs
    if is_roku_serial_number(&hostname.to_uppercase()) {
        return Some("Roku TV".to_string());
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

    // Samsung devices - comprehensive model detection
    if lower.contains("samsung") || lower.starts_with("galaxy") || lower.contains("sm-") {
        let parts: Vec<&str> = hostname.split(['-', '_', ' ', '.']).collect();

        // Samsung TVs: QN65Q80B, UN55NU8000, UA55AU8000
        for part in &parts {
            let upper = part.to_uppercase();
            if (upper.starts_with("QN") || upper.starts_with("UN") || upper.starts_with("UA"))
                && upper.len() >= 6
            {
                return Some(format!("Samsung TV {}", upper));
            }
        }

        // Galaxy phones by model number (SM-XXXX)
        for part in &parts {
            let upper = part.to_uppercase();
            if upper.starts_with("SM-") {
                // S series: SM-S9xx, SM-G9xx
                if upper.starts_with("SM-S9") || upper.starts_with("SM-S8") {
                    return Some(format!("Galaxy S{}", &upper[4..6]));
                }
                if upper.starts_with("SM-G99") {
                    return Some("Galaxy S21".to_string());
                }
                if upper.starts_with("SM-G98") {
                    return Some("Galaxy S20".to_string());
                }
                if upper.starts_with("SM-G97") {
                    return Some("Galaxy S10".to_string());
                }
                if upper.starts_with("SM-G96") {
                    return Some("Galaxy S9".to_string());
                }
                if upper.starts_with("SM-G95") {
                    return Some("Galaxy S8".to_string());
                }
                // A series: SM-A5xx, SM-A7xx
                if upper.starts_with("SM-A") {
                    let model_num = &upper[4..6];
                    return Some(format!("Galaxy A{}", model_num));
                }
                // Z Fold: SM-F9xx
                if upper.starts_with("SM-F9") {
                    return Some("Galaxy Z Fold".to_string());
                }
                // Z Flip: SM-F7xx
                if upper.starts_with("SM-F7") {
                    return Some("Galaxy Z Flip".to_string());
                }
                // Note series: SM-N9xx
                if upper.starts_with("SM-N9") {
                    return Some("Galaxy Note".to_string());
                }
                // Tab series: SM-T, SM-X
                if upper.starts_with("SM-T") || upper.starts_with("SM-X") {
                    return Some("Galaxy Tab".to_string());
                }
                return Some(format!("Galaxy ({})", upper));
            }
        }

        // Galaxy phones by name pattern
        if lower.contains("galaxy") {
            // S series
            if lower.contains("s24") {
                return Some("Galaxy S24".to_string());
            }
            if lower.contains("s23") {
                return Some("Galaxy S23".to_string());
            }
            if lower.contains("s22") {
                return Some("Galaxy S22".to_string());
            }
            if lower.contains("s21") {
                return Some("Galaxy S21".to_string());
            }
            if lower.contains("s20") {
                return Some("Galaxy S20".to_string());
            }
            if lower.contains("s10") {
                return Some("Galaxy S10".to_string());
            }
            // A series
            if lower.contains("a54") {
                return Some("Galaxy A54".to_string());
            }
            if lower.contains("a53") {
                return Some("Galaxy A53".to_string());
            }
            if lower.contains("a52") {
                return Some("Galaxy A52".to_string());
            }
            if lower.contains("a34") {
                return Some("Galaxy A34".to_string());
            }
            if lower.contains("a14") {
                return Some("Galaxy A14".to_string());
            }
            // Z series
            if lower.contains("z-fold") || lower.contains("zfold") || lower.contains("fold") {
                return Some("Galaxy Z Fold".to_string());
            }
            if lower.contains("z-flip") || lower.contains("zflip") || lower.contains("flip") {
                return Some("Galaxy Z Flip".to_string());
            }
            // Note
            if lower.contains("note") {
                return Some("Galaxy Note".to_string());
            }
            // Tab
            if lower.contains("tab") {
                if lower.contains("s9") {
                    return Some("Galaxy Tab S9".to_string());
                }
                if lower.contains("s8") {
                    return Some("Galaxy Tab S8".to_string());
                }
                if lower.contains("s7") {
                    return Some("Galaxy Tab S7".to_string());
                }
                if lower.contains("s6") {
                    return Some("Galaxy Tab S6".to_string());
                }
                return Some("Galaxy Tab".to_string());
            }
            // Watch
            if lower.contains("watch") {
                if lower.contains("ultra") {
                    return Some("Galaxy Watch Ultra".to_string());
                }
                if lower.contains("6") {
                    return Some("Galaxy Watch 6".to_string());
                }
                if lower.contains("5") {
                    return Some("Galaxy Watch 5".to_string());
                }
                if lower.contains("4") {
                    return Some("Galaxy Watch 4".to_string());
                }
                return Some("Galaxy Watch".to_string());
            }
            // Buds
            if lower.contains("buds") {
                if lower.contains("pro") {
                    return Some("Galaxy Buds Pro".to_string());
                }
                if lower.contains("live") {
                    return Some("Galaxy Buds Live".to_string());
                }
                if lower.contains("fe") {
                    return Some("Galaxy Buds FE".to_string());
                }
                if lower.contains("2") {
                    return Some("Galaxy Buds 2".to_string());
                }
                return Some("Galaxy Buds".to_string());
            }
            return Some("Galaxy".to_string());
        }

        // Samsung soundbars: HW-Q990C, HW-S800B
        for part in &parts {
            let upper = part.to_uppercase();
            if upper.starts_with("HW-") || upper.starts_with("HW") && upper.len() >= 6 {
                return Some(format!("Soundbar {}", upper));
            }
        }

        // SmartThings
        if lower.contains("smartthings") {
            if lower.contains("hub") {
                return Some("SmartThings Hub".to_string());
            }
            if lower.contains("station") {
                return Some("SmartThings Station".to_string());
            }
            return Some("SmartThings".to_string());
        }

        // Samsung appliances
        if lower.contains("fridge") || lower.contains("refrigerator") || lower.starts_with("rf") {
            return Some("Samsung Refrigerator".to_string());
        }
        if lower.contains("washer") || lower.starts_with("wf") || lower.starts_with("ww") {
            return Some("Samsung Washer".to_string());
        }
        if lower.contains("dryer") || lower.starts_with("dv") {
            return Some("Samsung Dryer".to_string());
        }
        if lower.contains("dishwasher") || lower.starts_with("dw") {
            return Some("Samsung Dishwasher".to_string());
        }
        if lower.contains("oven") || lower.contains("range") {
            return Some("Samsung Oven".to_string());
        }
        if lower.contains("vacuum") || lower.contains("jet") {
            return Some("Samsung Jet".to_string());
        }
    }

    // Huawei devices - phones, tablets, routers
    if lower.contains("huawei") || lower.starts_with("honor") || lower.contains("harmonyos") {
        let parts: Vec<&str> = hostname.split(['-', '_', ' ', '.']).collect();

        // Huawei phones: P40, P30, Mate 40, Mate 30, Nova, etc.
        for part in &parts {
            let upper = part.to_uppercase();
            // P series: P40, P30, P20
            if upper.starts_with("P")
                && upper.len() >= 2
                && upper.chars().skip(1).all(|c| c.is_ascii_digit())
            {
                return Some(format!("Huawei {}", upper));
            }
            // Mate series: MATE40, MATE30
            if upper.starts_with("MATE") && upper.len() >= 5 {
                return Some(format!("Huawei {}", upper));
            }
            // Nova series
            if upper.starts_with("NOVA") {
                return Some(format!("Huawei {}", upper));
            }
        }

        // Honor devices
        if lower.contains("honor") {
            for part in &parts {
                let upper = part.to_uppercase();
                // Honor number series: Honor 50, Honor 70, etc.
                if upper.chars().all(|c| c.is_ascii_digit()) && !upper.is_empty() {
                    return Some(format!("Honor {}", upper));
                }
                // Honor X series
                if upper.starts_with("X") && upper.len() >= 2 {
                    return Some(format!("Honor {}", upper));
                }
            }
            return Some("Honor Phone".to_string());
        }

        // MatePad tablets
        if lower.contains("matepad") {
            return Some("MatePad".to_string());
        }

        // HarmonyOS devices
        if lower.contains("harmonyos") {
            return Some("Huawei HarmonyOS Device".to_string());
        }

        return Some("Huawei Device".to_string());
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

    // Amazon Fire TV and Kindle
    if lower.contains("fire") {
        if lower.contains("tv") || lower.contains("stick") {
            if lower.contains("4k") {
                return Some("Fire TV Stick 4K".to_string());
            }
            if lower.contains("max") {
                return Some("Fire TV Stick 4K Max".to_string());
            }
            if lower.contains("lite") {
                return Some("Fire TV Stick Lite".to_string());
            }
            if lower.contains("cube") {
                return Some("Fire TV Cube".to_string());
            }
            return Some("Fire TV Stick".to_string());
        }
        if lower.contains("kindle") || lower.contains("hd") {
            return Some("Fire Tablet".to_string());
        }
    }
    if lower.contains("kindle") {
        if lower.contains("paperwhite") {
            return Some("Kindle Paperwhite".to_string());
        }
        if lower.contains("oasis") {
            return Some("Kindle Oasis".to_string());
        }
        return Some("Kindle".to_string());
    }

    // TP-Link/Tapo devices
    if lower.contains("tapo") {
        if lower.contains("c200") || lower.contains("c210") || lower.contains("c220") {
            let parts: Vec<&str> = lower.split(['-', '_']).collect();
            for part in &parts {
                if part.starts_with("c2") || part.starts_with("c3") || part.starts_with("c4") {
                    return Some(format!("Tapo {}", part.to_uppercase()));
                }
            }
            return Some("Tapo Camera".to_string());
        }
        if lower.contains("p100") || lower.contains("p110") || lower.contains("p105") {
            return Some("Tapo Smart Plug".to_string());
        }
        if lower.contains("l530") || lower.contains("l510") || lower.contains("l900") {
            return Some("Tapo Smart Bulb".to_string());
        }
        return Some("Tapo Device".to_string());
    }
    if lower.contains("kasa")
        || lower.contains("hs100")
        || lower.contains("hs110")
        || lower.contains("hs200")
    {
        return Some("Kasa Smart Plug".to_string());
    }
    if lower.contains("deco") {
        return Some("TP-Link Deco".to_string());
    }
    if lower.contains("archer") {
        return Some("TP-Link Archer".to_string());
    }

    // Wyze devices
    if lower.contains("wyze") {
        if lower.contains("cam") {
            if lower.contains("v3") {
                return Some("Wyze Cam v3".to_string());
            }
            if lower.contains("pan") {
                return Some("Wyze Cam Pan".to_string());
            }
            if lower.contains("outdoor") {
                return Some("Wyze Cam Outdoor".to_string());
            }
            return Some("Wyze Cam".to_string());
        }
        if lower.contains("plug") {
            return Some("Wyze Plug".to_string());
        }
        if lower.contains("bulb") {
            return Some("Wyze Bulb".to_string());
        }
        if lower.contains("lock") {
            return Some("Wyze Lock".to_string());
        }
        if lower.contains("vacuum") {
            return Some("Wyze Robot Vacuum".to_string());
        }
    }

    // iRobot Roomba
    if lower.contains("roomba") || lower.contains("irobot") {
        // Try to extract model number (e.g., Roomba-i7, Roomba-s9)
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in &parts {
            let p = part.to_lowercase();
            if (p.starts_with('i')
                || p.starts_with('s')
                || p.starts_with('j')
                || p.starts_with('e'))
                && p.len() >= 2
                && p.chars()
                    .nth(1)
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
            {
                return Some(format!("Roomba {}", part.to_uppercase()));
            }
            // Numeric models like 675, 960
            if p.chars().all(|c| c.is_ascii_digit()) && p.len() == 3 {
                return Some(format!("Roomba {}", part));
            }
        }
        return Some("Roomba".to_string());
    }

    // Philips Hue
    if lower.contains("hue") || lower.contains("philips") {
        if lower.contains("bridge") {
            return Some("Hue Bridge".to_string());
        }
        if lower.contains("bulb") || lower.contains("lamp") || lower.contains("light") {
            return Some("Hue Light".to_string());
        }
        if lower.contains("play") {
            return Some("Hue Play".to_string());
        }
        if lower.contains("strip") || lower.contains("lightstrip") {
            return Some("Hue Lightstrip".to_string());
        }
        if lower.contains("bloom") {
            return Some("Hue Bloom".to_string());
        }
        if lower.contains("go") {
            return Some("Hue Go".to_string());
        }
    }

    // Ecobee thermostats
    if lower.contains("ecobee") {
        if lower.contains("lite") {
            return Some("Ecobee Lite".to_string());
        }
        if lower.contains("smart") || lower.contains("premium") {
            return Some("Ecobee Smart Thermostat".to_string());
        }
        if lower.contains("sensor") {
            return Some("Ecobee Sensor".to_string());
        }
        return Some("Ecobee Thermostat".to_string());
    }

    // Canon printers
    if lower.contains("canon") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in &parts {
            let upper = part.to_uppercase();
            if upper.starts_with("MX")
                || upper.starts_with("MG")
                || upper.starts_with("TS")
                || upper.starts_with("TR")
                || upper.starts_with("PIXMA")
            {
                return Some(upper);
            }
        }
    }

    // Epson printers
    if lower.contains("epson") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in &parts {
            let upper = part.to_uppercase();
            if upper.starts_with("ET")
                || upper.starts_with("WF")
                || upper.starts_with("XP")
                || upper.starts_with("L")
                || upper.contains("ECOTANK")
                || upper.contains("WORKFORCE")
            {
                return Some(upper);
            }
        }
    }

    // Brother printers
    if lower.contains("brother") {
        let parts: Vec<&str> = hostname.split(['-', '_']).collect();
        for part in &parts {
            let upper = part.to_uppercase();
            if upper.starts_with("HL") || upper.starts_with("MFC") || upper.starts_with("DCP") {
                return Some(upper);
            }
        }
    }

    // Nintendo Switch
    if lower.contains("switch") && (lower.contains("nintendo") || lower.starts_with("switch")) {
        if lower.contains("lite") {
            return Some("Switch Lite".to_string());
        }
        if lower.contains("oled") {
            return Some("Switch OLED".to_string());
        }
        return Some("Nintendo Switch".to_string());
    }
    if lower.starts_with("nintendo") || lower.contains("nx-") {
        return Some("Nintendo Switch".to_string());
    }

    // eero mesh routers
    if lower.contains("eero") {
        if lower.contains("pro") {
            return Some("eero Pro".to_string());
        }
        if lower.contains("beacon") {
            return Some("eero Beacon".to_string());
        }
        return Some("eero".to_string());
    }

    // Apple Watch
    if lower.contains("apple-watch") || lower.contains("applewatch") {
        if lower.contains("ultra") {
            return Some("Apple Watch Ultra".to_string());
        }
        if lower.contains("se") {
            return Some("Apple Watch SE".to_string());
        }
        // Try to extract series number
        for i in 1..=10 {
            if lower.contains(&format!("series{}", i)) || lower.contains(&format!("series-{}", i)) {
                return Some(format!("Apple Watch Series {}", i));
            }
        }
        return Some("Apple Watch".to_string());
    }

    // HomePod
    if lower.contains("homepod") {
        if lower.contains("mini") {
            return Some("HomePod mini".to_string());
        }
        return Some("HomePod".to_string());
    }

    // Apple TV
    if lower.contains("apple-tv") || lower.contains("appletv") {
        if lower.contains("4k") {
            return Some("Apple TV 4K".to_string());
        }
        return Some("Apple TV".to_string());
    }

    // Belkin/Wemo smart devices
    if lower.contains("wemo") {
        if lower.contains("mini") {
            return Some("Wemo Mini".to_string());
        }
        if lower.contains("insight") {
            return Some("Wemo Insight".to_string());
        }
        if lower.contains("switch") || lower.contains("plug") {
            return Some("Wemo Smart Plug".to_string());
        }
        if lower.contains("dimmer") {
            return Some("Wemo Dimmer".to_string());
        }
    }

    // Tuya/Smart Life generic devices
    if lower.contains("tuya") || lower.contains("smartlife") || lower.contains("smart-life") {
        if lower.contains("plug") {
            return Some("Smart Plug".to_string());
        }
        if lower.contains("bulb") || lower.contains("light") {
            return Some("Smart Bulb".to_string());
        }
        if lower.contains("cam") {
            return Some("Smart Camera".to_string());
        }
    }

    None
}

/// Infer model from MAC vendor with additional context about discovery
/// This allows more specific model identification based on what protocols found (or didn't find) the device
pub fn infer_model_with_context(
    mac: &str,
    has_ssdp: bool,
    has_mdns: bool,
    has_open_ports: bool,
    open_ports: &[u16],
) -> Option<String> {
    let vendor = get_mac_vendor(mac)?;

    match vendor {
        "Amazon" => {
            // Fire TV: typically has ADB port 5555 when developer mode enabled, or port 8008/8443
            if open_ports.contains(&5555) {
                return Some("Amazon Fire TV".to_string());
            }
            if open_ports.contains(&8008) || open_ports.contains(&8443) {
                return Some("Amazon Fire TV".to_string());
            }
            // Ring devices: usually have SSDP or mDNS
            if has_ssdp || has_mdns {
                // Could be Ring, Fire TV, or other
                return Some("Amazon Device".to_string());
            }
            // Amazon MAC + no SSDP + no mDNS + no open ports = likely Echo
            // Echo devices communicate only with Amazon cloud, no local services
            if !has_ssdp && !has_mdns && !has_open_ports {
                return Some("Amazon Echo".to_string());
            }
            Some("Amazon Device".to_string())
        }
        "Ring" => Some("Ring Device".to_string()),
        "Google" | "Nest" => {
            // Chromecast has port 8008/8443
            if open_ports.contains(&8008) || open_ports.contains(&8443) {
                return Some("Chromecast".to_string());
            }
            // Google Home/Nest speakers respond to mDNS _googlecast
            if has_mdns {
                return Some("Google/Nest Speaker".to_string());
            }
            Some("Google Device".to_string())
        }
        _ => None,
    }
}

/// Infer model from MAC vendor when hostname detection fails
pub fn get_model_from_mac(mac: &str) -> Option<String> {
    let vendor = get_mac_vendor(mac)?;

    match vendor {
        "Nintendo" => Some("Nintendo Switch".to_string()),
        "Sony" => Some("PlayStation".to_string()),
        "Samsung" => Some("Samsung Device".to_string()),
        "LG" => Some("LG Device".to_string()),
        "Apple" => Some("Apple Device".to_string()),
        "Google" => Some("Google Device".to_string()),
        "Amazon" => Some("Amazon Device".to_string()),
        "Microsoft" => Some("Xbox".to_string()),
        "HP" => Some("HP Device".to_string()),
        "iRobot" => Some("Roomba".to_string()),
        "Ecobee" => Some("Ecobee Thermostat".to_string()),
        "Ring" => Some("Ring Device".to_string()),
        "Sonos" => Some("Sonos Speaker".to_string()),
        "Roku" => Some("Roku".to_string()),
        "Philips Hue" => Some("Hue Device".to_string()),
        "Wyze" => Some("Wyze Device".to_string()),
        "eero" => Some("eero Router".to_string()),
        "Nest" => Some("Nest Device".to_string()),
        "TP-Link" => Some("TP-Link Device".to_string()),
        "Ubiquiti" => Some("Ubiquiti Device".to_string()),
        "Vizio" => Some("Vizio TV".to_string()),
        "TCL" => Some("TCL TV".to_string()),
        "Hisense" => Some("Hisense TV".to_string()),
        "Texas Instruments" => Some("TI IoT Device".to_string()),
        "Samjin" => Some("SmartThings Sensor".to_string()),
        _ => None,
    }
}

/// Get a more specific model using both vendor and device classification
/// Called after device type classification is complete for better accuracy
pub fn get_model_from_vendor_and_type(vendor: &str, device_type: &str) -> Option<String> {
    match (vendor, device_type) {
        // Samsung by device type
        ("Samsung", "tv") => Some("Samsung Smart TV".to_string()),
        ("Samsung", "phone") => Some("Samsung Galaxy".to_string()),
        ("Samsung", "appliance") => Some("Samsung Appliance".to_string()),
        ("Samsung", "soundbar") => Some("Samsung Soundbar".to_string()),
        ("Samsung", _) => Some("Samsung Device".to_string()),

        // LG by device type
        ("LG", "tv") => Some("LG Smart TV".to_string()),
        ("LG", "phone") => Some("LG Phone".to_string()),
        ("LG", "appliance") => Some("LG ThinQ Appliance".to_string()),
        ("LG", "soundbar") => Some("LG Soundbar".to_string()),
        ("LG", _) => Some("LG Device".to_string()),

        // Sony by device type
        ("Sony", "tv") => Some("Sony Bravia TV".to_string()),
        ("Sony", "gaming") => Some("PlayStation".to_string()),
        ("Sony", "soundbar") => Some("Sony Soundbar".to_string()),
        ("Sony", _) => Some("Sony Device".to_string()),

        // Apple by device type
        ("Apple", "phone") => Some("iPhone".to_string()),
        ("Apple", "tv") => Some("Apple TV".to_string()),
        ("Apple", "local") => Some("Mac".to_string()),
        ("Apple", _) => Some("Apple Device".to_string()),

        // Microsoft by device type
        ("Microsoft", "gaming") => Some("Xbox".to_string()),
        ("Microsoft", _) => Some("Microsoft Device".to_string()),

        // Nintendo
        ("Nintendo", "gaming") => Some("Nintendo Switch".to_string()),
        ("Nintendo", _) => Some("Nintendo Device".to_string()),

        // Google by device type
        ("Google", "tv") => Some("Chromecast".to_string()),
        ("Google", "phone") => Some("Google Pixel".to_string()),
        ("Google", _) => Some("Google Device".to_string()),

        // Huawei by device type
        ("Huawei", "phone") => Some("Huawei Phone".to_string()),
        ("Huawei", "gateway") => Some("Huawei Router".to_string()),
        ("Huawei", "tv") => Some("Huawei Smart Screen".to_string()),
        ("Huawei", _) => Some("Huawei Device".to_string()),

        // Amazon by device type
        ("Amazon", "tv") => Some("Fire TV".to_string()),
        ("Amazon", _) => Some("Amazon Device".to_string()),

        // HP by device type
        ("HP", "printer") => Some("HP Printer".to_string()),
        ("HP", "local") => Some("HP Computer".to_string()),
        ("HP", _) => Some("HP Device".to_string()),

        // Belkin/WeMo by device type
        ("Belkin", "appliance") => Some("WeMo Smart Plug".to_string()),
        ("Belkin", "gateway") => Some("Belkin Router".to_string()),
        ("Belkin", _) => Some("WeMo Device".to_string()),

        // Wisol IoT devices (sensors, trackers)
        ("Wisol", "appliance") => Some("Wisol Sensor".to_string()),
        ("Wisol", _) => Some("Wisol IoT Device".to_string()),

        // USI (contract manufacturer - could be many things)
        ("USI", "phone") => Some("USI Mobile Device".to_string()),
        ("USI", "appliance") => Some("USI IoT Device".to_string()),
        ("USI", _) => Some("USI Device".to_string()),

        // Other vendors
        ("Roku", _) => Some("Roku".to_string()),
        ("Sonos", _) => Some("Sonos Speaker".to_string()),
        ("iRobot", _) => Some("Roomba".to_string()),
        ("Ecobee", _) => Some("Ecobee Thermostat".to_string()),
        ("Ring", _) => Some("Ring Device".to_string()),
        ("Philips Hue", _) => Some("Hue Device".to_string()),
        ("Wyze", _) => Some("Wyze Device".to_string()),
        ("eero", "gateway") => Some("eero Router".to_string()),
        ("eero", _) => Some("eero".to_string()),
        ("Nest", _) => Some("Nest Device".to_string()),
        ("Vizio", _) => Some("Vizio TV".to_string()),
        ("TCL", _) => Some("TCL TV".to_string()),
        ("Hisense", _) => Some("Hisense TV".to_string()),
        ("TP-Link", "appliance") => Some("Kasa Smart Plug".to_string()),
        ("TP-Link", "gateway") => Some("TP-Link Router".to_string()),
        ("TP-Link", _) => Some("TP-Link Device".to_string()),
        ("Tuya", _) => Some("Tuya Smart Device".to_string()),
        ("Dyson", _) => Some("Dyson Air Purifier".to_string()),

        _ => None,
    }
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

/// Check if any MAC address is from Apple
fn is_apple_mac(macs: &[String]) -> bool {
    macs.iter()
        .any(|mac| get_mac_vendor(mac).is_some_and(|v| v == "Apple"))
}

/// Check if device is likely a phone based on MAC and services
/// Apple devices that don't advertise file sharing services are likely iPhones/iPads
/// Check if hostname indicates a Mac computer (not a phone)
fn is_mac_computer_hostname(hostname: &str) -> bool {
    let mac_patterns = [
        "macbook",
        "mac-book",
        "imac",
        "i-mac",
        "mac-mini",
        "macmini",
        "mac-pro",
        "macpro",
        "mac-studio",
        "macstudio",
    ];
    mac_patterns.iter().any(|p| hostname.contains(p))
}

fn is_phone_mac(macs: &[String], ips: &[String], hostname: Option<&str>) -> bool {
    // Only applies to Apple devices (iPhones/iPads)
    if !is_apple_mac(macs) {
        return false;
    }

    // Never classify Mac computers as phones based on hostname
    if let Some(h) = hostname {
        let lower = h.to_lowercase();
        if is_mac_computer_hostname(&lower) {
            return false;
        }
    }

    // Check if device advertises any desktop/Mac services
    for ip_str in ips {
        let services = crate::network::mdns_lookup::MDnsLookup::get_services(ip_str);
        for service in &services {
            if MAC_DESKTOP_SERVICES.contains(&service.as_str()) {
                // This is a Mac (desktop), not a phone
                return false;
            }
        }
    }

    // Apple device without desktop services = likely iPhone/iPad
    true
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
fn classify_by_services(services: &[String], hostname: Option<&str>) -> Option<&'static str> {
    for service in services {
        let s = service.as_str();
        // Check more specific types first
        if APPLIANCE_SERVICES.contains(&s) {
            return Some(CLASSIFICATION_APPLIANCE);
        }
        // Skip phone classification for Mac computers (they also advertise _companion-link._tcp)
        if PHONE_SERVICES.contains(&s) {
            if let Some(h) = hostname
                && is_mac_computer_hostname(h)
            {
                continue;
            }
            return Some(CLASSIFICATION_PHONE);
        }
        if SOUNDBAR_SERVICES.contains(&s) {
            return Some(CLASSIFICATION_SOUNDBAR);
        }
        if PRINTER_SERVICES.contains(&s) {
            return Some(CLASSIFICATION_PRINTER);
        }
        if TV_SERVICES.contains(&s) {
            return Some(CLASSIFICATION_TV);
        }
    }
    None
}

/// Classify by port number
fn classify_by_port(port: u16) -> Option<&'static str> {
    match port {
        // Printer ports
        9100 | 631 | 515 => Some(CLASSIFICATION_PRINTER),
        // Gaming console ports (check BEFORE TV ports)
        9295..=9297 => Some(CLASSIFICATION_GAMING), // PlayStation Remote Play
        3478..=3480 => Some(CLASSIFICATION_GAMING), // PlayStation Network
        3074 => Some(CLASSIFICATION_GAMING),        // Xbox Live
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

/// Check if a MAC address is locally administered (randomized/private)
/// Locally administered addresses have the second-least-significant bit of the first octet set to 1
/// This means the second hex digit of the first octet is 2, 6, A, or E
pub fn is_locally_administered_mac(mac: &str) -> bool {
    let mac_lower = mac.to_lowercase();
    // Get the second character of the MAC (after potential delimiter handling)
    let chars: Vec<char> = mac_lower
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if chars.len() < 2 {
        return false;
    }
    // The second hex digit determines if it's locally administered
    // 2, 6, A, E have the second-least-significant bit set
    matches!(chars[1], '2' | '6' | 'a' | 'e')
}

/// Check if an IP address is an IPv6 link-local address (fe80::)
pub fn is_ipv6_link_local(ip: &str) -> bool {
    use std::net::Ipv6Addr;
    if let Ok(addr) = ip.parse::<Ipv6Addr>() {
        // Link-local addresses start with fe80::/10
        let segments = addr.segments();
        (segments[0] & 0xffc0) == 0xfe80
    } else {
        false
    }
}

/// Extract MAC address from IPv6 EUI-64 interface identifier
/// Works with link-local (fe80::) and other IPv6 addresses that use EUI-64 format
/// The EUI-64 format inserts ff:fe in the middle of the MAC and flips the 7th bit
/// Example: fe80::d48f:2ff:fefb:b5 -> d6:8f:02:fb:00:b5
pub fn extract_mac_from_ipv6_eui64(ip: &str) -> Option<String> {
    use std::net::Ipv6Addr;

    let addr: Ipv6Addr = ip.parse().ok()?;
    let segments = addr.segments();

    // Interface identifier is the last 4 segments (64 bits)
    // EUI-64 format has ff:fe in the middle (bytes 3-4 of the interface ID)
    // segments[4]:segments[5]:segments[6]:segments[7]
    // In bytes: [4h][4l]:[5h][5l]:[6h][6l]:[7h][7l]
    // EUI-64:   [mac0][mac1]:[mac2][ff]:[fe][mac3]:[mac4][mac5]

    let seg5 = segments[5];
    let seg6 = segments[6];

    // Check for ff:fe pattern: low byte of seg5 should be 0xff, high byte of seg6 should be 0xfe
    let byte3 = (seg5 & 0x00ff) as u8; // Low byte of segments[5]
    let byte4 = (seg6 >> 8) as u8; // High byte of segments[6]

    if byte3 != 0xff || byte4 != 0xfe {
        return None; // Not EUI-64 format
    }

    // Extract MAC bytes
    let mac0 = (segments[4] >> 8) as u8;
    let mac1 = (segments[4] & 0x00ff) as u8;
    let mac2 = (seg5 >> 8) as u8;
    // bytes 3-4 are ff:fe, skip them
    let mac3 = (seg6 & 0x00ff) as u8;
    let mac4 = (segments[7] >> 8) as u8;
    let mac5 = (segments[7] & 0x00ff) as u8;

    // Flip the 7th bit (Universal/Local bit) of the first byte
    let mac0_flipped = mac0 ^ 0x02;

    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac0_flipped, mac1, mac2, mac3, mac4, mac5
    ))
}

#[derive(Debug)]
pub enum InsertEndpointError {
    BothMacAndIpNone,
    LocallyAdministeredMac,
    ConstraintViolation,
    /// IP is an internet destination - recorded in internet_destinations table instead
    InternetDestination,
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

/// Represents an internet destination (external host) tracked separately from local endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternetDestination {
    pub id: i64,
    pub hostname: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub packet_count: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
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
        if let Some(ref hostname_str) = hostname {
            if Self::is_router_hostname(hostname_str) {
                return Some(CLASSIFICATION_GATEWAY);
            }

            // Check if hostname looks like an internet domain (has TLD, not local)
            if Self::is_internet_hostname(hostname_str) {
                return Some(CLASSIFICATION_INTERNET);
            }
        }

        // Local network device, no special classification
        None
    }

    /// Check if hostname looks like an internet domain
    fn is_internet_hostname(hostname: &str) -> bool {
        // Skip if it looks like an IP address
        if hostname.contains(':') || hostname.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return false;
        }
        // Skip local hostnames
        let lower = hostname.to_lowercase();
        if lower.ends_with(".local")
            || lower.ends_with(".lan")
            || lower.ends_with(".home")
            || lower.ends_with(".internal")
            || !lower.contains('.')
        {
            return false;
        }
        // Has a dot and a TLD-like suffix - likely internet
        true
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
        ips: &[String],
        ports: &[u16],
        macs: &[String],
        model: Option<&str>,
    ) -> Option<&'static str> {
        // Pre-compute lowercase hostname once
        let lower_hostname = hostname.map(|h| h.to_lowercase());
        let lower = lower_hostname.as_deref();

        // Check SSDP/UPnP model first - most reliable for identifying device type
        if let Some(m) = model
            && is_soundbar_model(m)
        {
            return Some(CLASSIFICATION_SOUNDBAR);
        }

        // Check for TV models (Samsung Frame, QLED, LG OLED, etc.)
        if let Some(m) = model
            && is_tv_model(m)
        {
            return Some(CLASSIFICATION_TV);
        }

        // Check for LG ThinQ appliances FIRST (they advertise AirPlay but aren't TVs)
        if let Some(h) = lower
            && is_lg_appliance(h)
        {
            return Some(CLASSIFICATION_APPLIANCE);
        }

        // Check hostname patterns FIRST - most reliable for user devices
        // This prevents mDNS services from misclassifying computers/phones as TVs
        if let Some(h) = lower {
            // Order matters: check more specific patterns first
            if is_printer_hostname(h) {
                return Some(CLASSIFICATION_PRINTER);
            }
            if is_phone_hostname(h) {
                return Some(CLASSIFICATION_PHONE);
            }
            if is_gaming_hostname(h) {
                return Some(CLASSIFICATION_GAMING);
            }
            if is_tv_hostname(h) {
                return Some(CLASSIFICATION_TV);
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

        // Check mDNS service advertisements for ALL IPs
        // This catches smart devices that don't have distinctive hostnames
        for ip_str in ips {
            let services = crate::network::mdns_lookup::MDnsLookup::get_services(ip_str);
            if let Some(classification) = classify_by_services(&services, lower) {
                return Some(classification);
            }
        }

        // MAC-based detection (identifies devices by vendor OUI)
        // Check phone first - Apple devices without desktop services are likely iPhones/iPads
        if is_phone_mac(macs, ips, lower) {
            return Some(CLASSIFICATION_PHONE);
        }
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
        // Migration: Add custom_name column if it doesn't exist
        let has_custom_name_column: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'custom_name'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_custom_name_column {
            conn.execute("ALTER TABLE endpoints ADD COLUMN custom_name TEXT", [])?;
        }

        // Migration: Add ssdp_model column for UPnP model name
        let has_ssdp_model: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'ssdp_model'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_ssdp_model {
            conn.execute("ALTER TABLE endpoints ADD COLUMN ssdp_model TEXT", [])?;
        }

        // Migration: Add ssdp_friendly_name column for UPnP friendly name
        let has_ssdp_friendly_name: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'ssdp_friendly_name'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_ssdp_friendly_name {
            conn.execute(
                "ALTER TABLE endpoints ADD COLUMN ssdp_friendly_name TEXT",
                [],
            )?;
        }

        // Migration: Add custom_model column for manual model override
        let has_custom_model: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'custom_model'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_custom_model {
            conn.execute("ALTER TABLE endpoints ADD COLUMN custom_model TEXT", [])?;
        }

        // Migration: Add custom_vendor column for manual vendor override
        let has_custom_vendor: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'custom_vendor'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_custom_vendor {
            conn.execute("ALTER TABLE endpoints ADD COLUMN custom_vendor TEXT", [])?;
        }

        // Migration: Add auto_device_type column for persisting auto-detected device type
        let has_auto_device_type: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'auto_device_type'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_auto_device_type {
            conn.execute("ALTER TABLE endpoints ADD COLUMN auto_device_type TEXT", [])?;
        }

        // Migration: Add netbios_name column for NetBIOS discovered names
        let has_netbios_name: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('endpoints') WHERE name = 'netbios_name'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        if !has_netbios_name {
            conn.execute("ALTER TABLE endpoints ADD COLUMN netbios_name TEXT", [])?;
        }

        // Create internet_destinations table for tracking external hosts
        conn.execute(
            "CREATE TABLE IF NOT EXISTS internet_destinations (
                id INTEGER PRIMARY KEY,
                hostname TEXT NOT NULL UNIQUE,
                first_seen_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                packet_count INTEGER DEFAULT 1,
                bytes_in INTEGER DEFAULT 0,
                bytes_out INTEGER DEFAULT 0
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_internet_destinations_hostname ON internet_destinations (hostname);",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_internet_destinations_last_seen ON internet_destinations (last_seen_at);",
            [],
        )?;

        Ok(())
    }

    /// Insert or update an internet destination (external host)
    /// This is called when traffic is detected to/from a non-local IP
    pub fn insert_or_update_internet_destination(
        conn: &Connection,
        hostname: &str,
        bytes: i64,
        is_outbound: bool,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Try to insert a new record
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO internet_destinations (hostname, first_seen_at, last_seen_at, packet_count, bytes_in, bytes_out)
             VALUES (?1, ?2, ?2, 1, ?3, ?4)",
            params![
                hostname,
                now,
                if is_outbound { 0i64 } else { bytes },
                if is_outbound { bytes } else { 0i64 }
            ],
        )?;

        // If insert was ignored (record exists), update instead
        if inserted == 0 {
            if is_outbound {
                conn.execute(
                    "UPDATE internet_destinations SET last_seen_at = ?1, packet_count = packet_count + 1, bytes_out = bytes_out + ?2 WHERE hostname = ?3",
                    params![now, bytes, hostname],
                )?;
            } else {
                conn.execute(
                    "UPDATE internet_destinations SET last_seen_at = ?1, packet_count = packet_count + 1, bytes_in = bytes_in + ?2 WHERE hostname = ?3",
                    params![now, bytes, hostname],
                )?;
            }
        }

        Ok(())
    }

    /// Get all internet destinations sorted by last_seen_at descending
    pub fn get_internet_destinations(conn: &Connection) -> Result<Vec<InternetDestination>> {
        let mut stmt = conn.prepare(
            "SELECT id, hostname, first_seen_at, last_seen_at, packet_count, bytes_in, bytes_out
             FROM internet_destinations
             WHERE hostname NOT GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'
               AND hostname NOT LIKE '%:%'
               AND hostname NOT LIKE '%.local'
               AND hostname LIKE '%.%'
             ORDER BY last_seen_at DESC",
        )?;

        let destinations = stmt
            .query_map([], |row| {
                Ok(InternetDestination {
                    id: row.get(0)?,
                    hostname: row.get(1)?,
                    first_seen_at: row.get(2)?,
                    last_seen_at: row.get(3)?,
                    packet_count: row.get(4)?,
                    bytes_in: row.get(5)?,
                    bytes_out: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(destinations)
    }

    /// Set the manual device type for an endpoint by name or custom_name
    /// Pass None to clear the manual override and revert to automatic classification
    pub fn set_manual_device_type(
        conn: &Connection,
        endpoint_name: &str,
        device_type: Option<&str>,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET manual_device_type = ? WHERE LOWER(name) = LOWER(?) OR LOWER(custom_name) = LOWER(?)",
            params![device_type, endpoint_name, endpoint_name],
        )
    }

    /// Set the auto-detected device type for an endpoint (persists across renames)
    pub fn set_auto_device_type(
        conn: &Connection,
        endpoint_name: &str,
        device_type: &str,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET auto_device_type = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![device_type, endpoint_name],
        )
    }

    /// Get all auto-detected device types (for endpoints without manual overrides)
    /// Returns a map of display_name -> auto_device_type
    pub fn get_all_auto_device_types(conn: &Connection) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT COALESCE(custom_name, name), auto_device_type FROM endpoints WHERE auto_device_type IS NOT NULL AND auto_device_type != '' AND (name IS NOT NULL OR custom_name IS NOT NULL)",
        ) && let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                map.insert(row.0, row.1);
            }
        }
        map
    }

    /// Set a custom name for an endpoint by name, existing custom_name, or hostname in endpoint_attributes
    /// Pass None to clear the custom name and revert to auto-discovered hostname
    pub fn set_custom_name(
        conn: &Connection,
        endpoint_name: &str,
        custom_name: Option<&str>,
    ) -> Result<usize> {
        // Must join with endpoint_attributes because endpoints.name may be NULL
        // and the actual hostname is stored in endpoint_attributes.hostname
        conn.execute(
            "UPDATE endpoints SET custom_name = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![custom_name, endpoint_name],
        )
    }

    /// Set a custom model for an endpoint by name, custom_name, or hostname in endpoint_attributes
    /// Pass None to clear the custom model and revert to auto-detected model
    pub fn set_custom_model(
        conn: &Connection,
        endpoint_name: &str,
        custom_model: Option<&str>,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET custom_model = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![custom_model, endpoint_name],
        )
    }

    /// Set a custom vendor for an endpoint by name, custom_name, or hostname in endpoint_attributes
    /// Pass None to clear the custom vendor and revert to auto-detected vendor
    pub fn set_custom_vendor(
        conn: &Connection,
        endpoint_name: &str,
        custom_vendor: Option<&str>,
    ) -> Result<usize> {
        conn.execute(
            "UPDATE endpoints SET custom_vendor = ?1
             WHERE id IN (
                 SELECT DISTINCT e.id FROM endpoints e
                 LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                 WHERE LOWER(e.name) = LOWER(?2)
                    OR LOWER(e.custom_name) = LOWER(?2)
                    OR LOWER(ea.hostname) = LOWER(?2)
                    OR LOWER(ea.ip) = LOWER(?2)
             )",
            params![custom_vendor, endpoint_name],
        )
    }

    /// Get the original name of an endpoint (the name field, not custom_name)
    /// This is used when clearing a custom name to redirect to the original URL
    pub fn get_original_name(conn: &Connection, endpoint_name: &str) -> Option<String> {
        conn.query_row(
            "SELECT COALESCE(e.name, ea.hostname, ea.ip) FROM endpoints e
             LEFT JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
             WHERE LOWER(e.name) = LOWER(?1)
                OR LOWER(e.custom_name) = LOWER(?1)
                OR LOWER(ea.hostname) = LOWER(?1)
                OR LOWER(ea.ip) = LOWER(?1)
             LIMIT 1",
            params![endpoint_name],
            |row| row.get(0),
        )
        .ok()
    }

    /// Get all manual device types as a HashMap
    pub fn get_all_manual_device_types(conn: &Connection) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT COALESCE(custom_name, name), manual_device_type FROM endpoints WHERE manual_device_type IS NOT NULL AND (name IS NOT NULL OR custom_name IS NOT NULL)",
        ) && let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                map.insert(row.0, row.1);
            }
        }
        map
    }

    #[allow(dead_code)]
    fn insert_endpoint(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        hostname: Option<String>,
    ) -> Result<i64, InsertEndpointError> {
        Self::insert_endpoint_with_dhcp(conn, mac, ip, hostname, None, None)
    }

    fn insert_endpoint_with_dhcp(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        hostname: Option<String>,
        dhcp_client_id: Option<String>,
        dhcp_vendor_class: Option<String>,
    ) -> Result<i64, InsertEndpointError> {
        conn.execute(
            "INSERT INTO endpoints (created_at) VALUES (strftime('%s', 'now'))",
            params![],
        )?;
        let endpoint_id = conn.last_insert_rowid();
        let hostname = hostname.unwrap_or(ip.clone().unwrap_or_default());
        EndPointAttribute::insert_endpoint_attribute_with_dhcp(
            conn,
            endpoint_id,
            mac,
            ip,
            hostname,
            dhcp_client_id,
            dhcp_vendor_class,
        )?;
        Ok(endpoint_id)
    }

    pub fn get_or_insert_endpoint(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        protocol: Option<String>,
        payload: &[u8],
    ) -> Result<i64, InsertEndpointError> {
        Self::get_or_insert_endpoint_with_dhcp(conn, mac, ip, protocol, payload, None, None, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn get_or_insert_endpoint_with_dhcp(
        conn: &Connection,
        mac: Option<String>,
        ip: Option<String>,
        protocol: Option<String>,
        payload: &[u8],
        dhcp_client_id: Option<String>,
        dhcp_vendor_class: Option<String>,
        dhcp_hostname: Option<String>,
    ) -> Result<i64, InsertEndpointError> {
        // Filter out IPv6 link-local addresses without EUI-64 format (privacy addresses)
        // These can't be reliably matched to a device and create duplicate endpoints
        if let Some(ref ip_str) = ip
            && is_ipv6_link_local(ip_str)
            && extract_mac_from_ipv6_eui64(ip_str).is_none()
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        // Try to extract MAC from IPv6 EUI-64 address if no MAC provided
        let mac = mac.or_else(|| {
            ip.as_ref()
                .and_then(|ip_str| extract_mac_from_ipv6_eui64(ip_str))
        });

        // Filter out broadcast/multicast MACs - these aren't real endpoints
        if let Some(ref mac_addr) = mac
            && Self::is_broadcast_or_multicast_mac(mac_addr)
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        // For locally administered (randomized/private) MACs:
        // - If we have a DHCP Client ID, we can still track the device
        // - Otherwise reject it (can't reliably track random MACs - they change frequently)
        let is_randomized_mac = mac
            .as_ref()
            .map(|m| is_locally_administered_mac(m))
            .unwrap_or(false);
        if is_randomized_mac && dhcp_client_id.is_none() {
            return Err(InsertEndpointError::LocallyAdministeredMac);
        }

        // For randomized MACs, don't use the MAC for lookups - use IP or DHCP Client ID instead
        let lookup_mac = if is_randomized_mac { None } else { mac.clone() };

        // Filter out multicast/broadcast IPs - these aren't real endpoints
        if let Some(ref ip_addr) = ip
            && Self::is_multicast_or_broadcast_ip(ip_addr)
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        if (lookup_mac.is_none() || lookup_mac == Some("00:00:00:00:00:00".to_string()))
            && ip.is_none()
            && dhcp_client_id.is_none()
        {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        // For LOCAL network IPs, require a MAC (even randomized) or DHCP Client ID to create an endpoint
        // This prevents creating orphan IP-only entries for local devices
        // (Remote/internet IPs are allowed without MAC since they're tracked by IP)
        let is_local_ip = ip
            .as_ref()
            .map(|ip| Self::is_on_local_network(ip))
            .unwrap_or(false);
        let has_any_mac = mac.is_some() && mac != Some("00:00:00:00:00:00".to_string());
        let has_identifier = has_any_mac || dhcp_client_id.is_some();
        if is_local_ip && !has_identifier {
            return Err(InsertEndpointError::BothMacAndIpNone);
        }

        // For INTERNET IPs (non-local), record in internet_destinations table instead of creating endpoint
        // This separates external hosts from local network devices
        if let Some(ref ip_str) = ip
            && !Self::is_on_local_network(ip_str)
        {
            // Use hostname if we have one, otherwise use the IP address
            let dest_name = dhcp_hostname
                .clone()
                .or_else(|| {
                    Self::lookup_hostname(ip.clone(), mac.clone(), protocol.clone(), payload)
                })
                .unwrap_or_else(|| ip_str.clone());

            // Record this internet destination (ignore errors - best effort)
            let _ = Self::insert_or_update_internet_destination(conn, &dest_name, 0, true);

            return Err(InsertEndpointError::InternetDestination);
        }

        // Strip .local and other local suffixes from hostnames and normalize to lowercase
        // Prefer DHCP hostname (Option 12) when available - this is the device's actual name
        let hostname = dhcp_hostname
            .clone()
            .or_else(|| Self::lookup_hostname(ip.clone(), mac.clone(), protocol.clone(), payload))
            .map(|h| strip_local_suffix(&h).to_lowercase());
        let endpoint_id = match EndPointAttribute::find_existing_endpoint_id_with_dhcp(
            conn,
            lookup_mac.clone(),
            ip.clone(),
            hostname.clone(),
            dhcp_client_id.clone(),
        ) {
            Some(id) => {
                // Only insert new attributes if we have useful data (MAC or hostname different from IP)
                // Don't insert empty MAC attributes for local IPs (causes bloat)
                let should_insert = if is_local_ip {
                    // For local IPs, only insert if we have a MAC or a real hostname
                    has_any_mac || (ip != hostname && hostname.is_some())
                } else {
                    // For remote IPs, insert if hostname is different from IP
                    ip != hostname && hostname.is_some()
                };

                if should_insert {
                    // Attempt to insert - will be ignored if duplicate due to UNIQUE constraint
                    let _ = EndPointAttribute::insert_endpoint_attribute_with_dhcp(
                        conn,
                        id,
                        lookup_mac,
                        ip.clone(),
                        hostname.clone().unwrap_or(ip.clone().unwrap_or_default()),
                        dhcp_client_id.clone(),
                        dhcp_vendor_class.clone(),
                    );
                }
                // Update DHCP Client ID if we have one and the endpoint doesn't
                if let Some(ref dhcp_id) = dhcp_client_id {
                    let _ = EndPointAttribute::update_dhcp_client_id(conn, id, dhcp_id);
                }
                // Update DHCP Vendor Class if we have one and the endpoint doesn't
                if let Some(ref vendor_class) = dhcp_vendor_class {
                    let _ = EndPointAttribute::update_dhcp_vendor_class(conn, id, vendor_class);
                }
                id
            }
            _ => Self::insert_endpoint_with_dhcp(
                conn,
                lookup_mac.clone(),
                ip.clone(),
                hostname.clone(),
                dhcp_client_id.clone(),
                dhcp_vendor_class.clone(),
            )?,
        };
        Self::check_and_update_endpoint_name(
            conn,
            endpoint_id,
            hostname.clone().unwrap_or_default(),
        )?;

        // If we have an IP but no hostname, spawn a background task to probe for the hostname
        // This is non-blocking and will update the endpoint if a hostname is found
        let hostname_is_ip = hostname
            .as_ref()
            .map(|h| h.parse::<std::net::IpAddr>().is_ok())
            .unwrap_or(true);
        if let Some(ref ip_addr) = ip
            && (hostname.is_none() || hostname_is_ip)
            && Self::is_on_local_network(ip_addr)
        {
            // Only probe for local IPs (remote servers probably won't respond to our mDNS)
            crate::network::mdns_lookup::MDnsLookup::probe_hostname_async(
                ip_addr.clone(),
                endpoint_id,
            );
        }

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
        // Strip local suffixes like .local, .lan, .home and normalize to lowercase
        let hostname = strip_local_suffix(&hostname).to_lowercase();

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
                // When updating from IP to hostname, try to merge other IPv6 endpoints on same prefix
                Self::merge_ipv6_siblings_into_endpoint(conn, endpoint_id);
            }
        }

        Ok(())
    }

    /// Merge other endpoints on the same IPv6 /64 prefix into this endpoint
    /// Called when an endpoint gets a proper hostname, to consolidate IPv6-only duplicates
    fn merge_ipv6_siblings_into_endpoint(conn: &Connection, target_endpoint_id: i64) {
        // Get IPv6 addresses for this endpoint
        let ipv6_addrs: Vec<String> = conn
            .prepare(
                "SELECT ip FROM endpoint_attributes WHERE endpoint_id = ?1 AND ip LIKE '%:%:%:%:%'",
            )
            .and_then(|mut stmt| {
                stmt.query_map([target_endpoint_id], |row| row.get(0))
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
            })
            .unwrap_or_default();

        if ipv6_addrs.is_empty() {
            return;
        }

        // Extract /64 prefixes (first 4 groups)
        let prefixes: Vec<String> = ipv6_addrs
            .iter()
            .filter_map(|ip| {
                let parts: Vec<&str> = ip.split(':').collect();
                if parts.len() >= 4 {
                    Some(format!(
                        "{}:{}:{}:{}",
                        parts[0], parts[1], parts[2], parts[3]
                    ))
                } else {
                    None
                }
            })
            .collect();

        if prefixes.is_empty() {
            return;
        }

        // Find other endpoints with IPv6 addresses on the same prefix that have IP-only names
        for prefix in prefixes {
            // Find endpoints with IPv6-like names (containing colons) on the same prefix
            let siblings: Vec<i64> = conn
                .prepare(
                    "SELECT DISTINCT e.id FROM endpoints e
                     JOIN endpoint_attributes ea ON e.id = ea.endpoint_id
                     WHERE ea.ip LIKE ?1 || ':%'
                       AND e.id != ?2
                       AND e.name LIKE '%:%'",
                )
                .and_then(|mut stmt| {
                    stmt.query_map(params![prefix, target_endpoint_id], |row| row.get(0))
                        .map(|rows| rows.filter_map(|r| r.ok()).collect())
                })
                .unwrap_or_default();

            for sibling_id in siblings {
                // Merge sibling into target
                let _ = conn.execute(
                    "UPDATE OR IGNORE endpoint_attributes SET endpoint_id = ?1 WHERE endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute(
                    "DELETE FROM endpoint_attributes WHERE endpoint_id = ?1",
                    [sibling_id],
                );
                let _ = conn.execute(
                    "UPDATE OR IGNORE communications SET src_endpoint_id = ?1 WHERE src_endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute(
                    "UPDATE OR IGNORE communications SET dst_endpoint_id = ?1 WHERE dst_endpoint_id = ?2",
                    params![target_endpoint_id, sibling_id],
                );
                let _ = conn.execute(
                    "DELETE FROM communications WHERE src_endpoint_id = ?1 OR dst_endpoint_id = ?1",
                    [sibling_id],
                );
                let _ = conn.execute("DELETE FROM endpoints WHERE id = ?1", [sibling_id]);
                println!(
                    "Merged IPv6 endpoint {} into {} (same /64 prefix: {})",
                    sibling_id, target_endpoint_id, prefix
                );
            }
        }
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

        // Insert an endpoint - use loopback IP which is always local
        let result = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("00:11:22:33:44:55".to_string()),
            Some("127.0.0.2".to_string()),
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

        // Insert endpoint first time - use loopback IP which is always local
        let id1 = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("00:11:22:33:44:55".to_string()),
            Some("127.0.0.2".to_string()),
            None,
            &[],
        )
        .unwrap();

        // Insert same endpoint again
        let id2 = EndPoint::get_or_insert_endpoint(
            &conn,
            Some("00:11:22:33:44:55".to_string()),
            Some("127.0.0.2".to_string()),
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

        // Roku serial number hostnames (e.g., YN00NJ468680)
        assert_eq!(is_tv_hostname("YN00NJ468680"), true);
        assert_eq!(is_tv_hostname("yn00nj468680"), true); // lowercase
        assert_eq!(is_tv_hostname("YK00KM123456"), true);

        // Non-TVs
        assert_eq!(is_tv_hostname("my-laptop"), false);
        assert_eq!(is_tv_hostname("printer"), false);
    }

    #[test]
    fn test_roku_serial_number_detection() {
        use super::*;

        // Valid Roku serial numbers: 2 letters + 2 digits + 2 letters + 6 digits
        assert_eq!(is_roku_serial_number("YN00NJ468680"), true);
        assert_eq!(is_roku_serial_number("YK00KM123456"), true);
        assert_eq!(is_roku_serial_number("AB12CD345678"), true);

        // Invalid patterns
        assert_eq!(is_roku_serial_number("YN00NJ46868"), false); // Too short (11 chars)
        assert_eq!(is_roku_serial_number("YN00NJ4686801"), false); // Too long (13 chars)
        assert_eq!(is_roku_serial_number("1N00NJ468680"), false); // First char not letter
        assert_eq!(is_roku_serial_number("YNA0NJ468680"), false); // Third char not digit
        assert_eq!(is_roku_serial_number("YN0ANJ468680"), false); // Fourth char not digit
        assert_eq!(is_roku_serial_number("YN001J468680"), false); // Fifth char not letter
        assert_eq!(is_roku_serial_number("YN00N1468680"), false); // Sixth char not letter
        assert_eq!(is_roku_serial_number("YN00NJA68680"), false); // Seventh char not digit
        assert_eq!(is_roku_serial_number("samsung-tv"), false); // Wrong format
        assert_eq!(is_roku_serial_number("7105X"), false); // Roku model, not serial
    }

    #[test]
    fn test_roku_tv_model_detection() {
        use super::*;

        // Roku TV platform identifiers (TCL, Hisense TVs running Roku OS)
        assert_eq!(is_roku_tv_model("7105X"), true);
        assert_eq!(is_roku_tv_model("7000X"), true);
        assert_eq!(is_roku_tv_model("6500X"), true);
        assert_eq!(is_roku_tv_model("3800X"), true);
        assert_eq!(is_roku_tv_model("4200"), true); // Without X suffix
        assert_eq!(is_roku_tv_model("8500X"), true);

        // Should be recognized as TV
        assert_eq!(is_tv_model("7105X"), true);
        assert_eq!(is_tv_model("7000X"), true);

        // Non-Roku TV models
        assert_eq!(is_roku_tv_model("HW-MS750"), false); // Samsung soundbar
        assert_eq!(is_roku_tv_model("OLED55C3"), false); // LG TV (different format)
        assert_eq!(is_roku_tv_model("12345X"), false); // Too many digits
        assert_eq!(is_roku_tv_model("710X"), false); // Only 3 digits
        assert_eq!(is_roku_tv_model("7105Y"), false); // Wrong suffix

        // Roku serial numbers should also be detected as Roku TV models
        assert_eq!(is_roku_tv_model("YN00NJ468680"), true);
        assert_eq!(is_roku_tv_model("yn00nj468680"), true); // lowercase

        // Vendor detection from model
        assert_eq!(get_vendor_from_model("7105X"), Some("TCL"));
        assert_eq!(get_vendor_from_model("7000X"), Some("TCL"));
        assert_eq!(get_vendor_from_model("YN00NJ468680"), Some("TCL")); // Roku serial number
        assert_eq!(get_vendor_from_model("HW-MS750"), Some("Samsung"));
        assert_eq!(get_vendor_from_model("OLED55C3"), Some("LG"));

        // Vendor detection from hostname
        assert_eq!(get_hostname_vendor("YN00NJ468680"), Some("TCL"));
        assert_eq!(get_hostname_vendor("yn00nj468680"), Some("TCL"));

        // Model detection from hostname
        assert_eq!(
            get_model_from_hostname("YN00NJ468680"),
            Some("Roku TV".to_string())
        );
        assert_eq!(
            get_model_from_hostname("yn00nj468680"),
            Some("Roku TV".to_string())
        );
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
    fn test_is_tv_model() {
        use super::*;

        // Samsung QLED TVs
        assert!(is_tv_model("QN43LS03TAFXZA")); // The Frame
        assert!(is_tv_model("QN65Q80AAFXZA")); // QLED Q80A
        assert!(is_tv_model("QN55QN90AAFXZA")); // Neo QLED

        // Samsung LED TVs
        assert!(is_tv_model("UN55TU8000FXZA"));
        assert!(is_tv_model("UA43AU7000KXXS"));

        // Samsung The Frame specific
        assert!(is_tv_model("LS03T"));
        assert!(is_tv_model("QN43LS01TAFXZA")); // The Serif

        // LG OLED TVs
        assert!(is_tv_model("OLED55C3PUA"));
        assert!(is_tv_model("OLED65G3PUA"));

        // LG NanoCell TVs
        assert!(is_tv_model("NANO75UPA"));

        // Sony Bravia
        assert!(is_tv_model("XR-55A80J"));
        assert!(is_tv_model("KD-55X80K"));
        assert!(is_tv_model("Sony Bravia"));

        // Vizio
        assert!(is_tv_model("Vizio M-Series"));

        // Generic patterns
        assert!(is_tv_model("Samsung The Frame"));
        assert!(is_tv_model("Samsung TV"));

        // Should NOT match
        assert!(!is_tv_model("HW-MS750")); // Soundbar
        assert!(!is_tv_model("Galaxy S23")); // Phone
        assert!(!is_tv_model("MacBook Pro")); // Computer
        assert!(!is_tv_model("random-device"));
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
            EndPoint::classify_device_type(Some("hp-laserjet"), &[], &[], &[], None),
            Some("printer")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("roku-ultra"), &[], &[], &[], None),
            Some("tv")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("unknown-device"), &[], &[9100], &[], None),
            Some("printer")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("my-laptop"), &[], &[80, 443], &[], None),
            None
        );
        // SSDP model-based classification
        assert_eq!(
            EndPoint::classify_device_type(Some("samsung-tv"), &[], &[], &[], Some("HW-MS750")),
            Some("soundbar")
        );
        assert_eq!(
            EndPoint::classify_device_type(Some("lg-device"), &[], &[], &[], Some("SL8YG")),
            Some("soundbar")
        );
    }

    #[test]
    fn test_classify_by_mac() {
        // Amazon device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                &[],
                &[],
                &["3c:5c:c4:90:a2:93".to_string()],
                None
            ),
            Some("appliance")
        );
        // Google/Nest device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("192.168.1.50"),
                &[],
                &[],
                &["18:d6:c7:12:34:56".to_string()],
                None
            ),
            Some("appliance")
        );
        // Ring device MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                &[],
                &[],
                &["34:3e:a4:00:00:00".to_string()],
                None
            ),
            Some("appliance")
        );
        // Apple MAC without desktop services = phone (iPhone/iPad)
        assert_eq!(
            EndPoint::classify_device_type(
                Some("unknown"),
                &[],
                &[],
                &["a4:83:e7:12:34:56".to_string()],
                None
            ),
            Some("phone")
        );
        // Hostname takes precedence over MAC
        assert_eq!(
            EndPoint::classify_device_type(
                Some("hp-printer"),
                &[],
                &[],
                &["3c:5c:c4:90:a2:93".to_string()],
                None
            ),
            Some("printer")
        );
    }

    #[test]
    fn test_extract_mac_from_ipv6_eui64() {
        use super::*;

        // Standard EUI-64 link-local address
        assert_eq!(
            extract_mac_from_ipv6_eui64("fe80::d48f:2ff:fefb:b5"),
            Some("d6:8f:02:fb:00:b5".to_string())
        );

        // Another example with different MAC
        assert_eq!(
            extract_mac_from_ipv6_eui64("fe80::1234:56ff:fe78:9abc"),
            Some("10:34:56:78:9a:bc".to_string())
        );

        // Full form address (no ::)
        assert_eq!(
            extract_mac_from_ipv6_eui64("fe80:0000:0000:0000:0211:22ff:fe33:4455"),
            Some("00:11:22:33:44:55".to_string())
        );

        // Non-EUI-64 address (no ff:fe pattern) should return None
        assert_eq!(extract_mac_from_ipv6_eui64("fe80::1"), None);

        // Global IPv6 with EUI-64 should also work
        assert_eq!(
            extract_mac_from_ipv6_eui64("2001:db8::0211:22ff:fe33:4455"),
            Some("00:11:22:33:44:55".to_string())
        );

        // Invalid IP should return None
        assert_eq!(extract_mac_from_ipv6_eui64("not-an-ip"), None);

        // IPv4 should return None
        assert_eq!(extract_mac_from_ipv6_eui64("192.168.1.1"), None);
    }

    #[test]
    fn test_normalize_model_name() {
        use super::*;

        // Samsung The Frame
        assert_eq!(
            normalize_model_name("QN43LS03TAFXZA", None),
            Some("Samsung The Frame".to_string())
        );
        assert_eq!(
            normalize_model_name("QN65LS03BAFXZA", None),
            Some("Samsung The Frame".to_string())
        );

        // Samsung The Serif
        assert_eq!(
            normalize_model_name("QN55LS01TAFXZA", None),
            Some("Samsung The Serif".to_string())
        );

        // Samsung QLED (numbered series)
        assert_eq!(
            normalize_model_name("QN65Q80CAFXZA", None),
            Some("Samsung QLED Q8".to_string())
        );
        assert_eq!(
            normalize_model_name("QN55Q60BAFXZA", None),
            Some("Samsung QLED Q6".to_string())
        );

        // Samsung Neo QLED
        assert_eq!(
            normalize_model_name("QN85QN90BAFXZA", None),
            Some("Samsung Neo QLED QN9".to_string())
        );

        // Samsung OLED
        assert_eq!(
            normalize_model_name("QN65S95BAFXZA", None),
            Some("Samsung OLED S95".to_string())
        );

        // Samsung Crystal UHD
        assert_eq!(
            normalize_model_name("UN55TU8000FXZA", None),
            Some("Samsung Crystal UHD TU8".to_string())
        );

        // LG OLED (with vendor hint)
        assert_eq!(
            normalize_model_name("OLED55C3PUA", Some("LG")),
            Some("LG OLED".to_string())
        );
        assert_eq!(
            normalize_model_name("55C2PUA", Some("LG")),
            Some("LG OLED C2".to_string())
        );

        // Sony Bravia (with vendor hint)
        assert_eq!(
            normalize_model_name("XR55A90J", Some("Sony")),
            Some("Sony Bravia XR A90".to_string())
        );

        // Soundbar models should normalize to friendly names
        assert_eq!(
            normalize_model_name("HW-MS750", None),
            Some("Samsung Soundbar MS750".to_string())
        );
        assert_eq!(
            normalize_model_name("HW-Q990B", None),
            Some("Samsung Soundbar Q990B".to_string())
        );
        assert_eq!(
            normalize_model_name("SPK-WAM750", None),
            Some("Samsung Soundbar WAM750".to_string())
        );
        assert_eq!(
            normalize_model_name("SL8YG", None),
            Some("LG Soundbar SL8YG".to_string())
        );

        // Unknown model should return None
        assert_eq!(normalize_model_name("XYZ123ABC", None), None);
    }
}
