// Classification type constants
pub(crate) const CLASSIFICATION_GATEWAY: &str = "gateway";
pub(crate) const CLASSIFICATION_INTERNET: &str = "internet";
pub(crate) const CLASSIFICATION_PRINTER: &str = "printer";
pub(crate) const CLASSIFICATION_TV: &str = "tv";
pub(crate) const CLASSIFICATION_GAMING: &str = "gaming";
pub(crate) const CLASSIFICATION_VIRTUALIZATION: &str = "virtualization";
pub(crate) const CLASSIFICATION_SOUNDBAR: &str = "soundbar";
pub(crate) const CLASSIFICATION_APPLIANCE: &str = "appliance";
pub(crate) const CLASSIFICATION_PHONE: &str = "phone";
pub(crate) const CLASSIFICATION_COMPUTER: &str = "computer";

// Device detection patterns
pub(crate) const PRINTER_PATTERNS: &[&str] = &[
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
pub(crate) const PRINTER_PREFIXES: &[&str] = &["hp", "npi", "np", "brn", "brw", "epson"];

pub(crate) const TV_PATTERNS: &[&str] = &[
    "tv",
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
    "the-frame",
    "theframe",
    "the-serif",
    "the-sero",
    "lgwebostv", // LG WebOS TVs
    "webostv",
];
// Note: "samsung" and "lg-" removed from TV_PATTERNS - too generic, matches soundbars/appliances
pub(crate) const TV_PREFIXES: &[&str] = &[];

pub(crate) const GAMING_PATTERNS: &[&str] = &[
    "xbox",
    "playstation",
    "ps4",
    "ps5",
    "nintendo",
    "switch",
    "steamdeck",
    "steam-deck",
];

pub(crate) const PHONE_PATTERNS: &[&str] = &[
    "iphone", "ipad", "ipod", "oneplus", "motorola", "oppo", "vivo", "realme", "redmi", "poco",
];
pub(crate) const PHONE_PREFIXES: &[&str] = &["sm-", "moto"];
pub(crate) const PHONE_CONDITIONAL: &[(&str, &str)] = &[
    ("galaxy", "tv"),
    ("pixel", "tv"),
    ("xiaomi", "tv"),
    ("huawei", "tv"),
    ("nokia", "tv"),
];

pub(crate) const VM_PATTERNS: &[&str] = &[
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

pub(crate) const SOUNDBAR_PATTERNS: &[&str] = &[
    "soundbar",
    "sound-bar",
    "sonos",
    "bose",
    "playbar",
    "playbase",
    "beam",
    // AV receivers
    "denon-avr",
    "denon-",
    "yamaha-rx",
    "rx-v", // Yamaha RX-V series receivers
    "marantz",
    "onkyo",
    "pioneer-vsx",
];

/// Soundbar and AV receiver model number prefixes (for SSDP model detection)
pub(crate) const SOUNDBAR_MODEL_PREFIXES: &[&str] = &[
    "hw-",  // Samsung soundbars (HW-MS750, HW-Q990B, etc.)
    "spk-", // Samsung speakers (SPK-WAM750, etc.)
    "wam",  // Samsung Wireless Audio Multiroom (WAM750, etc.)
    "sl",   // LG soundbars (SL8YG, SL10YG, etc.) - no dash in LG models
    "sn",   // LG soundbars (SN11RG, etc.)
    "sp",   // LG soundbars (SP9YA, etc.)
    "sc9",  // LG soundbars (SC9S, etc.) - sc9 to avoid matching other "sc" models
    "bar-", // JBL soundbars (Bar 5.1, etc.)
    // AV receivers
    "avr-",  // Denon AVR series (AVR-S940H, AVR-X3700H, etc.)
    "rx-v",  // Yamaha RX-V series (RX-V479, RX-V685, etc.)
    "rx-a",  // Yamaha RX-A Aventage series
    "sr",    // Marantz SR series (SR5015, SR6015, etc.)
    "nr",    // Marantz NR series (NR1711, etc.)
    "tx-nr", // Onkyo TX-NR series
    "tx-rz", // Onkyo TX-RZ series
    "vsx-",  // Pioneer VSX series
];

/// Samsung TV model series patterns mapped to friendly names
/// Model format: [Panel][Size][Series][Variant] e.g., QN43LS03TAFXZA
/// - QN = QLED, UN = UHD LED
/// - 43 = screen size
/// - LS03 = The Frame series
/// - TAFXZA = year/region variant
pub(crate) const SAMSUNG_TV_SERIES: &[(&str, &str)] = &[
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
pub(crate) const LG_TV_SERIES: &[(&str, &str)] = &[
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
pub(crate) const SONY_TV_SERIES: &[(&str, &str)] = &[
    ("a95", "Bravia XR A95"),
    ("a90", "Bravia XR A90"),
    ("a80", "Bravia XR A80"),
    ("x95", "Bravia XR X95"),
    ("x90", "Bravia XR X90"),
    ("x85", "Bravia X85"),
    ("x80", "Bravia X80"),
];

pub(crate) const APPLIANCE_PATTERNS: &[&str] = &[
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
    // Garage door openers
    "ratgdo", // Ratgdo garage door opener
    "myq",    // Chamberlain MyQ
    "garagedoor",
    "garage-door",
    // Smart lighting
    "wled",     // WLED smart LED controllers
    "hue",      // Philips Hue (not bridge)
    "lifx",     // LIFX smart bulbs
    "nanoleaf", // Nanoleaf panels
    // Smart plugs/switches
    "wemo",    // Belkin Wemo
    "kasa",    // TP-Link Kasa
    "tasmota", // Tasmota firmware devices
    "shelly",  // Shelly smart devices
    "meross",  // Meross smart devices
    // Other IoT
    "ecobee", // Ecobee thermostats
    "roomba", // iRobot Roomba
    "dyson",  // Dyson fans/purifiers
    // NAS devices (treated as appliances)
    "truenas",   // TrueNAS
    "synology",  // Synology NAS
    "qnap",      // QNAP NAS
    "freenas",   // FreeNAS
    "unraid",    // Unraid NAS
    "paperless", // Paperless-ngx document management
    // Security cameras
    "dahua",      // Dahua cameras/NVRs
    "hikvision",  // Hikvision cameras
    "simplisafe", // SimpliSafe security
    "arlo",       // Arlo cameras
    "blink",      // Blink cameras
    // Wyze cameras (often use lcc- hostname prefix)
    "lcc-", // Wyze camera cloud prefix
];
pub(crate) const LG_APPLIANCE_PREFIXES: &[&str] = &["lma", "lmw", "ldf", "ldt", "ldp", "dle", "dlex", "lrmv"];

// mDNS service types for device classification
pub(crate) const TV_SERVICES: &[&str] = &[
    "_googlecast._tcp",
    "_roku._tcp",
    "_webos._tcp", // LG WebOS TVs
                   // Note: _raop._tcp removed - too generic (MacBooks, iPhones, HomePods advertise it)
                   // Note: _spotify-connect._tcp removed - too generic (phones, speakers, consoles all use it)
                   // Note: _airplay._tcp removed - too generic (iPhones, MacBooks also advertise it)
];
pub(crate) const PRINTER_SERVICES: &[&str] = &["_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp"];

pub(crate) const PHONE_SERVICES: &[&str] = &[
    "_apple-mobdev2._tcp",  // Apple mobile device service (iPhones/iPads)
    "_companion-link._tcp", // iOS companion link (AirDrop, Handoff)
    "_rdlink._tcp",         // Remote desktop link (iOS)
];

pub(crate) const APPLIANCE_SERVICES: &[&str] = &[
    "_lge._tcp",        // LG ThinQ appliances
    "_xbcs._tcp",       // LG ThinQ appliances (dishwashers, etc.)
    "_dyson_mqtt._tcp", // Dyson devices (fans, purifiers)
];

pub(crate) const SOUNDBAR_SERVICES: &[&str] = &[
    "_sonos._tcp", // Sonos speakers/soundbars
];

// IoT vendors that should be classified as appliances (not general computing devices)
pub(crate) const APPLIANCE_VENDORS: &[&str] = &[
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
    "Dyson",
    "Roborock",          // Robot vacuums
    "SimpliSafe",        // Home security
    "Dahua",             // Security cameras
    "Nest",              // Smart home (Google)
    "Bosch",             // Home appliances
    "Seeed",             // IoT devices
    "Texas Instruments", // IoT chips (used in Wyze, SmartThings)
    "Espressif",         // ESP32/ESP8266 IoT modules
];

// Gaming vendors that should be classified as gaming devices
pub(crate) const GAMING_VENDORS: &[&str] = &["Nintendo", "Sony"];

// TV/streaming vendors that should be classified as TV
pub(crate) const TV_VENDORS: &[&str] = &["Roku", "TCL", "Hisense", "Vizio", "FN-Link"];

// Gateway/router vendors - cable modems, routers, networking equipment
pub(crate) const GATEWAY_VENDORS: &[&str] = &[
    "Commscope", // ARRIS cable modems/routers
    "ARRIS",     // Cable modems, routers
    "Netgear",   // Routers, modems
    "Linksys",   // Routers
    "Ubiquiti",  // UniFi networking equipment
    "MikroTik",  // Routers
    "Cisco",     // Networking equipment
    "Juniper",   // Networking equipment
    "Fortinet",  // Firewalls/routers
    "pfSense",   // Firewalls
    "Asus",      // Routers (among other things)
];

// Services that indicate a Mac (desktop/laptop) vs mobile device
// Macs typically advertise file sharing services; iPhones/iPads don't
pub(crate) const MAC_DESKTOP_SERVICES: &[&str] = &[
    "_afpovertcp._tcp", // Apple Filing Protocol
    "_smb._tcp",        // SMB file sharing
    "_ssh._tcp",        // SSH access (typically enabled on Macs)
    "_sftp-ssh._tcp",   // SFTP
];

