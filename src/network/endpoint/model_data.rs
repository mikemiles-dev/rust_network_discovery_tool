//! Vendor-specific model data constants for device model identification.
//! These data tables are used by `model.rs` functions to match and normalize model names.

// ---------------------------------------------------------------------------
// Soundbar prefix rules
// (prefix, vendor_label) - if a model starts with `prefix`, return "vendor_label <series>"
// ---------------------------------------------------------------------------

/// Samsung soundbar prefixes. Format: model starts with prefix -> "Samsung Soundbar <remainder>"
/// The tuple is (prefix, chars_to_skip) where chars_to_skip is how many chars to skip for the series.
pub(crate) const SAMSUNG_SOUNDBAR_PREFIXES: &[(&str, usize)] = &[
    ("hw-", 3),  // HW-MS750 -> Soundbar MS750
    ("spk-", 4), // SPK-WAM750 -> Soundbar WAM750
];

/// Samsung Wireless Audio Multiroom prefix
pub(crate) const SAMSUNG_WAM_PREFIX: &str = "wam";

/// LG soundbar prefixes (followed by a digit at position 2)
pub(crate) const LG_SOUNDBAR_PREFIXES: &[&str] = &["sl", "sn", "sp"];

/// LG soundbar special prefix (no digit check needed)
pub(crate) const LG_SOUNDBAR_SPECIAL_PREFIX: &str = "sc9";

/// JBL soundbar prefixes
pub(crate) const JBL_SOUNDBAR_PREFIXES: &[&str] = &["bar-", "bar "];

// ---------------------------------------------------------------------------
// AV Receiver prefix rules
// (prefix, vendor_format) - maps model prefix to vendor+series format string
// ---------------------------------------------------------------------------

/// AV receiver prefix-to-vendor rules.
/// Fields: (lowercase_prefix, format_label, skip_chars)
/// Result: "{format_label}{model_upper[skip_chars..]}"
pub(crate) const AV_RECEIVER_RULES: &[(&str, &str, usize)] = &[
    ("avr-", "Denon AVR ", 4),               // AVR-S940H -> "Denon AVR S940H"
    ("rx-v", "Yamaha RX-V", 4),              // RX-V479 -> "Yamaha RX-V479"
    ("rx-a", "Yamaha Aventage RX-A", 4),     // RX-A3080 -> "Yamaha Aventage RX-A3080"
    ("tx-nr", "Onkyo ", 0),                  // TX-NR686 -> "Onkyo TX-NR686"
    ("tx-rz", "Onkyo ", 0),                  // TX-RZ830 -> "Onkyo TX-RZ830"
    ("vsx-", "Pioneer ", 0),                 // VSX-LX504 -> "Pioneer VSX-LX504"
];

/// Marantz SR/NR prefix (starts with "sr" or "nr" followed by digit)
pub(crate) const MARANTZ_PREFIXES: &[&str] = &["sr", "nr"];

// ---------------------------------------------------------------------------
// Samsung model prefix flags for TV detection
// ---------------------------------------------------------------------------

/// Prefixes that indicate a Samsung TV model
pub(crate) const SAMSUNG_TV_MODEL_PREFIXES: &[&str] = &["QN", "UN"];

// ---------------------------------------------------------------------------
// LG model detection keywords
// ---------------------------------------------------------------------------

/// Keywords in model string that indicate LG TV
pub(crate) const LG_TV_MODEL_KEYWORDS: &[&str] = &["OLED", "NANO", "QNED"];

// ---------------------------------------------------------------------------
// Sony model prefix flags for TV detection
// ---------------------------------------------------------------------------

/// Prefixes that indicate a Sony TV model
pub(crate) const SONY_TV_MODEL_PREFIXES: &[&str] = &["XR", "KD"];

// ---------------------------------------------------------------------------
// Samsung Galaxy SM- model number mappings
// ---------------------------------------------------------------------------

/// Samsung Galaxy phone model number prefix rules.
/// Fields: (sm_prefix, model_name_or_format)
/// "literal" entries return the string as-is; "format" entries use the 2 chars after prefix.
pub(crate) const GALAXY_SM_PREFIX_RULES: &[(&str, &str)] = &[
    ("SM-S9", "Galaxy S"),  // + chars 4..6
    ("SM-S8", "Galaxy S"),  // + chars 4..6
];

/// Samsung Galaxy phone model number to fixed name mappings.
/// Older G-series model numbers map to specific Galaxy S models.
pub(crate) const GALAXY_SM_G_SERIES: &[(&str, &str)] = &[
    ("SM-G99", "Galaxy S21"),
    ("SM-G98", "Galaxy S20"),
    ("SM-G97", "Galaxy S10"),
    ("SM-G96", "Galaxy S9"),
    ("SM-G95", "Galaxy S8"),
];

/// Samsung Galaxy A-series prefix
pub(crate) const GALAXY_SM_A_PREFIX: &str = "SM-A";

/// Samsung Galaxy Z Fold prefix
pub(crate) const GALAXY_SM_FOLD_PREFIX: &str = "SM-F9";
/// Samsung Galaxy Z Flip prefix
pub(crate) const GALAXY_SM_FLIP_PREFIX: &str = "SM-F7";
/// Samsung Galaxy Note prefix
pub(crate) const GALAXY_SM_NOTE_PREFIX: &str = "SM-N9";
/// Samsung Galaxy Tab prefixes (SM-T or SM-X)
pub(crate) const GALAXY_SM_TAB_PREFIXES: &[&str] = &["SM-T", "SM-X"];

// ---------------------------------------------------------------------------
// Galaxy hostname-based model patterns
// ---------------------------------------------------------------------------

/// Galaxy S-series hostname patterns: (substring, model_name)
pub(crate) const GALAXY_S_HOSTNAME_PATTERNS: &[(&str, &str)] = &[
    ("s24", "Galaxy S24"),
    ("s23", "Galaxy S23"),
    ("s22", "Galaxy S22"),
    ("s21", "Galaxy S21"),
    ("s20", "Galaxy S20"),
    ("s10", "Galaxy S10"),
];

/// Galaxy A-series hostname patterns: (substring, model_name)
pub(crate) const GALAXY_A_HOSTNAME_PATTERNS: &[(&str, &str)] = &[
    ("a54", "Galaxy A54"),
    ("a53", "Galaxy A53"),
    ("a52", "Galaxy A52"),
    ("a34", "Galaxy A34"),
    ("a14", "Galaxy A14"),
];

/// Galaxy Z-series hostname detection patterns: (&[substrings], model_name)
pub(crate) const GALAXY_Z_FOLD_PATTERNS: &[&str] = &["z-fold", "zfold", "fold"];
pub(crate) const GALAXY_Z_FLIP_PATTERNS: &[&str] = &["z-flip", "zflip", "flip"];

/// Galaxy Tab series hostname patterns: (substring, model_name)
pub(crate) const GALAXY_TAB_HOSTNAME_PATTERNS: &[(&str, &str)] = &[
    ("s9", "Galaxy Tab S9"),
    ("s8", "Galaxy Tab S8"),
    ("s7", "Galaxy Tab S7"),
    ("s6", "Galaxy Tab S6"),
];

/// Galaxy Watch hostname patterns: (substring, model_name)
pub(crate) const GALAXY_WATCH_HOSTNAME_PATTERNS: &[(&str, &str)] = &[
    ("ultra", "Galaxy Watch Ultra"),
    ("6", "Galaxy Watch 6"),
    ("5", "Galaxy Watch 5"),
    ("4", "Galaxy Watch 4"),
];

/// Galaxy Buds hostname patterns: (substring, model_name)
pub(crate) const GALAXY_BUDS_HOSTNAME_PATTERNS: &[(&str, &str)] = &[
    ("pro", "Galaxy Buds Pro"),
    ("live", "Galaxy Buds Live"),
    ("fe", "Galaxy Buds FE"),
    ("2", "Galaxy Buds 2"),
];

// ---------------------------------------------------------------------------
// Samsung appliance hostname patterns
// ---------------------------------------------------------------------------

/// Samsung appliance detection: (patterns, prefixes, result)
/// Each entry: (&[hostname_contains], &[hostname_starts_with], appliance_name)
pub(crate) const SAMSUNG_APPLIANCE_RULES: &[(&[&str], &[&str], &str)] = &[
    (&["fridge", "refrigerator"], &["rf"], "Samsung Refrigerator"),
    (&["washer"], &["wf", "ww"], "Samsung Washer"),
    (&["dryer"], &["dv"], "Samsung Dryer"),
    (&["dishwasher"], &["dw"], "Samsung Dishwasher"),
    (&["oven", "range"], &[], "Samsung Oven"),
    (&["vacuum", "jet"], &[], "Samsung Jet"),
];

// ---------------------------------------------------------------------------
// LG appliance hostname patterns
// ---------------------------------------------------------------------------

/// LG ThinQ dishwasher prefixes
pub(crate) const LG_DISHWASHER_PREFIXES: &[&str] = &["ldp", "ldf"];

/// LG washing machine prefix
pub(crate) const LG_WASHER_PREFIX: &str = "wm";

/// LG dryer prefixes
pub(crate) const LG_DRYER_PREFIXES: &[&str] = &["dlex", "dle", "dlg"];

/// LG refrigerator prefixes
pub(crate) const LG_FRIDGE_PREFIXES: &[&str] = &["lrm", "lrf", "lrs"];

// ---------------------------------------------------------------------------
// Chromecast hostname patterns
// ---------------------------------------------------------------------------

/// Chromecast variant detection: (substring, model_name)
pub(crate) const CHROMECAST_VARIANTS: &[(&str, &str)] = &[
    ("ultra", "Chromecast Ultra"),
    ("4k", "Chromecast with Google TV"),
    ("google-tv", "Chromecast with Google TV"),
];

// ---------------------------------------------------------------------------
// Nest/Google Home hostname patterns
// ---------------------------------------------------------------------------

/// Nest Hub variant detection: (substring, model_name)
pub(crate) const NEST_HUB_VARIANTS: &[(&str, &str)] = &[
    ("max", "Nest Hub Max"),
];

/// Nest Mini detection patterns
pub(crate) const NEST_MINI_PATTERNS: &[&str] = &["nest-mini", "google-home-mini"];

// ---------------------------------------------------------------------------
// Amazon Echo hostname patterns
// ---------------------------------------------------------------------------

/// Echo device variant detection: (substring, model_name)
pub(crate) const ECHO_VARIANTS: &[(&str, &str)] = &[
    ("dot", "Echo Dot"),
    ("show", "Echo Show"),
    ("studio", "Echo Studio"),
    ("plus", "Echo Plus"),
];

// ---------------------------------------------------------------------------
// Sonos speaker hostname patterns
// ---------------------------------------------------------------------------

/// Sonos speaker variant detection: (substring, model_name)
pub(crate) const SONOS_VARIANTS: &[(&str, &str)] = &[
    ("one", "Sonos One"),
    ("beam", "Sonos Beam"),
    ("arc", "Sonos Arc"),
    ("move", "Sonos Move"),
    ("roam", "Sonos Roam"),
    ("sub", "Sonos Sub"),
    ("play:1", "Sonos Play:1"),
    ("play1", "Sonos Play:1"),
    ("play:3", "Sonos Play:3"),
    ("play3", "Sonos Play:3"),
    ("play:5", "Sonos Play:5"),
    ("play5", "Sonos Play:5"),
];

// ---------------------------------------------------------------------------
// Ring device hostname patterns
// ---------------------------------------------------------------------------

/// Ring product variant detection: (substring, model_name)
pub(crate) const RING_VARIANTS: &[(&str, &str)] = &[
    ("doorbell", "Ring Doorbell"),
    ("cam", "Ring Camera"),
    ("camera", "Ring Camera"),
    ("stick", "Ring Stick Up Cam"),
];

// ---------------------------------------------------------------------------
// HP Printer model prefixes
// ---------------------------------------------------------------------------

/// HP printer model name keywords to look for in hostname parts
pub(crate) const HP_PRINTER_KEYWORDS: &[&str] = &[
    "LASERJET",
    "OFFICEJET",
    "DESKJET",
    "ENVY",
    "PHOTOSMART",
];

// ---------------------------------------------------------------------------
// Canon printer model prefixes
// ---------------------------------------------------------------------------

/// Canon printer model prefixes to look for in hostname parts
pub(crate) const CANON_PRINTER_PREFIXES: &[&str] = &["MX", "MG", "TS", "TR", "PIXMA"];

// ---------------------------------------------------------------------------
// Epson printer model prefixes
// ---------------------------------------------------------------------------

/// Epson printer model prefixes/keywords
pub(crate) const EPSON_PRINTER_PREFIXES: &[&str] = &["ET", "WF", "XP", "L"];
pub(crate) const EPSON_PRINTER_KEYWORDS: &[&str] = &["ECOTANK", "WORKFORCE"];

// ---------------------------------------------------------------------------
// Brother printer model prefixes
// ---------------------------------------------------------------------------

/// Brother printer model prefixes
pub(crate) const BROTHER_PRINTER_PREFIXES: &[&str] = &["HL", "MFC", "DCP"];

// ---------------------------------------------------------------------------
// Amazon Fire TV hostname patterns
// ---------------------------------------------------------------------------

/// Fire TV variant detection: (substring, model_name)
pub(crate) const FIRE_TV_VARIANTS: &[(&str, &str)] = &[
    ("4k", "Fire TV Stick 4K"),
    ("max", "Fire TV Stick 4K Max"),
    ("lite", "Fire TV Stick Lite"),
    ("cube", "Fire TV Cube"),
];

/// Kindle variant detection: (substring, model_name)
pub(crate) const KINDLE_VARIANTS: &[(&str, &str)] = &[
    ("paperwhite", "Kindle Paperwhite"),
    ("oasis", "Kindle Oasis"),
];

// ---------------------------------------------------------------------------
// Tapo device model patterns
// ---------------------------------------------------------------------------

/// Tapo camera model prefixes (c2xx, c3xx, c4xx)
pub(crate) const TAPO_CAMERA_PREFIXES: &[&str] = &["c2", "c3", "c4"];

/// Tapo camera detection keywords
pub(crate) const TAPO_CAMERA_KEYWORDS: &[&str] = &["c200", "c210", "c220"];

/// Tapo smart plug keywords
pub(crate) const TAPO_PLUG_KEYWORDS: &[&str] = &["p100", "p110", "p105"];

/// Tapo smart bulb keywords
pub(crate) const TAPO_BULB_KEYWORDS: &[&str] = &["l530", "l510", "l900"];

/// Kasa/TP-Link smart plug keywords
pub(crate) const KASA_PLUG_KEYWORDS: &[&str] = &["kasa", "hs100", "hs110", "hs200"];

// ---------------------------------------------------------------------------
// Wyze device hostname patterns
// ---------------------------------------------------------------------------

/// Wyze Cam variant detection: (substring, model_name)
pub(crate) const WYZE_CAM_VARIANTS: &[(&str, &str)] = &[
    ("v3", "Wyze Cam v3"),
    ("pan", "Wyze Cam Pan"),
    ("outdoor", "Wyze Cam Outdoor"),
];

/// Wyze device variants (non-camera): (substring, model_name)
pub(crate) const WYZE_DEVICE_VARIANTS: &[(&str, &str)] = &[
    ("plug", "Wyze Plug"),
    ("bulb", "Wyze Bulb"),
    ("lock", "Wyze Lock"),
    ("vacuum", "Wyze Robot Vacuum"),
];

// ---------------------------------------------------------------------------
// iRobot Roomba model prefixes
// ---------------------------------------------------------------------------

/// Roomba model prefix letters (i7, s9, j7, e5, etc.)
pub(crate) const ROOMBA_MODEL_PREFIXES: &[char] = &['i', 's', 'j', 'e'];

// ---------------------------------------------------------------------------
// Philips Hue hostname patterns
// ---------------------------------------------------------------------------

/// Hue device variant detection: (substring, model_name)
pub(crate) const HUE_VARIANTS: &[(&str, &str)] = &[
    ("bridge", "Hue Bridge"),
    ("bulb", "Hue Light"),
    ("lamp", "Hue Light"),
    ("light", "Hue Light"),
    ("play", "Hue Play"),
    ("strip", "Hue Lightstrip"),
    ("lightstrip", "Hue Lightstrip"),
    ("bloom", "Hue Bloom"),
    ("go", "Hue Go"),
];

// ---------------------------------------------------------------------------
// Ecobee thermostat hostname patterns
// ---------------------------------------------------------------------------

/// Ecobee variant detection: (substring, model_name)
pub(crate) const ECOBEE_VARIANTS: &[(&str, &str)] = &[
    ("lite", "Ecobee Lite"),
    ("smart", "Ecobee Smart Thermostat"),
    ("premium", "Ecobee Smart Thermostat"),
    ("sensor", "Ecobee Sensor"),
];

// ---------------------------------------------------------------------------
// Apple Watch hostname patterns
// ---------------------------------------------------------------------------

/// Apple Watch variant detection: (substring, model_name)
pub(crate) const APPLE_WATCH_VARIANTS: &[(&str, &str)] = &[
    ("ultra", "Apple Watch Ultra"),
    ("se", "Apple Watch SE"),
];

/// Maximum Apple Watch series number to check
pub(crate) const APPLE_WATCH_MAX_SERIES: u32 = 10;

// ---------------------------------------------------------------------------
// SmartThings sensor MAC prefixes
// ---------------------------------------------------------------------------

/// MAC address prefixes that identify SmartThings sensors
/// (Wisol and Samjin manufacture sensors for Samsung SmartThings)
pub(crate) const SMARTTHINGS_SENSOR_MAC_PREFIXES: &[&str] = &[
    "70:2c:1f",
    "28:6d:97",
];

// ---------------------------------------------------------------------------
// Amazon device port-based inference rules
// ---------------------------------------------------------------------------

/// Ports that indicate Amazon Fire TV
pub(crate) const AMAZON_FIRE_TV_PORTS: &[u16] = &[5555, 8008, 8443];

/// Ports that indicate Google Chromecast
pub(crate) const GOOGLE_CHROMECAST_PORTS: &[u16] = &[8008, 8443];

// ---------------------------------------------------------------------------
// Huawei phone hostname detection prefixes
// ---------------------------------------------------------------------------

/// Huawei phone series prefixes (checked in uppercase against hostname parts)
pub(crate) const HUAWEI_PHONE_PREFIXES: &[&str] = &["MATE", "NOVA"];

// ---------------------------------------------------------------------------
// SmartThings hostname patterns
// ---------------------------------------------------------------------------

/// SmartThings variant detection: (substring, model_name)
pub(crate) const SMARTTHINGS_VARIANTS: &[(&str, &str)] = &[
    ("hub", "SmartThings Hub"),
    ("station", "SmartThings Station"),
];

// ---------------------------------------------------------------------------
// Wemo device hostname patterns
// ---------------------------------------------------------------------------

/// Wemo variant detection: (substring, model_name)
pub(crate) const WEMO_VARIANTS: &[(&str, &str)] = &[
    ("mini", "Wemo Mini"),
    ("insight", "Wemo Insight"),
    ("switch", "Wemo Smart Plug"),
    ("plug", "Wemo Smart Plug"),
    ("dimmer", "Wemo Dimmer"),
];
