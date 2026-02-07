/// 3-tier vendor name normalization pipeline.
///
/// Tier 1: Exact OUI overrides (handled externally - checked before calling normalize)
/// Tier 2: Organization name mapping via substring rules
/// Tier 3: Corporate suffix stripping for unknown vendors

/// Tier 2: Map IEEE organization names to our canonical vendor names via substring matching.
/// Returns None if no mapping matches (falls through to Tier 3).
pub fn map_organization_name(org_name: &str) -> Option<&'static str> {
    let lower = org_name.to_lowercase();

    // Order matters: more specific matches first
    let rules: &[(&[&str], &str)] = &[
        (&["eero"], "eero"),
        (&["philips lighting", "signify", "philips hue"], "Philips Hue"),
        (&["amazon", "amzn"], "Amazon"),
        (&["apple"], "Apple"),
        (&["samsung"], "Samsung"),
        (&["google", "nest labs"], "Google"),
        (&["huawei"], "Huawei"),
        (&["hewlett", "hp inc", "hp enterprise", "aruba"], "HP"),
        (&["cisco"], "Cisco"),
        (&["microsoft"], "Microsoft"),
        (&["sony"], "Sony"),
        (&["nintendo"], "Nintendo"),
        (&["lg electron", "lg innotek"], "LG"),
        (&["tp-link"], "TP-Link"),
        (&["belkin"], "Belkin"),
        (&["intel"], "Intel"),
        (&["ubiquiti"], "Ubiquiti"),
        (&["espressif"], "Espressif"),
        (&["roku"], "Roku"),
        (&["ring llc", "ring.com"], "Ring"),
        (&["texas instruments"], "Texas Instruments"),
        (&["arris"], "ARRIS"),
        (&["commscope"], "Commscope"),
        (&["netgear"], "Netgear"),
        (&["linksys"], "Linksys"),
        (&["brother"], "Brother"),
        (&["canon"], "Canon"),
        (&["epson"], "Epson"),
        (&["dell"], "Dell"),
        (&["lenovo"], "Lenovo"),
        (&["asus", "asustek"], "ASUS"),
        (&["logitech", "slim devices"], "Logitech"),
        (&["yamaha"], "Yamaha"),
        (&["denon"], "Denon"),
        (&["sonos"], "Sonos"),
        (&["irobot"], "iRobot"),
        (&["roborock"], "Roborock"),
        (&["dyson"], "Dyson"),
        (&["ecobee"], "Ecobee"),
        (&["wyze"], "Wyze"),
        (&["tuya", "hangzhou tuya"], "Tuya"),
        (&["simplisafe"], "SimpliSafe"),
        (&["dahua"], "Dahua"),
        (&["bosch", "bsh hausger"], "Bosch"),
        (&["synology"], "Synology"),
        (&["hisense"], "Hisense"),
        (&["vizio"], "Vizio"),
        (&["mikrotik", "routerboard"], "MikroTik"),
        (&["juniper"], "Juniper"),
        (&["fortinet"], "Fortinet"),
        (&["d-link"], "D-Link"),
        (&["zyxel"], "ZyXEL"),
        (&["tcl", "shenzhen tcl"], "TCL"),
        (&["fn-link"], "FN-Link"),
        (&["azurewave"], "AzureWave"),
        (&["liteon", "lite-on"], "LiteON"),
        (&["seeed"], "Seeed"),
        (&["asrock"], "ASRock"),
        (&["proxmox"], "Proxmox"),
        (&["raspberry"], "Raspberry Pi"),
        (&["nvidia"], "NVIDIA"),
        (&["qualcomm"], "Qualcomm"),
        (&["broadcom"], "Broadcom"),
        (&["realtek"], "Realtek"),
        (&["mediatek"], "MediaTek"),
        (&["motorola"], "Motorola"),
        (&["htc"], "HTC"),
        (&["oneplus"], "OnePlus"),
        (&["xiaomi"], "Xiaomi"),
        (&["oppo"], "OPPO"),
        (&["bose"], "Bose"),
        (&["harman"], "Harman"),
        (&["honeywell"], "Honeywell"),
        (&["whirlpool"], "Whirlpool"),
        (&["tesla"], "Tesla"),
        (&["echostar"], "EchoStar"),
        (&["wistron"], "Wistron"),
        (&["foxconn", "hon hai"], "Foxconn"),
        (&["quanta"], "Quanta"),
        (&["pegatron"], "Pegatron"),
        (&["compal"], "Compal"),
    ];

    for (keywords, canonical) in rules {
        for keyword in *keywords {
            if lower.contains(keyword) {
                return Some(canonical);
            }
        }
    }

    None
}

/// Tier 3: Strip common corporate suffixes to produce cleaner names.
/// Applied only when Tier 1 and Tier 2 don't match.
pub fn strip_corporate_suffixes(name: &str) -> String {
    let suffixes = [
        ", Inc.",
        ", Inc",
        " Inc.",
        " Inc",
        ", LLC",
        " LLC",
        ", Ltd.",
        ", Ltd",
        " Ltd.",
        " Ltd",
        " Limited",
        ", Corp.",
        ", Corp",
        " Corp.",
        " Corp",
        " Corporation",
        " GmbH",
        " AG",
        " Co.",
        " Co",
        ", Co.",
        ", Co",
        " S.A.",
        " S.A",
        " S.p.A.",
        " B.V.",
        " N.V.",
        " Pty",
        " PLC",
        " plc",
        " Technologies",
        " Technology",
        " Electronics",
        " International",
        " Solutions",
        " Systems",
        " Devices",
        " Communications",
        " Semiconductor",
        " Industries",
        " Group",
        " Holdings",
    ];

    let mut result = name.trim().to_string();

    // Multiple passes to handle combinations like "Foo Technologies, Inc."
    for _ in 0..3 {
        let before = result.clone();
        for suffix in &suffixes {
            if result.ends_with(suffix) {
                result = result[..result.len() - suffix.len()].trim_end().to_string();
            }
        }
        // Also strip trailing comma left after removal
        result = result.trim_end_matches(',').trim_end().to_string();
        if result == before {
            break;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_organization_name() {
        assert_eq!(map_organization_name("Apple, Inc."), Some("Apple"));
        assert_eq!(map_organization_name("Samsung Electronics Co.,Ltd"), Some("Samsung"));
        assert_eq!(map_organization_name("HUAWEI TECHNOLOGIES CO.,LTD"), Some("Huawei"));
        assert_eq!(map_organization_name("Intel Corporate"), Some("Intel"));
        assert_eq!(map_organization_name("Amazon Technologies Inc."), Some("Amazon"));
        assert_eq!(map_organization_name("eero inc."), Some("eero"));
        assert_eq!(map_organization_name("Unknown Company XYZ"), None);
    }

    #[test]
    fn test_strip_corporate_suffixes() {
        assert_eq!(strip_corporate_suffixes("Acme, Inc."), "Acme");
        assert_eq!(strip_corporate_suffixes("Foo Technologies, Ltd."), "Foo");
        assert_eq!(strip_corporate_suffixes("Bar Electronics Corporation"), "Bar");
        assert_eq!(strip_corporate_suffixes("Simple Name"), "Simple Name");
        assert_eq!(strip_corporate_suffixes("Baz GmbH"), "Baz");
    }
}
