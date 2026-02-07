use std::collections::HashMap;
use std::io::Read;

const IEEE_OUI_CSV_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";

/// Download and parse the IEEE MA-L OUI CSV database.
/// Returns a map of OUI prefix (lowercase, colon-separated) to organization name.
pub fn download_ieee_oui() -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    eprintln!("Downloading IEEE OUI database from {}...", IEEE_OUI_CSV_URL);

    let response = reqwest::blocking::get(IEEE_OUI_CSV_URL)?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}: failed to download IEEE OUI CSV", response.status()).into());
    }

    let mut body = String::new();
    response.take(50_000_000).read_to_string(&mut body)?; // 50MB limit

    parse_ieee_csv(&body)
}

/// Parse IEEE OUI CSV content.
/// CSV columns: Registry, Assignment (6-char hex), Organization Name, Organization Address
fn parse_ieee_csv(csv_content: &str) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut entries = HashMap::new();
    let mut reader = csv::Reader::from_reader(csv_content.as_bytes());

    for result in reader.records() {
        let record = result?;
        // Columns: Registry, Assignment, Organization Name, Organization Address
        if record.len() < 3 {
            continue;
        }

        let assignment = record.get(1).unwrap_or("").trim();
        let org_name = record.get(2).unwrap_or("").trim();

        if assignment.len() != 6 || org_name.is_empty() {
            continue;
        }

        // Convert "286FB9" -> "28:6f:b9"
        let hex_lower = assignment.to_lowercase();
        let prefix = format!("{}:{}:{}", &hex_lower[0..2], &hex_lower[2..4], &hex_lower[4..6]);

        entries.insert(prefix, org_name.to_string());
    }

    eprintln!("Parsed {} IEEE OUI entries", entries.len());
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ieee_csv() {
        let csv = "Registry,Assignment,Organization Name,Organization Address\n\
                   MA-L,286FB9,Juniper Networks,\"1133 Innovation Way Sunnyvale CA US 94089\"\n\
                   MA-L,AABBCC,Apple Inc.,\"1 Apple Park Way Cupertino CA US 95014\"\n";

        let result = parse_ieee_csv(csv).unwrap();
        assert_eq!(result.get("28:6f:b9").unwrap(), "Juniper Networks");
        assert_eq!(result.get("aa:bb:cc").unwrap(), "Apple Inc.");
    }

    #[test]
    fn test_hex_to_prefix_conversion() {
        let hex = "286FB9";
        let hex_lower = hex.to_lowercase();
        let prefix = format!("{}:{}:{}", &hex_lower[0..2], &hex_lower[2..4], &hex_lower[4..6]);
        assert_eq!(prefix, "28:6f:b9");
    }
}
