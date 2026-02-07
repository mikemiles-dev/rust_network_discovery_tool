use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const API_URL: &str = "https://api.macaddress.io/v1";
const CACHE_DIR: &str = "cache";
const CACHE_FILE: &str = "cache/macaddress_io.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MacAddressInfo {
    pub company_name: Option<String>,
    pub applications: Option<String>,
}

/// Load cached macaddress.io results from disk.
pub fn load_cache() -> HashMap<String, MacAddressInfo> {
    let path = Path::new(CACHE_FILE);
    if !path.exists() {
        return HashMap::new();
    }
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

/// Save cache to disk.
pub fn save_cache(cache: &HashMap<String, MacAddressInfo>) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(CACHE_DIR)?;
    let json = serde_json::to_string_pretty(cache)?;
    fs::write(CACHE_FILE, json)?;
    Ok(())
}

/// Query macaddress.io for a single OUI prefix. Returns None on error or rate limit.
pub fn query_oui(
    api_key: &str,
    oui: &str,
) -> Result<Option<MacAddressInfo>, Box<dyn std::error::Error>> {
    // Convert "aa:bb:cc" to "AABBCC" for API query
    let search = oui.replace(':', "").to_uppercase();
    let url = format!("{}?apiKey={}&output=json&search={}", API_URL, api_key, search);

    let response = reqwest::blocking::get(&url)?;

    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        eprintln!("Rate limited by macaddress.io - stopping enrichment");
        return Ok(None);
    }

    if !response.status().is_success() {
        return Ok(None);
    }

    let body: serde_json::Value = response.json()?;

    let company_name = body
        .get("vendorDetails")
        .and_then(|v| v.get("companyName"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let applications = body
        .get("blockDetails")
        .and_then(|v| v.get("blockFound"))
        .and_then(|v| {
            if v.as_bool() == Some(true) {
                body.get("blockDetails")
                    .and_then(|b| b.get("applicationType"))
                    .and_then(|a| a.as_str())
                    .map(|s| s.to_string())
            } else {
                None
            }
        });

    Ok(Some(MacAddressInfo {
        company_name,
        applications,
    }))
}

/// Enrich entries using macaddress.io API with caching and rate limiting.
/// Returns the number of new entries queried.
pub fn enrich_entries(
    api_key: &str,
    prefixes: &[String],
    max_queries: usize,
) -> Result<HashMap<String, MacAddressInfo>, Box<dyn std::error::Error>> {
    let mut cache = load_cache();
    let mut new_queries = 0;

    for prefix in prefixes {
        if cache.contains_key(prefix) {
            continue;
        }

        if new_queries >= max_queries {
            eprintln!(
                "Reached max queries limit ({}). Run again later to continue.",
                max_queries
            );
            break;
        }

        match query_oui(api_key, prefix)? {
            Some(info) => {
                cache.insert(prefix.clone(), info);
                new_queries += 1;

                // Save periodically
                if new_queries % 50 == 0 {
                    save_cache(&cache)?;
                    eprintln!("  Queried {} new entries (total cached: {})", new_queries, cache.len());
                }

                // Simple rate limiting: ~2 requests/second
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            None => {
                // Rate limited or error - stop
                break;
            }
        }
    }

    save_cache(&cache)?;
    eprintln!(
        "macaddress.io enrichment: {} new queries, {} total cached",
        new_queries,
        cache.len()
    );
    Ok(cache)
}
