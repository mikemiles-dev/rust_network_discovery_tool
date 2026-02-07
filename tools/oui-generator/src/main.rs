mod codegen;
mod ieee;
mod macaddress_io;
mod normalize;

use clap::Parser;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "oui-generator")]
#[command(about = "Generate mac_vendors.rs from IEEE OUI database with local overrides")]
struct Cli {
    /// Output path for generated mac_vendors.rs
    #[arg(long, default_value = "../../src/network/endpoint/mac_vendors.rs")]
    output: PathBuf,

    /// Path to overrides.toml file
    #[arg(long, default_value = "overrides.toml")]
    overrides: PathBuf,

    /// macaddress.io API key for optional enrichment
    #[arg(long)]
    macaddress_io_key: Option<String>,

    /// Maximum number of macaddress.io API queries per run
    #[arg(long, default_value = "100")]
    max_queries: usize,

    /// Verify that all original override entries are preserved in output
    #[arg(long)]
    verify: bool,

    /// Only verify existing output without regenerating
    #[arg(long)]
    verify_only: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Load overrides (Tier 1)
    let overrides = load_overrides(&cli.overrides)?;
    eprintln!("Loaded {} override entries", overrides.len());

    if cli.verify_only {
        return verify_output(&cli.output, &overrides);
    }

    // Download IEEE OUI database
    let ieee_entries = ieee::download_ieee_oui()?;

    // Optional macaddress.io enrichment
    if let Some(ref api_key) = cli.macaddress_io_key {
        let prefixes: Vec<String> = ieee_entries.keys().cloned().collect();
        let _enrichment = macaddress_io::enrich_entries(api_key, &prefixes, cli.max_queries)?;
        // Enrichment data is cached for future use but not directly used in vendor names yet
    }

    // Merge: overrides take priority, then normalize IEEE names
    let merged = merge_entries(&overrides, &ieee_entries);
    eprintln!(
        "Merged database: {} entries ({} from overrides, {} new from IEEE)",
        merged.len(),
        overrides.len(),
        merged.len() - overrides.len()
    );

    // Generate output
    codegen::generate_mac_vendors_rs(&merged, &cli.output)?;

    // Verify if requested
    if cli.verify {
        verify_output(&cli.output, &overrides)?;
    }

    Ok(())
}

/// Load override entries from TOML file.
fn load_overrides(path: &PathBuf) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let parsed: toml::Value = content.parse()?;

    let mut overrides = HashMap::new();

    if let Some(table) = parsed.get("overrides").and_then(|v| v.as_table()) {
        for (key, value) in table {
            if let Some(vendor) = value.as_str() {
                overrides.insert(key.clone(), vendor.to_string());
            }
        }
    }

    Ok(overrides)
}

/// Merge override entries with IEEE entries, applying normalization.
fn merge_entries(
    overrides: &HashMap<String, String>,
    ieee_entries: &HashMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged = BTreeMap::new();

    // First, add all IEEE entries with normalization (Tier 2 + Tier 3)
    for (prefix, org_name) in ieee_entries {
        let vendor = if let Some(canonical) = normalize::map_organization_name(org_name) {
            canonical.to_string()
        } else {
            normalize::strip_corporate_suffixes(org_name)
        };
        merged.insert(prefix.clone(), vendor);
    }

    // Then, override with our curated entries (Tier 1 - highest priority)
    for (prefix, vendor) in overrides {
        merged.insert(prefix.clone(), vendor.clone());
    }

    merged
}

/// Verify that all original override entries are present in the generated output.
fn verify_output(
    output_path: &PathBuf,
    overrides: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(output_path)?;

    let mut missing = Vec::new();
    let mut mismatched = Vec::new();

    for (prefix, expected_vendor) in overrides {
        let search = format!("(\"{}\", \"", prefix);
        if let Some(pos) = content.find(&search) {
            // Extract the vendor name from the line
            let after = &content[pos + search.len()..];
            if let Some(end) = after.find("\")") {
                let actual_vendor = &after[..end];
                if actual_vendor != expected_vendor {
                    mismatched.push((prefix.clone(), expected_vendor.clone(), actual_vendor.to_string()));
                }
            }
        } else {
            missing.push((prefix.clone(), expected_vendor.clone()));
        }
    }

    if missing.is_empty() && mismatched.is_empty() {
        eprintln!(
            "Verification PASSED: all {} override entries preserved correctly",
            overrides.len()
        );
        Ok(())
    } else {
        if !missing.is_empty() {
            eprintln!("MISSING entries ({}):", missing.len());
            for (prefix, vendor) in &missing {
                eprintln!("  {} -> {}", prefix, vendor);
            }
        }
        if !mismatched.is_empty() {
            eprintln!("MISMATCHED entries ({}):", mismatched.len());
            for (prefix, expected, actual) in &mismatched {
                eprintln!("  {} -> expected {:?}, got {:?}", prefix, expected, actual);
            }
        }
        Err(format!(
            "Verification FAILED: {} missing, {} mismatched",
            missing.len(),
            mismatched.len()
        )
        .into())
    }
}
