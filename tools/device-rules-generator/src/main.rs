mod codegen;
mod schema;

use clap::Parser;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "device-rules-generator")]
#[command(about = "Generate device_rules_data.rs from device_rules.toml")]
struct Cli {
    /// Path to TOML rules file
    #[arg(long, default_value = "device_rules.toml")]
    rules: PathBuf,

    /// Output path for generated Rust data file
    #[arg(long, default_value = "../../src/network/endpoint/device_rules_data.rs")]
    output: PathBuf,

    /// Validate TOML only (no output)
    #[arg(long)]
    verify: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let content = fs::read_to_string(&cli.rules)?;
    let rules: schema::DeviceRules = toml::from_str(&content)?;
    eprintln!("Loaded rules from {}", cli.rules.display());

    validate(&rules)?;

    if cli.verify {
        eprintln!("Validation PASSED");
        return Ok(());
    }

    codegen::generate(&rules, &cli.output)?;
    Ok(())
}

fn validate(rules: &schema::DeviceRules) -> Result<(), Box<dyn std::error::Error>> {
    let valid_classifications: HashSet<&str> = [
        "printer",
        "tv",
        "gaming",
        "phone",
        "vm",
        "soundbar",
        "appliance",
        "gateway",
        "computer",
        "internet",
    ]
    .into_iter()
    .collect();

    // Validate pattern classifications
    for key in rules.patterns.keys() {
        if !valid_classifications.contains(key.as_str()) {
            return Err(format!("Invalid classification in [patterns]: {}", key).into());
        }
    }

    // Validate prefix classifications
    for key in rules.prefixes.keys() {
        if !valid_classifications.contains(key.as_str()) {
            return Err(format!("Invalid classification in [prefixes]: {}", key).into());
        }
    }

    // Validate conditional classifications
    for c in &rules.conditionals {
        if !valid_classifications.contains(c.classification.as_str()) {
            return Err(format!(
                "Invalid classification in [[conditionals]]: {}",
                c.classification
            )
            .into());
        }
    }

    // Validate vendor_classes keys
    for key in rules.vendor_classes.keys() {
        if !valid_classifications.contains(key.as_str()) {
            return Err(format!("Invalid classification in [vendor_classes]: {}", key).into());
        }
    }

    // Validate services keys
    for key in rules.services.keys() {
        if !valid_classifications.contains(key.as_str()) {
            return Err(format!("Invalid classification in [services]: {}", key).into());
        }
    }

    // Check for duplicate patterns within same classification
    for (class, patterns) in &rules.patterns {
        let mut seen = HashSet::new();
        for p in patterns {
            if !seen.insert(p) {
                return Err(format!(
                    "Duplicate pattern \"{}\" in [patterns].{}",
                    p, class
                )
                .into());
            }
        }
    }

    // Check for duplicate hostname_vendor patterns with same match_type
    {
        let mut seen: HashSet<(String, String)> = HashSet::new();
        for rule in &rules.hostname_vendors {
            for pattern in &rule.patterns {
                let key = (rule.match_type.clone(), pattern.clone());
                if !seen.insert(key) {
                    return Err(format!(
                        "Duplicate hostname_vendor pattern: match_type={}, pattern={}",
                        rule.match_type, pattern
                    )
                    .into());
                }
            }
        }
    }

    // Validate match_type values
    for rule in &rules.hostname_vendors {
        if rule.match_type != "contains" && rule.match_type != "starts_with" {
            return Err(format!(
                "Invalid match_type in hostname_vendors: {}",
                rule.match_type
            )
            .into());
        }
    }
    for rule in &rules.hostname_models {
        if rule.match_type != "contains" && rule.match_type != "starts_with" {
            return Err(format!(
                "Invalid match_type in hostname_models: {}",
                rule.match_type
            )
            .into());
        }
    }

    eprintln!("Validation checks passed:");
    eprintln!("  {} classification groups", rules.patterns.len());
    eprintln!("  {} conditional rules", rules.conditionals.len());
    eprintln!("  {} vendor class groups", rules.vendor_classes.len());
    eprintln!("  {} service groups", rules.services.len());
    eprintln!("  {} tv series vendors", rules.tv_series.len());
    eprintln!("  {} hostname vendor rules", rules.hostname_vendors.len());
    eprintln!("  {} hostname model rules", rules.hostname_models.len());
    eprintln!(
        "  {} vendor type model rules",
        rules.vendor_type_models.len()
    );
    eprintln!("  {} mac vendor model rules", rules.mac_vendor_models.len());

    Ok(())
}
