//! `generate_crs` — Groth16 CRS generation tool.
//!
//! Reads a [`circuit::constants::CircuitConfig`] from a JSON file, runs the
//! Groth16 trusted setup via [`zkap_service::setup`], and writes the proving
//! key, verifying key, and Solidity verifier to the requested output directory.
//!
//! # Usage
//!
//! ```text
//! generate_crs --config path/to/config.json --output path/to/crs/
//! ```

use clap::Parser;
use std::path::PathBuf;
use zkap_cli::{die, load_config_or_exit};
use zkap_service::setup;

#[derive(Parser)]
#[command(about = "Generate Groth16 CRS (proving key, verifying key, and Solidity verifier)")]
struct Cli {
    /// Output directory for CRS files
    #[arg(long)]
    output: String,

    /// Path to the JSON config file
    #[arg(long)]
    config: String,
}

fn main() {
    let cli = Cli::parse();

    let config_path = std::path::Path::new(&cli.config);
    let params = load_config_or_exit(config_path);

    let output_dir = PathBuf::from(&cli.output);
    println!("Generate CRS files at path: {}", output_dir.display());
    println!("==================================================");
    println!(
        "{}",
        serde_json::to_string_pretty(&params)
            .unwrap_or_else(|e| { die(format!("Failed to serialise config for display: {}", e)) })
    );
    println!("==================================================");

    setup(&params, &output_dir).unwrap_or_else(|e| die(format!("CRS generation failed: {}", e)));

    println!("CRS generation complete.");
}
