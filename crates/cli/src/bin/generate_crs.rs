use clap::Parser;
use std::path::PathBuf;
use zkap_service::{CrsPersistConfig, groth16_setup_and_save};

#[derive(Parser)]
#[command(about = "Generate Groth16 CRS (proving key, verifying key, and Solidity verifier)")]
struct Cli {
    /// Output directory for CRS files
    #[arg(long)]
    output: String,

    /// Path to the JSON config file
    #[arg(long)]
    config: String,

    /// Profile name for manifest.json (e.g. "dev", "prod")
    #[arg(long, default_value = "dev")]
    profile: String,
}

fn main() {
    let cli = Cli::parse();

    let config_path = std::path::Path::new(&cli.config);
    let params =
        zkap_service::CircuitConfig::from_json_file(config_path).unwrap_or_else(|e| {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        });

    println!("Generate CRS files at path: {}", cli.output);
    println!("==================================================");
    println!(
        "  [JWT] Max Len: {}, Payload: {}",
        params.max_jwt_b64_len, params.max_payload_b64_len
    );
    println!(
        "  [JWT] Fields: Aud={}, Exp={}, Iss={}, Nonce={}, Sub={}",
        params.max_aud_len,
        params.max_exp_len,
        params.max_iss_len,
        params.max_nonce_len,
        params.max_sub_len
    );
    println!(
        "  [Logic] N={}, K={}, Height={}, NumAudienceLimit={}",
        params.n, params.k, params.tree_height, params.num_audience_limit
    );
    println!("==================================================");

    let persist_config = CrsPersistConfig {
        output_dir: PathBuf::from(&cli.output),
        profile: cli.profile.clone(),
    };

    groth16_setup_and_save(&params, &persist_config).unwrap_or_else(|e| {
        eprintln!("CRS generation failed: {}", e);
        std::process::exit(1);
    });

    println!("CRS generation complete.");
}
