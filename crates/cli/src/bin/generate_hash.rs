//! `generate_hash` — Poseidon hash utilities for audience lists and Merkle leaves.
//!
//! Reads a [`circuit::types::CircuitConfig`] from a JSON file and provides
//! two subcommands:
//!
//! - `aud` — compute the Poseidon hash of one or more audience strings and
//!   emit the individual field-element representations plus the combined
//!   `h_aud_list` hash as a JSON file.
//! - `leaf` — compute the Merkle leaf hash for each `(iss, pk)` pair and emit
//!   the results as a JSON file.
//!
//! # Usage
//!
//! ```text
//! generate_hash --config path/to/config.json aud --values "google.com,facebook.com"
//! generate_hash --config path/to/config.json leaf --iss "iss1,iss2" --pk "pk1,pk2"
//! ```

use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use zkap_cli::{die, load_config_or_exit, write_json_or_exit};

#[derive(Parser)]
struct Cli {
    /// Path to the JSON config file
    #[arg(long)]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate hash for audience list with padding
    Aud(AudArgs),

    /// Generate leaves from iss and pk lists
    Leaf(LeafArgs),
}

#[derive(Args)]
struct AudArgs {
    /// Audience values separated by comma (e.g. "google.com, facebook.com")
    #[arg(short, long)]
    values: String,

    /// Output json file path
    #[arg(short, long, default_value = "aud_output.json")]
    out: String,
}

#[derive(Args)]
struct LeafArgs {
    /// Issuer strings separated by comma (e.g. "iss1, iss2")
    #[arg(long)]
    iss: String,

    /// Public key strings separated by comma (e.g. "pk1, pk2")
    #[arg(long)]
    pk: String,

    /// Output json file path
    #[arg(short, long, default_value = "leaf_output.json")]
    out: String,
}

#[derive(Serialize)]
struct AudItem {
    aud_to_field: Vec<String>,
    h_aud_lists: String,
}

#[derive(Serialize)]
struct AudOutput {
    input: Vec<String>,
    output: AudItem,
}

#[derive(Serialize)]
struct LeafInput {
    iss: String,
    pk: String,
}

#[derive(Serialize)]
struct LeafOutput {
    input: Vec<LeafInput>,
    output: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    let config_path = std::path::Path::new(&cli.config);
    let params = load_config_or_exit(config_path);

    match &cli.command {
        Commands::Aud(args) => generate_aud_hash(args, &params),
        Commands::Leaf(args) => generate_pk_leaf(args, &params),
    }
}

fn generate_aud_hash(args: &AudArgs, params: &circuit::types::CircuitConfig) {
    let aud_vec: Vec<String> = args
        .values
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let aud_result = zkap_service::generate_aud_hash(params, aud_vec.clone())
        .unwrap_or_else(|e| die(format!("Error generating audience hash: {}", e)));

    let output = AudOutput {
        input: aud_vec,
        output: AudItem {
            aud_to_field: aud_result.individual,
            h_aud_lists: aud_result.combined,
        },
    };

    write_json_or_exit(&args.out, &output);
    println!("Successfully generated aud hashes to {}", &args.out);
}

fn generate_pk_leaf(args: &LeafArgs, params: &circuit::types::CircuitConfig) {
    let iss_list: Vec<&str> = args.iss.split(',').map(|s| s.trim()).collect();
    let pk_list: Vec<&str> = args.pk.split(',').map(|s| s.trim()).collect();

    if iss_list.len() != pk_list.len() {
        die(format!(
            "Error: Mismatch in input counts. iss count: {}, pk count: {}",
            iss_list.len(),
            pk_list.len()
        ));
    }

    println!("Processing {} items...", iss_list.len());

    let (inputs, outputs): (Vec<LeafInput>, Vec<String>) = iss_list
        .iter()
        .zip(pk_list.iter())
        .map(|(&iss, &pk)| {
            let input_data = LeafInput {
                iss: iss.to_string(),
                pk: pk.to_string(),
            };

            let leaf_hex = zkap_service::generate_leaf_hash(params, iss, pk)
                .unwrap_or_else(|e| die(format!("Error computing leaf for iss '{}': {}", iss, e)));

            (input_data, leaf_hex)
        })
        .unzip();

    let output_struct = LeafOutput {
        input: inputs,
        output: outputs,
    };

    write_json_or_exit(&args.out, &output_struct);
    println!(
        "Successfully generated {} leaves to {}",
        output_struct.output.len(),
        args.out
    );
}
