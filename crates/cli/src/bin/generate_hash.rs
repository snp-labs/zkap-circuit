use std::fs::File;

use ark_ff::PrimeField;
use clap::{Args, Parser, Subcommand};
use serde::Serialize;

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
    let params =
        circuit::constants::CircuitConfig::from_json_file(config_path).unwrap_or_else(|e| {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        });

    match &cli.command {
        Commands::Aud(args) => generate_aud_hash(args, &params),
        Commands::Leaf(args) => generate_pk_leaf(args, &params),
    }
}

fn generate_aud_hash(args: &AudArgs, params: &circuit::constants::CircuitConfig) {
    let aud_vec: Vec<String> = args
        .values
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let (aud_fields, h_aud_lists) = zkap_service::generate_aud_hash(params, aud_vec.clone())
        .unwrap_or_else(|e| {
            eprintln!("Error generating audience hash: {}", e);
            std::process::exit(1);
        });

    let output = AudOutput {
        input: aud_vec,
        output: AudItem {
            aud_to_field: aud_fields
                .iter()
                .map(|f| format!("0x{:X}", f.into_bigint()))
                .collect(),
            h_aud_lists: format!("0x{:X}", h_aud_lists.into_bigint()),
        },
    };

    write_json(&args.out, &output);
    println!("Successfully generated aud hashes to {}", &args.out);
}

fn generate_pk_leaf(args: &LeafArgs, params: &circuit::constants::CircuitConfig) {
    let iss_list: Vec<&str> = args.iss.split(',').map(|s| s.trim()).collect();
    let pk_list: Vec<&str> = args.pk.split(',').map(|s| s.trim()).collect();

    if iss_list.len() != pk_list.len() {
        eprintln!(
            "Error: Mismatch in input counts. iss count: {}, pk count: {}",
            iss_list.len(),
            pk_list.len()
        );
        std::process::exit(1);
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

            let leaf = zkap_service::generate_leaf_hash(params, iss, pk).unwrap_or_else(|e| {
                eprintln!("Error computing leaf for iss '{}': {}", iss, e);
                std::process::exit(1);
            });

            let leaf_hex = format!("0x{:X}", leaf.into_bigint());
            (input_data, leaf_hex)
        })
        .unzip();

    let output_struct = LeafOutput {
        input: inputs,
        output: outputs,
    };

    write_json(&args.out, &output_struct);
    println!(
        "Successfully generated {} leaves to {}",
        output_struct.output.len(),
        args.out
    );
}

fn write_json<T: Serialize>(path: &str, data: &T) {
    let file = File::create(path).expect("Failed to create output file");
    serde_json::to_writer_pretty(file, data).expect("Failed to write JSON");
}
