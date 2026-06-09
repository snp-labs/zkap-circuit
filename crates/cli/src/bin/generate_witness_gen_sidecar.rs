//! `generate_witness_gen_sidecar` — emit `witness_gen.json`, the
//! independent sidecar for a separately-distributed `witness_gen.wasm`.
//!
//! The witness generator ships outside the signed CRS manifest (Phase 2
//! removed the `witness_gen` manifest artifact) and is published in its
//! own release channel. This binary produces the sidecar that travels with
//! the wasm:
//!
//!   ```json
//!   { "version": "v0.1.1-rc.4",
//!     "sha256": "<sha256(witness_gen.wasm) hex>",
//!     "compatible_ar1cs_blake3": ["<1-of-1 blake3>", "<3-of-3 blake3>"] }
//!   ```
//!
//! `sha256` is a distribution-integrity guard (not a circuit-trust claim);
//! `compatible_ar1cs_blake3` gates which CRS shapes the wasm may pair with
//! and is collected from the `ar1cs_blake3` of each `--bundle` directory's
//! `manifest.json`. The optional `--circuit-commit` / `--circuit-id` are
//! recorded as non-gating provenance.
//!
//! This is intentionally independent of `generate_setup`: a witness-side
//! fix can be re-published without regenerating the CRS.

use clap::Parser;
use std::path::PathBuf;
use zkap_cli::{build_witness_gen_sidecar, die, write_json_or_exit};

#[derive(Parser)]
#[command(
    about = "Generate witness_gen.json — the independent witness_gen.wasm sidecar (sha256 + compatible_ar1cs_blake3)"
)]
struct Cli {
    /// Path to the pre-built `witness_gen.wasm` to hash and describe.
    #[arg(long)]
    witness_gen_wasm: PathBuf,

    /// Independent witness-generator version (e.g. `v0.1.1-rc.4`).
    #[arg(long)]
    version: String,

    /// CRS bundle directory whose `manifest.json` supplies an
    /// `ar1cs_blake3`. Repeatable: pass once per supported shape.
    #[arg(long = "bundle")]
    bundle: Vec<PathBuf>,

    /// Output path for the sidecar. Defaults to
    /// `<dir of --witness-gen-wasm>/witness_gen.json`.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Optional source commit that built the wasm (non-gating provenance).
    #[arg(long)]
    circuit_commit: Option<String>,

    /// Optional circuit identifier (non-gating provenance).
    #[arg(long)]
    circuit_id: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    if cli.bundle.is_empty() {
        die("--bundle is required (pass once per supported CRS shape)");
    }

    let sidecar = build_witness_gen_sidecar(
        &cli.witness_gen_wasm,
        cli.version.clone(),
        &cli.bundle,
        cli.circuit_commit.clone(),
        cli.circuit_id.clone(),
    )
    .unwrap_or_else(|e| die(e));

    let output = cli.output.unwrap_or_else(|| {
        cli.witness_gen_wasm
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("witness_gen.json")
    });

    write_json_or_exit(
        output
            .to_str()
            .unwrap_or_else(|| die("output path is not valid UTF-8")),
        &sidecar,
    );

    println!();
    println!("✓ generate_witness_gen_sidecar OK");
    println!("  version       : {}", sidecar.version);
    println!("  sha256        : {}", sidecar.sha256);
    println!(
        "  compatible    : {} shape(s)",
        sidecar.compatible_ar1cs_blake3.len()
    );
    for blake3 in &sidecar.compatible_ar1cs_blake3 {
        println!("                  {blake3}");
    }
    println!("  output        : {}", output.display());
}
