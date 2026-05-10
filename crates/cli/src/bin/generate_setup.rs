//! `generate_setup` — single-shot setup + wasm bundle.
//!
//! Combines [`zkap_service::setup`] (Groth16 trusted setup) and the host
//! side of `crates/zkap-witness-wasm/build-wasm.sh` (cargo wasm32 build,
//! `wasm-opt -Oz`, size gate, export verification, paired-fingerprint
//! report) into one command. Writes the V1 dist layout into a single
//! output directory:
//!
//! ```text
//!   <output>/
//!     circuit.arzkey
//!     pk.key
//!     vk.key
//!     pvk.key
//!     Groth16Verifier.sol
//!     config.json
//!     zkap_witness_wasm.opt.wasm
//! ```
//!
//! # Usage
//!
//! ```text
//! generate_setup --config example.json --output crs/<name>
//! ```
//!
//! # Behaviour
//!
//! 1. Runs [`zkap_service::setup`] into `<output>`. The setup writes
//!    `pk.arzkey` next to the proving/verifying key files.
//! 2. Renames `pk.arzkey` → `circuit.arzkey` (V1 naming convention).
//! 3. Spawns `cargo build -p zkap-witness-wasm --target
//!    wasm32-unknown-unknown --release` from the workspace root with
//!    `AR1CS_WITNESS_ARZKEY_PATH` pointing at `circuit.arzkey`. The wasm
//!    crate's `build.rs` reads bytes 16..48 of that file and bakes the
//!    `embedded_ar1cs_blake3` constant into the artifact.
//! 4. Runs `wasm-opt -Oz` (with the same feature-flag set as
//!    `build-wasm.sh`) to produce
//!    `<output>/zkap_witness_wasm.opt.wasm`. When `wasm-opt` is missing
//!    (`ErrorKind::NotFound`) the raw cargo output is copied with a
//!    `WARN:` line on stderr; any other spawn/exit failure is fatal.
//! 5. Hard-fails if the final wasm exceeds `--wasm-size-limit-mib` (8
//!    MiB by default).
//! 6. Verifies that `wasm_alloc`, `wasm_free`, `embedded_ar1cs_blake3`,
//!    and `witness_generator` are all present in the export section.
//! 7. Prints sha256 of the wasm and the `ar1cs_blake3` hex (= bytes
//!    16..48 of `circuit.arzkey`) so an operator can spot-check that
//!    the deployed wasm was paired with this `.arzkey`.

use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::Command;
use zkap_cli::{die, load_config_or_exit, read_arzkey_blake3, sha256_hex, verify_wasm_exports};
use zkap_service::setup;

const REQUIRED_EXPORTS: &[&str] = &[
    "wasm_alloc",
    "wasm_free",
    "embedded_ar1cs_blake3",
    "witness_generator",
];
const SIZE_LIMIT_MIB_DEFAULT: u64 = 8;

#[derive(Parser)]
#[command(
    about = "Generate Groth16 CRS and the paired wasm witness-generator artifact in one command"
)]
struct Cli {
    /// Path to the JSON config file
    #[arg(long)]
    config: String,

    /// Output directory for the bundle
    #[arg(long)]
    output: String,

    /// Skip wasm-opt size optimization (binaryen not installed)
    #[arg(long)]
    skip_wasm_opt: bool,

    /// Hard size gate for the final wasm artifact, in MiB
    #[arg(long, default_value_t = SIZE_LIMIT_MIB_DEFAULT)]
    wasm_size_limit_mib: u64,
}

fn main() {
    let cli = Cli::parse();
    let params = load_config_or_exit(Path::new(&cli.config));
    let out = PathBuf::from(&cli.output);

    println!("[1/5] Groth16 trusted setup → {}", out.display());
    setup(&params, &out).unwrap_or_else(|e| die(format!("setup failed: {e}")));

    let arzkey = out.join("circuit.arzkey");
    std::fs::rename(out.join("pk.arzkey"), &arzkey)
        .unwrap_or_else(|e| die(format!("rename pk.arzkey → circuit.arzkey: {e}")));
    let arzkey_blake3 = read_arzkey_blake3(&arzkey);
    let arzkey_canonical = arzkey
        .canonicalize()
        .unwrap_or_else(|e| die(format!("canonicalize arzkey '{}': {e}", arzkey.display())));

    println!(
        "[2/5] cargo build -p zkap-witness-wasm --target wasm32-unknown-unknown --release"
    );
    let workspace_root = locate_workspace_root();
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "-p",
            "zkap-witness-wasm",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
        ])
        .env("AR1CS_WITNESS_ARZKEY_PATH", &arzkey_canonical)
        .current_dir(&workspace_root)
        .status()
        .unwrap_or_else(|e| die(format!("cargo build spawn failed: {e}")));
    if !status.success() {
        die(format!(
            "cargo wasm32 build failed (exit {:?})",
            status.code()
        ));
    }
    let raw_wasm =
        workspace_root.join("target/wasm32-unknown-unknown/release/zkap_witness_wasm.wasm");
    if !raw_wasm.exists() {
        die(format!(
            "expected cargo to produce '{}' but it is missing",
            raw_wasm.display()
        ));
    }

    println!("[3/5] wasm-opt -Oz");
    let final_wasm = out.join("zkap_witness_wasm.opt.wasm");
    if cli.skip_wasm_opt {
        eprintln!("INFO: --skip-wasm-opt set; copying raw wasm without -Oz.");
        std::fs::copy(&raw_wasm, &final_wasm)
            .unwrap_or_else(|e| die(format!("copy raw wasm: {e}")));
    } else {
        run_wasm_opt(&raw_wasm, &final_wasm);
    }

    println!("[4/5] size gate {} MiB", cli.wasm_size_limit_mib);
    let size = std::fs::metadata(&final_wasm)
        .unwrap_or_else(|e| die(format!("stat final wasm: {e}")))
        .len();
    let limit = cli.wasm_size_limit_mib * 1024 * 1024;
    if size > limit {
        die(format!(
            "wasm {size} bytes > limit {limit} ({} MiB)",
            cli.wasm_size_limit_mib
        ));
    }

    println!("[5/5] export verification");
    verify_wasm_exports(&final_wasm, REQUIRED_EXPORTS)
        .unwrap_or_else(|e| die(format!("export verify failed: {e}")));

    let wasm_sha = sha256_hex(&final_wasm).unwrap_or_else(|e| die(format!("sha256: {e}")));
    println!();
    println!("✓ generate_setup OK");
    println!("  output dir    : {}", out.display());
    println!(
        "  wasm size     : {size} bytes (limit {} MiB)",
        cli.wasm_size_limit_mib
    );
    println!("  wasm sha256   : {wasm_sha}");
    println!("  ar1cs_blake3  : {}", hex::encode(arzkey_blake3));
    println!("  artifacts     : circuit.arzkey, pk.key, vk.key, pvk.key,");
    println!("                  Groth16Verifier.sol, config.json,");
    println!("                  zkap_witness_wasm.opt.wasm");
}

/// Workspace root: `crates/cli/..` `/..` (CARGO_MANIFEST_DIR points at
/// `crates/cli`).
fn locate_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/cli has parent")
        .parent()
        .expect("crates/ has parent")
        .to_path_buf()
}

/// Run `wasm-opt -Oz` with the same feature flags as
/// `crates/zkap-witness-wasm/build-wasm.sh`. On `ErrorKind::NotFound`
/// (binaryen not installed) the raw wasm is copied with a stderr
/// warning — every other failure is fatal so silent skips do not slip
/// past CI.
fn run_wasm_opt(input: &Path, output: &Path) {
    let status = Command::new("wasm-opt")
        .args([
            "-Oz",
            "--enable-bulk-memory",
            "--enable-mutable-globals",
            "--enable-nontrapping-float-to-int",
            "--enable-sign-ext",
            "--enable-reference-types",
            "--enable-multivalue",
        ])
        .arg(input)
        .arg("-o")
        .arg(output)
        .status();
    match status {
        Ok(s) if s.success() => (),
        Ok(s) => die(format!("wasm-opt exited {:?}", s.code())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("WARN: wasm-opt not on PATH; copying raw wasm without -Oz.");
            eprintln!(
                "      Install binaryen for production builds (`brew install binaryen`)."
            );
            std::fs::copy(input, output)
                .unwrap_or_else(|e| die(format!("copy raw wasm: {e}")));
        }
        Err(e) => die(format!("wasm-opt spawn: {e}")),
    }
}
