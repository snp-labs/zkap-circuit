//! `generate_setup` — Groth16 trusted setup + post-migration
//! `manifest.json`.
//!
//! Writes the seven-file post-migration CRS bundle:
//!
//!   1. `circuit.ar1cs`       (R1CS body in ark-ar1cs canonical envelope)
//!   2. `pk.bin`              (`ProvingKey<Bn254>` uncompressed)
//!   3. `vk.bin`              (`VerifyingKey<Bn254>` uncompressed)
//!   4. `pvk.bin`             (`PreparedVerifyingKey<Bn254>` uncompressed)
//!   5. `Groth16Verifier.sol` (Solidity on-chain verifier)
//!   6. `config.json`         (`CircuitConfig` JSON)
//!   7. `manifest.json`       (`zkap_service::manifest::Manifest` v1)
//!
//! Items 1–6 come from `zkap_service::setup()`; this binary produces
//! item 7 from the build metadata it owns (build commit, rustc, RFC3339
//! `built_at`).
//!
//! RNG is `OsRng` by default; pass `--rng-seed <hex> --allow-test-only`
//! for the deterministic `ChaCha20Rng` path. `SOURCE_DATE_EPOCH` pins
//! `built_at` for byte-reproducible runs.

use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::Command;
use zkap_cli::{
    ArtifactEntry, ArtifactKey, BuildMetadata, ManifestBuilder, SetupProvenance, built_at_now,
    canonical_json_bytes, compute_circuit_tag, die, load_config_or_exit, read_arcs_blake3_hex,
    sha256_hex,
};
use zkap_service::{SetupRng, setup};

/// ZKAP public-input names in the order the circuit allocates them.
///
/// Mirrors the canonical public-input ordering that downstream verifiers
/// rely on. Drift between this list and the circuit's
/// `CircuitPublicInputs::to_vec` is a host-side instance-vector bug.
const ZKAP_PUBLIC_INPUT_NAMES: &[&str] = &[
    "hanchor",
    "h_a",
    "root",
    "h_sign_user_op",
    "jwt_exp",
    "partial_rhs",
    "lhs",
    "h_aud_list",
];

#[derive(Parser)]
#[command(
    about = "Generate the post-migration Groth16 CRS bundle (circuit.ar1cs, pk.bin, vk.bin, pvk.bin, Groth16Verifier.sol, config.json, manifest.json)"
)]
struct Cli {
    /// Path to the JSON config file.
    #[arg(long)]
    config: String,

    /// Output directory for the bundle.
    #[arg(long)]
    output: String,

    /// Human-readable circuit identifier (becomes `manifest.circuit_id`).
    #[arg(long)]
    circuit_id: String,

    /// Deterministic seed for `ChaCha20Rng`, hex-encoded 32 bytes
    /// (`0x` prefix optional). Requires `--allow-test-only`.
    #[arg(long)]
    rng_seed: Option<String>,

    /// Gate for `--rng-seed`. Setting this acknowledges the bundle is
    /// test-only — production setups should use the OS RNG default.
    #[arg(long, default_value_t = false)]
    allow_test_only: bool,

    /// Powers-of-Tau file. Stage 2 placeholder — fails on Stage 1.
    #[arg(long)]
    ptau: Option<PathBuf>,

    /// Phase 2 attestation chain. Stage 2 placeholder — fails on Stage 1.
    #[arg(long)]
    phase2_attestations: Option<PathBuf>,

    /// Build commit recorded in `manifest.build.circuit_commit`. Defaults
    /// to `git rev-parse HEAD` when unset.
    #[arg(long)]
    build_commit: Option<String>,

    /// Path to a pre-built `witness_gen.wasm` (the cdylib output of
    /// `cargo build --target wasm32-unknown-unknown -p zkap-witness-gen-wasm`).
    /// When set, the file is copied to `<output>/witness_gen.wasm`
    /// and registered as an optional artifact in `manifest.json`.
    /// When omitted, the manifest is emitted without a `witness_gen`
    /// entry.
    #[arg(long)]
    witness_gen_wasm: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    if cli.ptau.is_some() || cli.phase2_attestations.is_some() {
        die("--ptau / --phase2-attestations are Stage 2 only (not yet active)");
    }
    let (setup_rng, provenance) = pick_rng(cli.rng_seed.as_deref(), cli.allow_test_only);

    let params = load_config_or_exit(Path::new(&cli.config));
    let out = PathBuf::from(&cli.output);

    let cfg_value =
        serde_json::to_value(&params).unwrap_or_else(|e| die(format!("canonicalize config: {e}")));
    let canonical_cfg_bytes = canonical_json_bytes(&cfg_value);
    let circuit_tag = compute_circuit_tag(&cli.circuit_id, &canonical_cfg_bytes);

    println!("[1/2] Groth16 trusted setup → {}", out.display());
    let setup_output = setup(&params, &out, setup_rng, None)
        .unwrap_or_else(|e| die(format!("setup failed: {e}")));

    // `circuit.ar1cs` / `pk.bin` / `vk.bin` / `pvk.bin` /
    // `Groth16Verifier.sol` / `config.json` are written by `setup()`.
    // Build the manifest from the resulting files.
    let arcs_path = out.join("circuit.ar1cs");
    let pk_path = out.join("pk.bin");
    let vk_path = out.join("vk.bin");
    let pvk_path = out.join("pvk.bin");
    let evm_path = out.join("Groth16Verifier.sol");
    let cfg_path = out.join("config.json");

    println!("[2/2] manifest.json emit");
    let ar1cs_blake3 = read_arcs_blake3_hex(&arcs_path);
    let build_commit = cli
        .build_commit
        .clone()
        .or_else(git_head_commit)
        .unwrap_or_else(|| "unknown".into());
    let built_at = built_at_now().unwrap_or_else(|e| die(e));

    let mut builder = ManifestBuilder::new(cli.circuit_id.clone(), circuit_tag.clone())
        .with_ar1cs_blake3(ar1cs_blake3.clone())
        .with_shape(
            setup_output.shape.num_instance,
            setup_output.shape.num_witness,
            setup_output.shape.num_constraints,
        )
        .with_public_input_names(
            ZKAP_PUBLIC_INPUT_NAMES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
        .with_artifact(
            ArtifactKey::Ar1cs,
            make_entry(&arcs_path, "circuit.ar1cs", "core", None, None),
        )
        .with_artifact(
            ArtifactKey::Pk,
            make_entry(&pk_path, "pk.bin", "core", None, None),
        )
        .with_artifact(
            ArtifactKey::Vk,
            make_entry(&vk_path, "vk.bin", "core", None, None),
        )
        .with_artifact(
            ArtifactKey::Pvk,
            make_entry(&pvk_path, "pvk.bin", "core", None, None),
        )
        .with_artifact(
            ArtifactKey::EvmVerifier,
            make_entry(
                &evm_path,
                "Groth16Verifier.sol",
                "domain-optional",
                None,
                None,
            ),
        )
        .with_artifact(
            ArtifactKey::CircuitConfig,
            make_entry(
                &cfg_path,
                "config.json",
                "domain",
                Some("npm:@baerae/zkap-zkp@^0.1".into()),
                Some("JsCircuitConfig".into()),
            ),
        )
        .with_setup_provenance(provenance)
        .with_build(BuildMetadata {
            circuit_repo: env!("CARGO_PKG_REPOSITORY").to_string(),
            circuit_commit: build_commit,
            ark_ar1cs_rev: env!("ZKAP_CLI_ARK_AR1CS_REV").to_string(),
            rustc: env!("ZKAP_CLI_RUSTC_VERSION").to_string(),
            built_at,
        });

    let witness_gen_attached = if let Some(wasm_src) = cli.witness_gen_wasm.as_deref() {
        let dest = out.join("witness_gen.wasm");
        std::fs::copy(wasm_src, &dest)
            .unwrap_or_else(|e| die(format!("copy witness_gen.wasm: {e}")));
        let entry = make_entry(&dest, "witness_gen.wasm", "domain-optional", None, None);
        builder = builder.with_artifact(ArtifactKey::WitnessGen, entry);
        true
    } else {
        false
    };

    let manifest = builder
        .build()
        .unwrap_or_else(|e| die(format!("manifest build: {e}")));

    let manifest_pretty = serde_json::to_string_pretty(&manifest)
        .unwrap_or_else(|e| die(format!("serialize manifest: {e}")));
    std::fs::write(out.join("manifest.json"), &manifest_pretty)
        .unwrap_or_else(|e| die(format!("write manifest.json: {e}")));

    println!();
    println!("✓ generate_setup OK");
    println!("  output dir    : {}", out.display());
    println!("  circuit_tag   : {circuit_tag}");
    println!("  ar1cs_blake3  : {ar1cs_blake3}");
    println!(
        "  setup_provenance: {}",
        match &manifest.setup_provenance {
            SetupProvenance::OsRng => "os-rng",
            SetupProvenance::Seed { .. } => "seed",
            SetupProvenance::Ceremony { .. } => "ceremony",
        }
    );
    if witness_gen_attached {
        println!(
            "  artifacts     : circuit.ar1cs, pk.bin, vk.bin, pvk.bin,\n                  Groth16Verifier.sol, config.json, manifest.json,\n                  witness_gen.wasm"
        );
    } else {
        println!(
            "  artifacts     : circuit.ar1cs, pk.bin, vk.bin, pvk.bin,\n                  Groth16Verifier.sol, config.json, manifest.json"
        );
    }
}

/// Build an [`ArtifactEntry`] by hashing `disk_path` and reading its size.
fn make_entry(
    disk_path: &Path,
    relative_path: &str,
    kind: &str,
    schema_owner: Option<String>,
    schema_ref: Option<String>,
) -> ArtifactEntry {
    let sha =
        sha256_hex(disk_path).unwrap_or_else(|e| die(format!("sha256({relative_path}): {e}")));
    let size = std::fs::metadata(disk_path)
        .unwrap_or_else(|e| die(format!("stat({relative_path}): {e}")))
        .len();
    ArtifactEntry {
        path: relative_path.into(),
        sha256: sha,
        size,
        kind: kind.into(),
        schema_owner,
        schema_ref,
    }
}

/// Decode `--rng-seed` and pick either `SetupRng::ChaCha20` or `SetupRng::OsRng`.
///
/// The `--rng-seed` path requires `--allow-test-only`; without the flag
/// the function terminates the process with an error message. This preserves
/// the safety gate: a deterministic-seed bundle can only be produced when the
/// operator explicitly acknowledges it is test-only.
fn pick_rng(seed_hex: Option<&str>, allow_test_only: bool) -> (SetupRng, SetupProvenance) {
    match (seed_hex, allow_test_only) {
        (Some(seed), true) => {
            let bytes = decode_seed_hex(seed).unwrap_or_else(|e| die(format!("--rng-seed: {e}")));
            (
                SetupRng::ChaCha20 { seed: bytes },
                SetupProvenance::Seed {
                    seed: seed.to_string(),
                },
            )
        }
        (Some(_), false) => die("--rng-seed requires --allow-test-only"),
        (None, _) => (SetupRng::OsRng, SetupProvenance::OsRng),
    }
}

/// Decode a 32-byte hex seed (with or without the `0x` prefix).
fn decode_seed_hex(s: &str) -> Result<[u8; 32], String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("must decode to 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `git rev-parse HEAD`, or `None` when git is unavailable.
fn git_head_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    Some(raw.trim().to_string())
}
