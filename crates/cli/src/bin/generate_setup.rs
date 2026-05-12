//! `generate_setup` — Groth16 trusted setup + paired wasm artifact +
//! v1 `manifest.json`. See plan
//! `2026-05-12-deployment-bundle-spec.md` §4/§5/§7 for the schema and
//! Stage 1 vs Stage 2 contract. RNG is `OsRng` by default; pass
//! `--rng-seed <hex> --allow-test-only` for the deterministic
//! `ChaCha20Rng` path. `SOURCE_DATE_EPOCH` pins `built_at` for
//! byte-reproducible runs.

use clap::Parser;
use rand::RngCore;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use std::path::{Path, PathBuf};
use std::process::Command;
use zkap_cli::{
    ArtifactEntry, ArtifactKey, BuildMetadata, ManifestBuilder, REQUIRED_EXPORTS, SetupProvenance,
    WasmAbi, built_at_now, canonical_json_bytes, compute_circuit_tag, die, load_config_or_exit,
    read_arzkey_blake3, read_arzkey_blake3_hex, sha256_hex, verify_wasm_exports,
};
use zkap_service::setup;

/// Default wasm size gate, in MiB.
const SIZE_LIMIT_MIB_DEFAULT: u64 = 8;

/// ZKAP public-input names in the order the circuit allocates them.
///
/// MUST stay in lockstep with `zkap_witness_wasm::ZKAP_PUBLIC_INPUT_NAMES`
/// (`crates/zkap-witness-wasm/src/lib.rs`). Drift between the two lists
/// is observable when the host SDK compares
/// `manifest.public_input_names` against the wasm export.
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
    about = "Generate Groth16 CRS, the paired wasm witness-generator artifact, and a manifest.json bundle"
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

    /// Skip wasm-opt size optimization (binaryen not installed).
    #[arg(long)]
    skip_wasm_opt: bool,

    /// Hard size gate for the final wasm artifact, in MiB.
    #[arg(long, default_value_t = SIZE_LIMIT_MIB_DEFAULT)]
    wasm_size_limit_mib: u64,
}

fn main() {
    let cli = Cli::parse();

    if cli.ptau.is_some() || cli.phase2_attestations.is_some() {
        die("--ptau / --phase2-attestations are Stage 2 only (not yet active)");
    }
    let (mut rng_box, provenance) = pick_rng(cli.rng_seed.as_deref(), cli.allow_test_only);

    let params = load_config_or_exit(Path::new(&cli.config));
    let out = PathBuf::from(&cli.output);

    let cfg_value = serde_json::to_value(&params)
        .unwrap_or_else(|e| die(format!("canonicalize config: {e}")));
    let canonical_cfg_bytes = canonical_json_bytes(&cfg_value);
    let circuit_tag = compute_circuit_tag(&cli.circuit_id, &canonical_cfg_bytes);

    println!("[1/6] Groth16 trusted setup → {}", out.display());
    let setup_output = setup(&params, &out, rng_box.as_mut(), None)
        .unwrap_or_else(|e| die(format!("setup failed: {e}")));

    let arzkey = out.join("circuit.arzkey");
    std::fs::rename(out.join("pk.arzkey"), &arzkey)
        .unwrap_or_else(|e| die(format!("rename pk.arzkey → circuit.arzkey: {e}")));
    let arzkey_blake3 = read_arzkey_blake3(&arzkey);
    let arzkey_canonical = arzkey
        .canonicalize()
        .unwrap_or_else(|e| die(format!("canonicalize arzkey '{}': {e}", arzkey.display())));

    println!("[2/6] cargo build -p zkap-witness-wasm --target wasm32-unknown-unknown --release");
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

    println!("[3/6] wasm-opt -Oz");
    let final_wasm = out.join("zkap_witness_wasm.opt.wasm");
    if cli.skip_wasm_opt {
        eprintln!("INFO: --skip-wasm-opt set; copying raw wasm without -Oz.");
        std::fs::copy(&raw_wasm, &final_wasm)
            .unwrap_or_else(|e| die(format!("copy raw wasm: {e}")));
    } else {
        run_wasm_opt(&raw_wasm, &final_wasm);
    }

    println!("[4/6] size gate {} MiB", cli.wasm_size_limit_mib);
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

    println!("[5/6] export verification");
    verify_wasm_exports(&final_wasm, REQUIRED_EXPORTS)
        .unwrap_or_else(|e| die(format!("export verify failed: {e}")));

    let wasm_sha = sha256_hex(&final_wasm).unwrap_or_else(|e| die(format!("sha256: {e}")));

    println!("[6/6] manifest.json emit");
    let build_commit = cli
        .build_commit
        .clone()
        .or_else(git_head_commit)
        .unwrap_or_else(|| "unknown".into());
    let built_at = built_at_now().unwrap_or_else(|e| die(e));
    let manifest = ManifestBuilder::new(cli.circuit_id.clone(), circuit_tag.clone())
        .with_ar1cs_blake3(read_arzkey_blake3_hex(&arzkey))
        .with_shape(
            setup_output.shape.num_instance,
            setup_output.shape.num_witness,
            setup_output.shape.num_constraints,
        )
        .with_public_input_names(ZKAP_PUBLIC_INPUT_NAMES.iter().map(|s| s.to_string()).collect())
        .with_artifact(
            ArtifactKey::Arzkey,
            make_artifact_entry(&arzkey, "circuit.arzkey", "core", None, None, None),
        )
        .with_artifact(
            ArtifactKey::Wasm,
            ArtifactEntry {
                abi: Some(WasmAbi {
                    version: 1,
                    exports: REQUIRED_EXPORTS.iter().map(|s| s.to_string()).collect(),
                }),
                ..make_artifact_entry_with_sha(
                    "zkap_witness_wasm.opt.wasm",
                    wasm_sha.clone(),
                    size,
                    "core",
                    None,
                    None,
                )
            },
        )
        .with_artifact(
            ArtifactKey::Vk,
            make_artifact_entry(&out.join("vk.key"), "vk.key", "core", None, None, None),
        )
        .with_artifact(
            ArtifactKey::EvmVerifier,
            make_artifact_entry(
                &out.join("Groth16Verifier.sol"),
                "Groth16Verifier.sol",
                "domain-optional",
                None,
                None,
                None,
            ),
        )
        .with_artifact(
            ArtifactKey::CircuitConfig,
            make_artifact_entry(
                &out.join("config.json"),
                "config.json",
                "domain",
                None,
                Some("npm:@baerae/zkap-zkp@^1".into()),
                Some("ZkapCircuitConfigV1".into()),
            ),
        )
        .with_setup_provenance(provenance)
        .with_build(BuildMetadata {
            circuit_repo: env!("CARGO_PKG_REPOSITORY").to_string(),
            circuit_commit: build_commit,
            ark_ar1cs_rev: env!("ZKAP_CLI_ARK_AR1CS_REV").to_string(),
            rustc: env!("ZKAP_CLI_RUSTC_VERSION").to_string(),
            built_at,
        })
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
    println!(
        "  wasm size     : {size} bytes (limit {} MiB)",
        cli.wasm_size_limit_mib
    );
    println!("  wasm sha256   : {wasm_sha}");
    println!("  ar1cs_blake3  : {}", hex::encode(arzkey_blake3));
    println!(
        "  setup_provenance: {}",
        match &manifest.setup_provenance {
            SetupProvenance::OsRng => "os-rng",
            SetupProvenance::Seed { .. } => "seed",
            SetupProvenance::Ceremony { .. } => "ceremony",
        }
    );
    println!("  artifacts     : manifest.json, circuit.arzkey, pk.key, vk.key, pvk.key,");
    println!("                  Groth16Verifier.sol, config.json,");
    println!("                  zkap_witness_wasm.opt.wasm");
}

/// Build an [`ArtifactEntry`] by hashing `disk_path` and reading its size.
/// `path` is the file name recorded in the manifest (relative to the
/// bundle dir), and `disk_path` is where the file currently lives.
fn make_artifact_entry(
    disk_path: &Path,
    path: &str,
    kind: &str,
    abi: Option<WasmAbi>,
    schema_owner: Option<String>,
    schema_ref: Option<String>,
) -> ArtifactEntry {
    let sha = sha256_hex(disk_path).unwrap_or_else(|e| die(format!("sha256({path}): {e}")));
    let size = std::fs::metadata(disk_path)
        .unwrap_or_else(|e| die(format!("stat({path}): {e}")))
        .len();
    make_artifact_entry_with_sha(path, sha, size, kind, schema_owner, schema_ref).with_abi(abi)
}

/// Variant of [`make_artifact_entry`] used when sha256 + size are already
/// computed (avoids a second pass over the file).
fn make_artifact_entry_with_sha(
    path: &str,
    sha256: String,
    size: u64,
    kind: &str,
    schema_owner: Option<String>,
    schema_ref: Option<String>,
) -> ArtifactEntry {
    ArtifactEntry {
        path: path.into(),
        sha256,
        size,
        kind: kind.into(),
        abi: None,
        schema_owner,
        schema_ref,
    }
}

/// Wire `abi` onto an existing entry using the struct-update shorthand.
trait WithAbi {
    fn with_abi(self, abi: Option<WasmAbi>) -> Self;
}
impl WithAbi for ArtifactEntry {
    fn with_abi(mut self, abi: Option<WasmAbi>) -> Self {
        self.abi = abi;
        self
    }
}

/// Decode `--rng-seed` and pick either `ChaCha20Rng` or `OsRng`.
fn pick_rng(seed_hex: Option<&str>, allow_test_only: bool) -> (Box<dyn RngCore>, SetupProvenance) {
    match (seed_hex, allow_test_only) {
        (Some(seed), true) => {
            let bytes = decode_seed_hex(seed)
                .unwrap_or_else(|e| die(format!("--rng-seed: {e}")));
            (
                Box::new(ChaCha20Rng::from_seed(bytes)),
                SetupProvenance::Seed { seed: seed.to_string() },
            )
        }
        (Some(_), false) => die("--rng-seed requires --allow-test-only"),
        (None, _) => (Box::new(OsRng), SetupProvenance::OsRng),
    }
}

/// Decode a 32-byte hex seed (with or without the `0x` prefix).
fn decode_seed_hex(s: &str) -> Result<[u8; 32], String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "must decode to 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `git rev-parse HEAD`, or `None` when git is unavailable or the working
/// directory is not a git repo.
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
            eprintln!("      Install binaryen for production builds (`brew install binaryen`).");
            std::fs::copy(input, output).unwrap_or_else(|e| die(format!("copy raw wasm: {e}")));
        }
        Err(e) => die(format!("wasm-opt spawn: {e}")),
    }
}
