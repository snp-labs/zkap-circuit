//! [`ArtifactSet`] — the in-memory bundle of `(pk, vk, pvk, prepared_arcs, cfg)`
//! and the two caller-facing loaders.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

use ark_ar1cs::{PreparedArcs, format::ArcsFile};
use ark_groth16::{PreparedVerifyingKey, ProvingKey, VerifyingKey as Groth16VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use circuit::types::{BN254, CircuitConfig, F};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use super::error::ArtifactError;
use crate::manifest::{ArtifactEntry, Manifest, verify_manifest};

/// Wall-clock timing for loading each artifact in a CRS bundle.
#[derive(Debug, Clone, Copy, Default)]
pub struct ArtifactLoadTiming {
    /// Total time spent in the shared artifact loader.
    pub total_ms: f64,
    /// Time spent reading, sha-checking, and parsing `circuit.ar1cs`.
    pub ar1cs_ms: f64,
    /// Time spent reading, sha-checking, and deserializing `pk.bin`.
    pub pk_ms: f64,
    /// Time spent reading, sha-checking, and deserializing `vk.bin`.
    pub vk_ms: f64,
    /// Time spent reading, sha-checking, and deserializing `pvk.bin`.
    pub pvk_ms: f64,
    /// Time spent reading, sha-checking, and parsing `config.json`.
    pub circuit_config_ms: f64,
    /// Time spent sha-checking the optional EVM verifier artifact.
    pub evm_verifier_ms: f64,
    /// Time spent reading the optional, unverified `witness_gen.wasm` file
    /// (not a manifest artifact; not sha-checked).
    pub witness_gen_wasm_ms: f64,
}

/// In-memory bundle of every CRS artifact a `Prover` needs.
///
/// Populated by [`ArtifactSet::load_signed`] — the single
/// manifest-validated trust gate for the prove flow.
pub struct ArtifactSet {
    /// Groth16 proving key — loaded from `pk.bin`.
    ///
    /// Crate-private: external consumers reach the prover through
    /// [`crate::prove`] / [`crate::prove_bundles`] instead of borrowing
    /// the key directly (semver-boundary field hiding).
    pub(crate) pk: ProvingKey<BN254>,
    /// Groth16 verifying key — loaded from `vk.bin`.
    ///
    /// Crate-private: not part of the stable boundary. Proof
    /// verification goes through [`crate::verify`], which uses the
    /// prepared key below.
    ///
    /// Retained even though no in-crate reader consumes it today: it is
    /// a first-class member of the loaded + hash-checked CRS bundle (the
    /// loader deserializes and integrity-checks `vk.bin`), and
    /// `SetupOutput::into_artifact_set` populates it. Dropping it would
    /// silently narrow what the loader binds. `#[allow(dead_code)]` is
    /// the intentional choice over deleting a load-bearing artifact slot.
    #[allow(dead_code)]
    pub(crate) vk: Groth16VerifyingKey<BN254>,
    /// Prepared verifying key — loaded from `pvk.bin`.
    ///
    /// Crate-private: external consumers verify via [`crate::verify`]
    /// rather than borrowing the prepared key directly.
    pub(crate) pvk: PreparedVerifyingKey<BN254>,
    /// Prepared `.ar1cs` body — loaded from `circuit.ar1cs` and prepared once.
    ///
    /// Crate-private: consumed internally by [`crate::prove_bundles`];
    /// external consumers never touch the prepared matrices (the leak
    /// this boundary closes).
    pub(crate) prepared_arcs: PreparedArcs<F>,
    /// Circuit configuration — loaded from `config.json`.
    pub cfg: CircuitConfig,
    /// Optional `witness_gen.wasm` bytes — loaded as a PLAIN, UNVERIFIED
    /// file `<dir>/witness_gen.wasm` when present (it is NOT a manifest
    /// artifact and is NOT sha/signature-checked).
    ///
    /// The witness generator carries no circuit trust: Groth16 soundness
    /// plus the on-chain public-input pins (e.g. `h_aud_list`,
    /// `Σ partial_rhs == lhs`) enforce correctness regardless of which
    /// generator produced the witness, and `prove`'s off-circuit
    /// validation catches generator drift before proving. So the bytes are
    /// surfaced here purely as a convenience for downstream
    /// circuit-agnostic prover packages, which instantiate this wasm via a
    /// runtime (wasmtime, browser native, …) and call `synthesize_witness`
    /// over the ABI documented in the `zkap-witness-gen-wasm` crate.
    /// `Some(bytes)` iff the file exists on disk.
    pub witness_gen_wasm: Option<Vec<u8>>,
}

impl ArtifactSet {
    /// Load every artifact named in `manifest` from `dir`, verify the
    /// ed25519 signature against `verifying_key`, **and** check all sha256
    /// / `ar1cs_blake3` integrity claims before returning.
    ///
    /// This is the **primary production entry point** for environments
    /// that issue signed bundles. The signature gate fires first so a
    /// tampered hash is caught by the signature before the recomputed-sha256
    /// gate runs. The hash gates remain in place as defence-in-depth.
    ///
    /// # Contract
    ///
    /// * `manifest.signature` must be `Some(_)` — if it is `None` the load
    ///   is rejected with [`ArtifactError::Signature`] (`SignatureMissing`).
    /// * The signature must verify against `verifying_key`; any mismatch
    ///   returns [`ArtifactError::Signature`].
    /// * All sha256 / `ar1cs_blake3` claims must match the on-disk files.
    ///
    /// After the signature + hash gates pass, Groth16 key material is
    /// deserialized with arkworks' unchecked canonical path. This loader
    /// treats the manifest-authenticated bytes as the artifact identity and
    /// does not repeat subgroup / validity checks on every cold load. A
    /// wrong-but-authentic key cannot produce a valid proof for the expected
    /// circuit; that failure belongs to proving / verification, not artifact
    /// identity loading.
    ///
    /// For loading unsigned bundles (e.g. CI test fixtures, pre-F5 legacy
    /// bundles) use [`ArtifactSet::load_unsigned`] — it is explicit about
    /// skipping signature authenticity.
    pub fn load_signed(
        manifest: &Manifest,
        dir: &Path,
        verifying_key: &VerifyingKey,
    ) -> Result<Self, ArtifactError> {
        verify_manifest(manifest, verifying_key)?;
        Self::load_artifacts(manifest, dir)
    }

    /// Load signed artifacts and return per-artifact timing.
    ///
    /// Semantics are identical to [`Self::load_signed`]; the second tuple
    /// element is only diagnostic timing for callers that need to attribute
    /// cold-load cost.
    pub fn load_signed_with_timing(
        manifest: &Manifest,
        dir: &Path,
        verifying_key: &VerifyingKey,
    ) -> Result<(Self, ArtifactLoadTiming), ArtifactError> {
        verify_manifest(manifest, verifying_key)?;
        Self::load_artifacts_with_timing(manifest, dir)
    }

    /// Load every artifact named in `manifest` from `dir` and verify the
    /// sha256 / `ar1cs_blake3` integrity claims before returning.
    ///
    /// # Security
    ///
    /// **Signature authenticity is NOT checked.** The manifest's `signature`
    /// field — and therefore the authenticity of all embedded sha256 hashes —
    /// is trusted without cryptographic verification. The sha256 / blake3
    /// gates still protect against accidental corruption or filesystem-level
    /// tampering after the manifest was written, but they cannot protect
    /// against an attacker who controls the manifest file itself.
    ///
    /// Use this constructor only when:
    /// * The bundle was produced without a signing key (unsigned CI fixtures,
    ///   pre-F5 legacy bundles), **or**
    /// * The caller has authenticated the manifest through an out-of-band
    ///   channel and explicitly opts out of the in-process signature check.
    ///
    /// For production environments that issue signed bundles, prefer
    /// [`ArtifactSet::load_signed`].
    pub fn load_unsigned(manifest: &Manifest, dir: &Path) -> Result<Self, ArtifactError> {
        Self::load_artifacts(manifest, dir)
    }

    /// Load unsigned artifacts and return per-artifact timing.
    ///
    /// Semantics are identical to [`Self::load_unsigned`]; the second tuple
    /// element is only diagnostic timing for callers that need to attribute
    /// cold-load cost.
    pub fn load_unsigned_with_timing(
        manifest: &Manifest,
        dir: &Path,
    ) -> Result<(Self, ArtifactLoadTiming), ArtifactError> {
        Self::load_artifacts_with_timing(manifest, dir)
    }

    // ── Shared loading logic ──────────────────────────────────────────────

    fn load_artifacts(manifest: &Manifest, dir: &Path) -> Result<Self, ArtifactError> {
        Ok(Self::load_artifacts_with_timing(manifest, dir)?.0)
    }

    fn load_artifacts_with_timing(
        manifest: &Manifest,
        dir: &Path,
    ) -> Result<(Self, ArtifactLoadTiming), ArtifactError> {
        let total_start = Instant::now();
        let mut timing = ArtifactLoadTiming::default();

        let start = Instant::now();
        let prepared_arcs = load_arcs(dir, &manifest.artifacts.ar1cs, &manifest.ar1cs_blake3)?;
        timing.ar1cs_ms = elapsed_ms(start);

        let start = Instant::now();
        let pk = load_canonical::<ProvingKey<BN254>>(dir, &manifest.artifacts.pk, "pk")?;
        timing.pk_ms = elapsed_ms(start);

        let start = Instant::now();
        let vk = load_canonical::<Groth16VerifyingKey<BN254>>(dir, &manifest.artifacts.vk, "vk")?;
        timing.vk_ms = elapsed_ms(start);

        let start = Instant::now();
        let pvk =
            load_canonical::<PreparedVerifyingKey<BN254>>(dir, &manifest.artifacts.pvk, "pvk")?;
        timing.pvk_ms = elapsed_ms(start);

        let start = Instant::now();
        let cfg = load_circuit_config(dir, &manifest.artifacts.circuit_config)?;
        timing.circuit_config_ms = elapsed_ms(start);

        if let Some(entry) = manifest.artifacts.evm_verifier.as_ref() {
            let start = Instant::now();
            verify_sha256(dir, entry, "artifacts.evm_verifier.sha256")?;
            timing.evm_verifier_ms = elapsed_ms(start);
        }

        // `witness_gen.wasm` is NOT a manifest artifact and carries no circuit
        // trust (see `ArtifactSet::witness_gen_wasm`). Load it as a plain,
        // UNVERIFIED optional file when present, purely for downstream
        // convenience; absence is normal (e.g. native-only bundles).
        let start = Instant::now();
        let wg_path = dir.join("witness_gen.wasm");
        let witness_gen_wasm = if wg_path.is_file() {
            Some(std::fs::read(&wg_path).map_err(|e| ArtifactError::Io {
                path: wg_path.clone(),
                source: e,
            })?)
        } else {
            None
        };
        timing.witness_gen_wasm_ms = elapsed_ms(start);
        timing.total_ms = elapsed_ms(total_start);

        Ok((
            Self {
                pk,
                vk,
                pvk,
                prepared_arcs,
                cfg,
                witness_gen_wasm,
            },
            timing,
        ))
    }
}

fn load_circuit_config(dir: &Path, entry: &ArtifactEntry) -> Result<CircuitConfig, ArtifactError> {
    let path = dir.join(&entry.path);
    let bytes = std::fs::read(&path).map_err(|e| ArtifactError::Io {
        path: path.clone(),
        source: e,
    })?;
    let sha_hex = sha256_hex(&bytes);
    if sha_hex != entry.sha256 {
        return Err(ArtifactError::HashMismatch {
            field: "artifacts.circuit_config.sha256",
            expected: entry.sha256.clone(),
            got: sha_hex,
        });
    }
    parse_circuit_config(&bytes)
}

fn parse_circuit_config(bytes: &[u8]) -> Result<CircuitConfig, ArtifactError> {
    serde_json::from_slice::<CircuitConfig>(bytes).map_err(|e| ArtifactError::Deserialize {
        what: "circuit_config",
        message: format!("{e}"),
    })
}

fn load_arcs(
    dir: &Path,
    entry: &ArtifactEntry,
    expected_body_blake3_hex: &str,
) -> Result<PreparedArcs<F>, ArtifactError> {
    let path = dir.join(&entry.path);

    // sha256 of the on-disk file vs manifest.
    let sha_hex = sha256_file(&path)?;
    if sha_hex != entry.sha256 {
        return Err(ArtifactError::HashMismatch {
            field: "artifacts.ar1cs.sha256",
            expected: entry.sha256.clone(),
            got: sha_hex,
        });
    }

    // Parse verifies the 32-byte trailer against the body. Once that
    // succeeds, the trailer itself is the body Blake3 hash, so avoid
    // `arcs.body_blake3()` here; that would reserialize the full matrix set.
    //
    // Feed `ArcsFile::read_seek` from disk so checksum verification streams
    // the body instead of buffering the full `circuit.ar1cs` file.
    let file = File::open(&path).map_err(|e| ArtifactError::Io {
        path: path.clone(),
        source: e,
    })?;
    let mut reader = BufReader::new(file);
    let arcs = ArcsFile::<F>::read_seek(&mut reader)
        .map_err(|e| ArtifactError::ArcsFormat(format!("{e}")))?;
    let body_blake3_hex = hex::encode(read_ar1cs_trailer(&path)?);
    if body_blake3_hex != expected_body_blake3_hex {
        return Err(ArtifactError::HashMismatch {
            field: "ar1cs_blake3",
            expected: expected_body_blake3_hex.to_string(),
            got: body_blake3_hex,
        });
    }
    Ok(arcs.prepare())
}

fn load_canonical<T: CanonicalDeserialize>(
    dir: &Path,
    entry: &ArtifactEntry,
    what: &'static str,
) -> Result<T, ArtifactError> {
    let path = dir.join(&entry.path);

    let sha_hex = sha256_file(&path)?;
    if sha_hex != entry.sha256 {
        let field: &'static str = match what {
            "pk" => "artifacts.pk.sha256",
            "vk" => "artifacts.vk.sha256",
            "pvk" => "artifacts.pvk.sha256",
            _ => "artifacts.unknown.sha256",
        };
        return Err(ArtifactError::HashMismatch {
            field,
            expected: entry.sha256.clone(),
            got: sha_hex,
        });
    }

    // Trust model: sha256 has already bound these bytes to the caller's
    // manifest (and `load_signed` authenticated that manifest before this
    // point). Use the unchecked canonical decoder to avoid repeating expensive
    // subgroup / curve-validity checks during every bundle load; malformed
    // wire bytes still fail to decode, and semantically wrong keys fail later
    // when proving or verifying against the expected circuit.
    let file = File::open(&path).map_err(|e| ArtifactError::Io {
        path: path.clone(),
        source: e,
    })?;
    let mut reader = BufReader::new(file);
    T::deserialize_uncompressed_unchecked(&mut reader).map_err(|e| ArtifactError::Deserialize {
        what,
        message: format!("{e}"),
    })
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1_000.0
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn sha256_file(path: &Path) -> Result<String, ArtifactError> {
    let file = File::open(path).map_err(|e| ArtifactError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];

    loop {
        let n = reader.read(&mut buf).map_err(|e| ArtifactError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn read_ar1cs_trailer(path: &Path) -> Result<[u8; 32], ArtifactError> {
    let mut file = File::open(path).map_err(|e| ArtifactError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let len = file
        .metadata()
        .map_err(|e| ArtifactError::Io {
            path: path.to_path_buf(),
            source: e,
        })?
        .len();
    if len < 32 {
        return Err(ArtifactError::ArcsFormat(
            "file too short to contain checksum trailer".into(),
        ));
    }

    file.seek(SeekFrom::End(-32))
        .map_err(|e| ArtifactError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    let mut trailer = [0u8; 32];
    file.read_exact(&mut trailer)
        .map_err(|e| ArtifactError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(trailer)
}

/// Read `dir/entry.path` and assert `sha256(bytes) == entry.sha256`.
///
/// Used for artifact entries that need only an integrity check (no
/// `CanonicalDeserialize` follow-up), e.g. the optional
/// `Groth16Verifier.sol`. The `field` argument is the manifest path
/// reported in [`ArtifactError::HashMismatch`] so the error message
/// names the failing slot.
fn verify_sha256(
    dir: &Path,
    entry: &ArtifactEntry,
    field: &'static str,
) -> Result<(), ArtifactError> {
    let path = dir.join(&entry.path);
    let sha_hex = sha256_file(&path)?;
    if sha_hex != entry.sha256 {
        return Err(ArtifactError::HashMismatch {
            field,
            expected: entry.sha256.clone(),
            got: sha_hex,
        });
    }
    Ok(())
}
