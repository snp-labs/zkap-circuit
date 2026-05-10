//! Per-proof Groth16 generator backed by the wasm witness runtime.
//!
//! Each proof:
//! 1. spins up a fresh [`DefaultRuntime`] (per-proof reset — plan §2 / §8),
//! 2. postcard-encodes the [`ZkapInputV1`] payload,
//! 3. drives `witness_generator` with `arzkey.header.ar1cs_blake3` as the
//!    paired blake3,
//! 4. parses the returned bytes as an [`ArwtnsFile`],
//! 5. calls [`ark_ar1cs_prover::prove`].
//!
//! **Per-proof reset trade-off**: instantiating a fresh [`DefaultRuntime`] for
//! each JWT costs `N+1` instantiations per batch (one for the up-front pair
//! check, one per proof). This is intentional — per-proof allocator reset
//! prevents fragmentation buildup across JWTs, and is preferred over reuse.

use std::io::Cursor;
use std::path::PathBuf;

use ark_ar1cs_wtns::ArwtnsFile;
use ark_ar1cs_zkey::ArzkeyFile;
use ark_groth16::Proof;
use ark_utils::wire::ZkapInputV1;
use circuit::constants::{BN254, F};
use rand::rngs::OsRng;

use crate::error::ApplicationError;
use crate::proof::runtime::{DefaultRuntime, RuntimeError, WasmWitnessRuntime};

#[cfg(any(target_os = "android", target_os = "ios"))]
unsafe extern "C" {
    fn mi_collect(force: bool);
}

/// Trigger a mimalloc GC cycle on mobile targets.
///
/// On Android/iOS the host link is expected to provide `mi_collect` (mimalloc).
/// If the symbol is absent the linker will fail — this is intentional: it
/// surfaces a missing-allocator misconfiguration at build time rather than
/// silently leaking memory at runtime.  On non-mobile targets this is a no-op.
/// If additional platforms need GC (e.g. Tizen), add their `target_os` here.
#[inline(always)]
fn gc() {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    unsafe {
        mi_collect(true);
    }
}

pub struct ProofOutput {
    pub proofs: Vec<Proof<BN254>>,
    pub public_inputs: Vec<Vec<F>>,
}

pub struct ProofGenerator {
    pk_path: PathBuf,
    wasm_path: PathBuf,
}

impl ProofGenerator {
    pub fn new(pk_path: PathBuf, wasm_path: PathBuf) -> Self {
        Self { pk_path, wasm_path }
    }

    /// Generate one Groth16 proof per [`ZkapInputV1`]. The wasm artifact
    /// at `wasm_path` is loaded once into memory but instantiated per
    /// proof so allocator state is reset between JWTs.
    pub fn generate(&self, inputs: &[ZkapInputV1]) -> Result<ProofOutput, ApplicationError> {
        log::info!(
            "[ProofGenerator] Starting proof generation for {} inputs...",
            inputs.len()
        );

        let arzkey = self.load_arzkey()?;
        let wasm_bytes = std::fs::read(&self.wasm_path).map_err(|e| {
            ApplicationError::InvalidFormat(format!(
                "Failed to read wasm `{}`: {}",
                self.wasm_path.display(),
                e
            ))
        })?;

        // Host-side fail-fast pair check.
        //
        // Confirm the witness-generator wasm's `embedded_ar1cs_blake3`
        // matches the loaded arzkey's `header.ar1cs_blake3` *before* we
        // enter the per-proof loop. This catches stale caches, wrong
        // dist paths, and other accidental mis-pairings with a clear
        // up-front error instead of waiting for the per-proof witness
        // generation or `bind_check` to fail later.
        //
        // The wasm-side `witness_generator` still enforces the same
        // equality check internally (defense in depth). This host-side
        // check is NOT a supply-chain defense against a malicious wasm —
        // a hostile wasm can lie about its embedded blake3.
        //
        // Per-proof allocator-reset semantics are preserved: this
        // runtime is dropped immediately, and the per-input loop below
        // still spins up a fresh `DefaultRuntime` for each proof.
        {
            let mut pair_check_runtime =
                DefaultRuntime::instantiate(&wasm_bytes).map_err(map_runtime_err)?;
            let embedded = pair_check_runtime
                .embedded_ar1cs_blake3()
                .map_err(map_runtime_err)?;
            if embedded != arzkey.header.ar1cs_blake3 {
                return Err(ApplicationError::InvalidFormat(format!(
                    "ar1cs_blake3 mismatch: wasm=0x{}, arzkey=0x{}",
                    hex::encode(embedded),
                    hex::encode(arzkey.header.ar1cs_blake3),
                )));
            }
        }

        let mut rng = OsRng;
        let mut proofs = Vec::with_capacity(inputs.len());
        let mut public_inputs = Vec::with_capacity(inputs.len());

        for (i, input_v1) in inputs.iter().enumerate() {
            log::info!(
                "[ProofGenerator] Generating proof {}/{}...",
                i + 1,
                inputs.len()
            );

            let mut runtime = DefaultRuntime::instantiate(&wasm_bytes).map_err(map_runtime_err)?;
            let postcard_bytes = postcard::to_allocvec(input_v1).map_err(|e| {
                ApplicationError::ProofGenerationFailed(format!("postcard encode: {}", e))
            })?;
            let arwtns_bytes = runtime
                .generate_witness(&postcard_bytes, &arzkey.header.ar1cs_blake3)
                .map_err(map_runtime_err)?;

            let arwtns: ArwtnsFile<F> = ArwtnsFile::<F>::read(&mut Cursor::new(&arwtns_bytes))
                .map_err(|e| {
                    ApplicationError::ProofGenerationFailed(format!(
                        "ArwtnsFile::read on wasm output: {}",
                        e
                    ))
                })?;

            public_inputs.push(arwtns.instance.clone());

            let proof = ark_ar1cs_prover::prove(&arzkey, &arwtns, &mut rng).map_err(|e| {
                ApplicationError::ProofGenerationFailed(format!("Proof generation failed: {}", e))
            })?;

            // Drop wasm runtime + postcard buffer + arwtns before next iteration
            // so the host allocator reclaims them (especially load-bearing on
            // mobile — see plan §2).
            drop(runtime);
            gc();
            proofs.push(proof);
        }

        log::info!("[ProofGenerator] All proofs generated successfully");
        Ok(ProofOutput {
            proofs,
            public_inputs,
        })
    }

    fn load_arzkey(&self) -> Result<ArzkeyFile<BN254>, ApplicationError> {
        let f = std::fs::File::open(&self.pk_path).map_err(|e| {
            ApplicationError::InvalidFormat(format!(
                "Failed to open arzkey '{}': {}",
                self.pk_path.display(),
                e
            ))
        })?;
        ArzkeyFile::read(&mut std::io::BufReader::new(f))
            .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to load arzkey: {}", e)))
    }
}

fn map_runtime_err(e: RuntimeError) -> ApplicationError {
    ApplicationError::ProofGenerationFailed(format!("wasm runtime: {}", e))
}
