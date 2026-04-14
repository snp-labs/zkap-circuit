use std::path::PathBuf;

use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_utils::io::load_key_uncompressed;
use circuit::ZkapCircuitInput;
use circuit::constants::{BN254, BNP, CG, F};
use circuit::zkap::ZkapCircuit;
use rand::rngs::OsRng;

use crate::error::ApplicationError;

#[cfg(any(target_os = "android", target_os = "ios"))]
unsafe extern "C" {
    fn mi_collect(force: bool);
}

/// Force freed mimalloc pages back to OS after each proof.
#[inline(always)]
fn gc() {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    // SAFETY: mi_collect is a mimalloc internal linked into this .so
    unsafe {
        mi_collect(true);
    }
}

/// Proof generation result
pub struct ProofOutput {
    /// Generated proofs
    pub proofs: Vec<Proof<BN254>>,

    /// Public inputs for each proof
    pub public_inputs: Vec<Vec<F>>,
}

/// Proof generator
///
/// Receives ZkapCircuitInputs and generates Groth16 proofs.
pub struct ProofGenerator {
    pk_path: PathBuf,
}

impl ProofGenerator {
    /// Creates a new ProofGenerator
    pub fn new(pk_path: PathBuf) -> Self {
        Self { pk_path }
    }

    /// Generates proofs for all ZkapCircuitInputs
    pub fn generate(
        &self,
        inputs: &[ZkapCircuitInput<F>],
    ) -> Result<ProofOutput, ApplicationError> {
        log::info!(
            "[ProofGenerator] Starting proof generation for {} inputs...",
            inputs.len()
        );

        let pk = self.load_proving_key()?;
        let mut rng = OsRng;

        let mut proofs = Vec::with_capacity(inputs.len());
        let mut public_inputs = Vec::with_capacity(inputs.len());

        for (i, input) in inputs.iter().enumerate() {
            log::info!(
                "[ProofGenerator] Generating proof {}/{}...",
                i + 1,
                inputs.len()
            );

            let circuit = ZkapCircuit::<CG, BNP>::from_input(input.clone());
            public_inputs.push(input.extract_public_inputs());

            let proof = Groth16::<BN254>::prove(&pk, circuit, &mut rng).map_err(|e| {
                ApplicationError::ProofGenerationFailed(format!("Proof generation failed: {}", e))
            })?;

            // Return freed CS/matrices pages to OS before next proof's allocation.
            gc();

            proofs.push(proof);
        }

        log::info!("[ProofGenerator] All proofs generated successfully");
        Ok(ProofOutput {
            proofs,
            public_inputs,
        })
    }

    /// Generates proofs using streaming mode (memory-optimised).
    ///
    /// Separates proof generation into two phases to avoid the ~1000 MB peak
    /// of `Groth16::prove` (PK + CS + matrices simultaneously):
    ///
    ///   Phase A — `witness_and_h`:    witness + h WITHOUT PK in memory (~666 MB peak)
    ///   Phase B — `compute_proof_msm`: load PK → MSM → proof              (~410 MB peak)
    ///
    /// PK is dropped before the next proof's Phase A begins.
    #[cfg(feature = "use-optimized")]
    pub fn generate_streaming(
        &self,
        inputs: &[ZkapCircuitInput<F>],
    ) -> Result<ProofOutput, ApplicationError> {
        use crate::proof::streaming_prover::{compute_proof_msm, gc, witness_and_h};
        use ark_ff::UniformRand;

        log::info!(
            "[ProofGenerator] Starting streaming proof generation for {} inputs...",
            inputs.len()
        );

        let mut rng = OsRng;
        let mut proofs = Vec::with_capacity(inputs.len());
        let mut public_inputs = Vec::with_capacity(inputs.len());

        for (i, input) in inputs.iter().enumerate() {
            log::info!(
                "[ProofGenerator] Streaming proof {}/{}...",
                i + 1,
                inputs.len()
            );

            // Phase A: witness + h — PK is NOT loaded yet
            let inp = input.clone();
            let (h, instance, w) =
                witness_and_h(move || ZkapCircuit::<CG, BNP>::from_input(inp.clone())).map_err(
                    |e| {
                        ApplicationError::ProofGenerationFailed(format!(
                            "Part 1 (witness_and_h) failed: {}",
                            e
                        ))
                    },
                )?;

            public_inputs.push(instance[1..].to_vec());

            // Return Phase A freed pages to OS before loading the 347 MB PK.
            gc();

            // Phase B: load PK → MSM — scoped so PK is freed before next iteration.
            {
                let pk = self.load_proving_key()?;
                let r = F::rand(&mut rng);
                let s = F::rand(&mut rng);
                let proof = compute_proof_msm(&pk, r, s, &h, &instance, &w).map_err(|e| {
                    ApplicationError::ProofGenerationFailed(format!(
                        "Part 2 (compute_proof_msm) failed: {}",
                        e
                    ))
                })?;
                proofs.push(proof);
            } // pk, h, instance, w dropped here before next proof's Phase A

            log::info!(
                "[ProofGenerator] Proof {}/{} completed",
                i + 1,
                inputs.len()
            );
        }

        log::info!("[ProofGenerator] Streaming generation completed");
        Ok(ProofOutput {
            proofs,
            public_inputs,
        })
    }

    /// Loads the ProvingKey
    fn load_proving_key(&self) -> Result<ProvingKey<BN254>, ApplicationError> {
        load_key_uncompressed::<ProvingKey<BN254>>(&self.pk_path).map_err(|e| {
            ApplicationError::InvalidFormat(format!("Failed to load proving key: {}", e))
        })
    }
}
