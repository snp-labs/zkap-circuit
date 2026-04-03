#![allow(dead_code)]

use std::path::PathBuf;

use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, Proof, ProvingKey};
use circuit::baerae::BaeraeLightWeightCircuit;
use circuit::BaeraeCircuitInput;
use circuit::constants::{BN254, BNP, CG, F, ZkPasskeyConfig};
use circuit::io::load_key_uncompressed;
use rand::rngs::OsRng;

use crate::error::ApplicationError;

/// Proof generation result
pub struct ProofOutput {
    /// Generated proofs
    pub proofs: Vec<Proof<BN254>>,

    /// Public inputs for each proof
    pub public_inputs: Vec<Vec<F>>,
}

/// Proof generator
///
/// Receives BaeraeCircuitInputs and generates Groth16 proofs.
pub struct ProofGenerator {
    pk_path: PathBuf,
}

impl ProofGenerator {
    /// Creates a new ProofGenerator
    pub fn new(pk_path: PathBuf) -> Self {
        Self { pk_path }
    }

    /// Generates proofs for all BaeraeCircuitInputs
    pub fn generate<Config: ZkPasskeyConfig>(
        &self,
        inputs: &[BaeraeCircuitInput<F>],
    ) -> Result<ProofOutput, ApplicationError> {
        log::info!("[ProofGenerator] Starting proof generation for {} inputs...", inputs.len());

        // Validate CRS manifest before loading the key
        crate::manifest::validate_crs_manifest::<Config>(&self.pk_path)?;

        let pk = self.load_proving_key()?;
        let mut rng = OsRng;

        let mut proofs = Vec::with_capacity(inputs.len());
        let mut public_inputs = Vec::with_capacity(inputs.len());

        for (i, input) in inputs.iter().enumerate() {
            log::info!("[ProofGenerator] Generating proof {}/{}...", i + 1, inputs.len());

            let circuit = BaeraeLightWeightCircuit::<CG, BNP, Config>::from_input(input.clone());
            public_inputs.push(input.extract_public_inputs());

            let proof = Groth16::<BN254>::prove(&pk, circuit, &mut rng)
                .map_err(|e| ApplicationError::InvalidFormat(format!("Proof generation failed: {}", e)))?;

            proofs.push(proof);
        }

        log::info!("[ProofGenerator] All proofs generated successfully");
        Ok(ProofOutput { proofs, public_inputs })
    }

    /// Loads the ProvingKey
    fn load_proving_key(&self) -> Result<ProvingKey<BN254>, ApplicationError> {
        load_key_uncompressed::<ProvingKey<BN254>>(&self.pk_path)
            .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to load proving key: {}", e)))
    }
}
