//! ZKAP proof generation service
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                           prove                                 │
//! │                          (entry point)                          │
//! └───────────────────────────────┬─────────────────────────────────┘
//!                                 │
//!                 ┌───────────────┼───────────────┐
//!                 ▼               ▼               ▼
//! ┌───────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
//! │  RawProofRequest  │ │  ProofRequest   │ │ ProofContextBuilder │
//! │  (input collect)  │→│ (validate/parse)│→│  (context build)    │
//! └───────────────────┘ └─────────────────┘ └──────────┬──────────┘
//!                                                      │
//!                                                      ▼
//!                                          ┌──────────────────────┐
//!                                          │    CircuitInput[]    │
//!                                          │  (circuit input structs) │
//!                                          └──────────┬───────────┘
//!                                                     │
//!                                                     ▼
//!                                          ┌──────────────────────┐
//!                                          │   ProofGenerator     │
//!                                          │  (proof generation)  │
//!                                          └──────────┬───────────┘
//!                                                     │
//!                                                     ▼
//!                                          ┌──────────────────────┐
//!                                          │    ProofOutput       │
//!                                          │ (proof + pub inputs) │
//!                                          └──────────────────────┘
//! ```

pub mod context;
pub mod generator;
pub mod request;
pub mod types;

pub use request::RawProofRequest;

#[allow(unused_imports)]
use ark_crypto_primitives::snark::SNARK;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey, prepare_verifying_key};
use circuit::constants::{BN254, BNP, CG, F, CircuitConfig};
use circuit::zkap::ZkapCircuit;
use rand::rngs::OsRng;

use crate::error::ApplicationError;

use self::context::ProofContextBuilder;
use self::generator::ProofGenerator;
use self::request::ProofRequest;

/// Setup output containing proving key, verifying key, and prepared verifying key
pub struct SetupOutput {
    pub pk: ProvingKey<BN254>,
    pub vk: VerifyingKey<BN254>,
    pub pvk: PreparedVerifyingKey<BN254>,
}

/// Groth16 trusted setup
pub fn groth16_setup(params: &CircuitConfig) -> Result<SetupOutput, ApplicationError> {
    let mut rng = OsRng;
    let circuit = ZkapCircuit::<CG, BNP>::generate_mock_circuit(params);

    let (pk, vk) = Groth16::<BN254>::setup(circuit, &mut rng)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Groth16 setup failed: {}", e)))?;

    let pvk = prepare_verifying_key(&vk);

    Ok(SetupOutput { pk, vk, pvk })
}

/// 1. RawProofRequest -> ProofRequest (validation and parsing)
/// 2. ProofRequest -> CircuitInput[] (context building)
/// 3. CircuitInput[] -> Proof[] (proof generation)
#[allow(clippy::type_complexity)]
pub fn prove(
    params: &CircuitConfig,
    raw: RawProofRequest,
) -> Result<(Vec<Proof<BN254>>, Vec<Vec<F>>), ApplicationError> {
    // 1. Validate and parse inputs
    log::info!("[ZKAP-v2] Step 1: Validating and parsing inputs...");
    let request = ProofRequest::from_raw(params, raw)?;
    log::info!("[ZKAP-v2] Step 1 completed: Input validation passed");

    // 2. Build context
    log::info!("[ZKAP-v2] Step 2: Building proof context...");
    let builder = ProofContextBuilder::new(params, request.clone())
        .build_anchor_context()?
        .build_audience_context()?;
    log::info!("[ZKAP-v2] Step 2 completed: Context built");

    // 3. Build circuit inputs
    log::info!("[ZKAP-v2] Step 3: Building circuit inputs...");
    let circuit_inputs = builder.build_all_circuit_inputs()?;
    log::info!(
        "[ZKAP-v2] Step 3 completed: {} circuit inputs created",
        circuit_inputs.len()
    );

    // 4. Generate proofs
    log::info!("[ZKAP-v2] Step 4: Generating proofs...");
    let generator = ProofGenerator::new(request.pk_path.clone());

    let output = generator.generate(params, &circuit_inputs)?;

    log::info!(
        "[ZKAP-v2] Step 4 completed: {} proofs generated",
        output.proofs.len()
    );

    Ok((output.proofs, output.public_inputs))
}

/// Verify a Groth16 proof
pub fn verify(
    pvk: &PreparedVerifyingKey<BN254>,
    proof: &Proof<BN254>,
    public_inputs: &[F],
) -> Result<bool, ApplicationError> {
    Groth16::<BN254>::verify_proof(pvk, proof, public_inputs)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Proof verification failed: {}", e)))
}
