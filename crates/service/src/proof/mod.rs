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

use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
#[allow(unused_imports)]
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{
    Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey, prepare_verifying_key,
};
use circuit::constants::{BN254, BNP, CG, CircuitConfig, F};
use circuit::zkap::ZkapCircuit;
use rand::rngs::OsRng;

use crate::error::ApplicationError;

use self::context::ProofContextBuilder;
use self::generator::ProofGenerator;
use self::request::ProofRequest;

/// Output of [`groth16_setup`]: the proving key, verifying key, and pre-processed verifying key
/// needed to generate and verify Groth16 proofs for the ZKAP circuit.
pub struct SetupOutput {
    pub pk: ProvingKey<BN254>,
    pub vk: VerifyingKey<BN254>,
    pub pvk: PreparedVerifyingKey<BN254>,
}

/// Perform a Groth16 trusted setup for the ZKAP circuit parameterised by `params`.
///
/// Generates a random proving key (`pk`), verifying key (`vk`), and prepared verifying key
/// (`pvk`). The resulting [`SetupOutput`] must be saved for later use by [`prove`] and [`verify`].
pub fn groth16_setup(params: &CircuitConfig) -> Result<SetupOutput, ApplicationError> {
    let mut rng = OsRng;
    let circuit = ZkapCircuit::<CG, BNP>::generate_mock_circuit(params);

    let (pk, vk) = Groth16::<BN254>::setup(circuit, &mut rng)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Groth16 setup failed: {}", e)))?;

    let pvk = prepare_verifying_key(&vk);

    Ok(SetupOutput { pk, vk, pvk })
}

/// Generate Groth16 proofs from raw user inputs via a 4-step pipeline:
///
/// 1. **Validate & parse** — [`RawProofRequest`] → [`ProofRequest`]: checks vector lengths and
///    parses field elements, JWT tokens, and the anchor array.
/// 2. **Build context** — constructs anchor and audience contexts from the parsed request.
/// 3. **Build circuit inputs** — assembles one [`ZkapCircuitInput`] per JWT token.
/// 4. **Generate proofs** — runs `Groth16::prove` for each circuit input using the proving key
///    at `raw.pk_path`.
///
/// Returns a pair `(proofs, public_inputs)` where each entry corresponds to one JWT token.
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

/// Verify a single Groth16 proof against the prepared verifying key and public inputs.
///
/// Returns `Ok(true)` if the proof is valid, `Ok(false)` if it is not, or an error if the
/// verifier itself fails (e.g. malformed inputs).
pub fn verify(
    pvk: &PreparedVerifyingKey<BN254>,
    proof: &Proof<BN254>,
    public_inputs: &[F],
) -> Result<bool, ApplicationError> {
    Groth16::<BN254>::verify_proof(pvk, proof, public_inputs)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Proof verification failed: {}", e)))
}
