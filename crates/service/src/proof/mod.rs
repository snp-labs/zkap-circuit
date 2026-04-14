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
#[cfg(feature = "use-optimized")]
mod streaming_prover;
pub mod types;

pub use request::RawProofRequest;

use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
#[allow(unused_imports)]
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey, prepare_verifying_key};
use circuit::constants::{BN254, BNP, CG, CircuitConfig, F};
use circuit::zkap::ZkapCircuit;
use rand::rngs::OsRng;
use std::path::Path;

use crate::dto::{ProofComponents, ZkapProofResult};
use crate::error::ApplicationError;
use ark_utils::hex_decimal_to_field;

use self::context::ProofContextBuilder;
use self::generator::ProofGenerator;
use self::request::ProofRequest;

/// Opaque handle to a Groth16 prepared verifying key.
///
/// Obtained from [`SetupOutput::verifying_context`]. Hides arkworks internals from callers.
pub struct VerifyingContext(pub(crate) PreparedVerifyingKey<BN254>);

/// Output of [`setup`]: the proving key, verifying key, and pre-processed verifying key
/// needed to generate and verify Groth16 proofs for the ZKAP circuit.
pub struct SetupOutput {
    pub(crate) pk: ProvingKey<BN254>,
    pub(crate) vk: VerifyingKey<BN254>,
    pub(crate) pvk: PreparedVerifyingKey<BN254>,
}

impl SetupOutput {
    /// Return an opaque [`VerifyingContext`] for use with [`verify`].
    pub fn verifying_context(&self) -> VerifyingContext {
        VerifyingContext(self.pvk.clone())
    }

    /// Number of public inputs in the verifying key (includes the constant "1" element).
    pub fn public_input_count(&self) -> usize {
        self.pvk.vk.gamma_abc_g1.len()
    }
}

/// Perform a Groth16 trusted setup and persist all artifacts to `output_dir`.
///
/// Writes five files to `output_dir`:
///   - `pk.key`              — proving key (uncompressed binary)
///   - `vk.key`              — verifying key (uncompressed binary)
///   - `pvk.key`             — prepared verifying key (uncompressed binary)
///   - `Groth16Verifier.sol` — Solidity on-chain verifier
///   - `config.json`         — the input `params` in JSON (loadable via [`crate::load_circuit_config`])
///
/// Returns the in-memory [`SetupOutput`] for immediate use with [`prove`] and [`verify`].
/// The proving key path for [`RawProofRequest`] is `output_dir.join("pk.key")`.
pub fn setup(params: &CircuitConfig, output_dir: &Path) -> Result<SetupOutput, ApplicationError> {
    let mut rng = OsRng;
    let circuit = ZkapCircuit::<CG, BNP>::generate_mock_circuit(params);

    let (pk, vk) = Groth16::<BN254>::setup(circuit, &mut rng)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Groth16 setup failed: {}", e)))?;

    let pvk = prepare_verifying_key(&vk);
    let output = SetupOutput { pk, vk, pvk };

    crate::crs::persist_setup_output(&output, params, output_dir)?;

    Ok(output)
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
/// Returns a [`ZkapProofResult`] containing proofs and hex-encoded public inputs.
pub fn prove(
    params: &CircuitConfig,
    raw: RawProofRequest,
) -> Result<ZkapProofResult, ApplicationError> {
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

    #[cfg(feature = "use-optimized")]
    let output = generator.generate_streaming(&circuit_inputs)?;

    #[cfg(not(feature = "use-optimized"))]
    let output = generator.generate(&circuit_inputs)?;
    log::info!(
        "[ZKAP-v2] Step 4 completed: {} proofs generated",
        output.proofs.len()
    );

    Ok((output.proofs, output.public_inputs).into())
}

/// Verify a single Groth16 proof against an opaque verifying context.
///
/// Accepts String-encoded public inputs (hex field-element format) and a
/// [`ProofComponents`] produced by [`prove`]. Returns `Ok(true)` if the proof is valid,
/// `Ok(false)` if it is not, or an error if inputs are malformed or the verifier fails.
pub fn verify(
    ctx: &VerifyingContext,
    proof: &ProofComponents,
    public_inputs: &[String],
) -> Result<bool, ApplicationError> {
    let ark_proof = proof.to_ark_proof()?;
    let ark_inputs: Vec<F> = public_inputs
        .iter()
        .map(|s| {
            hex_decimal_to_field::<F>(s).map_err(|e| ApplicationError::ParseError(e.to_string()))
        })
        .collect::<Result<_, _>>()?;
    Groth16::<BN254>::verify_proof(&ctx.0, &ark_proof, &ark_inputs)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Proof verification failed: {}", e)))
}
