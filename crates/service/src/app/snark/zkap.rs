//! ZKAP proof generation service (refactored version)
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

use ark_groth16::Proof;
use circuit::constants::{BN254, F, CircuitConfig};
use log;

use crate::error::ApplicationError;

use super::context::ProofContextBuilder;
use super::input::{ProofRequest, RawProofRequest};
use super::proof::ProofGenerator;

/// 1. RawProofRequest → ProofRequest (validation and parsing)
/// 2. ProofRequest → CircuitInput[] (context building)
/// 3. CircuitInput[] → Proof[] (proof generation)
///
/// # Arguments
/// * `params` - circuit configuration parameters
/// * `raw` - raw proof request data
///
/// # Returns
/// * tuple of proofs and public inputs
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
