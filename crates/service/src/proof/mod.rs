//! ZKAP proof generation service — wasm-witness-runtime variant.
//!
//! The host-facing entry point is [`prove`], which:
//! 1. validates [`RawProofRequest`] against the circuit shape,
//! 2. assembles one [`ZkapInputV1`] per JWT,
//! 3. dispatches each input through the wasm witness-generator runtime,
//! 4. runs `ark_ar1cs_prover::prove` against the matching `.arzkey`.
//!
//! Witness construction is fully delegated to the `.wasm` artifact —
//! `service` no longer pulls `circuit::ZkapCircuit` into the prove path.

pub mod generator;
pub mod request;
pub mod runtime;

pub use request::{RawProofRequest, ZkapPerJwtFields, ZkapSharedFields};

use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
#[allow(unused_imports)]
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode};
use circuit::constants::{CircuitConfig, BN254, BNP, CG, F};
use circuit::zkap::ZkapCircuit;
use rand::rngs::OsRng;
use std::path::Path;
use ark_utils::wire::ZkapInputV1;

use crate::dto::{ProofComponents, ZkapProofResult};
use crate::error::ApplicationError;
use ark_utils::hex_decimal_to_field;

use self::generator::ProofGenerator;

/// Opaque handle to a Groth16 prepared verifying key.
pub struct VerifyingContext(pub(crate) PreparedVerifyingKey<BN254>);

/// Output of [`setup`].
pub struct SetupOutput {
    pub(crate) pk: ProvingKey<BN254>,
    pub(crate) vk: VerifyingKey<BN254>,
    pub(crate) pvk: PreparedVerifyingKey<BN254>,
}

impl SetupOutput {
    pub fn verifying_context(&self) -> VerifyingContext {
        VerifyingContext(self.pvk.clone())
    }

    pub fn public_input_count(&self) -> usize {
        self.pvk.vk.gamma_abc_g1.len()
    }
}

/// Trusted setup. Persists pk/vk/pvk + Solidity verifier + config to
/// `output_dir`. Setup still synthesizes a circuit natively — removing
/// the `circuit` dep here is plan §16 follow-up.
pub fn setup(params: &CircuitConfig, output_dir: &Path) -> Result<SetupOutput, ApplicationError> {
    let mut rng = OsRng;
    let circuit = ZkapCircuit::<CG, BNP>::generate_mock_circuit(params);

    let (pk, vk) = Groth16::<BN254>::setup(circuit, &mut rng)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Groth16 setup failed: {}", e)))?;

    let pvk = prepare_verifying_key(&vk);
    let output = SetupOutput { pk, vk, pvk };

    let circuit_for_arcs = ZkapCircuit::<CG, BNP>::generate_mock_circuit(params);
    let cs_setup = ConstraintSystem::<F>::new_ref();
    cs_setup.set_mode(SynthesisMode::Setup);
    cs_setup.set_optimization_goal(OptimizationGoal::Constraints);
    circuit_for_arcs
        .generate_constraints(cs_setup.clone())
        .map_err(|e| ApplicationError::InvalidFormat(format!("Arcs synthesis failed: {}", e)))?;
    cs_setup.finalize();
    let matrices = cs_setup
        .to_matrices()
        .ok_or_else(|| ApplicationError::InvalidFormat("Failed to extract R1CS matrices".into()))?;
    let arcs = ArcsFile::from_matrices(CurveId::Bn254, &matrices);

    crate::crs::persist_setup_output(&output, params, output_dir, arcs)?;

    Ok(output)
}

/// Generate Groth16 proofs from raw user inputs via the wasm
/// witness-generator runtime.
pub fn prove(
    params: &CircuitConfig,
    raw: RawProofRequest,
) -> Result<ZkapProofResult, ApplicationError> {
    log::info!("[ZKAP-v3] Step 1: Validating RawProofRequest...");
    let k = params.k as usize;
    let n = params.n as usize;
    raw.validate(k, n)?;
    if raw.token_count() != k {
        return Err(ApplicationError::InvalidFormat(format!(
            "expected {} JWTs (k), got {}",
            k,
            raw.token_count()
        )));
    }

    log::info!("[ZKAP-v3] Step 2: Building {} ZkapInputV1 payloads...", k);

    let inputs: Vec<ZkapInputV1> = raw
        .per_jwt
        .iter()
        .map(|jwt| jwt.to_zkap_input_v1(&raw.shared, params))
        .collect();

    log::info!("[ZKAP-v3] Step 3: Generating proofs via wasm runtime...");
    let generator = ProofGenerator::new(raw.pk_path, raw.wasm_path);
    let output = generator.generate(&inputs)?;
    log::info!(
        "[ZKAP-v3] Step 3 completed: {} proofs generated",
        output.proofs.len()
    );

    Ok((output.proofs, output.public_inputs).into())
}

/// Verify a single Groth16 proof against an opaque verifying context.
pub fn verify(
    ctx: &VerifyingContext,
    proof: &ProofComponents,
    public_inputs: &[String],
) -> Result<bool, ApplicationError> {
    let ark_proof = proof.to_ark_proof()?;
    let ark_inputs: Vec<F> = public_inputs
        .iter()
        .map(|s| hex_decimal_to_field::<F>(s).map_err(ApplicationError::from))
        .collect::<Result<_, _>>()?;
    Groth16::<BN254>::verify_proof(&ctx.0, &ark_proof, &ark_inputs)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Proof verification failed: {}", e)))
}
