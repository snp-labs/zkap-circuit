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

pub use request::RawProofRequest;

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
use zkap_input_types::{ZkapCircuitConfigV1, ZkapInputV1};

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

/// Build a wire-format [`ZkapCircuitConfigV1`] from the circuit-side
/// [`CircuitConfig`]. Lives here (in service) rather than zkap-input-types
/// so the new crate stays free of `circuit` deps.
fn config_v1_from_circuit(c: &CircuitConfig) -> ZkapCircuitConfigV1 {
    ZkapCircuitConfigV1 {
        max_jwt_b64_len: c.max_jwt_b64_len,
        max_payload_b64_len: c.max_payload_b64_len,
        max_aud_len: c.max_aud_len,
        max_exp_len: c.max_exp_len,
        max_iss_len: c.max_iss_len,
        max_nonce_len: c.max_nonce_len,
        max_sub_len: c.max_sub_len,
        n: c.n,
        k: c.k,
        tree_height: c.tree_height,
        num_audience_limit: c.num_audience_limit,
        claims: c
            .claims
            .iter()
            .map(|b| {
                core::str::from_utf8(b)
                    .expect("CircuitConfig::claims entries are valid UTF-8")
                    .to_owned()
            })
            .collect(),
        forbidden_string: core::str::from_utf8(&c.forbidden_string)
            .expect("CircuitConfig::forbidden_string is valid UTF-8")
            .to_owned(),
    }
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
    let cfg_v1 = config_v1_from_circuit(params);

    let RawProofRequest {
        pk_path,
        wasm_path,
        random_be,
        h_sign_user_op_be,
        anchor_values_be,
        anchor_known_x_be,
        anchor_selector,
        merkle_root_be,
        jwt_bytes,
        rsa_modulus_be,
        rsa_signature_be,
        anchor_current_idx,
        merkle_leaf_sibling_hash_be,
        merkle_auth_path_be,
        merkle_leaf_idx,
    } = raw;

    let inputs: Vec<ZkapInputV1> = (0..k)
        .map(|i| ZkapInputV1 {
            jwt_bytes: jwt_bytes[i].clone(),
            rsa_modulus_be: rsa_modulus_be[i].clone(),
            rsa_signature_be: rsa_signature_be[i].clone(),
            random_be,
            h_sign_user_op_be,
            anchor_values_be: anchor_values_be.clone(),
            anchor_known_x_be: anchor_known_x_be.clone(),
            anchor_selector: anchor_selector.clone(),
            anchor_current_idx: anchor_current_idx[i],
            merkle_root_be,
            merkle_leaf_sibling_hash_be: merkle_leaf_sibling_hash_be[i],
            merkle_auth_path_be: merkle_auth_path_be[i].clone(),
            merkle_leaf_idx: merkle_leaf_idx[i],
            circuit_config: cfg_v1.clone(),
        })
        .collect();

    log::info!("[ZKAP-v3] Step 3: Generating proofs via wasm runtime...");
    let generator = ProofGenerator::new(pk_path, wasm_path);
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
        .map(|s| {
            hex_decimal_to_field::<F>(s).map_err(|e| ApplicationError::ParseError(e.to_string()))
        })
        .collect::<Result<_, _>>()?;
    Groth16::<BN254>::verify_proof(&ctx.0, &ark_proof, &ark_inputs)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Proof verification failed: {}", e)))
}
