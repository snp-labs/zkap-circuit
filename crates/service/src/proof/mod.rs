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
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey, prepare_verifying_key};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use circuit::types::{BN254, BNP, CG, CircuitConfig, F};
use circuit::zkap::ZkapCircuit;
use rand::{CryptoRng, RngCore};
use std::path::Path;

use ark_utils::wire::ZkapInputV1;

use crate::dto::{ProofComponents, ZkapProofResult};
use crate::error::ApplicationError;
use ark_utils::hex_decimal_to_field;

use self::generator::ProofGenerator;

/// Opaque handle to a Groth16 prepared verifying key.
pub struct VerifyingContext(pub(crate) PreparedVerifyingKey<BN254>);

/// Constraint-system shape produced by [`setup`].
///
/// Mirrors `manifest::Shape` in `zkap-cli` field-for-field. Kept in
/// `zkap-service` so callers that don't pull in `zkap-cli` (e.g. the
/// service crate's integration tests) can still read the counts off
/// [`SetupOutput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupShape {
    /// `cs.num_instance_variables()` — includes the constant-1 wire.
    pub num_instance: u64,
    /// `cs.num_witness_variables()`.
    pub num_witness: u64,
    /// `cs.num_constraints()` after `finalize()`.
    pub num_constraints: u64,
}

/// Output of [`setup`].
pub struct SetupOutput {
    pub(crate) pk: ProvingKey<BN254>,
    pub(crate) vk: VerifyingKey<BN254>,
    pub(crate) pvk: PreparedVerifyingKey<BN254>,
    /// Constraint-system shape — populated from the synthesized
    /// [`ConstraintSystem`] used to extract the R1CS matrices, so the
    /// counts always match the `.arzkey` payload.
    pub shape: SetupShape,
}

impl SetupOutput {
    /// Returns the prepared verifying-key handle that [`verify`] consumes.
    /// Cloning is cheap (the underlying `PreparedVerifyingKey` is `Arc`-free
    /// but small and fully owned).
    pub fn verifying_context(&self) -> VerifyingContext {
        VerifyingContext(self.pvk.clone())
    }

    /// Returns `gamma_abc_g1.len()` — i.e., the number of public inputs
    /// plus one for the constant term, matching the on-chain verifier's
    /// indexing into `gamma_abc_g1`. This is *not* the textbook
    /// `n_public_inputs` (which would be `gamma_abc_g1.len() - 1`); callers
    /// who want that count should subtract 1.
    pub fn public_input_count(&self) -> usize {
        self.pvk.vk.gamma_abc_g1.len()
    }
}

/// `&mut dyn RngCore` adapter that claims `CryptoRng`.
///
/// `Groth16::setup` bounds its rng with `R: RngCore + CryptoRng`. Stage 1
/// callers route either `OsRng` (cryptographically secure) or
/// `ChaCha20Rng` (a CSPRNG seeded by the operator) through the public
/// [`setup`] signature, which carries only `&mut dyn RngCore`. Both
/// concrete types already implement `CryptoRng`; this wrapper makes the
/// trait-object form explicit. It is a load-bearing assumption — passing
/// a non-CSPRNG through this adapter would compromise toxic-waste
/// secrecy, which is why the CLI only constructs `OsRng` or
/// `ChaCha20Rng` and why this wrapper stays `pub(crate)`.
struct AssumedCryptoRng<'a>(&'a mut dyn RngCore);

impl RngCore for AssumedCryptoRng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for AssumedCryptoRng<'_> {}

/// Trusted setup. Persists pk/vk/pvk + Solidity verifier + config to
/// `output_dir`, then returns the [`SetupOutput`] (including the
/// constraint-system [`SetupShape`]). Setup still synthesizes a circuit
/// natively — removing the `circuit` dep here is plan §16 follow-up.
///
/// # Parameters
///
/// * `rng` — caller-supplied randomness source. `OsRng` for production
///   fallback, `ChaCha20Rng` for `--rng-seed --allow-test-only` CI runs.
///   Both implement `RngCore + CryptoRng`; the function wraps the
///   trait-object in an `AssumedCryptoRng` adapter to satisfy
///   `Groth16::setup`'s bound.
/// * `ptau` — Stage 2 placeholder. The Stage 1 binary never sets this,
///   but the parameter is part of the signature so Stage 2 can land
///   without another breaking change. Passing `Some` returns an
///   explicit error.
pub fn setup(
    params: &CircuitConfig,
    output_dir: &Path,
    rng: &mut dyn RngCore,
    ptau: Option<&Path>,
) -> Result<SetupOutput, ApplicationError> {
    if ptau.is_some() {
        return Err(ApplicationError::InvalidFormat(
            "Stage 2 not yet active — `ptau` argument must be None".into(),
        ));
    }

    let circuit = ZkapCircuit::<CG, BNP>::generate_mock_circuit(params);
    let mut crypto_rng = AssumedCryptoRng(rng);

    let (pk, vk) = Groth16::<BN254>::setup(circuit, &mut crypto_rng)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Groth16 setup failed: {}", e)))?;

    let pvk = prepare_verifying_key(&vk);

    let circuit_for_arcs = ZkapCircuit::<CG, BNP>::generate_mock_circuit(params);
    let cs_setup = ConstraintSystem::<F>::new_ref();
    cs_setup.set_mode(SynthesisMode::Setup);
    cs_setup.set_optimization_goal(OptimizationGoal::Constraints);
    circuit_for_arcs
        .generate_constraints(cs_setup.clone())
        .map_err(|e| ApplicationError::InvalidFormat(format!("Arcs synthesis failed: {}", e)))?;
    cs_setup.finalize();

    let shape = SetupShape {
        num_instance: cs_setup.num_instance_variables() as u64,
        num_witness: cs_setup.num_witness_variables() as u64,
        num_constraints: cs_setup.num_constraints() as u64,
    };

    let matrices = ark_ar1cs_format::ConstraintMatrices::from_cs(&cs_setup).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to extract R1CS matrices: {e:?}"))
    })?;
    let arcs = ArcsFile::from_matrices(CurveId::Bn254, &matrices);

    let output = SetupOutput { pk, vk, pvk, shape };
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
