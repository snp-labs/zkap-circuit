//! ZKAP trusted-setup entry point.
//!
//! After Commit 4 of the 2026-05 ark-ar1cs boundary migration the
//! proving entry point lives in [`crate::prover`]
//! ([`crate::prover::Prover`] / [`crate::prover::prove_from_unverified_paths`]).
//! Commit 5 then removed the in-crate verify wrapper — callers verify
//! proofs by calling `Groth16::verify_proof` directly against the
//! `vk` / `pvk` exposed on [`Prover`] (or
//! [`crate::artifact::ArtifactSet`]). This module is now the home of
//! only the [`setup`] function.

use ark_ar1cs::format::{ArcsFile, ConstraintMatrices, CurveId};
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

use crate::error::ApplicationError;

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
///
/// Holds every artifact the post-migration CRS bundle needs:
/// `pk`, `vk`, `pvk` (uncompressed `CanonicalSerialize` targets),
/// `arcs` (R1CS body for `circuit.ar1cs`), and the [`CircuitConfig`]
/// the keys were built against — the same shape
/// [`crate::artifact::ArtifactSet`] mirrors on the read side.
pub struct SetupOutput {
    pub(crate) pk: ProvingKey<BN254>,
    pub(crate) vk: VerifyingKey<BN254>,
    pub(crate) pvk: PreparedVerifyingKey<BN254>,
    /// `.ar1cs` body extracted alongside the proving/verifying keys.
    /// Used by [`crate::crs::persist_setup_output`] to emit
    /// `circuit.ar1cs` and by CLI tooling to compute the manifest's
    /// `ar1cs_blake3` field.
    pub arcs: ArcsFile<F>,
    /// Constraint-system shape — populated from the synthesized
    /// [`ConstraintSystem`] used to extract the R1CS matrices, so the
    /// counts always match the `circuit.ar1cs` payload.
    pub shape: SetupShape,
    /// The [`CircuitConfig`] used to synthesize `pk`/`vk`/`arcs`. Kept
    /// here so [`Self::into_artifact_set`] can hand a `Prover` the
    /// same config without re-reading `config.json`.
    pub(crate) cfg: CircuitConfig,
}

impl SetupOutput {
    /// Returns the bundled prepared verifying key.
    ///
    /// The in-crate verify wrapper was retired in Commit 5 of the
    /// 2026-05 ark-ar1cs boundary migration; callers that need to
    /// verify a proof in-process hand this borrow straight to
    /// `ark_groth16::Groth16::verify_proof`.
    pub fn prepared_verifying_key(&self) -> &PreparedVerifyingKey<BN254> {
        &self.pvk
    }

    /// Returns `gamma_abc_g1.len()` — i.e., the number of public inputs
    /// plus one for the constant term, matching the on-chain verifier's
    /// indexing into `gamma_abc_g1`. This is *not* the textbook
    /// `n_public_inputs` (which would be `gamma_abc_g1.len() - 1`); callers
    /// who want that count should subtract 1.
    pub fn public_input_count(&self) -> usize {
        self.pvk.vk.gamma_abc_g1.len()
    }

    /// Convert this [`SetupOutput`] into a [`crate::artifact::ArtifactSet`]
    /// in memory, without going through disk.
    ///
    /// Useful for tests and in-process flows that want to feed the
    /// freshly-built `pk`/`vk`/`pvk`/`arcs` straight into a
    /// [`crate::prover::Prover::from_artifact`] call. Production callers
    /// should instead persist via [`setup`] and re-load through
    /// [`crate::artifact::ArtifactSet::load`] so the manifest hash check
    /// is exercised on every prove batch.
    pub fn into_artifact_set(self) -> crate::artifact::ArtifactSet {
        crate::artifact::ArtifactSet {
            pk: self.pk,
            vk: self.vk,
            pvk: self.pvk,
            arcs: self.arcs,
            cfg: self.cfg,
        }
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

    let matrices = ConstraintMatrices::from_cs(&cs_setup).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to extract R1CS matrices: {e:?}"))
    })?;
    let arcs = ArcsFile::from_matrices(CurveId::Bn254, &matrices);

    let output = SetupOutput {
        pk,
        vk,
        pvk,
        arcs,
        shape,
        cfg: params.clone(),
    };
    crate::crs::persist_setup_output(&output, params, output_dir, &output.arcs)?;

    Ok(output)
}
