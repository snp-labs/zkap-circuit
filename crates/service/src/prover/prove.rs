//! Native [`Prover`] handle + `prove_from_unverified_paths` shortcut.
//!
//! See the module-level docs in [`crate::prover`] for the canonical
//! call sequence. The prover internally chains
//! `build_input → into_circuit_input → ZkapCircuit::from_input →
//! synthesize_full_assignment → ark_ar1cs::prove`. Trust gating
//! ([`crate::artifact::ArtifactSet::load`] sha256 / `ar1cs_blake3`
//! checks) is the loader's responsibility — `Prover::prove` does
//! **not** re-validate the manifest, `arcs.body_blake3()`, or any
//! `pk` / `vk` hash.

use std::path::Path;

use ark_ar1cs::format::ArcsFile;
use ark_ar1cs::{prove as ar1cs_prove, synthesize_full_assignment};
use ark_groth16::{PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_std::rand::{CryptoRng, Rng};
use circuit::types::{BN254, BNP, CG, CircuitConfig, F};
use circuit::zkap::ZkapCircuit;

use crate::artifact::ArtifactSet;
use crate::dto::ZkapProofResult;
use crate::error::ApplicationError;
use crate::witness::{ProofRequest, build_input, into_circuit_input};

/// Native ZKAP prover backed by `ark_ar1cs::prove`.
///
/// Construct via [`Prover::from_artifact`] after obtaining a
/// manifest-verified [`ArtifactSet`] (canonical) or via
/// [`prove_from_unverified_paths`] (non-canonical shortcut for tests).
pub struct Prover {
    pk: ProvingKey<BN254>,
    vk: VerifyingKey<BN254>,
    pvk: PreparedVerifyingKey<BN254>,
    arcs: ArcsFile<F>,
    cfg: CircuitConfig,
}

impl Prover {
    /// Build a [`Prover`] from a manifest-verified [`ArtifactSet`].
    ///
    /// The set was produced by [`ArtifactSet::load`] (canonical) or
    /// [`ArtifactSet::load_unverified`] (non-canonical, tests only).
    /// `from_artifact` takes ownership; no further hash validation
    /// happens inside [`Self::prove`].
    pub fn from_artifact(set: ArtifactSet) -> Self {
        Self {
            pk: set.pk,
            vk: set.vk,
            pvk: set.pvk,
            arcs: set.arcs,
            cfg: set.cfg,
        }
    }

    /// Borrow the bundled Groth16 verifying key — useful when callers
    /// want to run `Groth16::verify_proof` directly without going
    /// through the (Commit-5-removable) `crate::proof::verify` wrapper.
    pub fn verifying_key(&self) -> &VerifyingKey<BN254> {
        &self.vk
    }

    /// Borrow the bundled prepared verifying key.
    pub fn prepared_verifying_key(&self) -> &PreparedVerifyingKey<BN254> {
        &self.pvk
    }

    /// Borrow the bundled [`CircuitConfig`] — the config the loaded
    /// `pk`/`vk` was actually generated against.
    pub fn circuit_config(&self) -> &CircuitConfig {
        &self.cfg
    }

    /// Run the native prove flow over every JWT credential in `req`.
    ///
    /// The flow per credential:
    /// 1. [`build_input`] reshapes the request into a `Vec<ZkapInputV1>`
    ///    (re-applies the shape invariants).
    /// 2. [`into_circuit_input`] converts each payload into a fully
    ///    assigned `ZkapCircuitInput<F>`.
    /// 3. [`ZkapCircuit::from_input`] wraps it in a
    ///    `ConstraintSynthesizer` ready for assignment extraction.
    /// 4. [`synthesize_full_assignment`] returns the prover-shaped
    ///    `[F::ONE, instance..., witness...]` vector.
    /// 5. [`ar1cs_prove`] produces the Groth16 proof against `self.pk`
    ///    and `self.arcs`.
    ///
    /// **Trust gating is `ArtifactSet::load`'s job.** This method
    /// performs no manifest lookup, no `arcs.body_blake3()` comparison,
    /// and no `pk`/`vk` hash check — the loader already did those.
    pub fn prove<R>(
        &self,
        req: &ProofRequest,
        rng: &mut R,
    ) -> Result<ZkapProofResult, ApplicationError>
    where
        R: Rng + CryptoRng,
    {
        let inputs = build_input(req, &self.cfg)?;
        let mut proofs = Vec::with_capacity(inputs.len());
        let mut public_input_vectors: Vec<Vec<F>> = Vec::with_capacity(inputs.len());

        for v1 in inputs {
            let circuit_input = into_circuit_input(v1)?;
            let pub_inputs = circuit_input.public_inputs.clone();
            let circuit: ZkapCircuit<CG, BNP> = ZkapCircuit::<CG, BNP>::from_input(circuit_input);

            let full_assignment = synthesize_full_assignment::<_, F>(circuit).map_err(|e| {
                ApplicationError::ProofGenerationFailed(format!(
                    "synthesize_full_assignment failed: {e}"
                ))
            })?;

            let proof =
                ar1cs_prove::<BN254, R>(&self.pk, &self.arcs, &full_assignment, rng).map_err(
                    |e| ApplicationError::ProofGenerationFailed(format!("ark_ar1cs::prove: {e}")),
                )?;

            // Canonical 8-element instance layout — see
            // `ZkapProofResult::from((proofs, public_inputs))` in
            // `crate::dto::proof` for the per-proof / shared split.
            let pub_vec = vec![
                pub_inputs.hanchor,
                pub_inputs.h_a,
                pub_inputs.root,
                pub_inputs.h_sign_user_op,
                pub_inputs.jwt_exp,
                pub_inputs.partial_rhs,
                pub_inputs.lhs,
                pub_inputs.h_aud_list,
            ];

            proofs.push(proof);
            public_input_vectors.push(pub_vec);
        }

        Ok((proofs, public_input_vectors).into())
    }
}

/// **non-canonical: bypasses manifest hash validation; production
/// callers MUST use `ArtifactSet::load(manifest, dir)` +
/// `Prover::from_artifact` + `Prover::prove`.**
///
/// Loads `pk.bin`, `vk.bin`, `pvk.bin`, `circuit.ar1cs`, and
/// `config.json` from `bundle_dir` via
/// [`ArtifactSet::load_unverified`] and forwards to
/// [`Prover::from_artifact`] + [`Prover::prove`]. Use only in tests,
/// dev tools, and caller-trusted environments where bundle integrity
/// is established out of band. The function name's `_unverified`
/// suffix and this rustdoc warning exist precisely so production
/// review can flag any call site as a policy violation.
pub fn prove_from_unverified_paths<R>(
    bundle_dir: &Path,
    req: &ProofRequest,
    rng: &mut R,
) -> Result<ZkapProofResult, ApplicationError>
where
    R: Rng + CryptoRng,
{
    let set = ArtifactSet::load_unverified(bundle_dir).map_err(|e| {
        ApplicationError::InvalidFormat(format!(
            "ArtifactSet::load_unverified({}) failed: {e}",
            bundle_dir.display()
        ))
    })?;
    let prover = Prover::from_artifact(set);
    prover.prove(req, rng)
}
