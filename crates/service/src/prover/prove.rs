//! Native [`prove`] free function — host-facing entry point for the
//! ark-ar1cs Groth16 prove flow.
//!
//! See the module-level docs in [`crate::prover`] for the canonical
//! call sequence. `prove` chains
//! `prove_request_to_internal → into_circuit_input →
//! ZkapCircuit::from_input → synthesize_full_assignment →
//! ark_ar1cs::prove`. Trust gating
//! ([`crate::artifact::ArtifactSet::load`] sha256 / `ar1cs_blake3`
//! checks) is the loader's responsibility — `prove` does **not**
//! re-validate the manifest, `arcs.body_blake3()`, or any `pk` / `vk`
//! hash.

use ark_ar1cs::{prove as ar1cs_prove, synthesize_full_assignment};
use ark_std::rand::rngs::OsRng;
use circuit::types::{BN254, BNP, CG, F};
use circuit::zkap::ZkapCircuit;

use crate::artifact::ArtifactSet;
use crate::dto::{ProveRequest, ProveResponse};
use crate::error::ApplicationError;
use crate::prover::adapter::prove_request_to_internal;
use crate::prover::witness::into_circuit_input;

/// Run the native ar1cs Groth16 prove flow over every JWT credential
/// in `request`, against the artifact bundle in `artifact`.
///
/// Mirrors the `generate_anchor` / `generate_audience_hashes` /
/// `generate_issuer_key_hash` / `generate_poseidon_hash` shape: a free
/// function taking borrowed config-bearing context plus a Request DTO,
/// returning a Response DTO. The binding-friendly signature is the
/// reason the prior `Prover` struct was retired in the 2026-05
/// refactor.
///
/// The call pipeline:
///
/// 1. The boundary adapter
///    ([`crate::prover::adapter::prove_request_to_internal`]) validates
///    [`ProveRequest`] shape against the bundled [`CircuitConfig`],
///    decodes every hex/base64 field, parses each JWT for `sub` / `iss`
///    / `aud`, derives the per-credential anchor `x`, and composes the
///    internal witness request.
/// 2. Per credential: [`into_circuit_input`] converts the shared +
///    per-JWT bundle into a fully assigned `ZkapCircuitInput<F>`;
///    [`ZkapCircuit::from_input`] wraps it in a `ConstraintSynthesizer`;
///    [`synthesize_full_assignment`] returns the prover-shaped
///    `[F::ONE, instance..., witness...]` vector; [`ar1cs_prove`]
///    produces the Groth16 proof against `artifact.pk` and
///    `artifact.arcs`.
/// 3. The collected proofs + parallel public-input vectors are folded
///    into a [`ProveResponse`] via the `From<(Vec<Proof>, Vec<Vec<F>>)>`
///    impl in [`crate::dto::proof`].
///
/// A fresh [`OsRng`] is constructed inside this function and reused
/// across every credential in the batch. The public API does not
/// expose a seedable RNG variant — that would undermine
/// zero-knowledge for downstream callers. (See `[crate::dto::proof]`
/// for the response shape.)
///
/// # Trust boundary
///
/// `prove` does **not** receive a `&Manifest`, does **not** recompute
/// `arcs.body_blake3()`, and does **not** re-verify any `sha256` hash
/// on `pk` / `vk` / `pvk` / `circuit_config` / `evm_verifier`. The
/// loader ([`ArtifactSet::load`]) is the **single** trust gate;
/// production callers MUST use it. Any reintroduction of manifest /
/// hash validation inside this function would be a duplication of the
/// loader's job and a policy break; the absence is enforced by the
/// `artifact_set_load` integration test
/// (`crates/service/tests/artifact_set_load.rs`) against the loader.
///
/// # Use
///
/// ```ignore
/// use zkap_service::{ArtifactSet, ProveRequest, prove};
///
/// let set = ArtifactSet::load(&manifest, dir)?;
/// let response = prove(&set, &request)?;
/// ```
pub fn prove(
    artifact: &ArtifactSet,
    request: &ProveRequest,
) -> Result<ProveResponse, ApplicationError> {
    let internal = prove_request_to_internal(request, &artifact.cfg)?;
    internal.validate(artifact.cfg.k as usize, artifact.cfg.n as usize)?;
    let mut rng = OsRng;
    let mut proofs = Vec::with_capacity(internal.per_jwt.len());
    let mut public_input_vectors: Vec<Vec<F>> = Vec::with_capacity(internal.per_jwt.len());

    for per_jwt in internal.per_jwt.iter() {
        let circuit_input = into_circuit_input(&internal.shared, per_jwt, &artifact.cfg)?;
        let pub_inputs = circuit_input.public_inputs.clone();
        let circuit: ZkapCircuit<CG, BNP> = ZkapCircuit::<CG, BNP>::from_input(circuit_input);

        let full_assignment = synthesize_full_assignment::<_, F>(circuit).map_err(|e| {
            ApplicationError::ProofGenerationFailed(format!(
                "synthesize_full_assignment failed: {e}"
            ))
        })?;

        let proof =
            ar1cs_prove::<BN254, _>(&artifact.pk, &artifact.arcs, &full_assignment, &mut rng)
                .map_err(|e| {
                    ApplicationError::ProofGenerationFailed(format!("ark_ar1cs::prove: {e}"))
                })?;

        // Canonical 8-element instance layout — see
        // `ProveResponse::from((proofs, public_inputs))` in
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
