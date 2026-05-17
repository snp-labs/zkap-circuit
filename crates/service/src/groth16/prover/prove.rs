//! Native [`prove`] free function — host-facing entry point for the
//! ark-ar1cs Groth16 prove flow, split into two stages:
//!
//! * [`synthesize_witnesses`] runs the **circuit-dependent** half —
//!   wire decoding, threshold-anchor crypto derivation, per-credential
//!   stage building, `ZkapCircuit::from_input`, and
//!   `synthesize_full_assignment`. It takes only `&CircuitConfig` (not
//!   the full [`ArtifactSet`]) because the proving key and `.ar1cs`
//!   body are not used here.
//! * [`prove`] composes [`synthesize_witnesses`] with the
//!   **circuit-agnostic** `ark_ar1cs::prove` call (the only step that
//!   needs `pk` / `arcs`).
//!
//! This split is the basis for the planned WASM witness-generator
//! artifact: a downstream `witness_gen.wasm` will host
//! [`synthesize_witnesses`] and emit serialized [`WitnessBundle`]s,
//! letting circuit-agnostic prover packages call only
//! `ark_ar1cs::prove` natively.
//!
//! Trust gating ([`crate::artifact::ArtifactSet::load`] sha256 /
//! `ar1cs_blake3` checks) is the loader's responsibility — neither
//! function re-validates the manifest, `arcs.body_blake3()`, or any
//! `pk` / `vk` hash.

use ark_ar1cs::{prove as ar1cs_prove, synthesize_full_assignment};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::OsRng;
use circuit::types::{BN254, BNP, CG, CircuitConfig, F};
use circuit::witness::{
    AnchorWitness, AudienceWitness, CircuitConstants, CircuitPublicInputs, MiscWitness,
    ZkapCircuitInput,
};
use circuit::zkap::ZkapCircuit;
use gadget::anchor::poseidon::{PoseidonAnchor, PoseidonAnchorPublicKey};
use gadget::base64::get_base64_table;
use gadget::matrix::VandermondeMatrix;

use crate::anchor::AnchorConfig;
use crate::anchor::poseidon::{derive_selector_from_x_list_and_anchor, derive_x_from_secret};
use crate::artifact::ArtifactSet;
use crate::dto::{ProveRequest, ProveResponse};
use crate::error::ApplicationError;
use crate::jwt::parser::parse_anchor_secret_from_jwt;

use super::adapter::prove_request_to_decoded;
use super::circuit_input::{
    build_anchor_stage, build_audience_stage, build_jwt_stage, build_merkle_witness,
    compute_public_inputs,
};

/// One credential's worth of circuit-synthesis output.
///
/// `full_assignment` is the flat wire-value vector produced by
/// `ark_ar1cs::synthesize_full_assignment` — feed it directly to
/// `ark_ar1cs::prove`.
///
/// `public_inputs` is the canonical 8-element layout that the on-chain
/// verifier consumes:
///
/// `[hanchor, h_a, root, h_sign_user_op, jwt_exp, partial_rhs, lhs,
///   h_aud_list]`
///
/// Both vectors are circuit-agnostic at the type level (just `Vec<F>`),
/// so a WASM module can serialize them via [`CanonicalSerialize`] and a
/// native host can [`CanonicalDeserialize`] and prove without touching
/// circuit code.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct WitnessBundle {
    /// Flat wire-value vector from `synthesize_full_assignment`.
    pub full_assignment: Vec<F>,
    /// 8-element canonical public-input layout (see struct docs).
    pub public_inputs: Vec<F>,
}

/// Circuit-dependent half of the prove pipeline — produce one
/// [`WitnessBundle`] per credential.
///
/// Runs `prove_request_to_decoded` → per-batch `derive_x` /
/// `derive_selector` → per-credential stage builders →
/// `ZkapCircuit::from_input` → `synthesize_full_assignment` and
/// returns the resulting `(Vec<F>, Vec<F>)` pairs. The proving key
/// and `.ar1cs` body are not used here, so this function takes only
/// [`CircuitConfig`] (intentionally smaller than the
/// [`prove`]-flavored `&ArtifactSet` surface).
///
/// All circuit / gadget dependencies live behind this entry point; a
/// future `witness_gen.wasm` artifact wraps it and emits the bundles
/// as `CanonicalSerialize` bytes so that a circuit-agnostic prover
/// host can finish the job by feeding `bundle.full_assignment` into
/// `ark_ar1cs::prove`.
pub fn synthesize_witnesses(
    cfg: &CircuitConfig,
    request: &ProveRequest,
) -> Result<Vec<WitnessBundle>, ApplicationError> {
    let (shared, credentials) = prove_request_to_decoded(request, cfg)?;
    let n = cfg.n as usize;
    let k = cfg.k as usize;
    let th = cfg.tree_height as usize;

    let matrix = VandermondeMatrix::<F>::new(n, k);
    let poseidon_param = crate::poseidon_params();
    let base64_table = get_base64_table();

    // ── Pre-batch crypto derivation ────────────────────────────────────
    // Parse each JWT for sub/iss/aud → derive_x_from_secret → x_list.
    let anchor_ctx = AnchorConfig::from_params(cfg);
    let x_list: Vec<F> = credentials
        .iter()
        .enumerate()
        .map(|(i, cred)| {
            let secret = parse_anchor_secret_from_jwt(&cred.jwt_bytes, i)?;
            derive_x_from_secret(&secret, poseidon_param, &anchor_ctx).map_err(|e| {
                ApplicationError::InvalidProveRequest {
                    field: format!("credentials[{}].jwt", i),
                    message: format!("derive_x_from_secret failed: {}", e),
                }
            })
        })
        .collect::<Result<_, _>>()?;

    // Recover the selector + one-positions from the anchor + x_list.
    let anchor_obj = PoseidonAnchor::new(shared.anchor_values.clone());
    let anchor_pk = PoseidonAnchorPublicKey::<F> {
        params: poseidon_param.clone(),
    };
    let selector =
        derive_selector_from_x_list_and_anchor(&anchor_pk, &x_list, &anchor_obj, &matrix).map_err(
            |e| ApplicationError::InvalidProveRequest {
                field: "anchor / jwts".into(),
                message: format!(
                    "no valid selector — anchor and JWT claim shares inconsistent: {}",
                    e
                ),
            },
        )?;
    let one_positions: Vec<usize> = selector
        .iter()
        .enumerate()
        .filter(|&(_, &s)| s == 1)
        .map(|(j, _)| j)
        .collect();
    // Defensive: selector must have cardinality k by construction.
    if one_positions.len() != k {
        return Err(ApplicationError::InvalidProveRequest {
            field: "anchor / jwts".into(),
            message: format!(
                "derived selector cardinality={} but expected k={}",
                one_positions.len(),
                k
            ),
        });
    }

    // ── Per-credential streaming: build → synthesize → next credential ─
    let mut bundles = Vec::with_capacity(credentials.len());

    for (i, cred) in credentials.iter().enumerate() {
        let path = format!("credentials[{}]", i);
        let current_idx = one_positions[i] as u64;

        let anchor_stage = build_anchor_stage(
            &path,
            &shared.anchor_values,
            &x_list,
            &selector,
            current_idx,
            n,
            k,
            poseidon_param,
            &matrix,
        )?;
        let jwt_stage = build_jwt_stage(
            &path,
            &cred.jwt_bytes,
            &cred.rsa_modulus_bytes,
            &cred.rsa_signature_bytes,
            cfg,
            poseidon_param,
        )?;
        let audience_stage = build_audience_stage(
            &path,
            &jwt_stage.payload_bytes,
            &jwt_stage.claim_indices,
            &cfg.claims,
            &jwt_stage.aud_packed,
            cfg,
            poseidon_param,
        )?;
        let merkle = build_merkle_witness(
            &path,
            cred.merkle_leaf_sibling_hash,
            &cred.merkle_auth_path,
            cred.merkle_leaf_idx,
            th,
        )?;
        let pub_stage = compute_public_inputs(
            &path,
            &anchor_stage,
            &jwt_stage.payload_bytes,
            &jwt_stage.claim_indices,
            &cfg.claims,
            &jwt_stage.aud_packed,
            shared.merkle_root,
            shared.random,
            cfg,
            poseidon_param,
        )?;

        let circuit_input = ZkapCircuitInput {
            params: cfg.clone(),
            constants: CircuitConstants {
                vandermonde_matrix: matrix.clone(),
                poseidon_param: poseidon_param.clone(),
                base64_table: base64_table.clone(),
            },
            public_inputs: CircuitPublicInputs {
                hanchor: pub_stage.hanchor,
                h_a: pub_stage.h_a,
                root: pub_stage.root,
                h_sign_user_op: shared.h_sign_user_op,
                jwt_exp: pub_stage.jwt_exp,
                partial_rhs: pub_stage.partial_rhs,
                lhs: pub_stage.lhs,
                h_aud_list: audience_stage.h_aud_list,
            },
            jwt: jwt_stage.jwt_witness,
            anchor: AnchorWitness {
                anchor: anchor_stage.anchor,
                a: anchor_stage.anchor_witness.a,
                selector: selector.clone(),
                current_idx: anchor_stage.current_idx,
            },
            merkle,
            audience: AudienceWitness {
                aud_list: audience_stage.aud_list,
            },
            misc: MiscWitness {
                random: shared.random,
            },
        };
        let pub_inputs = circuit_input.public_inputs.clone();
        let circuit: ZkapCircuit<CG, BNP> = ZkapCircuit::<CG, BNP>::from_input(circuit_input);

        let full_assignment = synthesize_full_assignment::<_, F>(circuit).map_err(|e| {
            ApplicationError::ProofGenerationFailed(format!(
                "synthesize_full_assignment failed: {e}"
            ))
        })?;

        // Canonical 8-element instance layout — see
        // `ProveResponse::from((proofs, public_inputs))` in
        // `crate::dto::proof` for the per-proof / shared split.
        let public_inputs = vec![
            pub_inputs.hanchor,
            pub_inputs.h_a,
            pub_inputs.root,
            pub_inputs.h_sign_user_op,
            pub_inputs.jwt_exp,
            pub_inputs.partial_rhs,
            pub_inputs.lhs,
            pub_inputs.h_aud_list,
        ];

        bundles.push(WitnessBundle {
            full_assignment,
            public_inputs,
        });
    }

    Ok(bundles)
}

/// Run the native ar1cs Groth16 prove flow over every JWT credential
/// in `request`, against the artifact bundle in `artifact`.
///
/// Thin composition of [`synthesize_witnesses`] (circuit-dependent
/// half) and `ark_ar1cs::prove` (circuit-agnostic half). A fresh
/// [`OsRng`] is constructed inside this function; the public API
/// does not expose a seedable RNG variant.
///
/// # Trust boundary
///
/// `prove` does **not** re-verify any manifest hash. The loader
/// ([`ArtifactSet::load`]) is the **single** trust gate; production
/// callers MUST use it.
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
    let bundles = synthesize_witnesses(&artifact.cfg, request)?;
    let mut rng = OsRng;
    let mut proofs = Vec::with_capacity(bundles.len());
    let mut public_input_vectors: Vec<Vec<F>> = Vec::with_capacity(bundles.len());
    for bundle in bundles {
        let proof = ar1cs_prove::<BN254, _>(
            &artifact.pk,
            &artifact.arcs,
            &bundle.full_assignment,
            &mut rng,
        )
        .map_err(|e| ApplicationError::ProofGenerationFailed(format!("ark_ar1cs::prove: {e}")))?;
        proofs.push(proof);
        public_input_vectors.push(bundle.public_inputs);
    }
    Ok((proofs, public_input_vectors).into())
}
