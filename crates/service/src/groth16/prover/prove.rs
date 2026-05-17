//! Native [`prove`] free function — host-facing entry point for the
//! ark-ar1cs Groth16 prove flow.
//!
//! See the module-level docs in [`crate::groth16::prover`] for the canonical
//! call sequence. `prove` chains
//! `prove_request_to_decoded → derive_x_from_secret per credential →
//! derive_selector_from_x_list_and_anchor → per-credential stage builders
//! → ZkapCircuit::from_input → synthesize_full_assignment →
//! ark_ar1cs::prove`. Trust gating
//! ([`crate::artifact::ArtifactSet::load`] sha256 / `ar1cs_blake3`
//! checks) is the loader's responsibility — `prove` does **not**
//! re-validate the manifest, `arcs.body_blake3()`, or any `pk` / `vk`
//! hash.

use ark_ar1cs::{prove as ar1cs_prove, synthesize_full_assignment};
use ark_std::rand::rngs::OsRng;
use circuit::types::{BN254, BNP, CG, F};
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

/// Run the native ar1cs Groth16 prove flow over every JWT credential
/// in `request`, against the artifact bundle in `artifact`.
///
/// See [`crate::groth16::prover`] for the full call pipeline. A fresh
/// [`OsRng`] is constructed inside this function; the public API does
/// not expose a seedable RNG variant.
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
    let (shared, credentials) = prove_request_to_decoded(request, &artifact.cfg)?;
    let cfg = &artifact.cfg;
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
    let pk = PoseidonAnchorPublicKey::<F> {
        params: poseidon_param.clone(),
    };
    let selector = derive_selector_from_x_list_and_anchor(&pk, &x_list, &anchor_obj, &matrix)
        .map_err(|e| ApplicationError::InvalidProveRequest {
            field: "anchor / jwts".into(),
            message: format!(
                "no valid selector — anchor and JWT claim shares inconsistent: {}",
                e
            ),
        })?;
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

    // ── Per-credential streaming: build → consume → next credential ───
    let mut rng = OsRng;
    let mut proofs = Vec::with_capacity(credentials.len());
    let mut public_input_vectors: Vec<Vec<F>> = Vec::with_capacity(credentials.len());

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
