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
//!   **circuit-agnostic** `ark_ar1cs::prove_with_mode` call (the only step
//!   that needs `pk` / prepared `.ar1cs` matrices).
//!
//! This split is the basis for the planned WASM witness-generator
//! artifact: a downstream `witness_gen.wasm` will host
//! [`synthesize_witnesses`] and emit serialized [`WitnessBundle`]s,
//! letting circuit-agnostic prover packages call only
//! `ark_ar1cs::prove_with_mode` natively.
//!
//! Trust gating ([`crate::artifact::ArtifactSet::load`] sha256 /
//! `ar1cs_blake3` checks) is the loader's responsibility — neither
//! function re-validates the manifest, `arcs.body_blake3()`, or any
//! `pk` / `vk` hash.

use ark_ar1cs::{
    PreflightMode as Ar1csPreflightMode, prove_with_mode as ar1cs_prove_with_mode,
    synthesize_full_assignment,
};
use ark_groth16::{Groth16, Proof};
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
use rayon::prelude::*;

use crate::anchor::AnchorConfig;
use crate::anchor::poseidon::{derive_selector_from_x_list_and_anchor, derive_x_from_secret};
use crate::artifact::ArtifactSet;
use crate::dto::{PUBLIC_INPUTS, ProveRequest, ProveResponse, PublicInputSlot, WitnessBundle};
use crate::error::ApplicationError;
use crate::jwt::parser::parse_anchor_secret_from_jwt;

use super::adapter::prove_request_to_decoded;
use super::circuit_input::{
    build_anchor_stage, build_audience_stage, build_jwt_stage, build_merkle_witness,
    compute_public_inputs,
};

/// Circuit-dependent half of the prove pipeline — emit one
/// [`WitnessBundle`] per credential via a caller-supplied sink.
///
/// Pulls each `WitnessBundle` (`Vec<F>` `full_assignment` ~27 MiB) into
/// the callback in turn and **drops it before producing the next one**.
/// Used by the wasm path so the serialised output stream replaces the
/// `Vec<WitnessBundle>` retention; recovers `(k-1) * sizeof(bundle)`
/// of linear-memory peak vs. the [`synthesize_witnesses`] (collect-into-
/// Vec) entry below. See `crates/witness-gen-wasm/PERF.md` ("Mobile
/// RSS investigation").
///
/// The flow is otherwise identical to [`synthesize_witnesses`]:
/// `prove_request_to_decoded` → per-batch `derive_x` /
/// `derive_selector` → per-credential stage builders →
/// `ZkapCircuit::from_input` → `synthesize_full_assignment`. The
/// proving key and `.ar1cs` body are not used here, so the function
/// takes only [`CircuitConfig`].
///
/// # Visibility
///
/// This is a low-memory implementation detail of the witness pipeline,
/// not part of the semver-stable `zkap-service` boundary. The function
/// lives in the `pub(crate) mod groth16` tree, so it is reachable from
/// outside the crate **only** through the `lib.rs` re-export, which is
/// gated behind the internal, non-default `internal-streaming-witness`
/// feature (enabled solely by the in-workspace `zkap-witness-gen-wasm`
/// crate). External native consumers and `zkap-zkp` never enable that
/// feature and use the collecting [`synthesize_witnesses`] entry — or,
/// for the host prove half, [`prove_bundles`] — instead.
pub fn synthesize_witnesses_streaming<Sink>(
    cfg: &CircuitConfig,
    request: &ProveRequest,
    mut on_bundle: Sink,
) -> Result<(), ApplicationError>
where
    Sink: FnMut(WitnessBundle) -> Result<(), ApplicationError>,
{
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

    // ── Per-credential: build → synthesize → emit → drop ───────────────
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
        let audience_stage = build_audience_stage(&jwt_stage.aud_packed, cfg, poseidon_param)?;
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

        // Canonical 8-element instance layout — derived from PUBLIC_INPUTS so
        // that adding a new PublicInputSlot variant forces a compiler error here
        // (exhaustive match, no `_` arm). See `crate::dto::public_inputs` for
        // the single source of truth.
        let public_inputs: Vec<F> = PUBLIC_INPUTS
            .iter()
            .map(|&slot| match slot {
                PublicInputSlot::Hanchor => pub_inputs.hanchor,
                PublicInputSlot::Ha => pub_inputs.h_a,
                PublicInputSlot::Root => pub_inputs.root,
                PublicInputSlot::HSignUserOp => pub_inputs.h_sign_user_op,
                PublicInputSlot::JwtExp => pub_inputs.jwt_exp,
                PublicInputSlot::PartialRhs => pub_inputs.partial_rhs,
                PublicInputSlot::Lhs => pub_inputs.lhs,
                PublicInputSlot::HAudList => pub_inputs.h_aud_list,
            })
            .collect();

        // Move the bundle into the sink; it drops at end of the
        // callback so the next iteration can reuse the freed
        // allocation pool. Wasm linear memory is monotonic, so this
        // does NOT shrink the live high-water mark immediately, but
        // it prevents the simultaneous `Vec<WitnessBundle>` +
        // serialised-output redundancy that doubled bundle storage
        // before this refactor.
        on_bundle(WitnessBundle {
            full_assignment,
            public_inputs,
        })?;
    }

    Ok(())
}

/// Vec-collecting wrapper around [`synthesize_witnesses_streaming`].
///
/// Native callers (e.g. [`prove`]) that consume every bundle in
/// memory anyway should use this entry. Wasm callers should drive the
/// streaming entry directly and serialise each bundle into an output
/// buffer to avoid holding the whole `Vec<WitnessBundle>` plus the
/// serialised output simultaneously.
pub fn synthesize_witnesses(
    cfg: &CircuitConfig,
    request: &ProveRequest,
) -> Result<Vec<WitnessBundle>, ApplicationError> {
    let mut bundles = Vec::with_capacity(request.credentials.len());
    synthesize_witnesses_streaming(cfg, request, |bundle| {
        bundles.push(bundle);
        Ok(())
    })?;
    Ok(bundles)
}

/// Run the native ar1cs Groth16 prove flow over every JWT credential
/// in `request`, against the artifact bundle in `artifact`.
///
/// Thin composition of [`synthesize_witnesses`] (circuit-dependent
/// half) and `ark_ar1cs::prove_with_mode(..., VerifyAfter)`
/// (circuit-agnostic half). A fresh [`OsRng`] is constructed inside this
/// function; the public API does not expose a seedable RNG variant.
///
/// # Trust boundary
///
/// `prove` does **not** re-verify any manifest hash. The loader
/// ([`ArtifactSet::load_signed`]) is the **single** trust gate;
/// production callers MUST use it.
///
/// # Use
///
/// ```ignore
/// use zkap_service::{ArtifactSet, ProveRequest, prove};
///
/// let set = ArtifactSet::load_signed(&manifest, dir, &verifying_key)?;
/// let response = prove(&set, &request)?;
/// ```
pub fn prove(
    artifact: &ArtifactSet,
    request: &ProveRequest,
) -> Result<ProveResponse, ApplicationError> {
    let bundles = synthesize_witnesses(&artifact.cfg, request)?;
    prove_bundles(artifact, bundles, PreflightMode::VerifyAfter)
}

/// Preflight policy for [`prove_bundles`] — the façade-owned mirror of
/// `ark_ar1cs::PreflightMode`.
///
/// This enum is the stable, semver-tracked control knob for the
/// circuit-agnostic prove half. It lets callers (standalone native
/// consumers and the downstream witness-gen prover package) select the
/// preflight behaviour **without importing `ark_ar1cs`** — the whole
/// point of the `zkap-service` boundary. New variants here are an
/// additive (non-breaking) change; renames / removals are breaking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PreflightMode {
    /// Generate the proof first, then verify it against `pk.vk` before
    /// returning. This is the default [`prove`] behaviour: it catches an
    /// unsatisfying witness as a loud error instead of emitting a proof
    /// that silently fails downstream verification. Use this when the
    /// witness pipeline is trusted and an invalid witness is an
    /// operational bug rather than expected input.
    #[default]
    VerifyAfter,
    /// Check every R1CS row for satisfaction *before* generating the
    /// proof, and skip the post-proof verify. Surfaces an unsatisfying
    /// witness as a row-level diagnostic instead of a silent bad proof.
    /// Maps to `ark_ar1cs::PreflightMode::Strict`.
    StrictPreflight,
}

impl PreflightMode {
    /// Lower the façade mode to the internal `ark_ar1cs` enum.
    ///
    /// The two ark-ar1cs modes are complementary, not "more vs less"
    /// checking: `Strict` runs the row-level R1CS satisfaction preflight
    /// before proving but performs **no** post-proof verify, whereas
    /// `VerifyAfter` skips the row preflight and instead verifies the
    /// finished proof against `pk.vk`. The façade names mirror that
    /// behaviour: `StrictPreflight → Strict`, `VerifyAfter → VerifyAfter`.
    fn to_ar1cs(self) -> Ar1csPreflightMode {
        match self {
            PreflightMode::VerifyAfter => Ar1csPreflightMode::VerifyAfter,
            PreflightMode::StrictPreflight => Ar1csPreflightMode::Strict,
        }
    }
}

/// Stable boundary entry point for the **circuit-agnostic** prove half:
/// turn pre-synthesized [`WitnessBundle`]s into a [`ProveResponse`].
///
/// This is the façade replacement for reaching into `ArtifactSet`'s
/// `pk` / `prepared_arcs` and calling `ark_ar1cs::prove_with_mode`
/// directly. Downstream prover packages that obtain bundles out-of-band
/// (e.g. from the `zkap-witness-gen-wasm` ABI) call this with a loaded
/// [`ArtifactSet`] and never need to depend on `ark_ar1cs`.
///
/// For each bundle it calls `ark_ar1cs::prove_with_mode` with the
/// proving key and prepared `.ar1cs` matrices borrowed from `artifact`,
/// using `mode` (lowered to the internal `ark_ar1cs` enum), then
/// collects the proofs alongside each bundle's public-input vector and
/// assembles the canonical [`ProveResponse`].
///
/// A fresh [`OsRng`] is constructed inside this function; the public API
/// does not expose a seedable RNG variant.
///
/// The per-bundle loop runs **in parallel** via rayon
/// (`into_par_iter`), so multi-credential proving (e.g. 3-of-3) fans the
/// independent Groth16 proofs across the rayon thread pool. Parallelism
/// is **native-only**: `rayon` is an optional dependency enabled solely
/// by the `native-witness` feature, so the wasm32 `host-primitives`
/// build of this crate never links it. Each task constructs its own
/// fresh [`OsRng`] (the RNG is not shared across threads); `&artifact`'s
/// `pk` / `prepared_arcs` are shared immutable (`Sync`) borrows. The
/// result is **order-preserving**: `collect`ing the parallel iterator
/// into a `Vec` yields proofs in the same order as the input `bundles`,
/// which the on-chain / response semantics depend on. A failure in any
/// bundle short-circuits the `collect` to the first
/// [`ApplicationError::ProofGenerationFailed`].
///
/// # Trust boundary
///
/// `prove_bundles` does **not** re-verify any manifest hash. The loader
/// ([`ArtifactSet::load_signed`]) is the **single** trust gate;
/// production callers MUST load through it before proving.
pub fn prove_bundles(
    artifact: &ArtifactSet,
    bundles: Vec<WitnessBundle>,
    mode: PreflightMode,
) -> Result<ProveResponse, ApplicationError> {
    let ar1cs_mode = mode.to_ar1cs();
    // Prove each bundle in parallel. `into_par_iter().map(...).collect()`
    // preserves input order, so the resulting (proof, public_inputs)
    // pairs line up with `bundles`. Each task builds a fresh `OsRng`
    // rather than sharing one across threads; `&artifact` is a shared
    // immutable (`Sync`) borrow. Collecting into `Result<Vec<_>, _>`
    // short-circuits to the first proof failure.
    let pairs: Vec<(Proof<BN254>, Vec<F>)> = bundles
        .into_par_iter()
        .map(|bundle| {
            let mut rng = OsRng;
            let proof = ar1cs_prove_with_mode::<BN254, _>(
                &artifact.pk,
                &artifact.prepared_arcs,
                &bundle.full_assignment,
                &mut rng,
                ar1cs_mode,
            )
            .map_err(|e| {
                ApplicationError::ProofGenerationFailed(format!("ark_ar1cs::prove_with_mode: {e}"))
            })?;
            Ok((proof, bundle.public_inputs))
        })
        .collect::<Result<Vec<_>, ApplicationError>>()?;

    let mut proofs = Vec::with_capacity(pairs.len());
    let mut public_input_vectors: Vec<Vec<F>> = Vec::with_capacity(pairs.len());
    for (proof, public_inputs) in pairs {
        proofs.push(proof);
        public_input_vectors.push(public_inputs);
    }
    Ok((proofs, public_input_vectors).into())
}

/// Verify a single Groth16 `proof` against `public_inputs`, using the
/// prepared verifying key bundled in `artifact`.
///
/// This is the stable verify counterpart to [`prove`] / [`prove_bundles`]:
/// it wraps `ark_groth16::Groth16::verify_proof` against
/// `ArtifactSet`'s (crate-private) `pvk`, so neither standalone native
/// consumers nor `zkap-zkp` need to borrow the prepared verifying key
/// directly.
///
/// `public_inputs` is the ordered instance vector for the proof — the
/// canonical 8-element layout `[hanchor, h_a, root, h_sign_user_op,
/// jwt_exp, partial_rhs, lhs, h_aud_list]` that
/// [`ProveResponse::public_inputs_for`] reconstructs (decoded back to
/// `F`). It must **not** include the implicit constant-1 wire; arkworks
/// prepends that internally. The proof is the ark-native
/// [`Proof`]`<`[`BN254`]`>` (re-exported from the crate root as
/// `zkap_service::Proof`); both `F` and `BN254` are the fundamental
/// field/curve types the boundary deliberately exposes.
///
/// Returns `Ok(true)` if the pairing check passes, `Ok(false)` if it
/// fails (e.g. a tampered public input), and
/// [`ApplicationError::ProofGenerationFailed`] only if the verifier
/// itself errors (malformed inputs).
pub fn verify(
    artifact: &ArtifactSet,
    proof: &Proof<BN254>,
    public_inputs: &[F],
) -> Result<bool, ApplicationError> {
    Groth16::<BN254>::verify_proof(&artifact.pvk, proof, public_inputs).map_err(|e| {
        ApplicationError::ProofGenerationFailed(format!("ark_groth16::verify_proof: {e}"))
    })
}

#[cfg(test)]
mod preflight_mode_tests {
    use super::{Ar1csPreflightMode, PreflightMode};

    /// Pin the façade → ark-ar1cs `PreflightMode` lowering so a future
    /// ark-ar1cs variant rename or reorder fails this test instead of
    /// silently changing prove semantics. `StrictPreflight` must stay the
    /// row-preflight / no-post-verify mode and `VerifyAfter` the
    /// prove-then-verify mode.
    #[test]
    fn preflight_mode_lowers_to_expected_ar1cs_variant() {
        assert_eq!(
            PreflightMode::VerifyAfter.to_ar1cs(),
            Ar1csPreflightMode::VerifyAfter,
        );
        assert_eq!(
            PreflightMode::StrictPreflight.to_ar1cs(),
            Ar1csPreflightMode::Strict,
        );
    }
}
