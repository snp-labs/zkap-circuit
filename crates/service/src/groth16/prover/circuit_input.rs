//! Per-credential witness stage builders for the native Groth16 prove flow.
//!
//! The adapter owns wire decoding and field canonicality checks; this module
//! receives decoded `F` values plus genuine byte sequences and builds the
//! anchor, JWT, audience, Merkle, and public-input witnesses. Stage builders
//! stay `pub(crate)` so `prove()` and golden tests can exercise each boundary.
//! Validation failures map to `InvalidProveRequest` with the caller's dotted
//! `field_path`; Poseidon and gadget failures keep their crypto-specific
//! error variants.

use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    merkle_tree::Path,
    sponge::poseidon::PoseidonConfig,
};
use ark_ff::Zero;

use circuit::token::ClaimIndices;
use circuit::types::{CircuitConfig, F};
use circuit::witness::{JwtWitness, MerkleWitness};
use gadget::{
    anchor::poseidon::{PoseidonAnchor, build_anchor_witness},
    base64::{IndexBits, decode_any_base64},
    hashes::poseidon::{
        output_mask_for_index as gadget_output_mask_for_index,
        selected_output_mask_sum as gadget_selected_output_mask_sum,
    },
    matrix::VandermondeMatrix,
    signature::rsa::{PublicKey, Signature},
};

use ark_codec::string::try_bytes_to_fields;

use crate::error::ApplicationError;
use crate::jwt::parser::locate_claim;

use super::RSA_2048_BYTES;

// Common helpers.

fn invalid_prove_request(
    field_path: &str,
    suffix: &str,
    message: impl Into<String>,
) -> ApplicationError {
    ApplicationError::InvalidProveRequest {
        field: format!("{field_path}.{suffix}"),
        message: message.into(),
    }
}

fn pad_claim_value_to_max(value: &[u8], max_len: usize) -> Vec<u8> {
    let mut v = value.to_vec();
    v.resize(max_len, 0x00);
    v
}

/// Recompute SHA-256 padding for `signing_input = header_b64.payload_b64`,
/// then zero-pad the buffer out to `max_jwt_b64_len`. Returns
/// `(sha_pad_jwt_b64, nblocks)` where `nblocks` is the 0-indexed final
/// SHA block.
fn sha_pad_signing_input(signing_input: &[u8], max_jwt_b64_len: usize) -> (Vec<u8>, usize) {
    let total_len = signing_input.len();
    let mut sha_padded: Vec<u8> = signing_input.to_vec();
    sha_padded.push(0x80);
    while (sha_padded.len() % 64) != 56 {
        sha_padded.push(0x00);
    }
    let bit_len = (total_len as u64) * 8;
    sha_padded.extend_from_slice(&bit_len.to_be_bytes());
    let nblocks = sha_padded.len() / 64 - 1;
    sha_padded.resize(max_jwt_b64_len, 0x00);
    (sha_padded, nblocks)
}

pub(super) fn claim_value_bytes_padded(
    payload_bytes: &[u8],
    indices: &ClaimIndices,
    max_len: usize,
) -> Vec<u8> {
    let value_start = indices.offset + indices.value_idx;
    let value_end = value_start + indices.value_len;
    let mut bytes = payload_bytes[value_start..value_end].to_vec();
    bytes.resize(max_len, 0x00);
    bytes
}

fn claim_indices_for<'a>(
    field_path: &str,
    claim_indices: &'a [ClaimIndices],
    claims: &[String],
    key: &str,
) -> Result<&'a ClaimIndices, ApplicationError> {
    for (idx, claim) in claim_indices.iter().zip(claims.iter()) {
        if claim == key {
            return Ok(idx);
        }
    }
    Err(invalid_prove_request(
        field_path,
        "jwt_bytes",
        format!("claim `{}` not found in JWT payload", key),
    ))
}

// Anchor stage.

/// Anchor stage output: decoded anchor values, the gadget anchor
/// witness, the anchor object, and the resolved current index.
pub(crate) struct AnchorStage {
    pub(crate) anchor_values: Vec<F>,
    pub(crate) anchor_witness: gadget::anchor::poseidon::PoseidonAnchorWitness<F>,
    pub(crate) anchor: PoseidonAnchor<F>,
    pub(crate) selector: Vec<u8>,
    pub(crate) current_idx: usize,
}

/// Build the anchor stage from already-decoded F inputs.
///
/// `field_path` is the dotted prefix (e.g. `"credentials[0]"`) used to
/// construct [`ApplicationError::InvalidProveRequest`] field labels when
/// the inputs fail shape validation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_anchor_stage(
    field_path: &str,
    anchor_values: &[F],
    anchor_known_x: &[F],
    anchor_selector: &[u8],
    anchor_current_idx: u64,
    n: usize,
    k: usize,
    poseidon_param: &PoseidonConfig<F>,
    matrix: &VandermondeMatrix<F>,
) -> Result<AnchorStage, ApplicationError> {
    let m_anchor = n - k + 1;
    if anchor_values.len() != m_anchor {
        return Err(invalid_prove_request(
            field_path,
            "anchor_values",
            format!(
                "length {} but n - k + 1 = {}",
                anchor_values.len(),
                m_anchor
            ),
        ));
    }
    if anchor_known_x.len() != k {
        return Err(invalid_prove_request(
            field_path,
            "anchor_known_x",
            format!("length {} but k = {}", anchor_known_x.len(), k),
        ));
    }
    if anchor_selector.len() != n {
        return Err(invalid_prove_request(
            field_path,
            "anchor_selector",
            format!("length {} but n = {}", anchor_selector.len(), n),
        ));
    }
    let cardinality = anchor_selector.iter().filter(|&&s| s == 1).count();
    if cardinality != k {
        return Err(invalid_prove_request(
            field_path,
            "anchor_selector",
            format!("cardinality = {} but k = {}", cardinality, k),
        ));
    }
    let current_idx = anchor_current_idx as usize;
    if current_idx >= n || anchor_selector.get(current_idx).copied().unwrap_or(0) != 1 {
        return Err(invalid_prove_request(
            field_path,
            "anchor_current_idx",
            format!(
                "anchor_current_idx={} not in 0..n or selector[idx] != 1",
                current_idx
            ),
        ));
    }

    let anchor_witness =
        build_anchor_witness(poseidon_param, anchor_known_x, anchor_selector, matrix)?;
    let anchor = PoseidonAnchor::new(anchor_values.to_vec());

    Ok(AnchorStage {
        anchor_values: anchor_values.to_vec(),
        anchor_witness,
        anchor,
        selector: anchor_selector.to_vec(),
        current_idx,
    })
}

// JWT stage.

/// JWT stage output: full circuit JWT witness plus the decoded payload
/// bytes, claim indices, and packed audience bytes downstream stages
/// reuse.
pub(crate) struct JwtStage {
    pub(crate) jwt_witness: JwtWitness,
    pub(crate) payload_bytes: Vec<u8>,
    pub(crate) claim_indices: Vec<ClaimIndices>,
    pub(crate) aud_packed: Vec<F>,
}

/// Build the JWT stage. `jwt_bytes` is the dot-separated
/// `header_b64.payload_b64.signature_b64` string; `rsa_modulus_bytes`
/// and `rsa_signature_bytes` are the 256-byte RSA-2048 byte sequences
/// already extracted by the adapter.
pub(crate) fn build_jwt_stage(
    field_path: &str,
    jwt_bytes: &[u8],
    rsa_modulus_bytes: &[u8],
    rsa_signature_bytes: &[u8],
    cfg: &CircuitConfig,
    poseidon_param: &PoseidonConfig<F>,
) -> Result<JwtStage, ApplicationError> {
    if rsa_modulus_bytes.len() != RSA_2048_BYTES {
        return Err(invalid_prove_request(
            field_path,
            "rsa_modulus_bytes",
            format!(
                "length {} but RSA-2048 requires exactly {} bytes",
                rsa_modulus_bytes.len(),
                RSA_2048_BYTES
            ),
        ));
    }
    if rsa_signature_bytes.len() != RSA_2048_BYTES {
        return Err(invalid_prove_request(
            field_path,
            "rsa_signature_bytes",
            format!(
                "length {} but RSA-2048 requires exactly {} bytes",
                rsa_signature_bytes.len(),
                RSA_2048_BYTES
            ),
        ));
    }

    let jwt_str = core::str::from_utf8(jwt_bytes)
        .map_err(|e| invalid_prove_request(field_path, "jwt_bytes", format!("not UTF-8: {}", e)))?;
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid_prove_request(
            field_path,
            "jwt_bytes",
            format!("expected 3 dot-separated segments, got {}", parts.len()),
        ));
    }
    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let sig_b64 = parts[2];

    let signing_input_bytes = {
        let mut s = Vec::with_capacity(header_b64.len() + 1 + payload_b64.len());
        s.extend_from_slice(header_b64.as_bytes());
        s.push(b'.');
        s.extend_from_slice(payload_b64.as_bytes());
        s
    };
    let total_len = signing_input_bytes.len();
    let pad_start_byte_idx = total_len;
    let (sha_pad_jwt_b64, nblocks) =
        sha_pad_signing_input(&signing_input_bytes, cfg.max_jwt_b64_len as usize);

    let pay_offset_b64 = header_b64.len() + 1;
    let pay_len_b64 = payload_b64.len();

    let index_bits = IndexBits::from_base64_url(payload_b64, cfg.max_payload_b64_len as usize)
        .map_err(|e| {
            invalid_prove_request(
                field_path,
                "jwt_bytes",
                format!("base64 index-bits build failed: {:?}", e),
            )
        })?;

    let payload_bytes = decode_any_base64(payload_b64).map_err(|e| {
        invalid_prove_request(
            field_path,
            "jwt_bytes",
            format!("payload base64 decode failed: {}", e),
        )
    })?;
    let payload_str = core::str::from_utf8(&payload_bytes).map_err(|e| {
        invalid_prove_request(field_path, "jwt_bytes", format!("payload not UTF-8: {}", e))
    })?;

    let mut claim_indices: Vec<ClaimIndices> = Vec::with_capacity(cfg.claims.len());
    for key in &cfg.claims {
        // locate_claim (jwt::parser) returns TokenError; convert to
        // ApplicationError::InvalidProveRequest with the credential field_path prefix.
        claim_indices.push(
            locate_claim(payload_str, key)
                .map_err(|e| invalid_prove_request(field_path, "jwt_bytes", e.to_string()))?,
        );
    }

    let pk = PublicKey {
        n: rsa_modulus_bytes.to_vec(),
        e: vec![0x01, 0x00, 0x01],
    };

    let sig_bytes_decoded = decode_any_base64(sig_b64).map_err(|e| {
        invalid_prove_request(
            field_path,
            "jwt_bytes",
            format!("signature base64 decode failed: {}", e),
        )
    })?;
    if sig_bytes_decoded != rsa_signature_bytes {
        return Err(invalid_prove_request(
            field_path,
            "rsa_signature_bytes",
            format!(
                "rsa_signature_bytes ({} bytes) != base64_decode(jwt sig_b64) ({} bytes)",
                rsa_signature_bytes.len(),
                sig_bytes_decoded.len()
            ),
        ));
    }
    let sig = Signature(rsa_signature_bytes.to_vec());

    let aud_idx = claim_indices
        .iter()
        .zip(cfg.claims.iter())
        .find(|(_, k)| *k == "aud")
        .map(|(idx, _)| idx)
        .ok_or_else(|| {
            invalid_prove_request(
                field_path,
                "jwt_bytes",
                "claim `aud` not found in JWT payload",
            )
        })?;
    let aud_bytes_padded =
        claim_value_bytes_padded(&payload_bytes, aud_idx, cfg.max_aud_len as usize);
    let aud_packed = try_bytes_to_fields::<F>(&aud_bytes_padded)?;
    CRH::<F>::evaluate(poseidon_param, aud_packed.clone())
        .map_err(|e| ApplicationError::PoseidonHashError(format!("aud_packed precheck: {e}")))?;

    let jwt_witness = JwtWitness {
        nblocks,
        claim_indices: claim_indices.clone(),
        pay_offset_b64,
        pay_len_b64,
        sha_pad_jwt_b64,
        index_bits,
        pk,
        sig,
        total_len,
        pad_start_byte_idx,
    };

    Ok(JwtStage {
        jwt_witness,
        payload_bytes,
        claim_indices,
        aud_packed,
    })
}

// Audience stage.

/// Audience stage output: the **batch-shared** audience allow-list and its
/// Poseidon hash.
///
/// Both the `aud_list` witness and the `h_aud_list` public input are shared
/// by every credential in a `k`-of-`n` batch: the list holds one
/// `Poseidon(aud_i)` entry per credential (in `credentials` order), padded
/// out to `cfg.num_audience_limit` with `Poseidon(forbidden_string)`. The
/// in-circuit membership check (`Poseidon(aud) ∈ aud_list`) then passes for
/// credential `i` at slot `i`, while `h_aud_list = Poseidon(aud_list)` is
/// identical across the batch — so the on-chain verifier sees one shared
/// audience commitment instead of `k` per-credential ones.
pub(crate) struct AudienceStage {
    pub(crate) aud_list: Vec<F>,
    pub(crate) h_aud_list: F,
}

/// Poseidon hash of the quote-wrapped, `max_aud_len`-padded
/// `forbidden_string` — the value that fills unused audience slots. Mirrors
/// the host-side recipe in [`crate::generate_audience_hashes`] and the
/// in-circuit padding.
fn compute_h_forbidden(
    cfg: &CircuitConfig,
    poseidon_param: &PoseidonConfig<F>,
) -> Result<F, ApplicationError> {
    let mut forbidden_bytes = Vec::with_capacity(cfg.forbidden_string.len() + 2);
    forbidden_bytes.push(b'"');
    forbidden_bytes.extend_from_slice(cfg.forbidden_string.as_bytes());
    forbidden_bytes.push(b'"');
    let forbidden_padded = pad_claim_value_to_max(&forbidden_bytes, cfg.max_aud_len as usize);
    let forbidden_packed = try_bytes_to_fields::<F>(&forbidden_padded)?;
    CRH::<F>::evaluate(poseidon_param, forbidden_packed)
        .map_err(|e| ApplicationError::PoseidonHashError(format!("h_forbidden: {e}")))
}

/// Extract one credential's `aud` claim from its JWT and pack it into the
/// same `max_aud_len` field-limb form [`build_jwt_stage`] produces, so the
/// pre-batch audience pass packs the identical bytes the per-credential JWT
/// stage (and the in-circuit extractor) see. Lightweight: decodes only the
/// payload segment — no RSA / SHA work.
pub(crate) fn aud_packed_from_jwt(
    field_path: &str,
    jwt_bytes: &[u8],
    cfg: &CircuitConfig,
) -> Result<Vec<F>, ApplicationError> {
    let jwt_str = core::str::from_utf8(jwt_bytes)
        .map_err(|e| invalid_prove_request(field_path, "jwt_bytes", format!("not UTF-8: {}", e)))?;
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid_prove_request(
            field_path,
            "jwt_bytes",
            format!("expected 3 dot-separated segments, got {}", parts.len()),
        ));
    }
    let payload_bytes = decode_any_base64(parts[1]).map_err(|e| {
        invalid_prove_request(
            field_path,
            "jwt_bytes",
            format!("payload base64 decode failed: {}", e),
        )
    })?;
    let payload_str = core::str::from_utf8(&payload_bytes).map_err(|e| {
        invalid_prove_request(field_path, "jwt_bytes", format!("payload not UTF-8: {}", e))
    })?;
    let aud_idx = locate_claim(payload_str, "aud")
        .map_err(|e| invalid_prove_request(field_path, "jwt_bytes", e.to_string()))?;
    let aud_bytes_padded =
        claim_value_bytes_padded(&payload_bytes, &aud_idx, cfg.max_aud_len as usize);
    Ok(try_bytes_to_fields::<F>(&aud_bytes_padded)?)
}

/// Compute `Poseidon(aud_packed)` for one credential — its slot value in the
/// shared audience list. The audience hash uses the same recipe as the
/// `aud_packed` slot-0 hash the per-credential JWT stage feeds in-circuit.
pub(crate) fn per_credential_h_aud(
    field_path: &str,
    jwt_bytes: &[u8],
    cfg: &CircuitConfig,
    poseidon_param: &PoseidonConfig<F>,
) -> Result<F, ApplicationError> {
    let aud_packed = aud_packed_from_jwt(field_path, jwt_bytes, cfg)?;
    CRH::<F>::evaluate(poseidon_param, aud_packed)
        .map_err(|e| ApplicationError::PoseidonHashError(format!("h_aud: {e}")))
}

/// Build the **batch-shared** audience stage from the per-credential
/// `Poseidon(aud_i)` hashes.
///
/// `per_credential_h_aud[i]` is credential `i`'s audience hash (see
/// [`per_credential_h_aud`]); the list is `[h_aud_0, …, h_aud_{k-1}]` padded
/// to `cfg.num_audience_limit` with `Poseidon(forbidden_string)`, then
/// `h_aud_list = Poseidon(aud_list)`. The same [`AudienceStage`] is reused for
/// every credential's witness, so all `k` proofs commit to one shared
/// `h_aud_list`. This matches [`crate::generate_audience_hashes`] called with
/// the same audiences in the same order, and the circuit's
/// `Poseidon(aud) ∈ aud_list` membership trick, which was designed for
/// exactly this multi-audience list.
pub(crate) fn build_shared_audience_stage(
    per_credential_h_aud: &[F],
    cfg: &CircuitConfig,
    poseidon_param: &PoseidonConfig<F>,
) -> Result<AudienceStage, ApplicationError> {
    let num_audience_limit = cfg.num_audience_limit as usize;
    if per_credential_h_aud.len() > num_audience_limit {
        return Err(ApplicationError::InvalidProveRequest {
            field: "credentials".into(),
            message: format!(
                "credential count {} exceeds num_audience_limit {}",
                per_credential_h_aud.len(),
                num_audience_limit
            ),
        });
    }

    let h_forbidden = compute_h_forbidden(cfg, poseidon_param)?;

    let mut aud_list = Vec::with_capacity(num_audience_limit);
    aud_list.extend_from_slice(per_credential_h_aud);
    while aud_list.len() < num_audience_limit {
        aud_list.push(h_forbidden);
    }
    let h_aud_list = CRH::<F>::evaluate(poseidon_param, aud_list.clone())
        .map_err(|e| ApplicationError::PoseidonHashError(format!("h_aud_list: {e}")))?;

    Ok(AudienceStage {
        aud_list,
        h_aud_list,
    })
}

// Merkle stage.

/// Build the merkle witness from already-decoded F leaf-sibling-hash
/// and auth path. `merkle_leaf_idx` is the 0-based leaf index.
pub(crate) fn build_merkle_witness(
    field_path: &str,
    leaf_sibling_hash: F,
    auth_path: &[F],
    merkle_leaf_idx: u64,
    tree_height: usize,
) -> Result<MerkleWitness<F>, ApplicationError> {
    let expected_path_len = tree_height.saturating_sub(1);
    if auth_path.len() != expected_path_len {
        return Err(invalid_prove_request(
            field_path,
            "auth_path",
            format!(
                "length {} but tree_height - 1 = {}",
                auth_path.len(),
                expected_path_len
            ),
        ));
    }

    Ok(MerkleWitness {
        path: Path {
            leaf_sibling_hash,
            auth_path: auth_path.to_vec(),
            leaf_index: merkle_leaf_idx as usize,
        },
        leaf_idx: merkle_leaf_idx as usize,
    })
}

// Public inputs.

/// Public inputs assembled from the prior stages plus the F-decoded
/// `merkle_root` and `random`.
pub(crate) struct PublicInputsStage {
    pub(crate) hanchor: F,
    pub(crate) h_a: F,
    pub(crate) root: F,
    pub(crate) lhs: F,
    pub(crate) partial_rhs: F,
    pub(crate) jwt_exp: F,
}

fn output_mask_for_index(
    poseidon_param: &PoseidonConfig<F>,
    random: F,
    index: usize,
) -> Result<F, ApplicationError> {
    gadget_output_mask_for_index(poseidon_param, random, index)
        .map_err(|e| ApplicationError::PoseidonHashError(e.to_string()))
}

fn selected_output_mask_sum(
    poseidon_param: &PoseidonConfig<F>,
    random: F,
    selector: &[u8],
) -> Result<F, ApplicationError> {
    gadget_selected_output_mask_sum(poseidon_param, random, selector)
        .map_err(|e| ApplicationError::PoseidonHashError(e.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_public_inputs(
    field_path: &str,
    anchor_stage: &AnchorStage,
    payload_bytes: &[u8],
    claim_indices: &[ClaimIndices],
    claims: &[String],
    aud_packed: &[F],
    merkle_root: F,
    random: F,
    cfg: &CircuitConfig,
    poseidon_param: &PoseidonConfig<F>,
) -> Result<PublicInputsStage, ApplicationError> {
    let current_idx = anchor_stage.current_idx;
    let anchor_values = &anchor_stage.anchor_values;
    let witness = &anchor_stage.anchor_witness;

    let root = merkle_root;

    let hanchor = crate::anchor::poseidon::chain_hash(anchor_values, poseidon_param)?;

    let mut h_a_inputs = witness.a.clone();
    h_a_inputs.push(random);
    let h_a = CRH::<F>::evaluate(poseidon_param, h_a_inputs)
        .map_err(|e| ApplicationError::PoseidonHashError(format!("h_a: {e}")))?;

    let inner: F = witness
        .a
        .iter()
        .zip(anchor_values.iter())
        .map(|(a, anc)| *a * *anc)
        .sum();
    let lhs_mask = selected_output_mask_sum(poseidon_param, random, &anchor_stage.selector)?;
    let lhs = inner * random + lhs_mask;

    let iss_bytes_padded = claim_value_bytes_padded(
        payload_bytes,
        claim_indices_for(field_path, claim_indices, claims, "iss")?,
        cfg.max_iss_len as usize,
    );
    let sub_bytes_padded = claim_value_bytes_padded(
        payload_bytes,
        claim_indices_for(field_path, claim_indices, claims, "sub")?,
        cfg.max_sub_len as usize,
    );
    let iss_packed = try_bytes_to_fields::<F>(&iss_bytes_padded)?;
    let sub_packed = try_bytes_to_fields::<F>(&sub_bytes_padded)?;

    let mut h_id_inputs: Vec<F> = Vec::new();
    h_id_inputs.extend_from_slice(aud_packed);
    h_id_inputs.extend_from_slice(&iss_packed);
    h_id_inputs.extend_from_slice(&sub_packed);
    let h_id_inner = CRH::<F>::evaluate(poseidon_param, h_id_inputs)
        .map_err(|e| ApplicationError::PoseidonHashError(format!("h_id_inner: {e}")))?;
    let h_id = CRH::<F>::evaluate(poseidon_param, [F::from(current_idx as u64), h_id_inner])
        .map_err(|e| ApplicationError::PoseidonHashError(format!("h_id: {e}")))?;
    let rhs_mask = output_mask_for_index(poseidon_param, random, current_idx)?;
    let partial_rhs = witness.b[current_idx] * h_id * random + rhs_mask;

    let exp_bytes_padded = claim_value_bytes_padded(
        payload_bytes,
        claim_indices_for(field_path, claim_indices, claims, "exp")?,
        cfg.max_exp_len as usize,
    );
    let jwt_exp = decimal_bytes_to_field(&exp_bytes_padded).map_err(|e| match e {
        ApplicationError::InvalidProveRequest { message, .. } => {
            ApplicationError::InvalidProveRequest {
                field: format!("{}.jwt_bytes", field_path),
                message,
            }
        }
        other => other,
    })?;

    Ok(PublicInputsStage {
        hanchor,
        h_a,
        root,
        lhs,
        partial_rhs,
        jwt_exp,
    })
}

fn decimal_bytes_to_field(bytes: &[u8]) -> Result<F, ApplicationError> {
    if bytes.len() < 10 {
        return Err(ApplicationError::InvalidProveRequest {
            field: "jwt.payload".into(),
            message: format!("exp claim padded length {} < 10", bytes.len()),
        });
    }
    let mut acc = F::zero();
    let ten = F::from(10u64);
    for &b in &bytes[..10] {
        if !b.is_ascii_digit() {
            return Err(ApplicationError::InvalidProveRequest {
                field: "jwt.payload".into(),
                message: format!("exp claim has non-digit byte 0x{:02x}", b),
            });
        }
        acc = acc * ten + F::from((b - b'0') as u64);
    }
    for &b in &bytes[10..] {
        if b != 0 {
            return Err(ApplicationError::InvalidProveRequest {
                field: "jwt.payload".into(),
                message: format!("exp claim padding byte 0x{:02x} is non-zero", b),
            });
        }
    }
    Ok(acc)
}

// The removed local base64 decoder is covered in `gadget` tests; this module
// now uses the same decoder as the adapter and JWT parser.

#[cfg(test)]
mod tests {
    use super::*;
    use gadget::hashes::poseidon::get_poseidon_params;

    fn sample_config_v1() -> CircuitConfig {
        CircuitConfig {
            max_jwt_b64_len: 1024,
            max_payload_b64_len: 640,
            max_aud_len: 155,
            max_exp_len: 20,
            max_iss_len: 93,
            max_nonce_len: 93,
            max_sub_len: 93,
            n: 6,
            k: 3,
            tree_height: 4,
            num_audience_limit: 5,
            claims: vec![
                "aud".into(),
                "exp".into(),
                "iss".into(),
                "nonce".into(),
                "sub".into(),
            ],
            forbidden_string: "forbidden".into(),
        }
    }

    /// Poseidon hash of one `aud` value via the canonical quote-wrapped,
    /// `max_aud_len`-padded recipe — the per-credential slot value that
    /// `build_shared_audience_stage` consumes.
    fn h_aud_for(aud: &str, cfg: &CircuitConfig, params: &PoseidonConfig<F>) -> F {
        let quoted = format!("\"{}\"", aud);
        let packed = try_bytes_to_fields::<F>(&pad_claim_value_to_max(
            quoted.as_bytes(),
            cfg.max_aud_len as usize,
        ))
        .expect("pack aud");
        CRH::<F>::evaluate(params, packed).expect("hash aud")
    }

    /// Regression gate for the batch-shared audience allow-list: the
    /// witness-side [`build_shared_audience_stage`] must reproduce, byte for
    /// byte, the canonical host helper [`crate::generate_audience_hashes`]
    /// called with the same `k` audiences in the same (credential) order.
    /// This is the invariant that lets all `k` proofs commit to ONE shared
    /// `h_aud_list = Poseidon([H(aud_0), …, H(aud_{k-1}), H(forbidden) …])`.
    #[test]
    fn build_shared_audience_stage_matches_generate_audience_hashes() {
        let cfg = sample_config_v1();
        let params = get_poseidon_params::<F>();

        // k = 3 DISTINCT audiences (the case the per-credential bug broke).
        let auds = ["aud-alpha", "aud-bravo", "aud-charlie"];
        assert_eq!(auds.len(), cfg.k as usize);

        let per_cred: Vec<F> = auds.iter().map(|a| h_aud_for(a, &cfg, &params)).collect();
        let stage = build_shared_audience_stage(&per_cred, &cfg, &params).expect("shared stage");

        // Independent reference: the public host helper over the same auds.
        let resp = crate::generate_audience_hashes(
            &cfg,
            crate::AudienceHashRequest {
                audiences: auds.iter().map(|s| s.to_string()).collect(),
            },
        )
        .expect("generate_audience_hashes");

        // (1) The shared list is padded out to the full slot count.
        assert_eq!(stage.aud_list.len(), cfg.num_audience_limit as usize);
        // (2) Every slot matches: slots 0..k are the k auds IN ORDER, slots
        //     k.. are Poseidon(forbidden_string) padding.
        let stage_hex: Vec<String> = stage
            .aud_list
            .iter()
            .map(|f| crate::field_to_hex(*f))
            .collect();
        assert_eq!(stage_hex, resp.audience_hashes, "padded slot list mismatch");
        // (3) The shared public input equals the canonical audience-list hash.
        assert_eq!(
            crate::field_to_hex(stage.h_aud_list),
            resp.audience_list_hash,
            "h_aud_list must equal generate_audience_hashes(audience_list_hash)"
        );
    }

    /// The shared list commits to the audiences IN CREDENTIAL ORDER: permuting
    /// two distinct audiences must change `h_aud_list`. (Guards against a
    /// regression that sorts/dedups the list and silently decouples it from
    /// the per-credential membership slots.)
    #[test]
    fn build_shared_audience_stage_is_order_sensitive() {
        let cfg = sample_config_v1();
        let params = get_poseidon_params::<F>();
        let a = h_aud_for("aud-alpha", &cfg, &params);
        let b = h_aud_for("aud-bravo", &cfg, &params);
        let c = h_aud_for("aud-charlie", &cfg, &params);

        let abc = build_shared_audience_stage(&[a, b, c], &cfg, &params).expect("abc");
        let bac = build_shared_audience_stage(&[b, a, c], &cfg, &params).expect("bac");
        assert_ne!(
            abc.h_aud_list, bac.h_aud_list,
            "credential order must be committed in h_aud_list"
        );
    }

    /// More credentials than `num_audience_limit` slots is a hard reject (the
    /// list cannot hold every `aud`), surfaced as `InvalidProveRequest`.
    #[test]
    fn build_shared_audience_stage_rejects_too_many_credentials() {
        let cfg = sample_config_v1();
        let params = get_poseidon_params::<F>();
        let too_many = vec![F::zero(); cfg.num_audience_limit as usize + 1];

        match build_shared_audience_stage(&too_many, &cfg, &params) {
            Err(ApplicationError::InvalidProveRequest { field, message }) => {
                assert!(field.contains("credentials"), "got field {}", field);
                assert!(message.contains("exceeds"), "got msg {}", message);
            }
            other => panic!(
                "expected InvalidProveRequest for credential overflow, got {:?}",
                other.map(|s| s.aud_list.len())
            ),
        }
    }

    #[test]
    fn build_anchor_stage_rejects_wrong_anchor_values_len() {
        let cfg = sample_config_v1();
        let n = cfg.n as usize;
        let k = cfg.k as usize;
        let matrix = VandermondeMatrix::<F>::new(n, k);
        let poseidon_param = get_poseidon_params::<F>();

        // anchor_values length must be n - k + 1; supply k+0 (wrong).
        let anchor_values = vec![F::zero(); k];
        let anchor_known_x = vec![F::zero(); k];
        let mut anchor_selector = vec![0u8; n];
        for slot in anchor_selector.iter_mut().take(k) {
            *slot = 1;
        }

        match build_anchor_stage(
            "credentials[0]",
            &anchor_values,
            &anchor_known_x,
            &anchor_selector,
            0,
            n,
            k,
            &poseidon_param,
            &matrix,
        ) {
            Err(ApplicationError::InvalidProveRequest { field, message }) => {
                assert!(field.contains("anchor_values"), "got field {}", field);
                assert!(message.contains("n - k + 1"), "got msg {}", message);
            }
            other => panic!(
                "expected InvalidProveRequest for anchor_values, got {:?}",
                other.err()
            ),
        }
    }

    #[test]
    fn build_anchor_stage_rejects_wrong_selector_cardinality() {
        let cfg = sample_config_v1();
        let n = cfg.n as usize;
        let k = cfg.k as usize;
        let matrix = VandermondeMatrix::<F>::new(n, k);
        let poseidon_param = get_poseidon_params::<F>();

        let anchor_values = vec![F::zero(); n - k + 1];
        let anchor_known_x = vec![F::zero(); k];
        // selector cardinality = 2, but k = 3.
        let anchor_selector = vec![1u8, 1, 0, 0, 0, 0];

        match build_anchor_stage(
            "credentials[0]",
            &anchor_values,
            &anchor_known_x,
            &anchor_selector,
            0,
            n,
            k,
            &poseidon_param,
            &matrix,
        ) {
            Err(ApplicationError::InvalidProveRequest { field, message }) => {
                assert!(field.contains("anchor_selector"), "got field {}", field);
                assert!(message.contains("cardinality"), "got msg {}", message);
            }
            other => panic!(
                "expected InvalidProveRequest for selector cardinality, got {:?}",
                other.err()
            ),
        }
    }

    #[test]
    fn build_jwt_stage_rejects_rsa_modulus_too_short() {
        let cfg = sample_config_v1();
        let poseidon_param = get_poseidon_params::<F>();
        let jwt_bytes = b"hdr.payload.sig".to_vec();
        let rsa_modulus_bytes = vec![0x12u8; 255]; // wrong length
        let rsa_signature_bytes = vec![0x34u8; 256];

        match build_jwt_stage(
            "credentials[0]",
            &jwt_bytes,
            &rsa_modulus_bytes,
            &rsa_signature_bytes,
            &cfg,
            &poseidon_param,
        ) {
            Err(ApplicationError::InvalidProveRequest { field, message }) => {
                assert!(field.contains("rsa_modulus_bytes"), "got field {}", field);
                assert!(message.contains("256 bytes"), "got msg {}", message);
            }
            other => panic!(
                "expected InvalidProveRequest for rsa_modulus_bytes, got {:?}",
                other.err()
            ),
        }
    }

    #[test]
    fn build_jwt_stage_rejects_malformed_jwt() {
        let cfg = sample_config_v1();
        let poseidon_param = get_poseidon_params::<F>();
        // Not 3 dot-separated segments.
        let jwt_bytes = b"only-one-segment".to_vec();
        let rsa_modulus_bytes = vec![0x12u8; 256];
        let rsa_signature_bytes = vec![0x34u8; 256];

        match build_jwt_stage(
            "credentials[0]",
            &jwt_bytes,
            &rsa_modulus_bytes,
            &rsa_signature_bytes,
            &cfg,
            &poseidon_param,
        ) {
            Err(ApplicationError::InvalidProveRequest { field, message }) => {
                assert!(field.contains("jwt_bytes"), "got field {}", field);
                assert!(
                    message.contains("3 dot-separated segments"),
                    "got msg {}",
                    message
                );
            }
            other => panic!(
                "expected InvalidProveRequest for malformed jwt, got {:?}",
                other.err()
            ),
        }
    }

    #[test]
    fn locate_claim_matches_canonical_payload() {
        let payload = r#"{"aud":"test-audience","exp":1700000000,"iss":"https://x","nonce":"0xdead","sub":"u_0"}"#;
        let aud = locate_claim(payload, "aud").expect("aud claim");
        assert_eq!(aud.offset, 1);
        let exp = locate_claim(payload, "exp").expect("exp claim");
        let val_byte = payload.as_bytes()[exp.offset + exp.value_idx];
        assert_eq!(val_byte, b'1');
        let sub = locate_claim(payload, "sub").expect("sub claim");
        assert_eq!(payload.as_bytes()[sub.offset + sub.claim_len - 1], b'}');
    }

    #[test]
    fn decimal_bytes_to_field_realistic_exp() {
        let mut bytes = b"1700000000".to_vec();
        bytes.resize(20, 0x00);
        let v = decimal_bytes_to_field(&bytes).expect("decode exp");
        assert_eq!(v, F::from(1700000000u64));
    }

    #[test]
    fn decimal_bytes_to_field_rejects_dirty_padding() {
        let mut bytes = b"1234567890".to_vec();
        bytes.resize(20, 0x00);
        bytes[12] = 0x01;
        match decimal_bytes_to_field(&bytes) {
            Err(ApplicationError::InvalidProveRequest { message, .. }) => {
                assert!(message.contains("padding"), "got msg {}", message);
            }
            other => panic!(
                "expected InvalidProveRequest for dirty padding, got {:?}",
                other.err()
            ),
        }
    }

    // The local hand-rolled `base64_url_no_pad_decode` was removed; its
    // coverage lives in `gadget/src/base64/decoder.rs` tests now.

    #[test]
    fn build_merkle_witness_rejects_wrong_path_length() {
        let cfg = sample_config_v1();
        let tree_height = cfg.tree_height as usize;
        // Expected path length is tree_height - 1 = 3; supply 2.
        let auth_path = vec![F::zero(); 2];

        match build_merkle_witness("credentials[0]", F::zero(), &auth_path, 0, tree_height) {
            Err(ApplicationError::InvalidProveRequest { field, message }) => {
                assert!(field.contains("auth_path"), "got field {}", field);
                assert!(message.contains("tree_height - 1"), "got msg {}", message);
            }
            other => panic!(
                "expected InvalidProveRequest for auth_path length, got {:?}",
                other.err()
            ),
        }
    }
}
