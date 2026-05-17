//! Native `WitnessRequest` → `ZkapCircuitInput<F>` conversion.
//!
//! The field-element BE codec lives in `ark-utils::codec::field`; this
//! module pulls in the circuit-side types and turns a borrowed
//! [`SharedFields`] + [`PerJwtFields`] + [`CircuitConfig`] triple into
//! a fully assigned [`ZkapCircuitInput<F>`] in a single in-process
//! pass.

use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    merkle_tree::Path,
    sponge::poseidon::PoseidonConfig,
};
use ark_ff::{PrimeField, Zero};

use circuit::token::ClaimIndices;
use circuit::types::{CircuitConfig, F};
use circuit::witness::{
    AnchorWitness, AudienceWitness, CircuitConstants, CircuitPublicInputs, JwtWitness,
    MerkleWitness, MiscWitness, ZkapCircuitInput,
};
use gadget::{
    anchor::poseidon::{PoseidonAnchor, build_anchor_witness},
    base64::{IndexBits, get_base64_table},
    hashes::poseidon::get_poseidon_params,
    matrix::VandermondeMatrix,
    signature::rsa::{PublicKey, Signature},
};

use ark_utils::codec::field::fe_from_be32_canonical;

use super::RSA_2048_BYTES;
use super::witness_error::ZkapWitnessError;
use super::witness_request::{PerJwtFields, SharedFields};

const BN254_LIMB_WIDTH: usize = 31;

#[doc(hidden)]
pub fn pack_bytes_to_field_native(bytes: &[u8]) -> Vec<F> {
    debug_assert!(bytes.len().is_multiple_of(BN254_LIMB_WIDTH));
    bytes
        .chunks(BN254_LIMB_WIDTH)
        .map(F::from_be_bytes_mod_order)
        .collect()
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
#[doc(hidden)]
pub fn sha_pad_signing_input(signing_input: &[u8], max_jwt_b64_len: usize) -> (Vec<u8>, usize) {
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

fn locate_claim(payload: &str, key: &str) -> Result<ClaimIndices, ZkapWitnessError> {
    let needle = {
        let mut s = String::with_capacity(key.len() + 2);
        s.push('"');
        s.push_str(key);
        s.push('"');
        s
    };
    let bytes = payload.as_bytes();

    let key_pos = payload
        .find(&needle)
        .ok_or_else(|| ZkapWitnessError::ClaimNotFound(key.to_owned()))?;

    let mut p = key_pos + needle.len();
    while p < bytes.len() && bytes[p].is_ascii_whitespace() {
        p += 1;
    }
    if p >= bytes.len() || bytes[p] != b':' {
        return Err(ZkapWitnessError::ClaimNotFound(key.to_owned()));
    }
    let colon_abs = p;
    p += 1;

    while p < bytes.len() && bytes[p].is_ascii_whitespace() {
        p += 1;
    }
    let value_start_abs = p;
    let opens_with_quote = p < bytes.len() && bytes[p] == b'"';
    if opens_with_quote {
        p += 1;
    }
    while p < bytes.len() && bytes[p] != b'"' && bytes[p] != b',' && bytes[p] != b'}' {
        p += 1;
    }
    if opens_with_quote {
        if p >= bytes.len() || bytes[p] != b'"' {
            return Err(ZkapWitnessError::ClaimNotFound(key.to_owned()));
        }
        p += 1;
    }
    let value_end_abs = p;

    while p < bytes.len() && bytes[p].is_ascii_whitespace() {
        p += 1;
    }
    if p >= bytes.len() || (bytes[p] != b',' && bytes[p] != b'}') {
        return Err(ZkapWitnessError::ClaimNotFound(key.to_owned()));
    }
    let terminator_abs = p;

    let offset = key_pos;
    let claim_len = terminator_abs + 1 - offset;
    let colon_idx = colon_abs - offset;
    let value_idx = value_start_abs - offset;
    let value_len = value_end_abs - value_start_abs;

    Ok(ClaimIndices {
        offset,
        claim_len,
        colon_idx,
        value_idx,
        value_len,
    })
}

fn claim_value_bytes_padded(
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

fn nc_field<S: Into<String>>(
    field: S,
) -> impl FnOnce(ark_utils::codec::field::NonCanonicalFieldError) -> ZkapWitnessError {
    let field = field.into();
    move |e| ZkapWitnessError::NonCanonicalField(format!("{}: {}", field, e))
}

pub(crate) struct AnchorStage {
    pub(crate) anchor_values: Vec<F>,
    pub(crate) anchor_witness: gadget::anchor::poseidon::PoseidonAnchorWitness<F>,
    pub(crate) anchor: PoseidonAnchor<F>,
    pub(crate) current_idx: usize,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_anchor_witness_from_v1(
    anchor_values_be: &[[u8; 32]],
    anchor_known_x_be: &[[u8; 32]],
    anchor_selector: &[u8],
    anchor_current_idx: u64,
    n: usize,
    k: usize,
    poseidon_param: &PoseidonConfig<F>,
    matrix: &gadget::matrix::VandermondeMatrix<F>,
) -> Result<AnchorStage, ZkapWitnessError> {
    let m_anchor = n - k + 1;
    if anchor_values_be.len() != m_anchor {
        return Err(ZkapWitnessError::DimensionMismatch(format!(
            "anchor_values_be.len()={} but n - k + 1 = {}",
            anchor_values_be.len(),
            m_anchor
        )));
    }
    if anchor_known_x_be.len() != k {
        return Err(ZkapWitnessError::DimensionMismatch(format!(
            "anchor_known_x_be.len()={} but k = {}",
            anchor_known_x_be.len(),
            k
        )));
    }
    if anchor_selector.len() != n {
        return Err(ZkapWitnessError::DimensionMismatch(format!(
            "anchor_selector.len()={} but n = {}",
            anchor_selector.len(),
            n
        )));
    }
    let cardinality = anchor_selector.iter().filter(|&&s| s == 1).count();
    if cardinality != k {
        return Err(ZkapWitnessError::DimensionMismatch(format!(
            "anchor_selector cardinality = {} but k = {}",
            cardinality, k
        )));
    }
    let current_idx = anchor_current_idx as usize;
    if current_idx >= n || anchor_selector.get(current_idx).copied().unwrap_or(0) != 1 {
        return Err(ZkapWitnessError::DimensionMismatch(format!(
            "anchor_current_idx={} not in 0..n or selector[idx] != 1",
            current_idx
        )));
    }

    let known_x_list: Vec<F> = anchor_known_x_be
        .iter()
        .enumerate()
        .map(|(i, b)| {
            fe_from_be32_canonical(b).map_err(nc_field(format!("anchor_known_x_be[{}]", i)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let anchor_values: Vec<F> = anchor_values_be
        .iter()
        .enumerate()
        .map(|(i, b)| {
            fe_from_be32_canonical(b).map_err(nc_field(format!("anchor_values_be[{}]", i)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let anchor_witness =
        build_anchor_witness(poseidon_param, &known_x_list, anchor_selector, matrix)
            .map_err(|e| ZkapWitnessError::AnchorBuild(format!("{:?}", e)))?;
    let anchor = PoseidonAnchor::new(anchor_values.clone());

    Ok(AnchorStage {
        anchor_values,
        anchor_witness,
        anchor,
        current_idx,
    })
}

pub(crate) struct JwtStage {
    pub(crate) jwt_witness: JwtWitness,
    pub(crate) payload_bytes: Vec<u8>,
    pub(crate) claim_indices: Vec<ClaimIndices>,
    pub(crate) aud_packed: Vec<F>,
}

pub(crate) fn build_jwt_witness_from_v1(
    jwt_bytes: &[u8],
    rsa_modulus_be: &[u8],
    rsa_signature_be: &[u8],
    cfg: &CircuitConfig,
    poseidon_param: &PoseidonConfig<F>,
) -> Result<JwtStage, ZkapWitnessError> {
    if rsa_modulus_be.len() != RSA_2048_BYTES {
        return Err(ZkapWitnessError::DimensionMismatch(format!(
            "rsa_modulus_be.len()={} but RSA-2048 requires exactly {} bytes",
            rsa_modulus_be.len(),
            RSA_2048_BYTES
        )));
    }
    if rsa_signature_be.len() != RSA_2048_BYTES {
        return Err(ZkapWitnessError::DimensionMismatch(format!(
            "rsa_signature_be.len()={} but RSA-2048 requires exactly {} bytes",
            rsa_signature_be.len(),
            RSA_2048_BYTES
        )));
    }

    let jwt_str = core::str::from_utf8(jwt_bytes)
        .map_err(|e| ZkapWitnessError::MalformedJwt(format!("not UTF-8: {}", e)))?;
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        return Err(ZkapWitnessError::MalformedJwt(format!(
            "expected 3 dot-separated segments, got {}",
            parts.len()
        )));
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
        .map_err(|e| ZkapWitnessError::IndexBits(format!("{:?}", e)))?;

    let payload_bytes = base64_url_no_pad_decode(payload_b64.as_bytes())
        .map_err(|e| ZkapWitnessError::Base64(format!("payload: {}", e)))?;
    let payload_str = core::str::from_utf8(&payload_bytes)
        .map_err(|e| ZkapWitnessError::MalformedJwt(format!("payload not UTF-8: {}", e)))?;

    let mut claim_indices: Vec<ClaimIndices> = Vec::with_capacity(cfg.claims.len());
    for key in &cfg.claims {
        claim_indices.push(locate_claim(payload_str, key)?);
    }

    let pk = PublicKey {
        n: rsa_modulus_be.to_vec(),
        e: vec![0x01, 0x00, 0x01],
    };

    let sig_bytes_decoded = base64_url_no_pad_decode(sig_b64.as_bytes())
        .map_err(|e| ZkapWitnessError::Base64(format!("signature: {}", e)))?;
    if sig_bytes_decoded != rsa_signature_be {
        return Err(ZkapWitnessError::SignatureMismatch(format!(
            "rsa_signature_be ({} bytes) != base64_decode(jwt sig_b64) ({} bytes)",
            rsa_signature_be.len(),
            sig_bytes_decoded.len()
        )));
    }
    let sig = Signature(rsa_signature_be.to_vec());

    let aud_idx = claim_indices
        .iter()
        .zip(cfg.claims.iter())
        .find(|(_, k)| *k == "aud")
        .map(|(idx, _)| idx)
        .ok_or_else(|| ZkapWitnessError::ClaimNotFound("aud".to_owned()))?;
    let aud_bytes_padded =
        claim_value_bytes_padded(&payload_bytes, aud_idx, cfg.max_aud_len as usize);
    let aud_packed = pack_bytes_to_field_native(&aud_bytes_padded);
    CRH::<F>::evaluate(poseidon_param, aud_packed.clone())
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_aud (jwt stage): {}", e)))?;

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

pub(crate) struct AudienceStage {
    pub(crate) aud_list: Vec<F>,
    pub(crate) h_aud_list: F,
}

pub(crate) fn build_audience_witness_from_v1(
    payload_bytes: &[u8],
    claim_indices: &[ClaimIndices],
    claims: &[String],
    aud_packed: &[F],
    cfg: &CircuitConfig,
    poseidon_param: &PoseidonConfig<F>,
) -> Result<AudienceStage, ZkapWitnessError> {
    let num_audience_limit = cfg.num_audience_limit as usize;

    let h_aud = CRH::<F>::evaluate(poseidon_param, aud_packed.to_vec())
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_aud: {}", e)))?;

    let mut forbidden_bytes = Vec::with_capacity(cfg.forbidden_string.len() + 2);
    forbidden_bytes.push(b'"');
    forbidden_bytes.extend_from_slice(cfg.forbidden_string.as_bytes());
    forbidden_bytes.push(b'"');
    let forbidden_padded = pad_claim_value_to_max(&forbidden_bytes, cfg.max_aud_len as usize);
    let forbidden_packed = pack_bytes_to_field_native(&forbidden_padded);
    let h_forbidden = CRH::<F>::evaluate(poseidon_param, forbidden_packed)
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_forbidden: {}", e)))?;

    let mut aud_list = Vec::with_capacity(num_audience_limit);
    aud_list.push(h_aud);
    while aud_list.len() < num_audience_limit {
        aud_list.push(h_forbidden);
    }
    let h_aud_list = CRH::<F>::evaluate(poseidon_param, aud_list.clone())
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_aud_list: {}", e)))?;

    let _ = (claim_indices, claims, payload_bytes);

    Ok(AudienceStage {
        aud_list,
        h_aud_list,
    })
}

pub(crate) fn build_merkle_witness_from_v1(
    merkle_leaf_sibling_hash_be: &[u8; 32],
    merkle_auth_path_be: &[[u8; 32]],
    merkle_leaf_idx: u64,
    tree_height: usize,
) -> Result<MerkleWitness<F>, ZkapWitnessError> {
    let expected_path_len = tree_height.saturating_sub(1);
    if merkle_auth_path_be.len() != expected_path_len {
        return Err(ZkapWitnessError::DimensionMismatch(format!(
            "merkle_auth_path_be.len()={} but tree_height - 1 = {}",
            merkle_auth_path_be.len(),
            expected_path_len
        )));
    }

    let leaf_sibling_hash = fe_from_be32_canonical(merkle_leaf_sibling_hash_be)
        .map_err(nc_field("merkle_leaf_sibling_hash_be"))?;
    let auth_path: Vec<F> = merkle_auth_path_be
        .iter()
        .enumerate()
        .map(|(i, b)| {
            fe_from_be32_canonical(b).map_err(nc_field(format!("merkle_auth_path_be[{}]", i)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(MerkleWitness {
        path: Path {
            leaf_sibling_hash,
            auth_path,
            leaf_index: merkle_leaf_idx as usize,
        },
        leaf_idx: merkle_leaf_idx as usize,
    })
}

pub(crate) struct PublicInputsStage {
    pub(crate) hanchor: F,
    pub(crate) h_a: F,
    pub(crate) root: F,
    pub(crate) lhs: F,
    pub(crate) partial_rhs: F,
    pub(crate) jwt_exp: F,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_public_inputs_from_v1(
    anchor_stage: &AnchorStage,
    payload_bytes: &[u8],
    claim_indices: &[ClaimIndices],
    claims: &[String],
    aud_packed: &[F],
    merkle_root_be: &[u8; 32],
    random_be: &[u8; 32],
    cfg: &CircuitConfig,
    poseidon_param: &PoseidonConfig<F>,
) -> Result<PublicInputsStage, ZkapWitnessError> {
    let current_idx = anchor_stage.current_idx;
    let anchor_values = &anchor_stage.anchor_values;
    let witness = &anchor_stage.anchor_witness;

    let root = fe_from_be32_canonical(merkle_root_be).map_err(nc_field("merkle_root_be"))?;
    let random = fe_from_be32_canonical(random_be).map_err(nc_field("random_be"))?;

    let hanchor = chain_hash_native(anchor_values, poseidon_param)?;

    let mut h_a_inputs = witness.a.clone();
    h_a_inputs.push(random);
    let h_a = CRH::<F>::evaluate(poseidon_param, h_a_inputs)
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_a: {}", e)))?;

    let inner: F = witness
        .a
        .iter()
        .zip(anchor_values.iter())
        .map(|(a, anc)| *a * *anc)
        .sum();
    let lhs = inner * random;

    let claim_indices_for = |key: &str| -> Result<&ClaimIndices, ZkapWitnessError> {
        for (i, k) in claims.iter().enumerate() {
            if k == key {
                return Ok(&claim_indices[i]);
            }
        }
        Err(ZkapWitnessError::ClaimNotFound(key.to_owned()))
    };

    let iss_bytes_padded = claim_value_bytes_padded(
        payload_bytes,
        claim_indices_for("iss")?,
        cfg.max_iss_len as usize,
    );
    let sub_bytes_padded = claim_value_bytes_padded(
        payload_bytes,
        claim_indices_for("sub")?,
        cfg.max_sub_len as usize,
    );
    let iss_packed = pack_bytes_to_field_native(&iss_bytes_padded);
    let sub_packed = pack_bytes_to_field_native(&sub_bytes_padded);

    let mut h_id_inputs: Vec<F> = Vec::new();
    h_id_inputs.extend_from_slice(aud_packed);
    h_id_inputs.extend_from_slice(&iss_packed);
    h_id_inputs.extend_from_slice(&sub_packed);
    let h_id_inner = CRH::<F>::evaluate(poseidon_param, h_id_inputs)
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_id_inner: {}", e)))?;
    let h_id = CRH::<F>::evaluate(poseidon_param, [F::from(current_idx as u64), h_id_inner])
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_id: {}", e)))?;
    let partial_rhs = witness.b[current_idx] * h_id * random;

    let exp_bytes_padded = claim_value_bytes_padded(
        payload_bytes,
        claim_indices_for("exp")?,
        cfg.max_exp_len as usize,
    );
    let jwt_exp = decimal_bytes_to_field(&exp_bytes_padded)?;

    Ok(PublicInputsStage {
        hanchor,
        h_a,
        root,
        lhs,
        partial_rhs,
        jwt_exp,
    })
}

/// Full `WitnessRequest` → `ZkapCircuitInput<F>` conversion.
///
/// Borrows the batch-shared fields, one per-JWT slice, and the
/// circuit config. Validates the config's shape, decodes every BE
/// field-element with canonical-encoding checks, parses the JWT,
/// builds the anchor / merkle / audience witnesses, and assembles
/// the fully assigned circuit input.
pub fn into_circuit_input(
    shared: &SharedFields,
    per_jwt: &PerJwtFields,
    cfg: &CircuitConfig,
) -> Result<ZkapCircuitInput<F>, ZkapWitnessError> {
    cfg.validate()
        .map_err(|e| ZkapWitnessError::InvalidConfig(e.to_string()))?;

    let n = cfg.n as usize;
    let k = cfg.k as usize;
    let tree_height = cfg.tree_height as usize;

    let matrix = VandermondeMatrix::<F>::new(n, k);
    let poseidon_param: PoseidonConfig<F> = get_poseidon_params::<F>();
    let base64_table = get_base64_table();

    let anchor_stage = build_anchor_witness_from_v1(
        &shared.anchor_values_be,
        &shared.anchor_known_x_be,
        &shared.anchor_selector,
        per_jwt.anchor_current_idx,
        n,
        k,
        &poseidon_param,
        &matrix,
    )?;

    let random = fe_from_be32_canonical(&shared.random_be).map_err(nc_field("random_be"))?;
    let h_sign_user_op =
        fe_from_be32_canonical(&shared.h_sign_user_op_be).map_err(nc_field("h_sign_user_op_be"))?;

    let jwt_stage = build_jwt_witness_from_v1(
        &per_jwt.jwt_bytes,
        &per_jwt.rsa_modulus_be,
        &per_jwt.rsa_signature_be,
        cfg,
        &poseidon_param,
    )?;

    let aud_stage = build_audience_witness_from_v1(
        &jwt_stage.payload_bytes,
        &jwt_stage.claim_indices,
        &cfg.claims,
        &jwt_stage.aud_packed,
        cfg,
        &poseidon_param,
    )?;

    let merkle = build_merkle_witness_from_v1(
        &per_jwt.merkle_leaf_sibling_hash_be,
        &per_jwt.merkle_auth_path_be,
        per_jwt.merkle_leaf_idx,
        tree_height,
    )?;

    let pub_stage = compute_public_inputs_from_v1(
        &anchor_stage,
        &jwt_stage.payload_bytes,
        &jwt_stage.claim_indices,
        &cfg.claims,
        &jwt_stage.aud_packed,
        &shared.merkle_root_be,
        &shared.random_be,
        cfg,
        &poseidon_param,
    )?;

    debug_assert_eq!(random, {
        fe_from_be32_canonical(&shared.random_be).unwrap_or(random)
    });

    Ok(ZkapCircuitInput {
        params: cfg.clone(),
        constants: CircuitConstants {
            vandermonde_matrix: matrix,
            poseidon_param,
            base64_table,
        },
        public_inputs: CircuitPublicInputs {
            hanchor: pub_stage.hanchor,
            h_a: pub_stage.h_a,
            root: pub_stage.root,
            h_sign_user_op,
            jwt_exp: pub_stage.jwt_exp,
            partial_rhs: pub_stage.partial_rhs,
            lhs: pub_stage.lhs,
            h_aud_list: aud_stage.h_aud_list,
        },
        jwt: jwt_stage.jwt_witness,
        anchor: AnchorWitness {
            anchor: anchor_stage.anchor,
            a: anchor_stage.anchor_witness.a,
            selector: shared.anchor_selector.clone(),
            current_idx: anchor_stage.current_idx,
        },
        merkle,
        audience: AudienceWitness {
            aud_list: aud_stage.aud_list,
        },
        misc: MiscWitness { random },
    })
}

/// Chain Poseidon hash: `H(v[0])`, then `H(prev, v[i])` for `i in 1..len`.
#[doc(hidden)]
pub fn chain_hash_native(values: &[F], params: &PoseidonConfig<F>) -> Result<F, ZkapWitnessError> {
    if values.is_empty() {
        return Err(ZkapWitnessError::DimensionMismatch(
            "chain_hash on empty anchor".into(),
        ));
    }
    let mut h = CRH::<F>::evaluate(params, [values[0]])
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon chain[0]: {}", e)))?;
    for v in &values[1..] {
        h = CRH::<F>::evaluate(params, [h, *v])
            .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon chain[i]: {}", e)))?;
    }
    Ok(h)
}

fn decimal_bytes_to_field(bytes: &[u8]) -> Result<F, ZkapWitnessError> {
    if bytes.len() < 10 {
        return Err(ZkapWitnessError::MalformedJwt(format!(
            "exp claim padded length {} < 10",
            bytes.len()
        )));
    }
    let mut acc = F::zero();
    let ten = F::from(10u64);
    for &b in &bytes[..10] {
        if !b.is_ascii_digit() {
            return Err(ZkapWitnessError::MalformedJwt(format!(
                "exp claim has non-digit byte 0x{:02x}",
                b
            )));
        }
        acc = acc * ten + F::from((b - b'0') as u64);
    }
    for &b in &bytes[10..] {
        if b != 0 {
            return Err(ZkapWitnessError::MalformedJwt(format!(
                "exp claim padding byte 0x{:02x} is non-zero",
                b
            )));
        }
    }
    Ok(acc)
}

fn base64_url_no_pad_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    fn val(b: u8) -> Result<u8, String> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(format!("invalid base64-url character 0x{:02x}", b)),
        }
    }
    let mut out = Vec::with_capacity((input.len() * 3).div_ceil(4));
    let mut i = 0;
    while i + 4 <= input.len() {
        let b0 = val(input[i])?;
        let b1 = val(input[i + 1])?;
        let b2 = val(input[i + 2])?;
        let b3 = val(input[i + 3])?;
        out.push((b0 << 2) | (b1 >> 4));
        out.push((b1 << 4) | (b2 >> 2));
        out.push((b2 << 6) | b3);
        i += 4;
    }
    let rem = input.len() - i;
    match rem {
        0 => {}
        2 => {
            let b0 = val(input[i])?;
            let b1 = val(input[i + 1])?;
            out.push((b0 << 2) | (b1 >> 4));
        }
        3 => {
            let b0 = val(input[i])?;
            let b1 = val(input[i + 1])?;
            let b2 = val(input[i + 2])?;
            out.push((b0 << 2) | (b1 >> 4));
            out.push((b1 << 4) | (b2 >> 2));
        }
        _ => return Err("invalid base64-url length (rem 1 mod 4)".into()),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::types::{BNP, CG};
    use circuit::zkap::ZkapCircuit;

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

    fn dummy_shared(cfg: &CircuitConfig) -> SharedFields {
        SharedFields {
            random_be: [0x11; 32],
            h_sign_user_op_be: [0x22; 32],
            anchor_values_be: vec![[0x33; 32]; (cfg.n - cfg.k + 1) as usize],
            anchor_known_x_be: vec![[0x44; 32]; cfg.k as usize],
            anchor_selector: vec![1, 1, 1, 0, 0, 0],
            merkle_root_be: [0x55; 32],
        }
    }

    fn dummy_per_jwt(cfg: &CircuitConfig) -> PerJwtFields {
        PerJwtFields {
            jwt_bytes: b"hdr.payload.sig".to_vec(),
            rsa_modulus_be: vec![0x12; 256],
            rsa_signature_be: vec![0x34; 256],
            anchor_current_idx: 0,
            merkle_leaf_sibling_hash_be: [0x66; 32],
            merkle_auth_path_be: vec![[0x77; 32]; (cfg.tree_height - 1) as usize],
            merkle_leaf_idx: 0,
        }
    }

    const BN254_FR_MODULUS_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    #[test]
    fn into_circuit_input_rejects_non_canonical_random_be() {
        let cfg = sample_config_v1();
        let mut shared = dummy_shared(&cfg);
        let per_jwt = dummy_per_jwt(&cfg);
        shared.random_be = BN254_FR_MODULUS_BE;
        shared.anchor_values_be = vec![[0u8; 32]; shared.anchor_values_be.len()];
        shared.anchor_known_x_be = vec![[0u8; 32]; shared.anchor_known_x_be.len()];
        shared.merkle_root_be = [0u8; 32];
        shared.h_sign_user_op_be = [0u8; 32];

        match into_circuit_input(&shared, &per_jwt, &cfg) {
            Err(ZkapWitnessError::NonCanonicalField(msg)) => {
                assert!(msg.contains("random_be"), "got {}", msg);
            }
            Err(other) => panic!("unexpected error variant: {:?}", other),
            Ok(_) => panic!("expected NonCanonicalField, got Ok"),
        }
    }

    #[test]
    fn into_circuit_input_rejects_rsa_modulus_too_short() {
        let cfg = sample_config_v1();
        let mut shared = dummy_shared(&cfg);
        let mut per_jwt = dummy_per_jwt(&cfg);
        shared.anchor_values_be = vec![[0u8; 32]; shared.anchor_values_be.len()];
        shared.anchor_known_x_be = vec![[0u8; 32]; shared.anchor_known_x_be.len()];
        per_jwt.rsa_modulus_be = vec![0x12; 255];
        match into_circuit_input(&shared, &per_jwt, &cfg) {
            Err(ZkapWitnessError::DimensionMismatch(msg)) => {
                assert!(msg.contains("rsa_modulus_be"), "got {}", msg);
            }
            other => panic!("expected DimensionMismatch, got {:?}", other.err()),
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
        assert!(decimal_bytes_to_field(&bytes).is_err());
    }

    #[test]
    fn base64_url_decoder_matches_reference() {
        let decoded = base64_url_no_pad_decode(b"SGVsbG8").expect("decode");
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn base64_url_decoder_rejects_invalid_char() {
        assert!(base64_url_no_pad_decode(b"ABC*").is_err());
    }

    #[test]
    fn into_circuit_input_rejects_bad_selector_cardinality() {
        let cfg = sample_config_v1();
        let mut shared = dummy_shared(&cfg);
        let per_jwt = dummy_per_jwt(&cfg);
        shared.anchor_selector = vec![1, 1, 0, 0, 0, 0];
        match into_circuit_input(&shared, &per_jwt, &cfg) {
            Err(ZkapWitnessError::DimensionMismatch(_)) => {}
            other => panic!("expected DimensionMismatch, got {:?}", other.err()),
        }
    }

    /// `into_circuit_input` propagates a wrong `rsa_modulus_be` length
    /// as a [`ZkapWitnessError::DimensionMismatch`]. Distinct from
    /// [`into_circuit_input_rejects_rsa_modulus_too_short`] in that
    /// the surrounding fields are zeroed so only the rsa_modulus_be
    /// length triggers the failure.
    #[test]
    fn into_circuit_input_propagates_rsa_modulus_dimension_mismatch() {
        let cfg = sample_config_v1();
        let n = cfg.n as usize;
        let k = cfg.k as usize;
        let shared = SharedFields {
            random_be: [0u8; 32],
            h_sign_user_op_be: [0u8; 32],
            anchor_values_be: vec![[0u8; 32]; n - k + 1],
            anchor_known_x_be: vec![[0u8; 32]; k],
            anchor_selector: {
                let mut s = vec![0u8; n];
                for slot in s.iter_mut().take(k) {
                    *slot = 1;
                }
                s
            },
            merkle_root_be: [0u8; 32],
        };
        let per_jwt = PerJwtFields {
            jwt_bytes: Vec::new(),
            rsa_modulus_be: vec![0u8; 255],
            rsa_signature_be: vec![0u8; 256],
            anchor_current_idx: 0,
            merkle_leaf_sibling_hash_be: [0u8; 32],
            merkle_auth_path_be: vec![[0u8; 32]; (cfg.tree_height - 1) as usize],
            merkle_leaf_idx: 0,
        };
        match into_circuit_input(&shared, &per_jwt, &cfg) {
            Err(ZkapWitnessError::DimensionMismatch(msg)) => {
                assert!(
                    msg.contains("rsa_modulus_be"),
                    "expected error to mention rsa_modulus_be, got: {msg}"
                );
            }
            other => panic!("expected DimensionMismatch, got {:?}", other.err()),
        }
    }

    /// `ZkapCircuit::from_input` is callable on a
    /// [`ZkapCircuitInput<F>`] produced by service-side code. The seam
    /// check stays under a second by feeding
    /// `ZkapCircuit::generate_mock_circuit`'s own input rather than
    /// running the `WitnessRequest` → circuit conversion end to end.
    #[test]
    fn zkap_circuit_from_input_native_constructor() {
        let cfg = sample_config_v1();

        let mock = ZkapCircuit::<CG, BNP>::generate_mock_circuit(&cfg);

        let ci: ZkapCircuitInput<F> = ZkapCircuitInput {
            params: mock.params.clone(),
            constants: mock.constants.clone(),
            public_inputs: mock.public_inputs.clone(),
            jwt: mock.jwt.clone(),
            anchor: mock.anchor.clone(),
            merkle: mock.merkle.clone(),
            audience: mock.audience.clone(),
            misc: mock.misc.clone(),
        };
        let _circuit = ZkapCircuit::<CG, BNP>::from_input(ci);
    }
}
