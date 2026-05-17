//! F-based per-stage witness builders for the ZKAP groth16 prove flow.
//!
//! This module owns the per-credential algorithm that the wire-decoded
//! `(SharedDecoded, Vec<CredentialDecoded>)` tuple is folded through.
//! Key design points:
//!
//! 1. Stage builders are `pub(crate)` (callable directly by `prove()`),
//!    not just package-private helpers wrapped in a single batch-level
//!    free function.
//! 2. Builder signatures take field elements (`F`) directly for fields
//!    that *are* field elements (anchor_values, anchor_known_x, merkle_root,
//!    merkle_leaf_sibling_hash, merkle_auth_path, random). The previous
//!    `*_be: &[[u8; 32]]` byte intermediate representation is gone.
//!    Genuine byte sequences (`jwt_bytes`, `rsa_modulus_bytes`,
//!    `rsa_signature_bytes`) remain `&[u8]`.
//! 3. Errors map directly onto [`ApplicationError`]:
//!    - input validation (shape, length, JWT parse, claim missing) →
//!      [`ApplicationError::InvalidProveRequest`] with a dotted
//!      `field_path` injected by the caller
//!    - Poseidon `CRH::<F>::evaluate(...)` failure →
//!      [`ApplicationError::PoseidonHashError`]
//!    - gadget [`AnchorError`](gadget::anchor::error::AnchorError) →
//!      [`ApplicationError::CryptographicError`] via the
//!      `From<AnchorError>` impl in `crate::error`
//! 4. Non-canonical field encoding detection is intentionally absent —
//!    that responsibility now lives entirely in the adapter's
//!    `decode_field_string`, which decodes wire strings to `F` and rejects
//!    inputs `>= F::MODULUS` before they reach these builders.

use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    merkle_tree::Path,
    sponge::poseidon::PoseidonConfig,
};
use ark_ff::{PrimeField, Zero};

use circuit::token::ClaimIndices;
use circuit::types::{CircuitConfig, F};
use circuit::witness::{JwtWitness, MerkleWitness};
use gadget::{
    anchor::poseidon::{PoseidonAnchor, build_anchor_witness},
    base64::IndexBits,
    matrix::VandermondeMatrix,
    signature::rsa::{PublicKey, Signature},
};

use crate::error::ApplicationError;

use super::RSA_2048_BYTES;

const BN254_LIMB_WIDTH: usize = 31;

fn pack_bytes_to_field_native(bytes: &[u8]) -> Vec<F> {
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

fn locate_claim(payload: &str, key: &str) -> Result<ClaimIndices, ApplicationError> {
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
        .ok_or_else(|| ApplicationError::InvalidProveRequest {
            field: "jwt.payload".into(),
            message: format!("claim `{}` not found in JWT payload", key),
        })?;

    let mut p = key_pos + needle.len();
    while p < bytes.len() && bytes[p].is_ascii_whitespace() {
        p += 1;
    }
    if p >= bytes.len() || bytes[p] != b':' {
        return Err(ApplicationError::InvalidProveRequest {
            field: "jwt.payload".into(),
            message: format!("claim `{}` missing `:` separator", key),
        });
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
            return Err(ApplicationError::InvalidProveRequest {
                field: "jwt.payload".into(),
                message: format!("claim `{}` quoted value not terminated", key),
            });
        }
        p += 1;
    }
    let value_end_abs = p;

    while p < bytes.len() && bytes[p].is_ascii_whitespace() {
        p += 1;
    }
    if p >= bytes.len() || (bytes[p] != b',' && bytes[p] != b'}') {
        return Err(ApplicationError::InvalidProveRequest {
            field: "jwt.payload".into(),
            message: format!("claim `{}` not terminated by `,` or `}}`", key),
        });
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

/// Anchor stage output: decoded anchor values, the gadget anchor
/// witness, the anchor object, and the resolved current index.
pub(crate) struct AnchorStage {
    pub(crate) anchor_values: Vec<F>,
    pub(crate) anchor_witness: gadget::anchor::poseidon::PoseidonAnchorWitness<F>,
    pub(crate) anchor: PoseidonAnchor<F>,
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
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("{}.anchor_values", field_path),
            message: format!(
                "length {} but n - k + 1 = {}",
                anchor_values.len(),
                m_anchor
            ),
        });
    }
    if anchor_known_x.len() != k {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("{}.anchor_known_x", field_path),
            message: format!("length {} but k = {}", anchor_known_x.len(), k),
        });
    }
    if anchor_selector.len() != n {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("{}.anchor_selector", field_path),
            message: format!("length {} but n = {}", anchor_selector.len(), n),
        });
    }
    let cardinality = anchor_selector.iter().filter(|&&s| s == 1).count();
    if cardinality != k {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("{}.anchor_selector", field_path),
            message: format!("cardinality = {} but k = {}", cardinality, k),
        });
    }
    let current_idx = anchor_current_idx as usize;
    if current_idx >= n || anchor_selector.get(current_idx).copied().unwrap_or(0) != 1 {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("{}.anchor_current_idx", field_path),
            message: format!(
                "anchor_current_idx={} not in 0..n or selector[idx] != 1",
                current_idx
            ),
        });
    }

    let anchor_witness =
        build_anchor_witness(poseidon_param, anchor_known_x, anchor_selector, matrix)?;
    let anchor = PoseidonAnchor::new(anchor_values.to_vec());

    Ok(AnchorStage {
        anchor_values: anchor_values.to_vec(),
        anchor_witness,
        anchor,
        current_idx,
    })
}

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
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("{}.rsa_modulus_bytes", field_path),
            message: format!(
                "length {} but RSA-2048 requires exactly {} bytes",
                rsa_modulus_bytes.len(),
                RSA_2048_BYTES
            ),
        });
    }
    if rsa_signature_bytes.len() != RSA_2048_BYTES {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("{}.rsa_signature_bytes", field_path),
            message: format!(
                "length {} but RSA-2048 requires exactly {} bytes",
                rsa_signature_bytes.len(),
                RSA_2048_BYTES
            ),
        });
    }

    let jwt_str =
        core::str::from_utf8(jwt_bytes).map_err(|e| ApplicationError::InvalidProveRequest {
            field: format!("{}.jwt_bytes", field_path),
            message: format!("not UTF-8: {}", e),
        })?;
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("{}.jwt_bytes", field_path),
            message: format!("expected 3 dot-separated segments, got {}", parts.len()),
        });
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
        .map_err(|e| ApplicationError::InvalidProveRequest {
            field: format!("{}.jwt_bytes", field_path),
            message: format!("base64 index-bits build failed: {:?}", e),
        })?;

    let payload_bytes = base64_url_no_pad_decode(payload_b64.as_bytes()).map_err(|e| {
        ApplicationError::InvalidProveRequest {
            field: format!("{}.jwt_bytes", field_path),
            message: format!("payload base64 decode failed: {}", e),
        }
    })?;
    let payload_str = core::str::from_utf8(&payload_bytes).map_err(|e| {
        ApplicationError::InvalidProveRequest {
            field: format!("{}.jwt_bytes", field_path),
            message: format!("payload not UTF-8: {}", e),
        }
    })?;

    let mut claim_indices: Vec<ClaimIndices> = Vec::with_capacity(cfg.claims.len());
    for key in &cfg.claims {
        // locate_claim returns InvalidProveRequest{field:"jwt.payload", ...};
        // wrap to include the credential field_path prefix.
        claim_indices.push(locate_claim(payload_str, key).map_err(|e| match e {
            ApplicationError::InvalidProveRequest { message, .. } => {
                ApplicationError::InvalidProveRequest {
                    field: format!("{}.jwt_bytes", field_path),
                    message,
                }
            }
            other => other,
        })?);
    }

    let pk = PublicKey {
        n: rsa_modulus_bytes.to_vec(),
        e: vec![0x01, 0x00, 0x01],
    };

    let sig_bytes_decoded = base64_url_no_pad_decode(sig_b64.as_bytes()).map_err(|e| {
        ApplicationError::InvalidProveRequest {
            field: format!("{}.jwt_bytes", field_path),
            message: format!("signature base64 decode failed: {}", e),
        }
    })?;
    if sig_bytes_decoded != rsa_signature_bytes {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("{}.rsa_signature_bytes", field_path),
            message: format!(
                "rsa_signature_bytes ({} bytes) != base64_decode(jwt sig_b64) ({} bytes)",
                rsa_signature_bytes.len(),
                sig_bytes_decoded.len()
            ),
        });
    }
    let sig = Signature(rsa_signature_bytes.to_vec());

    let aud_idx = claim_indices
        .iter()
        .zip(cfg.claims.iter())
        .find(|(_, k)| *k == "aud")
        .map(|(idx, _)| idx)
        .ok_or_else(|| ApplicationError::InvalidProveRequest {
            field: format!("{}.jwt_bytes", field_path),
            message: "claim `aud` not found in JWT payload".into(),
        })?;
    let aud_bytes_padded =
        claim_value_bytes_padded(&payload_bytes, aud_idx, cfg.max_aud_len as usize);
    let aud_packed = pack_bytes_to_field_native(&aud_bytes_padded);
    CRH::<F>::evaluate(poseidon_param, aud_packed.clone())
        .map_err(|_| ApplicationError::PoseidonHashError)?;

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

/// Audience stage output: padded audience list and its chained
/// Poseidon hash.
pub(crate) struct AudienceStage {
    pub(crate) aud_list: Vec<F>,
    pub(crate) h_aud_list: F,
}

/// Build the audience stage from `aud_packed` (already produced by
/// [`build_jwt_stage`]). `payload_bytes`/`claim_indices`/`claims` are
/// retained for parity with the legacy signature but are not used by
/// the current algorithm.
pub(crate) fn build_audience_stage(
    field_path: &str,
    payload_bytes: &[u8],
    claim_indices: &[ClaimIndices],
    claims: &[String],
    aud_packed: &[F],
    cfg: &CircuitConfig,
    poseidon_param: &PoseidonConfig<F>,
) -> Result<AudienceStage, ApplicationError> {
    let _ = field_path;
    let num_audience_limit = cfg.num_audience_limit as usize;

    let h_aud = CRH::<F>::evaluate(poseidon_param, aud_packed.to_vec())
        .map_err(|_| ApplicationError::PoseidonHashError)?;

    let mut forbidden_bytes = Vec::with_capacity(cfg.forbidden_string.len() + 2);
    forbidden_bytes.push(b'"');
    forbidden_bytes.extend_from_slice(cfg.forbidden_string.as_bytes());
    forbidden_bytes.push(b'"');
    let forbidden_padded = pad_claim_value_to_max(&forbidden_bytes, cfg.max_aud_len as usize);
    let forbidden_packed = pack_bytes_to_field_native(&forbidden_padded);
    let h_forbidden = CRH::<F>::evaluate(poseidon_param, forbidden_packed)
        .map_err(|_| ApplicationError::PoseidonHashError)?;

    let mut aud_list = Vec::with_capacity(num_audience_limit);
    aud_list.push(h_aud);
    while aud_list.len() < num_audience_limit {
        aud_list.push(h_forbidden);
    }
    let h_aud_list = CRH::<F>::evaluate(poseidon_param, aud_list.clone())
        .map_err(|_| ApplicationError::PoseidonHashError)?;

    let _ = (claim_indices, claims, payload_bytes);

    Ok(AudienceStage {
        aud_list,
        h_aud_list,
    })
}

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
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("{}.auth_path", field_path),
            message: format!(
                "length {} but tree_height - 1 = {}",
                auth_path.len(),
                expected_path_len
            ),
        });
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

    let hanchor = chain_hash_native(anchor_values, poseidon_param)?;

    let mut h_a_inputs = witness.a.clone();
    h_a_inputs.push(random);
    let h_a = CRH::<F>::evaluate(poseidon_param, h_a_inputs)
        .map_err(|_| ApplicationError::PoseidonHashError)?;

    let inner: F = witness
        .a
        .iter()
        .zip(anchor_values.iter())
        .map(|(a, anc)| *a * *anc)
        .sum();
    let lhs = inner * random;

    let claim_indices_for = |key: &str| -> Result<&ClaimIndices, ApplicationError> {
        for (i, k) in claims.iter().enumerate() {
            if k == key {
                return Ok(&claim_indices[i]);
            }
        }
        Err(ApplicationError::InvalidProveRequest {
            field: format!("{}.jwt_bytes", field_path),
            message: format!("claim `{}` not found in JWT payload", key),
        })
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
        .map_err(|_| ApplicationError::PoseidonHashError)?;
    let h_id = CRH::<F>::evaluate(poseidon_param, [F::from(current_idx as u64), h_id_inner])
        .map_err(|_| ApplicationError::PoseidonHashError)?;
    let partial_rhs = witness.b[current_idx] * h_id * random;

    let exp_bytes_padded = claim_value_bytes_padded(
        payload_bytes,
        claim_indices_for("exp")?,
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

/// Chain Poseidon hash: `H(v[0])`, then `H(prev, v[i])` for `i in 1..len`.
fn chain_hash_native(values: &[F], params: &PoseidonConfig<F>) -> Result<F, ApplicationError> {
    if values.is_empty() {
        return Err(ApplicationError::InvalidProveRequest {
            field: "anchor_values".into(),
            message: "chain_hash on empty anchor".into(),
        });
    }
    let mut h =
        CRH::<F>::evaluate(params, [values[0]]).map_err(|_| ApplicationError::PoseidonHashError)?;
    for v in &values[1..] {
        h = CRH::<F>::evaluate(params, [h, *v]).map_err(|_| ApplicationError::PoseidonHashError)?;
    }
    Ok(h)
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

fn base64_url_no_pad_decode(input: &[u8]) -> Result<Vec<u8>, ApplicationError> {
    fn val(b: u8) -> Result<u8, ApplicationError> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(ApplicationError::InvalidProveRequest {
                field: "jwt_bytes".into(),
                message: format!("invalid base64-url character 0x{:02x}", b),
            }),
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
        _ => {
            return Err(ApplicationError::InvalidProveRequest {
                field: "jwt_bytes".into(),
                message: "invalid base64-url length (rem 1 mod 4)".into(),
            });
        }
    }
    Ok(out)
}

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

    #[test]
    fn base64_url_decoder_matches_reference() {
        let decoded = base64_url_no_pad_decode(b"SGVsbG8").expect("decode");
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn base64_url_decoder_rejects_invalid_char() {
        match base64_url_no_pad_decode(b"ABC*") {
            Err(ApplicationError::InvalidProveRequest { message, .. }) => {
                assert!(
                    message.contains("invalid base64-url character"),
                    "got msg {}",
                    message
                );
            }
            other => panic!(
                "expected InvalidProveRequest for invalid base64-url char, got {:?}",
                other.err()
            ),
        }
    }

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
