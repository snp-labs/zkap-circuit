//! V1 → `ZkapCircuitInput<F>` conversion for the wasm witness-generator.
//!
//! The wire types ([`ZkapInputV1`], [`ZkapCircuitConfigV1`]) and the
//! field-element BE codec live in `zkap-input-types` (no `circuit`/`gadget`
//! deps). This module is the conversion-side companion: it pulls in the
//! circuit-side types and turns a postcard-decoded V1 payload into a fully
//! assigned [`ZkapMainCircuit`].
//!
//! # V1 — semantic input
//!
//! [`ZkapInputV1`] is the long-term wire format. The host sends raw
//! authentication material (full JWT bytes, RSA modulus, anchor scalars
//! together with selector and index, Merkle path, audience-related
//! circuit config), and the wasm side reconstructs the entire
//! [`ZkapMainCircuit`] — constants, public inputs, JWT, anchor, Merkle,
//! audience witnesses. The wasm artifact is the single source of truth
//! for circuit-witness construction; the host needs no dependency on
//! `circuit::ZkapCircuit`.
//!
//! ## Wire format (postcard, fields in declaration order)
//!
//! | Field                          | Encoding                                        |
//! |--------------------------------|-------------------------------------------------|
//! | `jwt_bytes`                    | postcard `Vec<u8>` (varint len + raw bytes)     |
//! | `rsa_modulus_be`               | postcard `Vec<u8>` (RSA-2048 N, exactly 256 BE bytes) |
//! | `rsa_signature_be`             | postcard `Vec<u8>` (RSA-2048 sig, exactly 256 BE bytes) |
//! | `random_be`                    | raw 32 bytes (no length prefix)                 |
//! | `h_sign_user_op_be`            | raw 32 bytes (no length prefix)                 |
//! | `anchor_values_be`             | postcard `Vec<[u8;32]>`, length = `n - k + 1`   |
//! | `anchor_known_x_be`            | postcard `Vec<[u8;32]>`, length = `k`           |
//! | `anchor_selector`              | postcard `Vec<u8>`, length = `n`, each `0`/`1`  |
//! | `anchor_current_idx`           | postcard u64 varint                             |
//! | `merkle_root_be`               | raw 32 bytes (no length prefix)                 |
//! | `merkle_leaf_sibling_hash_be`  | raw 32 bytes (no length prefix)                 |
//! | `merkle_auth_path_be`          | postcard `Vec<[u8;32]>`, length = `tree_height - 1` |
//! | `merkle_leaf_idx`              | postcard u64 varint                             |
//! | `circuit_config`               | nested struct, see [`ZkapCircuitConfigV1`]      |
//!
//! Bumping the order of any of the above fields, or changing
//! big-endian / variable-vs-fixed-length conventions, is a wire-format
//! break — the `WitnessGenerator::CIRCUIT_ID` MUST be bumped in lockstep.

use ark_crypto_primitives::{
    crh::{poseidon::CRH, CRHScheme},
    merkle_tree::Path,
    sponge::poseidon::PoseidonConfig,
};
use ark_ff::{PrimeField, Zero};

use circuit::constants::{CircuitConfig, RawCircuitConfig, BNP, CG, F};
use circuit::input::{
    AnchorWitness, AudienceWitness, CircuitConstants, CircuitPublicInputs, JwtWitness,
    MerkleWitness, MiscWitness, ZkapCircuitInput,
};
use circuit::token::ClaimIndices;
use circuit::zkap::ZkapCircuit;
use gadget::{
    anchor::poseidon::{build_anchor_witness, PoseidonAnchor},
    base64::{get_base64_table, IndexBits},
    hashes::poseidon::get_poseidon_params,
    matrix::VandermondeMatrix,
    signature::rsa::{PublicKey, Signature},
};

use zkap_input_types::{fe_from_be32_canonical, ZkapCircuitConfigV1, ZkapInputV1, RSA_2048_BYTES};

use crate::error::ZkapWitnessError;

/// Concrete `ZkapCircuit` instantiation used by this wasm artifact —
/// `(Curve = ed_on_bn254, BigNat = 2048-bit limbs)`.
pub type ZkapMainCircuit = ZkapCircuit<CG, BNP>;

// ---------- circuit-side ↔ V1 config conversions ----------
//
// `From` impls would violate the orphan rule (both `ZkapCircuitConfigV1`
// and `CircuitConfig` are foreign to this crate from the perspective of
// any future caller that sees both types via re-exports), so the
// conversions are exposed as free functions.

/// Build a wire-format [`ZkapCircuitConfigV1`] from the circuit-side
/// [`CircuitConfig`].
pub fn config_v1_from_circuit(c: &CircuitConfig) -> ZkapCircuitConfigV1 {
    ZkapCircuitConfigV1 {
        max_jwt_b64_len: c.max_jwt_b64_len,
        max_payload_b64_len: c.max_payload_b64_len,
        max_aud_len: c.max_aud_len,
        max_exp_len: c.max_exp_len,
        max_iss_len: c.max_iss_len,
        max_nonce_len: c.max_nonce_len,
        max_sub_len: c.max_sub_len,
        n: c.n,
        k: c.k,
        tree_height: c.tree_height,
        num_audience_limit: c.num_audience_limit,
        claims: c
            .claims
            .iter()
            .map(|b| {
                core::str::from_utf8(b)
                    .expect("CircuitConfig::claims entries are valid UTF-8")
                    .to_owned()
            })
            .collect(),
        forbidden_string: core::str::from_utf8(&c.forbidden_string)
            .expect("CircuitConfig::forbidden_string is valid UTF-8")
            .to_owned(),
    }
}

/// Build a circuit-side [`CircuitConfig`] from a wire-format
/// [`ZkapCircuitConfigV1`].
pub fn circuit_config_from_v1(c: &ZkapCircuitConfigV1) -> CircuitConfig {
    let raw = RawCircuitConfig {
        max_jwt_b64_len: c.max_jwt_b64_len,
        max_payload_b64_len: c.max_payload_b64_len,
        max_aud_len: c.max_aud_len,
        max_exp_len: c.max_exp_len,
        max_iss_len: c.max_iss_len,
        max_nonce_len: c.max_nonce_len,
        max_sub_len: c.max_sub_len,
        n: c.n,
        k: c.k,
        tree_height: c.tree_height,
        num_audience_limit: c.num_audience_limit,
        claims: c.claims.clone(),
        forbidden_string: c.forbidden_string.clone(),
    };
    CircuitConfig::from(raw)
}

// ---------- limb packing (mirrors test fixtures' pack_bytes_to_field_native) ----------

/// 31 = (254 - 1) / 8 — the BN254 byte-limb width.
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

// ---------- JWT byte-level helpers ----------

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

/// Locate a top-level JSON claim and return its [`ClaimIndices`] in the
/// shape produced by the test-suite regex:
/// `\s*("key")\s*:\s*("?[^",]*"?)\s*([,}])`.
///
/// The decoded JWT payloads emitted by the test fixtures are canonical
/// (no insignificant whitespace), so this scanner mirrors the regex's
/// observable behavior on those inputs without pulling the `regex`
/// crate into the wasm bundle.
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

/// Extract the claim's *value* bytes (with quotes for strings, unquoted for
/// numbers), zero-padded to `max_len`.
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

// ---------- main conversion ----------

/// One-shot host/wasm entry point: `V1 → ZkapMainCircuit` ready for
/// `ConstraintSynthesizer`. Wraps [`into_circuit_input`] and
/// `ZkapCircuit::from_input`.
pub fn build_main_circuit(input: ZkapInputV1) -> Result<ZkapMainCircuit, ZkapWitnessError> {
    let ci = into_circuit_input(input)?;
    Ok(ZkapMainCircuit::from_input(ci))
}

/// Map a [`zkap_input_types::NonCanonicalFieldError`] into the local
/// error variant, prefixing with the field name so failures stay
/// actionable when a host sends a `>= p` encoding.
fn nc_field<S: Into<String>>(field: S) -> impl FnOnce(zkap_input_types::NonCanonicalFieldError) -> ZkapWitnessError {
    let field = field.into();
    move |e| ZkapWitnessError::NonCanonicalField(format!("{}: {}", field, e))
}

/// Full V1 → `ZkapCircuitInput<F>` conversion. Compiles for both native
/// and `wasm32-unknown-unknown`; called from
/// `WitnessGenerator::build_circuit` and from V1 round-trip integration
/// tests.
pub fn into_circuit_input(input: ZkapInputV1) -> Result<ZkapCircuitInput<F>, ZkapWitnessError> {
    let ZkapInputV1 {
        jwt_bytes,
        rsa_modulus_be,
        rsa_signature_be,
        random_be,
        h_sign_user_op_be,
        anchor_values_be,
        anchor_known_x_be,
        anchor_selector,
        anchor_current_idx,
        merkle_root_be,
        merkle_leaf_sibling_hash_be,
        merkle_auth_path_be,
        merkle_leaf_idx,
        circuit_config,
    } = input;

    // 1. Validate config + dimensions.
    let cfg = circuit_config_from_v1(&circuit_config);
    cfg.validate().map_err(ZkapWitnessError::InvalidConfig)?;

    let n = cfg.n as usize;
    let k = cfg.k as usize;
    let m_anchor = n - k + 1;
    let tree_height = cfg.tree_height as usize;
    let num_audience_limit = cfg.num_audience_limit as usize;

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
    if current_idx >= n
        || anchor_selector
            .get(current_idx)
            .copied()
            .unwrap_or(0)
            != 1
    {
        return Err(ZkapWitnessError::DimensionMismatch(format!(
            "anchor_current_idx={} not in 0..n or selector[idx] != 1",
            current_idx
        )));
    }
    let expected_path_len = tree_height.saturating_sub(1);
    if merkle_auth_path_be.len() != expected_path_len {
        return Err(ZkapWitnessError::DimensionMismatch(format!(
            "merkle_auth_path_be.len()={} but tree_height - 1 = {}",
            merkle_auth_path_be.len(),
            expected_path_len
        )));
    }
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

    // 2. Constants.
    let matrix = VandermondeMatrix::<F>::new(n, k);
    let poseidon_param: PoseidonConfig<F> = get_poseidon_params::<F>();
    let base64_table = get_base64_table();

    // 3. Anchor witness — canonical-decode every BE field element.
    let known_x_list: Vec<F> = anchor_known_x_be
        .iter()
        .enumerate()
        .map(|(i, b)| fe_from_be32_canonical(b).map_err(nc_field(format!("anchor_known_x_be[{}]", i))))
        .collect::<Result<Vec<_>, _>>()?;
    let anchor_values: Vec<F> = anchor_values_be
        .iter()
        .enumerate()
        .map(|(i, b)| fe_from_be32_canonical(b).map_err(nc_field(format!("anchor_values_be[{}]", i))))
        .collect::<Result<Vec<_>, _>>()?;
    let witness =
        build_anchor_witness(&poseidon_param, &known_x_list, &anchor_selector, &matrix)
            .map_err(|e| ZkapWitnessError::AnchorBuild(format!("{:?}", e)))?;
    let anchor = PoseidonAnchor::new(anchor_values.clone());

    // 4. Misc / blinding (canonical).
    let random = fe_from_be32_canonical(&random_be).map_err(nc_field("random_be"))?;
    let h_sign_user_op =
        fe_from_be32_canonical(&h_sign_user_op_be).map_err(nc_field("h_sign_user_op_be"))?;

    // 5. Parse JWT.
    let jwt_str = core::str::from_utf8(&jwt_bytes)
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

    let signing_input_len = header_b64.len() + 1 + payload_b64.len();
    let signing_input_bytes = {
        let mut s = Vec::with_capacity(signing_input_len);
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

    // Decode payload (URL-safe, no padding) for claim location.
    let payload_bytes = base64_url_no_pad_decode(payload_b64.as_bytes())
        .map_err(|e| ZkapWitnessError::Base64(format!("payload: {}", e)))?;
    let payload_str = core::str::from_utf8(&payload_bytes)
        .map_err(|e| ZkapWitnessError::MalformedJwt(format!("payload not UTF-8: {}", e)))?;

    let mut claim_indices: Vec<ClaimIndices> = Vec::with_capacity(cfg.claims.len());
    for key_bytes in &cfg.claims {
        let key = core::str::from_utf8(key_bytes)
            .map_err(|e| ZkapWitnessError::InvalidConfig(format!("claim key: {}", e)))?;
        claim_indices.push(locate_claim(payload_str, key)?);
    }

    // RSA pk: e is fixed to 65537 (circuit asserts this).
    let pk = PublicKey {
        n: rsa_modulus_be.clone(),
        e: vec![0x01, 0x00, 0x01],
    };

    // Signature consistency: rsa_signature_be MUST byte-match the
    // base64-decoded sig_b64 segment of jwt_bytes.
    let sig_bytes_decoded = base64_url_no_pad_decode(sig_b64.as_bytes())
        .map_err(|e| ZkapWitnessError::Base64(format!("signature: {}", e)))?;
    if sig_bytes_decoded != rsa_signature_be {
        return Err(ZkapWitnessError::SignatureMismatch(format!(
            "rsa_signature_be ({} bytes) != base64_decode(jwt sig_b64) ({} bytes)",
            rsa_signature_be.len(),
            sig_bytes_decoded.len()
        )));
    }
    let sig = Signature(rsa_signature_be.clone());

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

    // 6. Audience derivation.
    let claim_indices_for = |key: &str| -> Result<&ClaimIndices, ZkapWitnessError> {
        for (i, k_bytes) in cfg.claims.iter().enumerate() {
            if k_bytes.as_slice() == key.as_bytes() {
                return Ok(&claim_indices[i]);
            }
        }
        Err(ZkapWitnessError::ClaimNotFound(key.to_owned()))
    };

    let aud_bytes_padded = claim_value_bytes_padded(
        &payload_bytes,
        claim_indices_for("aud")?,
        cfg.max_aud_len as usize,
    );
    let aud_packed = pack_bytes_to_field_native(&aud_bytes_padded);
    let h_aud = CRH::<F>::evaluate(&poseidon_param, aud_packed.clone())
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_aud: {}", e)))?;

    // forbidden = "\"<forbidden_string>\"" padded to max_aud_len, packed, hashed.
    let mut forbidden_bytes = Vec::with_capacity(cfg.forbidden_string.len() + 2);
    forbidden_bytes.push(b'"');
    forbidden_bytes.extend_from_slice(&cfg.forbidden_string);
    forbidden_bytes.push(b'"');
    let forbidden_padded = pad_claim_value_to_max(&forbidden_bytes, cfg.max_aud_len as usize);
    let forbidden_packed = pack_bytes_to_field_native(&forbidden_padded);
    let h_forbidden = CRH::<F>::evaluate(&poseidon_param, forbidden_packed)
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_forbidden: {}", e)))?;

    let mut aud_list = Vec::with_capacity(num_audience_limit);
    aud_list.push(h_aud);
    while aud_list.len() < num_audience_limit {
        aud_list.push(h_forbidden);
    }
    let h_aud_list = CRH::<F>::evaluate(&poseidon_param, aud_list.clone())
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_aud_list: {}", e)))?;

    // 7. Merkle witness (Path).
    let leaf_sibling_hash =
        fe_from_be32_canonical(&merkle_leaf_sibling_hash_be)
            .map_err(nc_field("merkle_leaf_sibling_hash_be"))?;
    let auth_path: Vec<F> = merkle_auth_path_be
        .iter()
        .enumerate()
        .map(|(i, b)| {
            fe_from_be32_canonical(b).map_err(nc_field(format!("merkle_auth_path_be[{}]", i)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let merkle = MerkleWitness {
        path: Path {
            leaf_sibling_hash,
            auth_path,
            leaf_index: merkle_leaf_idx as usize,
        },
        leaf_idx: merkle_leaf_idx as usize,
    };

    // 8. Public inputs derived from witnesses.
    let root = fe_from_be32_canonical(&merkle_root_be).map_err(nc_field("merkle_root_be"))?;
    let hanchor = chain_hash_native(&anchor_values, &poseidon_param)?;

    let mut h_a_inputs = witness.a.clone();
    h_a_inputs.push(random);
    let h_a = CRH::<F>::evaluate(&poseidon_param, h_a_inputs)
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_a: {}", e)))?;

    let inner: F = witness
        .a
        .iter()
        .zip(anchor_values.iter())
        .map(|(a, anc)| *a * *anc)
        .sum();
    let lhs = inner * random;

    // partial_rhs = b[current_idx] * h_id * random
    let iss_bytes_padded = claim_value_bytes_padded(
        &payload_bytes,
        claim_indices_for("iss")?,
        cfg.max_iss_len as usize,
    );
    let sub_bytes_padded = claim_value_bytes_padded(
        &payload_bytes,
        claim_indices_for("sub")?,
        cfg.max_sub_len as usize,
    );
    let iss_packed = pack_bytes_to_field_native(&iss_bytes_padded);
    let sub_packed = pack_bytes_to_field_native(&sub_bytes_padded);

    let mut h_id_inputs: Vec<F> = Vec::new();
    h_id_inputs.extend_from_slice(&aud_packed);
    h_id_inputs.extend_from_slice(&iss_packed);
    h_id_inputs.extend_from_slice(&sub_packed);
    let h_id_inner = CRH::<F>::evaluate(&poseidon_param, h_id_inputs)
        .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_id_inner: {}", e)))?;
    let h_id = CRH::<F>::evaluate(
        &poseidon_param,
        [F::from(current_idx as u64), h_id_inner],
    )
    .map_err(|e| ZkapWitnessError::AnchorBuild(format!("Poseidon h_id: {}", e)))?;
    let partial_rhs = witness.b[current_idx] * h_id * random;

    // jwt_exp = decimal-decode of exp claim.
    let exp_bytes_padded = claim_value_bytes_padded(
        &payload_bytes,
        claim_indices_for("exp")?,
        cfg.max_exp_len as usize,
    );
    let jwt_exp = decimal_bytes_to_field(&exp_bytes_padded)?;

    Ok(ZkapCircuitInput {
        params: cfg,
        constants: CircuitConstants {
            vandermonde_matrix: matrix,
            poseidon_param,
            base64_table,
        },
        public_inputs: CircuitPublicInputs {
            hanchor,
            h_a,
            root,
            h_sign_user_op,
            jwt_exp,
            partial_rhs,
            lhs,
            h_aud_list,
        },
        jwt: jwt_witness,
        anchor: AnchorWitness {
            anchor,
            a: witness.a,
            selector: anchor_selector,
            current_idx,
        },
        merkle,
        audience: AudienceWitness { aud_list },
        misc: MiscWitness { random },
    })
}

/// Chain Poseidon hash: `H(v[0])`, then `H(prev, v[i])` for `i in 1..len`.
fn chain_hash_native(values: &[F], params: &PoseidonConfig<F>) -> Result<F, ZkapWitnessError> {
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

/// Read a 10-digit zero-padded ASCII decimal (`exp` claim) into a field
/// element. Bytes after position 10 must be zero.
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

/// Minimal URL-safe-no-pad base64 decoder (RFC 4648 §5).
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

    fn sample_config_v1() -> ZkapCircuitConfigV1 {
        ZkapCircuitConfigV1 {
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

    fn dummy_v1() -> ZkapInputV1 {
        let cfg = sample_config_v1();
        ZkapInputV1 {
            jwt_bytes: b"hdr.payload.sig".to_vec(),
            rsa_modulus_be: vec![0x12; 256],
            rsa_signature_be: vec![0x34; 256],
            random_be: [0x11; 32],
            h_sign_user_op_be: [0x22; 32],
            anchor_values_be: vec![[0x33; 32]; (cfg.n - cfg.k + 1) as usize],
            anchor_known_x_be: vec![[0x44; 32]; cfg.k as usize],
            anchor_selector: vec![1, 1, 1, 0, 0, 0],
            anchor_current_idx: 0,
            merkle_root_be: [0x55; 32],
            merkle_leaf_sibling_hash_be: [0x66; 32],
            merkle_auth_path_be: vec![[0x77; 32]; (cfg.tree_height - 1) as usize],
            merkle_leaf_idx: 0,
            circuit_config: cfg,
        }
    }

    /// BN254 Fr modulus, big-endian.
    const BN254_FR_MODULUS_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    #[test]
    fn into_circuit_input_rejects_non_canonical_random_be() {
        let mut v1 = dummy_v1();
        v1.random_be = BN254_FR_MODULUS_BE;
        v1.anchor_values_be = vec![[0u8; 32]; v1.anchor_values_be.len()];
        v1.anchor_known_x_be = vec![[0u8; 32]; v1.anchor_known_x_be.len()];
        v1.merkle_root_be = [0u8; 32];
        v1.merkle_leaf_sibling_hash_be = [0u8; 32];
        v1.merkle_auth_path_be = vec![[0u8; 32]; v1.merkle_auth_path_be.len()];
        v1.h_sign_user_op_be = [0u8; 32];

        match into_circuit_input(v1) {
            Err(ZkapWitnessError::NonCanonicalField(msg)) => {
                assert!(msg.contains("random_be"), "got {}", msg);
            }
            Err(other) => panic!("unexpected error variant: {:?}", other),
            Ok(_) => panic!("expected NonCanonicalField, got Ok"),
        }
    }

    #[test]
    fn into_circuit_input_rejects_rsa_modulus_too_short() {
        let mut v1 = dummy_v1();
        v1.rsa_modulus_be = vec![0x12; 255];
        match into_circuit_input(v1) {
            Err(ZkapWitnessError::DimensionMismatch(msg)) => {
                assert!(msg.contains("rsa_modulus_be"), "got {}", msg);
            }
            other => panic!("expected DimensionMismatch, got {:?}", other.err()),
        }
    }

    #[test]
    fn into_circuit_input_rejects_rsa_signature_too_long() {
        let mut v1 = dummy_v1();
        v1.rsa_signature_be = vec![0x34; 257];
        match into_circuit_input(v1) {
            Err(ZkapWitnessError::DimensionMismatch(msg)) => {
                assert!(msg.contains("rsa_signature_be"), "got {}", msg);
            }
            other => panic!("expected DimensionMismatch, got {:?}", other.err()),
        }
    }

    #[test]
    fn config_v1_round_trip_through_circuit_config() {
        let cfg_v1 = sample_config_v1();
        let cfg = circuit_config_from_v1(&cfg_v1);
        cfg.validate().expect("sample config validates");
        let back = config_v1_from_circuit(&cfg);
        assert_eq!(cfg_v1, back);
    }

    #[test]
    fn locate_claim_matches_canonical_payload() {
        let payload = r#"{"aud":"test-audience","exp":1700000000,"iss":"https://x","nonce":"0xdead","sub":"u_0"}"#;
        let aud = locate_claim(payload, "aud").expect("aud claim");
        assert_eq!(aud.offset, 1);
        assert_eq!(&payload.as_bytes()[aud.offset..aud.offset + aud.claim_len].last().unwrap(), &&b',');
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
        let mut v1 = dummy_v1();
        v1.anchor_selector = vec![1, 1, 0, 0, 0, 0]; // cardinality 2, k = 3
        match into_circuit_input(v1) {
            Err(ZkapWitnessError::DimensionMismatch(_)) => {}
            other => panic!("expected DimensionMismatch, got {:?}", other.err()),
        }
    }

    #[test]
    fn into_circuit_input_rejects_wrong_anchor_length() {
        let mut v1 = dummy_v1();
        v1.anchor_values_be.pop();
        match into_circuit_input(v1) {
            Err(ZkapWitnessError::DimensionMismatch(_)) => {}
            other => panic!("expected DimensionMismatch, got {:?}", other.err()),
        }
    }
}
