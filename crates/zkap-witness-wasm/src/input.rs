//! Postcard-decodable input for the zkap-witness-wasm runtime.
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
//! ### Encoding rules (locked — bumping these requires `CIRCUIT_ID`
//! bump)
//!
//! - **Field elements** (anything `*_be` of length 32 or per-entry width
//!   32) are written as **32-byte big-endian** and decoded via
//!   [`fe_from_be32_canonical`]: the input integer MUST be strictly less
//!   than `F::MODULUS`. Encodings of `value >= F::MODULUS` are rejected
//!   with [`ZkapWitnessError::NonCanonicalField`] — silent `mod p`
//!   reduction is forbidden so that a malformed wire payload cannot
//!   silently re-target a different field element.
//! - **`rsa_modulus_be`** is the RSA-2048 modulus N as the natural
//!   big-endian byte string. Length MUST equal 256 bytes
//!   (`RSA_2048_BYTES`); other lengths are rejected. The circuit
//!   hard-asserts public exponent `e == 65537`, so `e` is not transmitted.
//! - **`rsa_signature_be`** is the PKCS#1 v1.5 SHA-256 signature, also
//!   256 bytes BE. The same signature bytes appear base64url-encoded
//!   inside the `sig_b64` segment of `jwt_bytes`; the wasm side
//!   cross-checks `base64_decode(sig_b64) == rsa_signature_be` and
//!   rejects with [`ZkapWitnessError::SignatureMismatch`] on
//!   disagreement. Carrying both makes the host's intent explicit and
//!   converts JWT/RSA inconsistency into an early hard error rather than
//!   a downstream RSA-verify failure deep inside the circuit.
//! - **Fixed-size arrays (`[u8; 32]`)** are postcard-encoded as raw bytes
//!   with no length prefix.
//! - **`Vec<...>` and `String`** are postcard-encoded with the standard
//!   varint length prefix.
//! - **Integer counts/indices** are u64 varints.
//! - The wire order is the **struct declaration order**.
//!
//! ## Anchor trust boundary
//!
//! V1 carries `anchor_values_be` (the `n - k + 1` Vandermonde-projected
//! anchor scalars) as a host-supplied semantic witness. The wasm /
//! circuit layer enforces only **internal consistency** between this
//! witness and the `hanchor` public input via the constraint
//! `hanchor == chain_hash(anchor_values)` (see
//! `circuit::zkap::ZkapCircuit::generate_constraints` — phase 3,
//! `chain_hash_gadget(anchor.anchor) == hanchor`). It does NOT compare
//! `anchor_values_be` against any registered or trusted anchor — that
//! check is **outside this crate**.
//!
//! The integrity guarantee for the anchor itself comes from the
//! verifier / service layer comparing the `hanchor` public input
//! against an expected/registered hanchor (currently in
//! `zkap-circuit/crates/service`'s proof-verification surface). With
//! that comparison in place, accepting raw `anchor_values_be` as a V1
//! semantic witness input is sound: a rogue host can only swap to
//! anchor scalars that chain-hash to a registered `hanchor` — which is
//! equivalent to supplying a registered anchor in the first place. If a
//! deployment removes the verifier-side `hanchor` registry check, this
//! schema's trust assumption breaks; document that contract loudly at
//! the deployment layer.
//!
//! ## Wasm-side derivation
//!
//! [`ZkapInputV1::into_circuit_input`] performs the conversion. It depends
//! only on `circuit + gadget` runtime and is wasm32-compatible (no `rsa`,
//! `regex`, or std-only file I/O). Steps:
//!
//! 1. Validate `circuit_config` and dimension fields (anchor lengths,
//!    selector cardinality, Merkle path length).
//! 2. Re-derive constants: Vandermonde matrix `(n, k)`, Poseidon
//!    parameters, base64 table.
//! 3. Build the anchor witness via
//!    [`gadget::anchor::poseidon::build_anchor_witness`]
//!    from `(known_x_list, selector, matrix)`.
//! 4. Parse the JWT into header/payload/signature segments, recompute
//!    SHA-256 padding, locate every claim's byte offsets, build
//!    [`gadget::base64::IndexBits`].
//! 5. Assemble the Merkle [`Path`] from `(root, leaf_sibling_hash,
//!    auth_path, leaf_idx)`.
//! 6. Derive the audience list (Poseidon-hash JWT aud bytes, pad with
//!    Poseidon-hash of the quoted `forbidden_string`) up to
//!    `num_audience_limit` entries.
//! 7. Compute the eight public inputs (`hanchor`, `h_a`, `root`,
//!    `h_sign_user_op`, `jwt_exp`, `partial_rhs`, `lhs`, `h_aud_list`).
//!
//! Bumping the order of any of the above fields, or changing
//! big-endian / variable-vs-fixed-length conventions, is a wire-format
//! break — the `WitnessGenerator::CIRCUIT_ID` MUST be bumped in lockstep.
//! The current value is `"zkap-main-v1"`; pair-check tooling relies on
//! it as the canonical schema id.
//!
//! [`circuit_to_arwtns`]: ark_ar1cs_wasm_witness::circuit_to_arwtns
//! [`Path`]: ark_crypto_primitives::merkle_tree::Path

use ark_crypto_primitives::{
    crh::{poseidon::CRH, CRHScheme},
    merkle_tree::Path,
    sponge::poseidon::PoseidonConfig,
};
use ark_ff::{BigInteger, PrimeField, Zero};
use serde::{Deserialize, Serialize};

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

use crate::error::ZkapWitnessError;

/// Concrete `ZkapCircuit` instantiation used by this wasm artifact —
/// `(Curve = ed_on_bn254, BigNat = 2048-bit limbs)`.
pub type ZkapMainCircuit = ZkapCircuit<CG, BNP>;

// ============================================================
// V1 — semantic schema
// ============================================================

/// Serializable mirror of [`circuit::constants::RawCircuitConfig`] —
/// matches its field set so V1 inputs can be produced without a runtime
/// `circuit` dependency on the host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkapCircuitConfigV1 {
    pub max_jwt_b64_len: u64,
    pub max_payload_b64_len: u64,
    pub max_aud_len: u64,
    pub max_exp_len: u64,
    pub max_iss_len: u64,
    pub max_nonce_len: u64,
    pub max_sub_len: u64,
    pub n: u64,
    pub k: u64,
    pub tree_height: u64,
    pub num_audience_limit: u64,
    pub claims: Vec<String>,
    pub forbidden_string: String,
}

impl From<&CircuitConfig> for ZkapCircuitConfigV1 {
    fn from(c: &CircuitConfig) -> Self {
        Self {
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
}

impl From<&ZkapCircuitConfigV1> for CircuitConfig {
    fn from(c: &ZkapCircuitConfigV1) -> Self {
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
}

/// Semantic V1 wire format. See module-level docs for the encoding
/// contract — every change to field order, BE/LE, or variable-vs-fixed
/// length requires a `WitnessGenerator::CIRCUIT_ID` bump.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkapInputV1 {
    /// Full JWT as raw ASCII bytes — the canonical
    /// `<header_b64>.<payload_b64>.<sig_b64>` triple. The wasm side splits
    /// at the two `.` separators, recomputes SHA-256 padding, locates each
    /// claim, and decodes the signature segment.
    pub jwt_bytes: Vec<u8>,

    /// RSA-2048 modulus N as the natural big-endian byte string
    /// (`pk.n().to_bytes_be()`). Length MUST equal
    /// [`RSA_2048_BYTES`] (256). The circuit hard-asserts public exponent
    /// `e == 65537`, so e is not transmitted.
    pub rsa_modulus_be: Vec<u8>,

    /// PKCS#1 v1.5 SHA-256 RSA-2048 signature, big-endian. Length MUST
    /// equal [`RSA_2048_BYTES`] (256). The same bytes appear
    /// base64url-encoded inside the `sig_b64` segment of `jwt_bytes`;
    /// the wasm side cross-checks the two and rejects on disagreement.
    pub rsa_signature_be: Vec<u8>,

    /// Big-endian field encoding of the proof's blinding `random` scalar.
    pub random_be: [u8; 32],

    /// Big-endian field encoding of `h_sign_user_op` (public input).
    pub h_sign_user_op_be: [u8; 32],

    /// Anchor scalar list (`anchor.0`) — Vandermonde-projected secrets.
    /// Length = `n - k + 1`.
    pub anchor_values_be: Vec<[u8; 32]>,

    /// Known-secret list `known_x_list = [Poseidon(pad(aud)||pad(iss)||
    /// pad(sub)) for the K real secrets in selector order]`. Length = `k`.
    pub anchor_known_x_be: Vec<[u8; 32]>,

    /// Selector vector — boolean values in `0/1`. Length = `n`,
    /// cardinality = `k`.
    pub anchor_selector: Vec<u8>,

    /// Position in `0..n` this proof claims; `selector[current_idx]` MUST
    /// be `1`.
    pub anchor_current_idx: u64,

    /// Merkle root (public input `root`).
    pub merkle_root_be: [u8; 32],

    /// First-level sibling hash (`Path::leaf_sibling_hash`).
    pub merkle_leaf_sibling_hash_be: [u8; 32],

    /// Inner-node sibling hashes (`Path::auth_path`). Length =
    /// `tree_height - 1`.
    pub merkle_auth_path_be: Vec<[u8; 32]>,

    /// Index of the leaf within the Merkle tree.
    pub merkle_leaf_idx: u64,

    /// Circuit shape parameters. Bumping any shape value requires
    /// regenerating the `.arzkey` and rebuilding the wasm.
    pub circuit_config: ZkapCircuitConfigV1,
}

// ---------- field-element ↔ 32 byte BE helpers ----------

/// Required wire-format length for `rsa_modulus_be` and
/// `rsa_signature_be`. RSA-2048 keys/signatures are exactly 256 bytes;
/// any other length is a host bug or a malformed payload.
pub const RSA_2048_BYTES: usize = 256;

/// Strict canonical 32-byte BE → `F` decoder.
///
/// Returns `Err(ZkapWitnessError::NonCanonicalField)` when the input
/// bytes encode an integer `>= F::MODULUS`. The check uses a round-trip
/// equality: `fe_to_be32(F::from_be_bytes_mod_order(bytes)) == bytes`
/// holds iff the input was already a canonical encoding. For non-
/// canonical inputs `from_be_bytes_mod_order` would silently reduce
/// `mod p` and the re-encoded bytes (canonical encoding of `value mod p`)
/// would differ from the input.
///
/// Edge cases:
/// - `[0; 32]` → `F::zero()` (canonical, accepted).
/// - BE encoding of `p - 1` → canonical, accepted.
/// - BE encoding of `p` → `from_be_bytes_mod_order` returns 0,
///   re-encoded as `[0; 32]` ≠ input → rejected.
/// - BE encoding of `p + 1` → returns 1, re-encoded as
///   `[0…, 0x01]` ≠ input → rejected.
pub fn fe_from_be32_canonical(bytes: &[u8; 32]) -> Result<F, ZkapWitnessError> {
    let f = F::from_be_bytes_mod_order(bytes);
    if fe_to_be32(&f) != *bytes {
        return Err(ZkapWitnessError::NonCanonicalField(format!(
            "32-byte BE encoding 0x{} represents an integer >= F::MODULUS",
            hex_encode(bytes)
        )));
    }
    Ok(f)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Pack a field element into 32 BE bytes. `into_bigint().to_bytes_be()`
/// for BN254 Fr always returns exactly 32 bytes (limbs = 4 × u64), so
/// the leading-zero pad is defensive.
pub fn fe_to_be32(value: &F) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    debug_assert!(bytes.len() <= 32);
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
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
///
/// TODO(v1.x): pretty-printed JWT payloads (whitespace before/after the
/// `"key"` token, e.g. `{ "aud" : "x" }`) are not currently supported —
/// the regex captures `\s*` before the key into its full match, so its
/// `offset` would shift to the leading whitespace. To match that, this
/// scanner needs to backtrack over leading whitespace and verify the
/// preceding non-whitespace byte is `{` or `,`. Real-world IdPs (Google,
/// Auth0) emit canonical JSON, so this gap is benign in production
/// today; deployments targeting non-canonical-JSON IdPs must add the
/// backtrack + a `locate_claim_handles_pretty_payload` test before
/// shipping.
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
/// numbers), zero-padded to `max_len`. Mirrors the test helper
/// `claim_value_bytes`.
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

impl ZkapInputV1 {
    /// One-shot host/wasm entry point: `V1 → ZkapMainCircuit` ready for
    /// `ConstraintSynthesizer`. Wraps [`Self::into_circuit_input`] and
    /// `ZkapCircuit::from_input`. PR2 commit 3 wires this into the
    /// `WitnessGenerator::build_circuit` impl.
    pub fn build_main_circuit(self) -> Result<ZkapMainCircuit, ZkapWitnessError> {
        let input = self.into_circuit_input()?;
        Ok(ZkapMainCircuit::from_input(input))
    }

    /// Full V1 → `ZkapCircuitInput<F>` conversion. Compiles for both
    /// native and `wasm32-unknown-unknown`; called from
    /// `WitnessGenerator::build_circuit` (after PR2 commit 3) and from
    /// the V1 round-trip integration test.
    pub fn into_circuit_input(self) -> Result<ZkapCircuitInput<F>, ZkapWitnessError> {
        // 1. Validate config + dimensions.
        let cfg = CircuitConfig::from(&self.circuit_config);
        cfg.validate().map_err(ZkapWitnessError::InvalidConfig)?;

        let n = cfg.n as usize;
        let k = cfg.k as usize;
        let m_anchor = n - k + 1;
        let tree_height = cfg.tree_height as usize;
        let num_audience_limit = cfg.num_audience_limit as usize;

        if self.anchor_values_be.len() != m_anchor {
            return Err(ZkapWitnessError::DimensionMismatch(format!(
                "anchor_values_be.len()={} but n - k + 1 = {}",
                self.anchor_values_be.len(),
                m_anchor
            )));
        }
        if self.anchor_known_x_be.len() != k {
            return Err(ZkapWitnessError::DimensionMismatch(format!(
                "anchor_known_x_be.len()={} but k = {}",
                self.anchor_known_x_be.len(),
                k
            )));
        }
        if self.anchor_selector.len() != n {
            return Err(ZkapWitnessError::DimensionMismatch(format!(
                "anchor_selector.len()={} but n = {}",
                self.anchor_selector.len(),
                n
            )));
        }
        let cardinality = self.anchor_selector.iter().filter(|&&s| s == 1).count();
        if cardinality != k {
            return Err(ZkapWitnessError::DimensionMismatch(format!(
                "anchor_selector cardinality = {} but k = {}",
                cardinality, k
            )));
        }
        let current_idx = self.anchor_current_idx as usize;
        if current_idx >= n
            || self
                .anchor_selector
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
        if self.merkle_auth_path_be.len() != expected_path_len {
            return Err(ZkapWitnessError::DimensionMismatch(format!(
                "merkle_auth_path_be.len()={} but tree_height - 1 = {}",
                self.merkle_auth_path_be.len(),
                expected_path_len
            )));
        }
        if self.rsa_modulus_be.len() != RSA_2048_BYTES {
            return Err(ZkapWitnessError::DimensionMismatch(format!(
                "rsa_modulus_be.len()={} but RSA-2048 requires exactly {} bytes",
                self.rsa_modulus_be.len(),
                RSA_2048_BYTES
            )));
        }
        if self.rsa_signature_be.len() != RSA_2048_BYTES {
            return Err(ZkapWitnessError::DimensionMismatch(format!(
                "rsa_signature_be.len()={} but RSA-2048 requires exactly {} bytes",
                self.rsa_signature_be.len(),
                RSA_2048_BYTES
            )));
        }

        // 2. Constants.
        let matrix = VandermondeMatrix::<F>::new(n, k);
        let poseidon_param: PoseidonConfig<F> = get_poseidon_params::<F>();
        let base64_table = get_base64_table();

        // 3. Anchor witness — canonical-decode every BE field element.
        //    Prefixing the failure with the field name keeps the error
        //    actionable when a host sends a >= p encoding.
        let known_x_list: Vec<F> = self
            .anchor_known_x_be
            .iter()
            .enumerate()
            .map(|(i, b)| {
                fe_from_be32_canonical(b).map_err(|e| {
                    ZkapWitnessError::NonCanonicalField(format!("anchor_known_x_be[{}]: {}", i, e))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let anchor_values: Vec<F> = self
            .anchor_values_be
            .iter()
            .enumerate()
            .map(|(i, b)| {
                fe_from_be32_canonical(b).map_err(|e| {
                    ZkapWitnessError::NonCanonicalField(format!("anchor_values_be[{}]: {}", i, e))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let witness =
            build_anchor_witness(&poseidon_param, &known_x_list, &self.anchor_selector, &matrix)
                .map_err(|e| ZkapWitnessError::AnchorBuild(format!("{:?}", e)))?;
        let anchor = PoseidonAnchor::new(anchor_values.clone());

        // 4. Misc / blinding (canonical).
        let random = fe_from_be32_canonical(&self.random_be).map_err(|e| {
            ZkapWitnessError::NonCanonicalField(format!("random_be: {}", e))
        })?;
        let h_sign_user_op = fe_from_be32_canonical(&self.h_sign_user_op_be).map_err(|e| {
            ZkapWitnessError::NonCanonicalField(format!("h_sign_user_op_be: {}", e))
        })?;

        // 5. Parse JWT.
        let jwt_str = core::str::from_utf8(&self.jwt_bytes)
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
            n: self.rsa_modulus_be.clone(),
            e: vec![0x01, 0x00, 0x01],
        };

        // Signature consistency: rsa_signature_be MUST byte-match the
        // base64-decoded sig_b64 segment of jwt_bytes. We carry both
        // because the host's intent is explicit, and we reject
        // disagreement here so a tampered JWT segment cannot smuggle a
        // different RSA signature past the circuit's RSA-verify gadget.
        let sig_bytes_decoded = base64_url_no_pad_decode(sig_b64.as_bytes())
            .map_err(|e| ZkapWitnessError::Base64(format!("signature: {}", e)))?;
        if sig_bytes_decoded != self.rsa_signature_be {
            return Err(ZkapWitnessError::SignatureMismatch(format!(
                "rsa_signature_be ({} bytes) != base64_decode(jwt sig_b64) ({} bytes)",
                self.rsa_signature_be.len(),
                sig_bytes_decoded.len()
            )));
        }
        // Use the consistency-verified bytes. Either source is valid
        // here; pick `rsa_signature_be` so a hypothetical future schema
        // could omit `sig_b64` from `jwt_bytes` without breaking this
        // call site.
        let sig = Signature(self.rsa_signature_be.clone());

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

        // 6. Audience derivation: aud bytes from JWT, padded + Poseidon.
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

        // 7. Merkle witness (Path) — canonical decode each F.
        let leaf_sibling_hash =
            fe_from_be32_canonical(&self.merkle_leaf_sibling_hash_be).map_err(|e| {
                ZkapWitnessError::NonCanonicalField(format!("merkle_leaf_sibling_hash_be: {}", e))
            })?;
        let auth_path: Vec<F> = self
            .merkle_auth_path_be
            .iter()
            .enumerate()
            .map(|(i, b)| {
                fe_from_be32_canonical(b).map_err(|e| {
                    ZkapWitnessError::NonCanonicalField(format!(
                        "merkle_auth_path_be[{}]: {}",
                        i, e
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let merkle = MerkleWitness {
            path: Path {
                leaf_sibling_hash,
                auth_path,
                leaf_index: self.merkle_leaf_idx as usize,
            },
            leaf_idx: self.merkle_leaf_idx as usize,
        };

        // 8. Public inputs derived from witnesses (canonical decode).
        let root = fe_from_be32_canonical(&self.merkle_root_be).map_err(|e| {
            ZkapWitnessError::NonCanonicalField(format!("merkle_root_be: {}", e))
        })?;
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
        // h_id = Poseidon(current_idx, Poseidon(aud || iss || sub))
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
                selector: self.anchor_selector,
                current_idx,
            },
            merkle,
            audience: AudienceWitness { aud_list },
            misc: MiscWitness { random },
        })
    }
}

/// Chain Poseidon hash: `H(v[0])`, then `H(prev, v[i])` for `i in 1..len`.
/// Mirrors test fixture `chain_hash_native` and the in-circuit
/// `chain_hash_gadget` driver order.
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
/// element. The circuit gadget enforces that bytes after position 10 are
/// zero; this native side mirrors that contract.
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

/// Minimal URL-safe-no-pad base64 decoder (RFC 4648 §5). We avoid pulling
/// the `base64` crate's full feature set into the wasm bundle, but we
/// also don't want to silently re-emit incorrect bytes — every invalid
/// character returns `Err`.
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

    /// BN254 Fr modulus, big-endian. Used by the canonical-encoding
    /// reject tests below.
    const BN254_FR_MODULUS_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    /// Acceptance: the V1 wire round-trips through postcard byte-for-byte.
    #[test]
    fn v1_postcard_round_trip() {
        let v1 = dummy_v1();
        let bytes = postcard::to_allocvec(&v1).expect("encode");
        let decoded: ZkapInputV1 = postcard::from_bytes(&bytes).expect("decode");
        // Field-by-field — ZkapInputV1 has no PartialEq derive (mixed
        // [u8;32] arrays + Vecs), so re-encode and assert byte equality.
        let bytes2 = postcard::to_allocvec(&decoded).expect("re-encode");
        assert_eq!(bytes, bytes2);
    }

    /// Acceptance: every field encoded in the documented order. We freeze
    /// a couple of byte positions so future re-orderings of `ZkapInputV1`
    /// surface as a test failure instead of a silent CIRCUIT_ID mismatch.
    #[test]
    fn v1_postcard_field_layout_is_stable() {
        let v1 = dummy_v1();
        let bytes = postcard::to_allocvec(&v1).expect("encode");
        // jwt_bytes is the first field — postcard writes its varint length
        // (15 = 0x0f) then the raw bytes "hdr.payload.sig".
        assert_eq!(bytes[0], 15);
        assert_eq!(&bytes[1..16], b"hdr.payload.sig");
        // rsa_modulus_be follows: varint(256) = 2 bytes (0x80 0x02), then
        // 256 bytes of 0x12.
        assert_eq!(bytes[16], 0x80);
        assert_eq!(bytes[17], 0x02);
        for &b in &bytes[18..18 + 256] {
            assert_eq!(b, 0x12);
        }
        // rsa_signature_be follows: varint(256) = 0x80 0x02, then 256
        // bytes of 0x34.
        let sig_off = 18 + 256;
        assert_eq!(bytes[sig_off], 0x80);
        assert_eq!(bytes[sig_off + 1], 0x02);
        for &b in &bytes[sig_off + 2..sig_off + 2 + 256] {
            assert_eq!(b, 0x34);
        }
        // random_be is a fixed [u8;32] — no length prefix, raw 0x11s.
        let random_off = sig_off + 2 + 256;
        for &b in &bytes[random_off..random_off + 32] {
            assert_eq!(b, 0x11);
        }
        let h_sign_off = random_off + 32;
        for &b in &bytes[h_sign_off..h_sign_off + 32] {
            assert_eq!(b, 0x22);
        }
    }

    /// Acceptance: `fe_from_be32_canonical` accepts the canonical
    /// encoding of `p - 1` (the largest valid field element) and returns
    /// the matching `F`.
    #[test]
    fn canonical_decoder_accepts_p_minus_one() {
        let mut bytes = BN254_FR_MODULUS_BE;
        // p ends in ...0x00 0x00 0x01, so p - 1 ends in ...0x00 0x00 0x00.
        bytes[31] = 0x00;
        let decoded = fe_from_be32_canonical(&bytes).expect("p - 1 must be canonical");
        // Round-trip back to bytes must equal the input.
        assert_eq!(fe_to_be32(&decoded), bytes);
    }

    /// Acceptance: the canonical encoding of `0` is accepted.
    #[test]
    fn canonical_decoder_accepts_zero() {
        let bytes = [0u8; 32];
        let decoded = fe_from_be32_canonical(&bytes).expect("zero is canonical");
        assert_eq!(decoded, F::zero());
    }

    /// Acceptance: the BE encoding of `p` itself is rejected — silent
    /// `mod p` reduction would map it to 0.
    #[test]
    fn canonical_decoder_rejects_p() {
        let bytes = BN254_FR_MODULUS_BE;
        match fe_from_be32_canonical(&bytes) {
            Err(ZkapWitnessError::NonCanonicalField(_)) => {}
            Err(other) => panic!("unexpected error: {:?}", other),
            Ok(_) => panic!("p must NOT decode as canonical"),
        }
    }

    /// Acceptance: the BE encoding of `p + 1` is rejected — silent
    /// `mod p` reduction would map it to 1.
    #[test]
    fn canonical_decoder_rejects_p_plus_one() {
        let mut bytes = BN254_FR_MODULUS_BE;
        // p ends in 0x...01, so p + 1 ends in 0x...02.
        bytes[31] = 0x02;
        match fe_from_be32_canonical(&bytes) {
            Err(ZkapWitnessError::NonCanonicalField(_)) => {}
            Err(other) => panic!("unexpected error: {:?}", other),
            Ok(_) => panic!("p + 1 must NOT decode as canonical"),
        }
    }

    /// Acceptance: `into_circuit_input` propagates a non-canonical
    /// `random_be` as `NonCanonicalField`. We use `random_be` because
    /// it's a top-level dimension-clean field — the validator runs
    /// before the JWT/RSA path, and the non-canonical decode happens
    /// shortly after.
    ///
    /// The fixture replaces `random_be` with the BE encoding of `p`
    /// (which `from_be_bytes_mod_order` would silently reduce to 0).
    /// Other dim-clean fields (anchor_values_be, merkle_root_be, etc.)
    /// share the same code path.
    #[test]
    fn into_circuit_input_rejects_non_canonical_random_be() {
        // First make a fixture whose dimensions are valid and whose
        // RSA fields have correct length so we don't hit those checks
        // before the canonical decode.
        let mut v1 = dummy_v1();
        v1.random_be = BN254_FR_MODULUS_BE;
        // Override field elements that would also fail canonicality so
        // the test pinpoints `random_be` specifically. The dummy
        // anchor_values / merkle_* values use bytes >= 0x33 which
        // happen to be `>= p`; replace them with all-zeros (canonical
        // encoding of 0) so the failure must come from `random_be`.
        v1.anchor_values_be = vec![[0u8; 32]; v1.anchor_values_be.len()];
        v1.anchor_known_x_be = vec![[0u8; 32]; v1.anchor_known_x_be.len()];
        v1.merkle_root_be = [0u8; 32];
        v1.merkle_leaf_sibling_hash_be = [0u8; 32];
        v1.merkle_auth_path_be = vec![[0u8; 32]; v1.merkle_auth_path_be.len()];
        v1.h_sign_user_op_be = [0u8; 32];

        match v1.into_circuit_input() {
            Err(ZkapWitnessError::NonCanonicalField(msg)) => {
                assert!(
                    msg.contains("random_be"),
                    "expected NonCanonicalField to mention random_be, got {}",
                    msg
                );
            }
            Err(other) => panic!("unexpected error variant: {:?}", other),
            Ok(_) => panic!("expected NonCanonicalField, got Ok"),
        }
    }

    /// Acceptance: `into_circuit_input` rejects `rsa_modulus_be` length
    /// 255 (one byte short of RSA-2048).
    #[test]
    fn into_circuit_input_rejects_rsa_modulus_too_short() {
        let mut v1 = dummy_v1();
        v1.rsa_modulus_be = vec![0x12; 255];
        match v1.into_circuit_input() {
            Err(ZkapWitnessError::DimensionMismatch(msg)) => {
                assert!(
                    msg.contains("rsa_modulus_be"),
                    "expected DimensionMismatch on rsa_modulus_be, got {}",
                    msg
                );
            }
            Err(other) => panic!("unexpected error variant: {:?}", other),
            Ok(_) => panic!("expected DimensionMismatch, got Ok"),
        }
    }

    /// Acceptance: `into_circuit_input` rejects `rsa_modulus_be` length
    /// 257 (one byte over RSA-2048).
    #[test]
    fn into_circuit_input_rejects_rsa_modulus_too_long() {
        let mut v1 = dummy_v1();
        v1.rsa_modulus_be = vec![0x12; 257];
        match v1.into_circuit_input() {
            Err(ZkapWitnessError::DimensionMismatch(msg)) => {
                assert!(
                    msg.contains("rsa_modulus_be"),
                    "expected DimensionMismatch on rsa_modulus_be, got {}",
                    msg
                );
            }
            Err(other) => panic!("unexpected error variant: {:?}", other),
            Ok(_) => panic!("expected DimensionMismatch, got Ok"),
        }
    }

    /// Acceptance: `into_circuit_input` rejects `rsa_signature_be`
    /// length 255.
    #[test]
    fn into_circuit_input_rejects_rsa_signature_too_short() {
        let mut v1 = dummy_v1();
        v1.rsa_signature_be = vec![0x34; 255];
        match v1.into_circuit_input() {
            Err(ZkapWitnessError::DimensionMismatch(msg)) => {
                assert!(
                    msg.contains("rsa_signature_be"),
                    "expected DimensionMismatch on rsa_signature_be, got {}",
                    msg
                );
            }
            Err(other) => panic!("unexpected error variant: {:?}", other),
            Ok(_) => panic!("expected DimensionMismatch, got Ok"),
        }
    }

    /// Acceptance: `into_circuit_input` rejects `rsa_signature_be`
    /// length 257.
    #[test]
    fn into_circuit_input_rejects_rsa_signature_too_long() {
        let mut v1 = dummy_v1();
        v1.rsa_signature_be = vec![0x34; 257];
        match v1.into_circuit_input() {
            Err(ZkapWitnessError::DimensionMismatch(msg)) => {
                assert!(
                    msg.contains("rsa_signature_be"),
                    "expected DimensionMismatch on rsa_signature_be, got {}",
                    msg
                );
            }
            Err(other) => panic!("unexpected error variant: {:?}", other),
            Ok(_) => panic!("expected DimensionMismatch, got Ok"),
        }
    }

    /// Acceptance: BE field-element packing round-trips through
    /// `from_be_bytes_mod_order` for low-bit values that need leading
    /// zero padding.
    #[test]
    fn fe_be32_round_trip_low_value() {
        let v = F::from(42u64);
        let bytes = fe_to_be32(&v);
        let mut leading = 0;
        for &b in &bytes {
            if b != 0 {
                break;
            }
            leading += 1;
        }
        assert!(leading > 0, "expected leading zeros for low-bit value");
        let back = F::from_be_bytes_mod_order(&bytes);
        assert_eq!(back, v);
    }

    /// Acceptance: ZkapCircuitConfigV1 ↔ CircuitConfig round-trip
    /// preserves every field semantically.
    #[test]
    fn config_v1_round_trip_through_circuit_config() {
        let cfg_v1 = sample_config_v1();
        let cfg: CircuitConfig = (&cfg_v1).into();
        cfg.validate().expect("sample config validates");
        let back: ZkapCircuitConfigV1 = (&cfg).into();
        assert_eq!(cfg_v1, back);
    }

    /// Acceptance: `locate_claim` mirrors the test regex's offsets on the
    /// canonical no-whitespace JWT payload format produced by the test
    /// fixtures.
    #[test]
    fn locate_claim_matches_canonical_payload() {
        let payload = r#"{"aud":"test-audience","exp":1700000000,"iss":"https://x","nonce":"0xdead","sub":"u_0"}"#;
        let aud = locate_claim(payload, "aud").expect("aud claim");
        assert_eq!(aud.offset, 1);
        // claim_len = total bytes from `"aud"` to and including the `,`.
        assert_eq!(&payload.as_bytes()[aud.offset..aud.offset + aud.claim_len].last().unwrap(), &&b',');
        let exp = locate_claim(payload, "exp").expect("exp claim");
        // value_idx within full match should point at the first digit.
        let val_byte = payload.as_bytes()[exp.offset + exp.value_idx];
        assert_eq!(val_byte, b'1');
        let sub = locate_claim(payload, "sub").expect("sub claim");
        // sub is the last claim — terminator is `}`.
        assert_eq!(
            payload.as_bytes()[sub.offset + sub.claim_len - 1],
            b'}'
        );
    }

    /// Acceptance: `decimal_bytes_to_field` matches manual expectation for
    /// a realistic `exp` value padded to 20 bytes.
    #[test]
    fn decimal_bytes_to_field_realistic_exp() {
        let mut bytes = b"1700000000".to_vec();
        bytes.resize(20, 0x00);
        let v = decimal_bytes_to_field(&bytes).expect("decode exp");
        assert_eq!(v, F::from(1700000000u64));
    }

    /// Acceptance: `decimal_bytes_to_field` rejects non-zero padding.
    #[test]
    fn decimal_bytes_to_field_rejects_dirty_padding() {
        let mut bytes = b"1234567890".to_vec();
        bytes.resize(20, 0x00);
        bytes[12] = 0x01;
        assert!(decimal_bytes_to_field(&bytes).is_err());
    }

    /// Acceptance: `base64_url_no_pad_decode` matches the canonical
    /// "Hello" → "SGVsbG8" URL-safe-no-pad fixture (RFC 4648 §5).
    #[test]
    fn base64_url_decoder_matches_reference() {
        let decoded = base64_url_no_pad_decode(b"SGVsbG8").expect("decode");
        assert_eq!(decoded, b"Hello");
    }

    /// Acceptance: `base64_url_no_pad_decode` rejects an out-of-alphabet
    /// character.
    #[test]
    fn base64_url_decoder_rejects_invalid_char() {
        assert!(base64_url_no_pad_decode(b"ABC*").is_err());
    }

    /// Acceptance: dimension-mismatch validation catches a wrong-shape
    /// anchor selector before any cryptographic work happens.
    /// `ZkapCircuitInput` has no `Debug` impl (pitfall #1 in PR2 handoff),
    /// so the test pattern-matches without `expect_err`.
    #[test]
    fn into_circuit_input_rejects_bad_selector_cardinality() {
        let mut v1 = dummy_v1();
        v1.anchor_selector = vec![1, 1, 0, 0, 0, 0]; // cardinality 2, k = 3
        match v1.into_circuit_input() {
            Err(ZkapWitnessError::DimensionMismatch(_)) => {}
            Err(other) => panic!("unexpected error variant: {:?}", other),
            Ok(_) => panic!("expected DimensionMismatch, got Ok"),
        }
    }

    /// Acceptance: dimension-mismatch validation catches a wrong-length
    /// anchor_values_be (must equal n - k + 1).
    #[test]
    fn into_circuit_input_rejects_wrong_anchor_length() {
        let mut v1 = dummy_v1();
        v1.anchor_values_be.pop();
        match v1.into_circuit_input() {
            Err(ZkapWitnessError::DimensionMismatch(_)) => {}
            Err(other) => panic!("unexpected error variant: {:?}", other),
            Ok(_) => panic!("expected DimensionMismatch, got Ok"),
        }
    }
}
