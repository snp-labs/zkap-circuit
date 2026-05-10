//! V1 wire-format types for the ZKAP main circuit, with no dependency on
//! `circuit` or `gadget`. This crate is the single source of truth for the
//! semantic [`ZkapInputV1`] payload that the host hands to the wasm
//! witness-generator and that the wasm side decodes via postcard.
//!
//! The full encoding contract — field order, BE/LE rules, length prefixes,
//! the `WitnessGenerator::CIRCUIT_ID` lockstep requirement — lives in
//! `zkap-witness-wasm::input` (the conversion-side companion). Bumping
//! anything here is a wire-format break.
//!
//! Splitting these types into their own crate lets `zkap-service`, mobile
//! bindings, and any other host-side caller construct a V1 payload without
//! pulling the full circuit / gadget compile graph.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};

/// Required wire-format length for `rsa_modulus_be` and `rsa_signature_be`.
/// RSA-2048 keys/signatures are exactly 256 bytes; any other length is a
/// host bug or a malformed payload.
pub const RSA_2048_BYTES: usize = 256;

// ============================================================
// V1 — semantic schema
// ============================================================

/// Plain-data mirror of the circuit's `RawCircuitConfig` field set. This
/// crate intentionally does NOT depend on `circuit::constants::CircuitConfig`;
/// hosts and the wasm side both convert between this struct and the
/// circuit-side type at their respective boundaries.
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

/// Semantic V1 wire format. See `zkap-witness-wasm::input` module docs for
/// the full encoding contract — every change to field order, BE/LE, or
/// variable-vs-fixed length requires a `WitnessGenerator::CIRCUIT_ID` bump.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkapInputV1 {
    /// Full JWT as raw ASCII bytes — the canonical
    /// `<header_b64>.<payload_b64>.<sig_b64>` triple.
    pub jwt_bytes: Vec<u8>,

    /// RSA-2048 modulus N as the natural big-endian byte string. Length
    /// MUST equal [`RSA_2048_BYTES`] (256). Public exponent is fixed to
    /// 65537 by the circuit and is not transmitted.
    pub rsa_modulus_be: Vec<u8>,

    /// PKCS#1 v1.5 SHA-256 RSA-2048 signature, big-endian. Length MUST
    /// equal [`RSA_2048_BYTES`] (256). Cross-checked by the wasm side
    /// against base64-decoded `sig_b64` segment of `jwt_bytes`.
    pub rsa_signature_be: Vec<u8>,

    /// Big-endian field encoding of the proof's blinding `random` scalar.
    pub random_be: [u8; 32],

    /// Big-endian field encoding of `h_sign_user_op` (public input).
    pub h_sign_user_op_be: [u8; 32],

    /// Anchor scalar list (`anchor.0`) — Vandermonde-projected secrets.
    /// Length = `n - k + 1`.
    pub anchor_values_be: Vec<[u8; 32]>,

    /// Known-secret list — length = `k`.
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

/// Returned by [`fe_from_be32_canonical`] when the input bytes encode an
/// integer that is `>= F::MODULUS`. V1 wire format requires canonical
/// encodings — silent `mod p` reduction would let a malformed wire
/// payload silently re-target a different field element.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("non-canonical 32-byte BE field encoding: {0}")]
pub struct NonCanonicalFieldError(pub String);

/// Strict canonical 32-byte BE → `F` decoder.
///
/// Returns `Err(NonCanonicalFieldError)` when the input bytes encode an
/// integer `>= F::MODULUS`. The check uses a round-trip equality:
/// `fe_to_be32(F::from_be_bytes_mod_order(bytes)) == bytes` holds iff the
/// input was already a canonical encoding.
pub fn fe_from_be32_canonical<F: PrimeField>(
    bytes: &[u8; 32],
) -> Result<F, NonCanonicalFieldError> {
    let f = F::from_be_bytes_mod_order(bytes);
    if fe_to_be32(&f) != *bytes {
        return Err(NonCanonicalFieldError(format!(
            "0x{} represents an integer >= F::MODULUS",
            hex_encode(bytes)
        )));
    }
    Ok(f)
}

/// Pack a field element into 32 BE bytes. `into_bigint().to_bytes_be()`
/// for fields whose modulus fits in 254 bits (e.g. BN254 Fr) returns at
/// most 32 bytes; the leading-zero pad covers low-bit values.
pub fn fe_to_be32<F: PrimeField>(value: &F) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    debug_assert!(bytes.len() <= 32);
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::Zero;

    /// BN254 Fr modulus, big-endian.
    const BN254_FR_MODULUS_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    #[test]
    fn canonical_decoder_accepts_zero() {
        let bytes = [0u8; 32];
        let decoded: Fr = fe_from_be32_canonical(&bytes).expect("zero is canonical");
        assert_eq!(decoded, Fr::zero());
    }

    #[test]
    fn canonical_decoder_accepts_p_minus_one() {
        let mut bytes = BN254_FR_MODULUS_BE;
        bytes[31] = 0x00;
        let decoded: Fr = fe_from_be32_canonical(&bytes).expect("p - 1 must be canonical");
        assert_eq!(fe_to_be32(&decoded), bytes);
    }

    #[test]
    fn canonical_decoder_rejects_p() {
        let bytes = BN254_FR_MODULUS_BE;
        let err: Result<Fr, _> = fe_from_be32_canonical(&bytes);
        assert!(err.is_err());
    }

    #[test]
    fn canonical_decoder_rejects_p_plus_one() {
        let mut bytes = BN254_FR_MODULUS_BE;
        bytes[31] = 0x02;
        let err: Result<Fr, _> = fe_from_be32_canonical(&bytes);
        assert!(err.is_err());
    }

    #[test]
    fn fe_be32_round_trip_low_value() {
        let v = Fr::from(42u64);
        let bytes = fe_to_be32(&v);
        let mut leading = 0;
        for &b in &bytes {
            if b != 0 {
                break;
            }
            leading += 1;
        }
        assert!(leading > 0, "expected leading zeros for low-bit value");
        let back = Fr::from_be_bytes_mod_order(&bytes);
        assert_eq!(back, v);
    }

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
            claims: alloc::vec![
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
            rsa_modulus_be: alloc::vec![0x12; 256],
            rsa_signature_be: alloc::vec![0x34; 256],
            random_be: [0x11; 32],
            h_sign_user_op_be: [0x22; 32],
            anchor_values_be: alloc::vec![[0x33; 32]; (cfg.n - cfg.k + 1) as usize],
            anchor_known_x_be: alloc::vec![[0x44; 32]; cfg.k as usize],
            anchor_selector: alloc::vec![1, 1, 1, 0, 0, 0],
            anchor_current_idx: 0,
            merkle_root_be: [0x55; 32],
            merkle_leaf_sibling_hash_be: [0x66; 32],
            merkle_auth_path_be: alloc::vec![[0x77; 32]; (cfg.tree_height - 1) as usize],
            merkle_leaf_idx: 0,
            circuit_config: cfg,
        }
    }

    /// Acceptance: V1 wire round-trips through postcard byte-for-byte.
    #[test]
    fn v1_postcard_round_trip() {
        let v1 = dummy_v1();
        let bytes = postcard::to_allocvec(&v1).expect("encode");
        let decoded: ZkapInputV1 = postcard::from_bytes(&bytes).expect("decode");
        let bytes2 = postcard::to_allocvec(&decoded).expect("re-encode");
        assert_eq!(bytes, bytes2);
    }

    /// Acceptance: every field is encoded in declaration order. Freezing a
    /// few byte positions surfaces accidental field re-orderings as a
    /// failing test instead of a silent CIRCUIT_ID mismatch.
    #[test]
    fn v1_postcard_field_layout_is_stable() {
        let v1 = dummy_v1();
        let bytes = postcard::to_allocvec(&v1).expect("encode");
        // jwt_bytes: varint(15) + "hdr.payload.sig"
        assert_eq!(bytes[0], 15);
        assert_eq!(&bytes[1..16], b"hdr.payload.sig");
        // rsa_modulus_be: varint(256) = 0x80 0x02, then 256 bytes of 0x12
        assert_eq!(bytes[16], 0x80);
        assert_eq!(bytes[17], 0x02);
        for &b in &bytes[18..18 + 256] {
            assert_eq!(b, 0x12);
        }
        let sig_off = 18 + 256;
        assert_eq!(bytes[sig_off], 0x80);
        assert_eq!(bytes[sig_off + 1], 0x02);
        for &b in &bytes[sig_off + 2..sig_off + 2 + 256] {
            assert_eq!(b, 0x34);
        }
        let random_off = sig_off + 2 + 256;
        for &b in &bytes[random_off..random_off + 32] {
            assert_eq!(b, 0x11);
        }
        let h_sign_off = random_off + 32;
        for &b in &bytes[h_sign_off..h_sign_off + 32] {
            assert_eq!(b, 0x22);
        }
    }
}
