//! V1 wire-format payload (`ZkapInputV1`) and its RSA byte-length
//! constant. Absorbed verbatim from former `zkap-input-types` crate.

extern crate alloc;

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::CircuitConfig;

/// Required wire-format length for `rsa_modulus_be` and `rsa_signature_be`.
/// RSA-2048 keys/signatures are exactly 256 bytes; any other length is a
/// host bug or a malformed payload.
pub const RSA_2048_BYTES: usize = 256;

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
    pub circuit_config: CircuitConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

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
