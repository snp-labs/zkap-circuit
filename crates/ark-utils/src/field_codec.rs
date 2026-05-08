//! Canonical field-element codecs.
//!
//! Centralizes the byte-level encodings of `PrimeField` values used by
//! the V1 wire format ([`super::wire`]) and by service-level DTOs:
//!
//! - [`fe_to_be32`] / [`fe_from_be32_canonical`] — strict 32-byte
//!   big-endian round-trip used by the V1 wire format.
//! - [`field_to_hex`] — `0x`-prefixed big-endian hex serialization used
//!   by service-level DTOs and the EVM verifier interface.
//!
//! All three helpers are `<F: PrimeField>` generic (BN254 Fr is the
//! current production caller) and have no R1CS or feature-flag
//! dependencies — they're pure data conversions.

extern crate alloc;

use alloc::format;
use alloc::string::String;

use ark_ff::{BigInteger, PrimeField};

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

/// Serialize a field element as a `0x`-prefixed big-endian hex string.
///
/// Used by service-level DTOs (`ProofComponents`, `ZkapProofResult`) and
/// for EVM-verifier-compatible input formatting.
pub fn field_to_hex<F: PrimeField>(f: F) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in &bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
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

    #[test]
    fn field_to_hex_starts_with_0x() {
        let v = Fr::from(0x42u64);
        let s = field_to_hex(v);
        assert!(s.starts_with("0x"));
        assert!(s.ends_with("42"));
    }

    #[test]
    fn field_to_hex_zero() {
        // BN254 Fr's BigInteger::to_bytes_be() pads to 32 bytes; the hex
        // string is therefore the full 64-char zero string with the `0x`
        // prefix. (This matches the legacy `service::field_to_hex` behavior.)
        let s = field_to_hex(Fr::zero());
        assert_eq!(s, "0x0000000000000000000000000000000000000000000000000000000000000000");
    }
}
