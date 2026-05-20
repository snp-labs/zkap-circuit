//! Parity tests: `ark_codec::field_to_hex` ≡ `Solidity::to_solidity` for `Fp`.
//!
//! Audit §2.6 Option 2 — divergence retention with CI-pinned parity.
//!
//! Three hex implementations exist in the workspace (see §2.6 audit report).
//! Two of them — `ark_codec::field_to_hex` and `zkap_evm_verifier::Solidity`
//! for `Fp` — happen to produce byte-for-byte identical output for any
//! `PrimeField` whose `to_bytes_be()` yields a fixed-width big-endian encoding
//! (BN254 Fr ✓, BN254 Fq ✓). These tests pin that equivalence so future drift
//! breaks CI rather than silently producing different on-chain vs. off-chain hex.
//!
//! The third implementation (`ark_codec::affine_to_hex_str`) intentionally
//! diverges (UPPERCASE, variable width); its divergence is pinned separately
//! in `crates/ark-codec/src/affine.rs`.

use ark_bn254::{Fq, Fr};
use ark_codec::field_to_hex;
use ark_ff::{One, Zero};
use zkap_evm_verifier::Solidity;

// ── BN254 Fr test vectors ─────────────────────────────────────────────────────

/// `field_to_hex` and `Solidity::to_solidity` must agree on Fr::zero().
///
/// Pinned expected string: 0x-prefix + 64 hex zeros (32 zero bytes BE).
#[test]
fn parity_fr_zero() {
    let v = Fr::zero();
    let codec_hex = field_to_hex(v);
    let solidity_hex = v.to_solidity();
    assert_eq!(solidity_hex.len(), 1, "Fp encodes to exactly one hex word");
    assert_eq!(
        codec_hex, solidity_hex[0],
        "field_to_hex and Solidity for Fp diverged on Fr::zero()"
    );
    // Pinned exact string — guards against both implementations silently
    // changing format in lockstep.
    assert_eq!(
        codec_hex, "0x0000000000000000000000000000000000000000000000000000000000000000",
        "Fr::zero() must encode to 64 hex zeros with 0x prefix (66 chars total)"
    );
    assert_eq!(
        codec_hex.len(),
        66,
        "Fr hex string must be 66 chars (0x + 64)"
    );
}

/// `field_to_hex` and `Solidity::to_solidity` must agree on Fr::one().
///
/// Pinned expected string: 63 zero hex chars followed by '1'.
#[test]
fn parity_fr_one() {
    let v = Fr::one();
    let codec_hex = field_to_hex(v);
    let solidity_hex = v.to_solidity();
    assert_eq!(solidity_hex.len(), 1, "Fp encodes to exactly one hex word");
    assert_eq!(
        codec_hex, solidity_hex[0],
        "field_to_hex and Solidity for Fp diverged on Fr::one()"
    );
    // Pinned exact string.
    assert_eq!(
        codec_hex, "0x0000000000000000000000000000000000000000000000000000000000000001",
        "Fr::one() must encode to 0x followed by 63 zeros and '1'"
    );
    assert_eq!(codec_hex.len(), 66);
}

/// `field_to_hex` and `Solidity::to_solidity` must agree on Fr::from(255u64).
///
/// 255 == 0xff. The fixed-width 32-byte BE encoding pads with leading zeros.
/// Pinned expected string ends in "ff" with 62 zero hex chars before it.
#[test]
fn parity_fr_255() {
    let v = Fr::from(255u64);
    let codec_hex = field_to_hex(v);
    let solidity_hex = v.to_solidity();
    assert_eq!(solidity_hex.len(), 1, "Fp encodes to exactly one hex word");
    assert_eq!(
        codec_hex, solidity_hex[0],
        "field_to_hex and Solidity for Fp diverged on Fr::from(255)"
    );
    // Pinned — leading-zero padding must be present in both impls.
    assert_eq!(
        codec_hex, "0x00000000000000000000000000000000000000000000000000000000000000ff",
        "Fr::from(255) must be zero-padded to 64 hex chars"
    );
    assert_eq!(codec_hex.len(), 66);
}

/// `field_to_hex` and `Solidity::to_solidity` must agree on Fr::from(0x123456u64).
///
/// Multi-byte small value — the three significant bytes must be present and
/// zero-padded to the full 32-byte width.
#[test]
fn parity_fr_0x123456() {
    let v = Fr::from(0x123456u64);
    let codec_hex = field_to_hex(v);
    let solidity_hex = v.to_solidity();
    assert_eq!(solidity_hex.len(), 1);
    assert_eq!(
        codec_hex, solidity_hex[0],
        "field_to_hex and Solidity for Fp diverged on Fr::from(0x123456)"
    );
    assert!(
        codec_hex.ends_with("123456"),
        "0x123456 must appear in the last three bytes of the encoding"
    );
    assert_eq!(codec_hex.len(), 66);
}

/// `field_to_hex` and `Solidity::to_solidity` must agree on `-Fr::one()` (MODULUS − 1).
///
/// High-magnitude value — exercises all 32 bytes of the encoding.
#[test]
fn parity_fr_neg_one() {
    let v = -Fr::one();
    let codec_hex = field_to_hex(v);
    let solidity_hex = v.to_solidity();
    assert_eq!(solidity_hex.len(), 1);
    assert_eq!(
        codec_hex, solidity_hex[0],
        "field_to_hex and Solidity for Fp diverged on -Fr::one() (MODULUS - 1)"
    );
    // Must be 66 chars (0x + 64 hex chars) — not variable-width.
    assert_eq!(codec_hex.len(), 66);
    // Must start with a non-zero hex byte (the modulus fills most bits).
    let without_prefix = codec_hex.strip_prefix("0x").unwrap();
    assert_ne!(
        &without_prefix[..2],
        "00",
        "-Fr::one() must not start with a zero byte"
    );
}

/// `field_to_hex` and `Solidity::to_solidity` must agree on a "random-looking"
/// deterministic value: `Fr::from(0xdeadbeefcafebabeu64)`.
///
/// Explicit constant for reproducibility — anyone can verify the encoding
/// independently by computing the 32-byte BE representation of 0xdeadbeefcafebabe.
#[test]
fn parity_fr_deadbeef_cafebabe() {
    let v = Fr::from(0xdeadbeef_cafebabeu64);
    let codec_hex = field_to_hex(v);
    let solidity_hex = v.to_solidity();
    assert_eq!(solidity_hex.len(), 1);
    assert_eq!(
        codec_hex, solidity_hex[0],
        "field_to_hex and Solidity for Fp diverged on Fr::from(0xdeadbeefcafebabe)"
    );
    assert!(
        codec_hex.ends_with("deadbeefcafebabe"),
        "0xdeadbeefcafebabe must appear in the last 8 bytes of the encoding"
    );
    assert_eq!(codec_hex.len(), 66);
}

// ── BN254 Fq test vector (base field, not scalar field) ───────────────────────

/// Confirms both implementations agree on BN254 Fq as well as Fr.
///
/// Fq is the base field (coordinate field) of BN254 G1/G2. Its modulus is
/// also 254-bit, so `to_bytes_be()` also yields 32 bytes. The parity that
/// holds for Fr must hold for Fq as well.
#[test]
fn parity_fq_one() {
    let v = Fq::one();
    let codec_hex = field_to_hex(v);
    let solidity_hex = v.to_solidity();
    assert_eq!(solidity_hex.len(), 1, "Fq encodes to exactly one hex word");
    assert_eq!(
        codec_hex, solidity_hex[0],
        "field_to_hex and Solidity for Fp diverged on Fq::one()"
    );
    // Pinned — same fixed-width 32-byte BE encoding.
    assert_eq!(
        codec_hex, "0x0000000000000000000000000000000000000000000000000000000000000001",
        "Fq::one() must encode identically to Fr::one()"
    );
    assert_eq!(codec_hex.len(), 66);
}
