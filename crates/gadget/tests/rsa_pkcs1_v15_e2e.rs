//! End-to-end integration test for RSA-2048 PKCS#1 v1.5 signature verification.
//!
//! Verifies the byte-order contract between `SHA256Gadget::digest` (big-endian output)
//! and `output_with_prefix` (expects little-endian input). The full path exercised here
//! is identical to [`RSA2048VerifyGadget::verify_opt`] in the circuit crate:
//!
//! 1. Hash the message with `SHA256Gadget::digest` → big-endian digest (BE)
//! 2. Reverse the digest bytes → little-endian (LE)
//! 3. Call `output_with_prefix(&reversed)` → PKCS#1 EM integer in LE limb order
//! 4. Compute `sig^65537 mod n` via 16 squarings + 1 multiply, serialise in LE
//! 5. Assert constraint-field equality of EM and sig^e
//!
//! **Byte-order contract (auditor reference §5-1 H-1):**
//! - `SHA256Gadget::digest*` returns BE (FIPS 180-4; index 0 = MSB).
//! - `output_with_prefix` expects LE (index 0 = LSB).
//! - The reversal is the caller's responsibility.
//! - Passing a BE digest without reversal produces a permanently unsatisfied system
//!   (confirmed by the adversarial `test_wrong_digest_order` case below).

#![cfg(all(feature = "rsa", feature = "hashes-sha256"))]

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    convert::{ToBytesGadget, ToConstraintFieldGadget},
    eq::EqGadget,
    uint8::UInt8,
};
use ark_relations::gr1cs::ConstraintSystem;
use gadget::{
    bigint::constraints::{BigNatCircuitParams, BigNatVar},
    hashes::sha256::constraints::SHA256Gadget,
    signature::rsa::{PublicKey, Signature, constraints::{PublicKeyVar, SignatureVar, output_with_prefix}},
};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::SigningKey,
    signature::RandomizedSigner,
    traits::PublicKeyParts,
};
use sha2::Sha256;

/// RSA-2048 BigNat parameters matching the production `BigNat2048Params` in the circuit crate.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Rsa2048Params;

impl BigNatCircuitParams for Rsa2048Params {
    const LIMB_WIDTH: usize = 64;
    const N_LIMBS: usize = 32; // 2048 / 64
}

/// Generate a deterministic RSA-2048 key pair and sign a message.
///
/// Uses `ChaCha20Rng::from_seed([42; 32])` so the test is fully reproducible.
/// Returns `(public_key_bytes_n, sig_bytes, message)` where `public_key_bytes_n`
/// is the 256-byte big-endian modulus.
fn keygen_and_sign(message: &[u8]) -> (PublicKey, Signature) {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA-2048 keygen failed");
    let pub_key_rsa = RsaPublicKey::from(&priv_key);

    let pk = PublicKey {
        n: pub_key_rsa.n().to_bytes_be(),
        e: pub_key_rsa.e().to_bytes_be(),
    };

    let signing_key = SigningKey::<Sha256>::new(priv_key);
    let mut signing_rng = ChaCha20Rng::from_seed([43u8; 32]);
    let raw_sig: Box<[u8]> = signing_key.sign_with_rng(&mut signing_rng, message).into();
    let sig = Signature(raw_sig.to_vec());

    (pk, sig)
}

/// Allocate a `PublicKeyVar` and `SignatureVar` into a constraint system,
/// then run the RSA-2048 PKCS#1 v1.5 verification gadget (mirroring `verify_opt`).
///
/// Returns `cs.is_satisfied()`.
fn run_verify_gadget(
    message: &[u8],
    pk: &PublicKey,
    sig: &Signature,
) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Allocate message bytes as witnesses.
    let mut message_vars: Vec<UInt8<Fr>> = message
        .iter()
        .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap())
        .collect();

    // Hash the message with SHA256Gadget — output is big-endian (FIPS 180-4).
    let digest = SHA256Gadget::digest(&message_vars).unwrap();
    // Move the digest bytes into message_vars for the verify path.
    message_vars = digest.0;

    // Allocate public key and signature.
    let pk_var = PublicKeyVar::<Fr, Rsa2048Params>::new_witness(cs.clone(), || Ok(pk.clone()))
        .unwrap();
    let sig_var = SignatureVar::<Fr, Rsa2048Params>::new_witness(cs.clone(), || Ok(sig.clone()))
        .unwrap();

    // === Mirror RSA2048VerifyGadget::verify_opt ===

    // Enforce sig < n and range-check both.
    sig_var.sig.enforce_limb_range_via_bits().unwrap();
    pk_var.n.enforce_limb_range_via_bits().unwrap();
    BigNatVar::<Fr, Rsa2048Params>::enforce_lt_strict_borrow_chain(
        cs.clone(),
        &sig_var.sig,
        &pk_var.n,
    )
    .unwrap();

    // Step 1: reverse digest bytes BE → LE.
    message_vars.reverse();

    // Step 2: build PKCS#1 EM in LE order.
    let em = output_with_prefix(&message_vars);
    let em_fp = em.to_constraint_field().unwrap();

    // Step 3: sig^65537 mod n via 16 squarings + 1 multiply (optimised path).
    let mut acc = sig_var.sig.clone();
    for _ in 0..16 {
        acc = acc.square_mod_unchecked(&pk_var.n).unwrap();
    }
    let result_bytes = acc
        .mult_mod_unchecked(&sig_var.sig, &pk_var.n)
        .unwrap()
        .to_bytes_le()
        .unwrap();
    let result_fp = result_bytes.to_constraint_field().unwrap();

    // Step 4: assert equality.
    result_fp.is_eq(&em_fp).unwrap()
        .enforce_equal(&ark_r1cs_std::prelude::Boolean::TRUE)
        .unwrap();

    cs.is_satisfied().unwrap()
}

// ── Happy path ────────────────────────────────────────────────────────────────

/// Happy path: a real PKCS#1 v1.5 / SHA-256 signature produced by the `rsa` crate
/// must satisfy the constraint system.
#[test]
fn test_valid_signature_satisfies() {
    let message = b"zkap-circuit RSA-2048 PKCS1v15 byte-order regression test";
    let (pk, sig) = keygen_and_sign(message);

    assert!(
        run_verify_gadget(message, &pk, &sig),
        "valid RSA-2048 signature must satisfy the constraint system"
    );
}

// ── Adversarial: flipped signature byte ──────────────────────────────────────

/// Adversarial: flip one byte of the signature. The modified value is no longer
/// the correct RSA decryption, so `sig^e mod n ≠ EM` and the system must NOT be satisfied.
#[test]
fn test_flipped_signature_byte_unsatisfied() {
    let message = b"zkap-circuit RSA-2048 PKCS1v15 byte-order regression test";
    let (pk, mut sig) = keygen_and_sign(message);

    // Flip the middle byte of the signature.
    let flip_idx = sig.0.len() / 2;
    sig.0[flip_idx] ^= 0xFF;

    assert!(
        !run_verify_gadget(message, &pk, &sig),
        "a signature with one byte flipped must NOT satisfy the constraint system"
    );
}

// ── Adversarial: wrong message ────────────────────────────────────────────────

/// Adversarial: the signature is valid for `message` but the circuit is given a
/// different message.  `SHA256Gadget::digest` will produce a different EM, so
/// `sig^e mod n ≠ EM` and the system must NOT be satisfied.
#[test]
fn test_wrong_message_unsatisfied() {
    let message = b"zkap-circuit RSA-2048 PKCS1v15 byte-order regression test";
    let wrong_message = b"zkap-circuit RSA-2048 PKCS1v15 byte-order regression WRONG";
    let (pk, sig) = keygen_and_sign(message);

    // Sign was done over `message`; we feed `wrong_message` into the circuit.
    assert!(
        !run_verify_gadget(wrong_message, &pk, &sig),
        "a signature verified against the wrong message must NOT satisfy"
    );
}

// ── Adversarial: digest order reversed (byte-order contract regression) ────────

/// Adversarial: compute the SHA-256 digest in-circuit but skip the BE→LE reversal
/// before calling `output_with_prefix`.  This violates the byte-order contract, so
/// the EM built from the unreversed (BE) digest will not match `sig^e mod n`, and
/// the constraint system must NOT be satisfied.
///
/// This is the direct regression test for audit finding §5-1 H-1: if
/// `SHA256Gadget` were ever changed to produce LE output, the happy-path test
/// above would break and this test would pass — unambiguously revealing the mismatch.
#[test]
fn test_digest_order_reversed_unsatisfied() {
    let message = b"zkap-circuit RSA-2048 PKCS1v15 byte-order regression test";
    let (pk, sig) = keygen_and_sign(message);

    let cs = ConstraintSystem::<Fr>::new_ref();

    // Allocate message bytes.
    let message_vars: Vec<UInt8<Fr>> = message
        .iter()
        .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap())
        .collect();

    // Hash — produces BE digest.
    let digest = SHA256Gadget::digest(&message_vars).unwrap();
    let message_vars: Vec<UInt8<Fr>> = digest.0;

    // Allocate public key and signature.
    let pk_var = PublicKeyVar::<Fr, Rsa2048Params>::new_witness(cs.clone(), || Ok(pk.clone()))
        .unwrap();
    let sig_var = SignatureVar::<Fr, Rsa2048Params>::new_witness(cs.clone(), || Ok(sig.clone()))
        .unwrap();

    sig_var.sig.enforce_limb_range_via_bits().unwrap();
    pk_var.n.enforce_limb_range_via_bits().unwrap();
    BigNatVar::<Fr, Rsa2048Params>::enforce_lt_strict_borrow_chain(
        cs.clone(),
        &sig_var.sig,
        &pk_var.n,
    )
    .unwrap();

    // INTENTIONALLY omit message_vars.reverse() — violates the byte-order contract.
    let em = output_with_prefix(&message_vars);
    let em_fp = em.to_constraint_field().unwrap();

    let mut acc = sig_var.sig.clone();
    for _ in 0..16 {
        acc = acc.square_mod_unchecked(&pk_var.n).unwrap();
    }
    let result_bytes = acc
        .mult_mod_unchecked(&sig_var.sig, &pk_var.n)
        .unwrap()
        .to_bytes_le()
        .unwrap();
    let result_fp = result_bytes.to_constraint_field().unwrap();

    result_fp.is_eq(&em_fp).unwrap()
        .enforce_equal(&ark_r1cs_std::prelude::Boolean::TRUE)
        .unwrap();

    assert!(
        !cs.is_satisfied().unwrap(),
        "passing a BE digest (without reversal) to output_with_prefix must NOT satisfy — \
         this is the byte-order contract regression guard from audit §5-1 H-1"
    );
}
