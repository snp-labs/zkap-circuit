//! Pin the behaviour of `FpVar::enforce_cmp(Ordering::Less, true)` in the
//! ark-r1cs-std version this workspace currently depends on (0.5.0) and
//! confirm that the `is_less_than | is_eq` workaround used by
//! `circuit::token::claimverifier::format::claim_format_verifier_v2`
//! checks 1 and 2 produces the same satisfaction verdict on every input
//! we care about.
//!
//! # Why this test exists
//!
//! `claim_format_verifier_v2` was originally written with two
//! `enforce_cmp(Ordering::Less, true)` calls on `name_len/colon_idx` and
//! `colon_idx/value_idx`. Those calls were replaced with the
//! `is_less_than(...) | is_eq(...)` expression because the original
//! `enforce_cmp` path produced unsound constraints on at least some
//! inputs in ark-r1cs-std 0.5.0. The replacement is now part of the
//! deployed R1CS shape and is L1-locked — see
//! `.omc/plans/2026-05-08-per-crate-refactor/00-cross-cutting-locks.md § L1`.
//!
//! This test does **not** change the deployed circuit. It captures the
//! observed behaviour of both expressions across the value range we use
//! (small unsigned integers that come from `UInt16::to_fp()`), so:
//!
//! - If a future ark-r1cs-std bump fixes the bug and the two expressions
//!   produce identical results on every case below, the diff will still
//!   pass — that is the *trigger* to file a follow-up PR (with a fresh
//!   trusted setup) to delete the workaround. Do **not** delete the
//!   workaround opportunistically inside an unrelated PR — the
//!   constraint expression is L1-locked.
//!
//! - If a future bump changes the behaviour in a way that flips
//!   `enforce_cmp_satisfied(...)` for some case, this test fails loudly.
//!   That is a clear signal that the workaround is still load-bearing.

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::Boolean,
};
use ark_relations::r1cs::ConstraintSystem;
use core::cmp::Ordering;

/// Build a circuit that enforces `a <= b` using
/// `FpVar::enforce_cmp(Ordering::Less, true)` and report whether the
/// constraint system is satisfied.
fn enforce_cmp_satisfied(a: u64, b: u64) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let a_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(a))).unwrap();
    let b_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(b))).unwrap();
    a_var
        .enforce_cmp(&b_var, Ordering::Less, true)
        .expect("enforce_cmp must allocate constraints (small inputs satisfy <= (p-1)/2)");
    cs.is_satisfied().unwrap()
}

/// Build a circuit that enforces `a <= b` using the workaround the
/// production code uses: `(is_less_than(a, b) | is_eq(a, b)) == true`,
/// taking the bottom 16 bits of each input — same shape as the
/// production call site, where both inputs come from `UInt16::to_fp()`.
fn workaround_satisfied(a: u64, b: u64) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let a_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(a))).unwrap();
    let b_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(b))).unwrap();
    let a_bits = a_var.to_bits_le().unwrap();
    let b_bits = b_var.to_bits_le().unwrap();
    let bits_16 = 16usize;
    let lt = ark_utils::is_less_than(&a_bits[..bits_16], &b_bits[..bits_16]).unwrap();
    let eq = a_var.is_eq(&b_var).unwrap();
    (lt | eq).enforce_equal(&Boolean::TRUE).unwrap();
    cs.is_satisfied().unwrap()
}

/// Cases representative of the production usage:
///   `name_len <= colon_idx` and `colon_idx <= value_idx`,
/// where each side is a 16-bit unsigned index.  The expected verdict
/// is the mathematical `a <= b`.
const PINNED_CASES: &[(u64, u64, bool)] = &[
    (0, 0, true),
    (0, 1, true),
    (1, 0, false),
    (3, 5, true),
    (5, 3, false),
    (5, 5, true),
    (10, 11, true),
    (11, 10, false),
    (255, 256, true),
    (256, 255, false),
    (1000, 1000, true),
    (65_535, 65_535, true),
    (65_534, 65_535, true),
    (65_535, 65_534, false),
];

#[test]
fn enforce_cmp_pinned_to_a_le_b_semantics() {
    for &(a, b, expected) in PINNED_CASES {
        let observed = enforce_cmp_satisfied(a, b);
        assert_eq!(
            observed, expected,
            "FpVar::enforce_cmp(Ordering::Less, true) on ({a}, {b}) produced satisfied={observed}, \
             expected {expected} (a <= b semantics)"
        );
    }
}

#[test]
fn workaround_pinned_to_a_le_b_semantics() {
    for &(a, b, expected) in PINNED_CASES {
        let observed = workaround_satisfied(a, b);
        assert_eq!(
            observed, expected,
            "is_less_than | is_eq workaround on ({a}, {b}) produced satisfied={observed}, \
             expected {expected} (a <= b semantics)"
        );
    }
}

#[test]
fn enforce_cmp_and_workaround_agree_on_every_pinned_case() {
    for &(a, b, _) in PINNED_CASES {
        let ec = enforce_cmp_satisfied(a, b);
        let wa = workaround_satisfied(a, b);
        assert_eq!(
            ec, wa,
            "FpVar::enforce_cmp(Ordering::Less, true) and the is_less_than|is_eq workaround \
             disagree on ({a}, {b}): enforce_cmp={ec}, workaround={wa}. \
             If this test ever fails, the workaround in claim_format_verifier_v2 is doing \
             real work — do NOT remove it without a fresh trusted setup."
        );
    }
}
