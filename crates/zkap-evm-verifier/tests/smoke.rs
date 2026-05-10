//! Smoke tests for the Solidity verifier codegen.
//!
//! Phase 5 (P5-evm-test) introduced structural-only smoke tests that
//! used `G1Affine::generator()` / `G2Affine::generator()` for every
//! field of the synthetic `VerifyingKey<Bn254>`. Phase 6 (P6-evm-distinct,
//! WM2 follow-up) extends them with **distinct** group elements so that
//! coordinate-swap regressions in the codegen become detectable:
//!
//! - x↔y swap inside [`groth16_verifier_solidity::g1_constant`] is
//!   visible because `(G1 · 7).x ≠ (G1 · 7).y`.
//! - alpha/beta/gamma/delta misordering between fields of
//!   [`VerifyingKey`] is visible because each scalar multiple gives a
//!   different point.
//! - off-by-one in the `gamma_abc_g1` loop is visible because `ic000`,
//!   `ic001`, … each carry a different decimal value in the emitted
//!   contract.
//! - the Solidity Fp2 component reversal (c1 before c0) inside
//!   [`solidity_types::Solidity for Fp2`] is pinned to a distinct G2
//!   point where `c1 ≠ c0`, so a "fix" that drops the reversal would
//!   flip the asserted hex words.
//! - the per-G2 negation in [`groth16_verifier_solidity::generate_solidity`]
//!   (beta/gamma/delta are emitted as `-pt`) is pinned by comparing the
//!   contract bytes against `pt.into_group().neg().into_affine()`.
//!
//! The tests stay light (no symbolic Solidity parser); end-to-end
//! Solidity logic is exercised by `zkap-service::tests::service_integration`.
//!
//! Plan refs:
//! - `.omc/plans/2026-05-08-per-crate-refactor/service.md` §S11
//! - Phase 5 critic WM2 (Phase 6 follow-up)

use std::ops::Neg;

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_groth16::data_structures::VerifyingKey;
use ark_std::path::PathBuf;

use zkap_evm_verifier::{Solidity, SolidityContractGenerator};

/// `G1Affine::generator() * scalar`. Used to build distinct, deterministic
/// G1 points for codegen smoke tests without an RNG or trusted setup.
fn g1_scaled(scalar: u64) -> G1Affine {
    (G1Affine::generator() * Fr::from(scalar)).into_affine()
}

/// `G2Affine::generator() * scalar`. Companion to [`g1_scaled`].
fn g2_scaled(scalar: u64) -> G2Affine {
    (G2Affine::generator() * Fr::from(scalar)).into_affine()
}

/// Build a deterministic, non-cryptographic `VerifyingKey` whose group
/// elements are pairwise distinct so that coordinate/field swaps in the
/// codegen surface as test failures. Scalars are arbitrary primes; the
/// only constraint is "all different and none of them 1".
fn synthetic_vk_distinct(public_input_count: usize) -> VerifyingKey<Bn254> {
    VerifyingKey::<Bn254> {
        alpha_g1: g1_scaled(7),
        beta_g2: g2_scaled(11),
        gamma_g2: g2_scaled(13),
        delta_g2: g2_scaled(17),
        // gamma_abc_g1 has length `public_input_count + 1` — ic000 plus
        // one entry per public input. Each entry is a distinct multiple
        // so off-by-one indexing surfaces in the contract bytes.
        gamma_abc_g1: (0..=public_input_count)
            .map(|i| g1_scaled(19 + i as u64))
            .collect(),
    }
}

/// Lower-level field assertion helper: format an Fp element using its
/// Display impl (decimal), matching the format `g1_constant` /
/// `g2_constant` emit into the Solidity source.
fn fp_decimal<F: core::fmt::Display>(f: &F) -> String {
    format!("{}", f)
}

/// Hex-word form used by [`Solidity::to_solidity`] for `Fp` elements.
fn fp_hex_word<F: PrimeField>(f: &F) -> String {
    format!("0x{}", hex::encode(f.into_bigint().to_bytes_be()))
}

#[test]
fn fp_to_solidity_is_single_be_hex_word() {
    let one = Fr::from(1u64);
    let out = one.to_solidity();
    assert_eq!(out.len(), 1, "Fp must encode to a single hex word");
    let word = &out[0];
    assert!(word.starts_with("0x"), "hex prefix");
    // Fr is 254-bit; encoded as 32 BE bytes = 64 hex chars + "0x".
    assert_eq!(word.len(), 2 + 64, "Fp hex word width");
    assert!(
        word.ends_with('1'),
        "Fr::from(1) BE encoding ends in 0x...01"
    );
}

#[test]
fn affine_g1_to_solidity_emits_x_then_y_in_pinned_order() {
    // Distinct (non-generator) point so x ≠ y in a way that a x↔y swap
    // would surface as a hex-word mismatch.
    let p = g1_scaled(7);
    let out = p.to_solidity();
    assert_eq!(out.len(), 2, "G1Affine must serialise to (x, y)");

    let expected_x = fp_hex_word(&p.x().unwrap());
    let expected_y = fp_hex_word(&p.y().unwrap());
    assert_eq!(out[0], expected_x, "x must come first");
    assert_eq!(out[1], expected_y, "y must come second");
    assert_ne!(
        out[0], out[1],
        "distinct G1 point: x ≠ y, so an x↔y swap would be detectable"
    );

    for w in &out {
        assert!(w.starts_with("0x"));
        assert_eq!(w.len(), 2 + 64);
    }
}

#[test]
fn fp2_to_solidity_emits_c1_before_c0_for_solidity_convention() {
    // The on-chain Groth16 verifier expects each Fp2 component reversed
    // (high limb before low). With a distinct G2 point both Fp2
    // components differ, so an accidental "fix" that drops the reversal
    // would flip these hex words.
    let g2 = g2_scaled(11);
    let x_fp2 = g2.x().unwrap();
    let out = x_fp2.to_solidity();

    let coords: Vec<_> = x_fp2.to_base_prime_field_elements().collect();
    // Fp2::to_base_prime_field_elements yields (c0, c1).
    let c0 = &coords[0];
    let c1 = &coords[1];
    assert_ne!(c0, c1, "distinct G2 yields distinct Fp2 components");

    assert_eq!(out.len(), 2, "Fp2 → 2 hex words");
    assert_eq!(
        out[0],
        fp_hex_word(c1),
        "Solidity reverses Fp2: c1 first"
    );
    assert_eq!(
        out[1],
        fp_hex_word(c0),
        "Solidity reverses Fp2: c0 second"
    );
}

#[test]
fn affine_g2_to_solidity_concatenates_x_then_y_each_in_c1_c0_order() {
    let g2 = g2_scaled(11);
    let out = g2.to_solidity();
    assert_eq!(out.len(), 4, "G2 → 4 hex words: x.c1, x.c0, y.c1, y.c0");

    let x_coords: Vec<_> = g2.x().unwrap().to_base_prime_field_elements().collect();
    let y_coords: Vec<_> = g2.y().unwrap().to_base_prime_field_elements().collect();

    assert_eq!(out[0], fp_hex_word(&x_coords[1]), "x.c1");
    assert_eq!(out[1], fp_hex_word(&x_coords[0]), "x.c0");
    assert_eq!(out[2], fp_hex_word(&y_coords[1]), "y.c1");
    assert_eq!(out[3], fp_hex_word(&y_coords[0]), "y.c0");
}

#[test]
fn vec_to_solidity_concatenates_in_order() {
    let xs = vec![Fr::from(1u64), Fr::from(2u64)];
    let flat = xs.to_solidity();
    assert_eq!(flat.len(), 2);
    assert!(flat[0].ends_with('1'));
    assert!(flat[1].ends_with('2'));
}

/// `generate_solidity` round-trip with distinct group elements.
/// Pins the on-disk constants against alpha_g1's actual coordinates,
/// the negated beta/gamma/delta, and `gamma_abc_g1[i]` in order, so
/// codegen regressions (x↔y swap, alpha/delta swap, missing `.neg()`,
/// off-by-one in the `ic###` loop) are detected without relying on a
/// real Groth16 setup.
#[test]
fn generate_solidity_round_trip_pins_distinct_vk_constants() {
    use std::sync::atomic::{AtomicU64, Ordering};

    const PUBLIC_INPUTS: usize = 8; // matches ZKAP main circuit
    let vk = synthetic_vk_distinct(PUBLIC_INPUTS);

    // Per-process monotonic counter: guarantees a fresh directory per
    // call regardless of stack layout, ASLR, or `--test-threads=1`.
    // (Earlier draft used `&vk as *const _ as usize` for uniqueness;
    // that's unsound — co-located stack frames can repeat addresses
    // across thread starts and the optimiser can reuse slots, so the
    // suffix wasn't actually unique. `create_dir_all` made the bug
    // benign in practice, but the counter form is correct by
    // construction.)
    static UNIQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zkap-evm-verifier-smoke-{}-{}",
        std::process::id(),
        UNIQ.fetch_add(1, Ordering::Relaxed),
    ));
    let path: PathBuf = dir.join("Groth16Verifier.sol");

    vk.generate_solidity(&path)
        .expect("generate_solidity write");

    let body = std::fs::read_to_string(&path).expect("read written contract");

    // 1. Standard scaffolding.
    assert!(
        body.contains("// SPDX-License-Identifier: GPL-3.0"),
        "license header"
    );
    assert!(body.contains("pragma solidity ^0.8.0;"), "pragma");
    assert!(
        body.contains("library Groth16Verifier {"),
        "library scaffold"
    );
    assert!(
        body.contains("error InvalidProofLength();"),
        "error: InvalidProofLength"
    );
    assert!(
        body.contains("error InvalidInstanceLength();"),
        "error: InvalidInstanceLength"
    );
    assert!(
        body.contains("error PrepareInstanceFailed();"),
        "error: PrepareInstanceFailed"
    );
    assert!(
        body.contains("error PairingFailed();"),
        "error: PairingFailed"
    );

    // 2. _verify signature carries the right public-input count.
    let expected_signature = format!(
        "function _verify(uint256[{}] calldata instance, uint256[8] calldata proof) public view returns (bool)",
        PUBLIC_INPUTS
    );
    assert!(
        body.contains(&expected_signature),
        "_verify signature shaped by gamma_abc_g1 length: expected substring `{}`",
        expected_signature
    );

    // 3. Exactly one ic### constant pair per gamma_abc_g1 entry.
    for i in 0..=PUBLIC_INPUTS {
        let icx = format!("uint256 private constant ic{:03}X", i);
        let icy = format!("uint256 private constant ic{:03}Y", i);
        assert!(body.contains(&icx), "missing constant {}", icx);
        assert!(body.contains(&icy), "missing constant {}", icy);
    }

    // 4. No trailing ic constant past the actual length.
    let past = format!("ic{:03}X", PUBLIC_INPUTS + 1);
    assert!(
        !body.contains(&past),
        "unexpected extra ic constant `{}` past gamma_abc_g1 length",
        past
    );

    // 5. alpha_g1 byte-pinning. The .sol emits `uint256 ... = <decimal>;`
    // using ark-ff's Display impl. Verify the emitted decimal matches
    // alpha_g1.{x,y}, not y/x swapped or some other VK field.
    let alpha_x = fp_decimal(&vk.alpha_g1.x().unwrap());
    let alpha_y = fp_decimal(&vk.alpha_g1.y().unwrap());
    assert_ne!(
        alpha_x, alpha_y,
        "synthetic distinct G1 point must have x ≠ y"
    );
    assert!(
        body.contains(&format!("alphaX = {};", alpha_x)),
        "alphaX must equal alpha_g1.x (catches x↔y swap in g1_constant)"
    );
    assert!(
        body.contains(&format!("alphaY = {};", alpha_y)),
        "alphaY must equal alpha_g1.y"
    );

    // 6. ic000 ≠ ic001 ≠ ic002 (catches off-by-one or duplicate-element
    // bugs in the gamma_abc_g1 enumeration loop).
    let ic000_x = fp_decimal(&vk.gamma_abc_g1[0].x().unwrap());
    let ic001_x = fp_decimal(&vk.gamma_abc_g1[1].x().unwrap());
    let ic002_x = fp_decimal(&vk.gamma_abc_g1[2].x().unwrap());
    assert_ne!(ic000_x, ic001_x);
    assert_ne!(ic001_x, ic002_x);
    assert!(body.contains(&format!("ic000X = {};", ic000_x)));
    assert!(body.contains(&format!("ic001X = {};", ic001_x)));
    assert!(body.contains(&format!("ic002X = {};", ic002_x)));

    // 7. beta/gamma/delta are emitted as the **negated** G2 points (the
    // contract evaluates the Groth16 pairing with `-beta`, `-gamma`,
    // `-delta`). With distinct G2 points we can pin the negation by
    // comparing against `pt.into_group().neg().into_affine()` and
    // separately confirm the un-negated form would not match. Phase 5
    // initially pinned only beta; Phase 7 (P7-evm-gamma-delta-pin, WM(c)
    // follow-up) extends the same pin to gamma and delta so a regression
    // that drops `.neg()` on either of them — but not beta — is also
    // surfaced. `assert_g2_neg_pinned` is the per-tag helper.
    assert_g2_neg_pinned(&body, "beta", &vk.beta_g2);
    assert_g2_neg_pinned(&body, "gamma", &vk.gamma_g2);
    assert_g2_neg_pinned(&body, "delta", &vk.delta_g2);

    // Cleanup. Best-effort — temp_dir leftovers are harmless.
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

/// Asserts that the Solidity `<tag>{X0,X1,Y0,Y1}` constants in `body`
/// match the **negated** form of `pt` and not the un-negated form.
/// Surfaces missing `.neg()` calls in `generate_solidity` for any of
/// beta/gamma/delta. Tag is the lowercased VK field name (`"beta"`,
/// `"gamma"`, `"delta"`).
fn assert_g2_neg_pinned(body: &str, tag: &str, pt: &G2Affine) {
    let neg = pt.into_group().neg().into_affine();
    let neg_x: Vec<_> = neg
        .x()
        .unwrap()
        .to_base_prime_field_elements()
        .collect();
    let neg_y: Vec<_> = neg
        .y()
        .unwrap()
        .to_base_prime_field_elements()
        .collect();
    // g2_constant emits Fp2 reversed: X0 = c1, X1 = c0, Y0 = c1, Y1 = c0.
    assert!(
        body.contains(&format!("{tag}X0 = {};", fp_decimal(&neg_x[1]))),
        "{tag}X0 must equal negated {tag}_g2.x.c1"
    );
    assert!(
        body.contains(&format!("{tag}X1 = {};", fp_decimal(&neg_x[0]))),
        "{tag}X1 must equal negated {tag}_g2.x.c0"
    );
    assert!(
        body.contains(&format!("{tag}Y0 = {};", fp_decimal(&neg_y[1]))),
        "{tag}Y0 must equal negated {tag}_g2.y.c1"
    );
    assert!(
        body.contains(&format!("{tag}Y1 = {};", fp_decimal(&neg_y[0]))),
        "{tag}Y1 must equal negated {tag}_g2.y.c0"
    );

    // The un-negated y-coordinate must NOT appear under this tag — this
    // is what catches a regression that drops the `.neg()` call on
    // `<tag>_g2` while leaving the others intact.
    let pos_y: Vec<_> = pt
        .y()
        .unwrap()
        .to_base_prime_field_elements()
        .collect();
    assert_ne!(
        neg_y[1], pos_y[1],
        "{tag}: negated y must differ from un-negated y on a distinct G2 point"
    );
    assert!(
        !body.contains(&format!("{tag}Y0 = {};", fp_decimal(&pos_y[1]))),
        "{tag}Y0 must NOT carry the un-negated y (catches missing .neg() on {tag}_g2)"
    );
}
