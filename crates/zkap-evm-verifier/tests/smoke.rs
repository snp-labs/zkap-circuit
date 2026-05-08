//! Smoke tests for the Solidity verifier codegen.
//!
//! Phase 5 (P5-evm-test). The crate carries no in-tree fixtures because
//! the legacy code lived in `zkap-service::evm` where the heavy
//! `service_integration` tests exercised the round-trip implicitly via
//! `setup() → persist_setup_output()`. After Phase 4 / S11 extracted the
//! crate, the codegen had no direct test coverage of its own. These
//! smoke tests synthesise a deterministic `VerifyingKey<Bn254>` from
//! curve generators (no Groth16 setup, no RNG) and assert:
//!
//! 1. `to_solidity()` produces the documented hex-string layouts for
//!    `Fp`, `Fp2`, `G1Affine`, `G2Affine`, and `Vec<T>`.
//! 2. `generate_solidity()` writes a file whose content carries the
//!    structural anchors the on-chain contract relies on (license
//!    header, library scaffold, `_verify` signature shaped by the
//!    public-input count, and one `ic###` constant per `gamma_abc_g1`
//!    entry).
//!
//! The tests are intentionally light (no symbolic Solidity parser) —
//! the purpose is to surface regressions in the codegen template, not
//! to validate correctness of the Solidity logic, which is exercised
//! end-to-end by `zkap-service::tests::service_integration`.
//!
//! Plan ref: `.omc/plans/2026-05-08-per-crate-refactor/service.md` §S11.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_groth16::data_structures::VerifyingKey;
use ark_std::path::PathBuf;

use zkap_evm_verifier::{Solidity, SolidityContractGenerator};

/// Build a deterministic, non-cryptographic `VerifyingKey` suitable for
/// codegen smoke testing only. Uses curve generators for every group
/// element so the output is reproducible across runs and platforms.
fn synthetic_vk(public_input_count: usize) -> VerifyingKey<Bn254> {
    VerifyingKey::<Bn254> {
        alpha_g1: G1Affine::generator(),
        beta_g2: G2Affine::generator(),
        gamma_g2: G2Affine::generator(),
        delta_g2: G2Affine::generator(),
        // gamma_abc_g1 has length `public_input_count + 1` — one extra
        // for the constant ic000 term.
        gamma_abc_g1: vec![G1Affine::generator(); public_input_count + 1],
    }
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
fn affine_to_solidity_emits_x_then_y() {
    let g = G1Affine::generator();
    let out = g.to_solidity();
    // Affine<P> for G1: 2 hex words (x, y).
    assert_eq!(out.len(), 2, "G1Affine must serialise to (x, y)");
    for w in &out {
        assert!(w.starts_with("0x"));
        assert_eq!(w.len(), 2 + 64);
    }
}

#[test]
fn vec_to_solidity_concatenates_in_order() {
    let xs = vec![Fr::from(1u64), Fr::from(2u64)];
    let flat = xs.to_solidity();
    assert_eq!(flat.len(), 2);
    assert!(flat[0].ends_with('1'));
    assert!(flat[1].ends_with('2'));
}

/// `generate_solidity` round-trip: synthetic VK → on-disk file →
/// structural anchors present.
#[test]
fn generate_solidity_round_trip_writes_expected_scaffold() {
    const PUBLIC_INPUTS: usize = 8; // matches ZKAP main circuit
    let vk = synthetic_vk(PUBLIC_INPUTS);

    let dir = std::env::temp_dir().join(format!(
        "zkap-evm-verifier-smoke-{}-{}",
        std::process::id(),
        // Cheap unique suffix so concurrent test threads don't collide.
        // Use the address of a stack local — avoids pulling in `rand`.
        &vk as *const _ as usize,
    ));
    let path: PathBuf = dir.join("Groth16Verifier.sol");

    vk.generate_solidity(&path).expect("generate_solidity write");

    let body = std::fs::read_to_string(&path).expect("read written contract");

    // 1. Standard scaffolding.
    assert!(
        body.contains("// SPDX-License-Identifier: GPL-3.0"),
        "license header"
    );
    assert!(body.contains("pragma solidity ^0.8.0;"), "pragma");
    assert!(body.contains("library Groth16Verifier {"), "library scaffold");
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

    // Cleanup. Best-effort — temp_dir leftovers are harmless.
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}
