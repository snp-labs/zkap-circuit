//! L4 input-conversion drift guard (Phase 3 C1, plan circuit.md § C-A12).
//!
//! Isolates the V1 → `ZkapCircuitInput<F>` conversion path from the rest
//! of the wasm pipeline. The end-to-end test in `wasm_to_prove.rs` already
//! asserts that the wasm-built `.arwtns` is byte-identical to a native
//! `circuit_to_arwtns` baseline — but it does so after a wasm32 rebuild
//! and a Groth16 setup, which conflates four sources of drift:
//!
//! 1. V1 → ZkapCircuitInput conversion (`into_circuit_input`)
//! 2. wasm32 build (target codegen, panic strategy, allocator)
//! 3. wasmi runtime (host imports, allocator)
//! 4. prover pipeline (`ark-ar1cs-prover::prove`)
//!
//! When the circuit-side splits planned for Phase 3 (C8 claim_verifier,
//! C9 jwt_field, C11 zkap.rs phase split) regress, the e2e test fails
//! without telling you which layer broke. This test hits layer (1) only.
//!
//! The fixture bundle [`build_v1_fixture_bundle`] hands back `v1_inputs`
//! (V1 wire payloads) and `circuit_inputs` (the natively-built
//! `ZkapCircuitInput` baselines for the same logical fixtures). For every
//! pair we drive both ends through `circuit_to_arwtns` (no wasm32, no
//! Groth16 setup) and assert the resulting `.arwtns` bytes are equal.

mod common;

use ark_ar1cs_format::CurveId;
use ark_ar1cs_wasm_witness::circuit_to_arwtns;
use ark_bn254::Fr;

use common::{build_v1_fixture_bundle, TestCircuit, V1FixtureBundle};

/// Acceptance: `into_circuit_input(v1)` produces a `ZkapCircuitInput`
/// whose synthesized `.arwtns` is byte-identical to the native baseline
/// for every fixture. Any divergence here means
/// [`zkap_witness_wasm::into_circuit_input`] drifted from the host-side
/// fixture builder — investigate `crates/zkap-witness-wasm/src/input.rs`
/// before looking at circuit-side splits.
#[test]
fn into_circuit_input_matches_native_baseline_byte_identical() {
    // Any fixed 32-byte tag works — both ends use the same value, so the
    // arwtns header binds to the same blake3 and the bytes after it can
    // be compared directly.
    let blake3 = [0xA5u8; 32];

    let V1FixtureBundle {
        v1_inputs,
        circuit_inputs,
    } = build_v1_fixture_bundle();

    assert_eq!(
        v1_inputs.len(),
        circuit_inputs.len(),
        "V1 wire payloads and circuit-input baselines must be paired 1:1",
    );
    assert!(!v1_inputs.is_empty(), "fixture bundle is empty");

    for (i, v1) in v1_inputs.iter().cloned().enumerate() {
        let via_v1 = zkap_witness_wasm::into_circuit_input(v1)
            .unwrap_or_else(|e| panic!("V1[{}] → ZkapCircuitInput failed: {:?}", i, e));
        let circuit_via_v1 = TestCircuit::from_input(via_v1);
        let arwtns_via_v1 = circuit_to_arwtns::<Fr, _>(circuit_via_v1, CurveId::Bn254, blake3)
            .unwrap_or_else(|e| panic!("V1[{}] circuit_to_arwtns(via_v1): {:?}", i, e));
        let mut bytes_via_v1 = Vec::new();
        arwtns_via_v1
            .write(&mut bytes_via_v1)
            .unwrap_or_else(|e| panic!("V1[{}] arwtns.write(via_v1): {:?}", i, e));

        let circuit_native = TestCircuit::from_input(circuit_inputs[i].clone());
        let arwtns_native = circuit_to_arwtns::<Fr, _>(circuit_native, CurveId::Bn254, blake3)
            .unwrap_or_else(|e| panic!("V1[{}] circuit_to_arwtns(native): {:?}", i, e));
        let mut bytes_native = Vec::new();
        arwtns_native
            .write(&mut bytes_native)
            .unwrap_or_else(|e| panic!("V1[{}] arwtns.write(native): {:?}", i, e));

        assert_eq!(
            bytes_via_v1, bytes_native,
            "V1[{}]: wasm-side input conversion drifted from native baseline \
             — bytes differ at the .arwtns layer",
            i,
        );
    }
}
