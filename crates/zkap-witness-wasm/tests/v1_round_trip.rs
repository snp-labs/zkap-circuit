//! V1 schema round-trip equivalence test (PR2 commit 1).
//!
//! Builds the K satisfying `ZkapInputV1` payloads from the same source
//! data the existing PR1 fixtures use, drives each through
//! `ZkapInputV1::into_circuit_input` → `ZkapCircuit::from_input`, and
//! asserts that the resulting constraint system is satisfied.
//!
//! This is the strongest "V1 → ZkapCircuitInput equivalence" check
//! available without going through the wasm boundary itself; PR2 commit 3
//! tightens it further by routing the same payload through the actual
//! `wasm32` `witness_generator` export.

mod common;

use ark_ar1cs_format::CurveId;
use ark_ar1cs_wasm_witness::{witness_generator_native, WitnessGenerator};
use ark_ar1cs_wtns::ArwtnsFile;
use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
use zkap_witness_wasm::{ZkapInputV1, ZkapWitnessGenerator};

use common::{build_v1_fixture_bundle, TestCircuit, V1FixtureBundle};

/// Acceptance: every V1 payload produced from the test fixtures yields a
/// satisfying `ZkapCircuit`. Drives the circuit in `Prove` mode (the
/// witness-extraction mode used by `circuit_to_arwtns`) so the public
/// inputs and witness wires are evaluated end-to-end.
#[test]
fn v1_round_trip_satisfies_constraints() {
    let V1FixtureBundle {
        v1_inputs,
        circuit_inputs,
    } = build_v1_fixture_bundle();

    assert_eq!(
        v1_inputs.len(),
        circuit_inputs.len(),
        "V1 wire payloads and circuit-input baselines must have the same length",
    );
    assert!(!v1_inputs.is_empty(), "fixture bundle is empty");

    for (i, v1) in v1_inputs.iter().cloned().enumerate() {
        let circuit_input = v1
            .into_circuit_input()
            .unwrap_or_else(|e| panic!("V1[{}] → ZkapCircuitInput failed: {:?}", i, e));

        let circuit = TestCircuit::from_input(circuit_input);

        // Default mode = `Prove { construct_matrices: true }` so the
        // a/b/c LC tables exist and `is_satisfied()` can iterate them
        // (a `construct_matrices: false` synthesis stores witness
        // assignments only and panics inside which_is_unsatisfied).
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        circuit
            .generate_constraints(cs.clone())
            .unwrap_or_else(|e| panic!("V1[{}] generate_constraints: {:?}", i, e));

        assert!(
            cs.is_satisfied()
                .unwrap_or_else(|e| panic!("V1[{}] is_satisfied error: {:?}", i, e)),
            "V1[{}] constraint system not satisfied",
            i
        );
    }
}

/// Acceptance (PR2 commit 2): the V1 generator drives the same
/// `witness_generator_native` pipeline the wasm `witness_generator`
/// export uses — with V1 already wired to `WitnessGeneratorV1`, the
/// native helper produces an `.arwtns` blob whose blake3 binding,
/// curve_id, and instance/witness counts line up with what the V1 code
/// path is supposed to emit. Commit 3 reuses this evidence to swap the
/// wasm export to `ZkapWitnessGenerator`.
#[test]
fn v1_native_witness_generator_pipeline() {
    let bundle = build_v1_fixture_bundle();
    let v1 = bundle
        .v1_inputs
        .first()
        .expect("at least one V1 fixture")
        .clone();

    // Stand-in for the wasm `embedded` constant: any 32-byte value will
    // do because we pass `host == embedded`. Commit 4 / commit 3 wire
    // this up to the real arzkey blake3.
    let blake3 = [0xCDu8; 32];
    let postcard_bytes = postcard::to_allocvec(&v1).expect("postcard encode V1");
    let arwtns_bytes = witness_generator_native::<ZkapWitnessGenerator>(
        &postcard_bytes,
        &blake3,
        &blake3,
    )
    .expect("witness_generator_native::<V1> failed");

    assert!(!arwtns_bytes.is_empty(), "arwtns output is empty");
    let arwtns: ArwtnsFile<Fr> =
        ArwtnsFile::<Fr>::read(&mut std::io::Cursor::new(&arwtns_bytes))
            .expect("ArwtnsFile::read on V1 output");
    assert_eq!(arwtns.header.ar1cs_blake3, blake3, "blake3 binding mismatch");
    assert_eq!(
        arwtns.header.curve_id as u8,
        CurveId::Bn254 as u8,
        "curve id mismatch",
    );
    // Eight public inputs for the ZKAP circuit.
    assert_eq!(arwtns.header.num_instance, 8);
    assert_eq!(
        arwtns.instance.len(),
        ZkapWitnessGenerator::public_input_names().len(),
        "instance vector length mismatches public_input_names()",
    );
    assert!(
        arwtns.header.num_witness > 0,
        "witness section must be populated",
    );
}

/// Acceptance (PR2 fix-up): a real fixture whose `rsa_signature_be`
/// has been tampered with one bit MUST be rejected by
/// `into_circuit_input` as `SignatureMismatch` — `base64_decode(sig_b64)`
/// no longer matches the wire `rsa_signature_be`. This guards the
/// trust-boundary the PR2 fix-up established between the two redundant
/// signature sources.
#[test]
fn v1_into_circuit_input_rejects_signature_mismatch() {
    let bundle = build_v1_fixture_bundle();
    let mut v1 = bundle
        .v1_inputs
        .first()
        .expect("at least one V1 fixture")
        .clone();
    assert_eq!(v1.rsa_signature_be.len(), 256, "RSA-2048 signature");
    // Flip one bit so the wire `rsa_signature_be` no longer matches
    // `base64_decode(jwt_bytes' sig_b64)`.
    v1.rsa_signature_be[0] ^= 0x01;

    match v1.into_circuit_input() {
        Err(zkap_witness_wasm::ZkapWitnessError::SignatureMismatch(_)) => {}
        Err(other) => panic!("expected SignatureMismatch, got {:?}", other),
        Ok(_) => panic!("expected SignatureMismatch, got Ok"),
    }
}

/// Acceptance: `postcard::to_allocvec` then `from_bytes` round-trips a
/// fixture-built V1 payload byte-for-byte. Pairs the wire-format
/// stability check with a representative real payload (large RSA
/// modulus + Merkle path), not just the dummy fixture used in the lib
/// unit tests.
#[test]
fn v1_postcard_round_trip_real_fixture() {
    let bundle = build_v1_fixture_bundle();
    let v1 = bundle.v1_inputs.first().expect("at least one V1 fixture");
    let bytes = postcard::to_allocvec(v1).expect("postcard encode");
    let decoded: ZkapInputV1 = postcard::from_bytes(&bytes).expect("postcard decode");
    let bytes2 = postcard::to_allocvec(&decoded).expect("postcard re-encode");
    assert_eq!(
        bytes, bytes2,
        "real-fixture V1 payload must round-trip through postcard byte-for-byte",
    );
}
