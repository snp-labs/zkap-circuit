//! Audit-only test: emit `cs.num_constraints()`, `cs.num_witness_variables()`,
//! and `cs.num_instance_variables()` for `ZkapCircuit::generate_mock_circuit`
//! at the dev-profile `CircuitConfig` shape.
//!
//! This supports the downgraded AC-C3.3 of `docs/audit/constraint-audit-2026-05-20.md`:
//! the audit reports a single total constraint count for the full circuit (no
//! per-Phase split — per project memory P2 #15c the phase-extraction approach
//! was rejected, and the audit-only principle forbids cfg-gated instrumentation
//! inside `src/zkap.rs`).
//!
//! Run: `cargo test --release -p circuit --test total_circuit_count -- --nocapture`

use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use circuit::{
    types::{BNP, CG, CircuitConfig},
    zkap::ZkapCircuit,
};

type F = <CG as ark_ec::CurveGroup>::BaseField;
type TestCircuit = ZkapCircuit<CG, BNP>;

/// Dev-profile config — same shape as
/// `crates/circuit/tests/groth16_integration.rs::test_params()`.
fn audit_dev_config() -> CircuitConfig {
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
        claims: vec![
            "aud".into(),
            "exp".into(),
            "iss".into(),
            "nonce".into(),
            "sub".into(),
        ],
        forbidden_string: "forbidden".into(),
    }
}

#[test]
fn total_circuit_count_dev_profile() {
    let cfg = audit_dev_config();
    let circuit = TestCircuit::generate_mock_circuit(&cfg);
    let cs = ConstraintSystem::<F>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("generate_constraints must not fail on mock witness");

    let num_constraints = cs.num_constraints();
    let num_witness = cs.num_witness_variables();
    let num_instance = cs.num_instance_variables();

    println!("=== ZkapCircuit total counts (dev profile, audit AC-C3.3) ===");
    println!("CircuitConfig: n=6, k=3, tree_height=4, max_jwt_b64_len=1024, max_payload_b64_len=640");
    println!("num_constraints       = {num_constraints}");
    println!("num_witness_variables = {num_witness}");
    println!("num_instance_variables= {num_instance}");
    println!("=============================================================");

    // Sanity checks — total must be non-trivial.
    assert_eq!(num_constraints, 911_941, "Track B PRs must not alter R1CS layout for dev-profile (n=6,k=3,tree_height=4) — see docs/audit/constraint-audit-2026-05-20.md §3.2");
    assert!(num_witness > 1000, "expected > 1000 witness vars, got {num_witness}");
    // 8 public inputs per spec; allow for arkworks's implicit ONE.
    assert!(num_instance >= 8, "expected >= 8 instance vars, got {num_instance}");
}
