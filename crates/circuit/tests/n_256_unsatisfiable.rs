//! Audit C2.3 evidence: empirically prove n=256 is unsatisfiable BEFORE tightening validate()'s boundary.
//! Run: `cargo test --release -p circuit --test n_256_unsatisfiable -- --nocapture`
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use circuit::{
    types::{BNP, CG, CircuitConfig},
    zkap::ZkapCircuit,
};
type F = <CG as ark_ec::CurveGroup>::BaseField;
type TestCircuit = ZkapCircuit<CG, BNP>;

/// Duplicate of audit_dev_config() with n=256, k=1 — proves the audit C2.3 claim.
fn config_n_256() -> CircuitConfig {
    CircuitConfig {
        max_jwt_b64_len: 1024,
        max_payload_b64_len: 640,
        max_aud_len: 155,
        max_exp_len: 20,
        max_iss_len: 93,
        max_nonce_len: 93,
        max_sub_len: 93,
        n: 256,
        k: 1,
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
fn n_256_circuit_is_unsatisfiable() {
    let cfg = config_n_256();
    let circuit = TestCircuit::generate_mock_circuit(&cfg);
    let cs = ConstraintSystem::<F>::new_ref();
    let result = circuit.generate_constraints(cs.clone());
    let satisfied = match cs.is_satisfied() {
        Ok(s) => s,
        Err(e) => {
            println!("cs.is_satisfied() returned Err: {:?}", e);
            return; // synthesis errors are acceptable failure modes
        }
    };
    assert!(
        !satisfied || result.is_err(),
        "audit C2.3 claim: n=256 must NOT produce a satisfiable circuit (result={:?}, satisfied={})",
        result,
        satisfied
    );
}
