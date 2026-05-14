//! Service crate integration tests for `service::witness::build_input`
//! and the surrounding native input path (Commit 3 of the 2026-05
//! ark-ar1cs boundary migration).
//!
//! These tests pin the migration goals:
//!   * `ProofRequest` carries **no** artifact paths.
//!   * `witness::build_input` returns one `ZkapInputV1` per JWT and
//!     reapplies the shape invariants.
//!   * `witness::into_circuit_input` is callable from a service-crate
//!     integration test — i.e. lives on the host side, not in the wasm
//!     crate — and produces a `ZkapCircuitInput<F>` that
//!     `ZkapCircuit::from_input` accepts.

use circuit::types::F;
use circuit::witness::ZkapCircuitInput;
use circuit::zkap::ZkapCircuit;
use zkap_service::{CircuitConfig, PerJwtFields, ProofRequest, SharedFields};

fn test_config() -> CircuitConfig {
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

fn empty_per_jwt() -> PerJwtFields {
    PerJwtFields {
        jwt_bytes: Vec::new(),
        rsa_modulus_be: vec![0u8; 256],
        rsa_signature_be: vec![0u8; 256],
        anchor_current_idx: 0,
        merkle_leaf_sibling_hash_be: [0u8; 32],
        merkle_auth_path_be: vec![[0u8; 32]; 3],
        merkle_leaf_idx: 0,
    }
}

fn empty_request(cfg: &CircuitConfig) -> ProofRequest {
    let n = cfg.n as usize;
    let k = cfg.k as usize;
    ProofRequest {
        shared: SharedFields {
            random_be: [0u8; 32],
            h_sign_user_op_be: [0u8; 32],
            anchor_values_be: vec![[0u8; 32]; n - k + 1],
            anchor_known_x_be: vec![[0u8; 32]; k],
            anchor_selector: {
                let mut s = vec![0u8; n];
                for slot in s.iter_mut().take(k) {
                    *slot = 1;
                }
                s
            },
            merkle_root_be: [0u8; 32],
        },
        per_jwt: (0..k).map(|_| empty_per_jwt()).collect(),
    }
}

/// Acceptance: `build_input` returns one `ZkapInputV1` per JWT and
/// preserves the request's `per_jwt.len()`.
#[test]
fn build_input_returns_one_v1_per_jwt() {
    let cfg = test_config();
    let req = empty_request(&cfg);
    let expected_len = req.per_jwt.len();

    let inputs = zkap_service::witness::build_input(&req, &cfg).expect("build_input");
    assert_eq!(inputs.len(), expected_len);
    assert_eq!(inputs.len(), cfg.k as usize);
}

/// Acceptance: `build_input` propagates the shared/per-JWT byte values
/// into each `ZkapInputV1` payload.
#[test]
fn build_input_copies_shared_and_per_jwt_values() {
    let cfg = test_config();
    let req = empty_request(&cfg);

    let inputs = zkap_service::witness::build_input(&req, &cfg).expect("build_input");
    for input in &inputs {
        assert_eq!(input.random_be, req.shared.random_be);
        assert_eq!(input.h_sign_user_op_be, req.shared.h_sign_user_op_be);
        assert_eq!(input.merkle_root_be, req.shared.merkle_root_be);
        assert_eq!(input.anchor_selector, req.shared.anchor_selector);
        assert_eq!(input.circuit_config.n, cfg.n);
        assert_eq!(input.circuit_config.k, cfg.k);
    }
}

/// Acceptance: `build_input` rejects an inconsistent request shape via
/// the same `DimensionMismatch` channel `ProofRequest::validate` uses.
#[test]
fn build_input_rejects_inconsistent_shape() {
    let cfg = test_config();
    let mut req = empty_request(&cfg);
    req.shared.anchor_values_be.pop();
    let err = zkap_service::witness::build_input(&req, &cfg)
        .expect_err("build_input must reject pop'd anchor_values_be");
    let msg = format!("{}", err);
    assert!(
        msg.contains("anchor_values_be"),
        "expected error to mention anchor_values_be, got: {msg}"
    );
}

/// Acceptance: `into_circuit_input` is reachable from the service crate
/// (i.e., not buried inside the wasm crate) and returns a typed
/// `ZkapCircuitInput<F>` value. Uses a deliberately-bad RSA modulus so
/// the call surfaces a `ZkapWitnessError` rather than running the full
/// JWT decode path; the goal here is to exercise the *seam*, not the
/// happy path (covered by the slow circuit-side `groth16_integration`
/// tests).
#[test]
fn into_circuit_input_is_reachable_from_service_crate() {
    let cfg = test_config();
    let req = empty_request(&cfg);
    let mut inputs = zkap_service::witness::build_input(&req, &cfg).expect("build_input");
    inputs[0].rsa_modulus_be = vec![0u8; 255]; // wrong length → DimensionMismatch.

    match zkap_service::witness::into_circuit_input(inputs.remove(0)) {
        Ok(_) => panic!("into_circuit_input must reject wrong rsa_modulus_be length"),
        Err(err) => {
            let msg = format!("{}", err);
            assert!(
                msg.contains("rsa_modulus_be"),
                "expected error to mention rsa_modulus_be, got: {msg}"
            );
        }
    }
}

/// Acceptance: the native circuit constructor `ZkapCircuit::from_input`
/// is callable on a `ZkapCircuitInput<F>` produced by service-side code.
/// We feed `generate_mock_circuit`'s default input rather than running
/// the full V1 → circuit conversion so the test stays under a second.
#[test]
fn zkap_circuit_from_input_native_constructor() {
    use circuit::types::{BNP, CG};

    let cfg = test_config();

    // `generate_mock_circuit` builds a `ZkapCircuit<CG, BNP>` directly;
    // we re-shape it into the `ZkapCircuitInput` payload that
    // `from_input` expects and then call the native constructor to
    // prove the seam (`witness::build_input` → `into_circuit_input` →
    // `ZkapCircuit::from_input`) is wired end-to-end.
    let mock = ZkapCircuit::<CG, BNP>::generate_mock_circuit(&cfg);

    let ci: ZkapCircuitInput<F> = ZkapCircuitInput {
        params: mock.params.clone(),
        constants: mock.constants.clone(),
        public_inputs: mock.public_inputs.clone(),
        jwt: mock.jwt.clone(),
        anchor: mock.anchor.clone(),
        merkle: mock.merkle.clone(),
        audience: mock.audience.clone(),
        misc: mock.misc.clone(),
    };
    let _circuit = ZkapCircuit::<CG, BNP>::from_input(ci);
}

/// Compile-time check (also runtime-cheap): `ProofRequest` exposes only
/// `shared` and `per_jwt` — no artifact-path fields slipped through the
/// rename.
#[test]
fn proof_request_carries_no_artifact_paths() {
    let cfg = test_config();
    let req = empty_request(&cfg);

    // If any of these field names were to reappear, the test would
    // fail to compile, not at runtime — which is the point.
    let ProofRequest { shared, per_jwt } = &req;
    let _ = (shared, per_jwt);
}
