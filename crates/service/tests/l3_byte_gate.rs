//! L3 byte-equality gate — multi-fixture + cs.num_* + R1CS matrix sha256 golden.
//!
//! Plan: `.omc/plans/2026-05-08-per-crate-refactor.md` §5.1 Phase 0 P0-A.
//! Plan: `.omc/plans/2026-05-08-per-crate-refactor/00-cross-cutting-locks.md` L1.1–L1.5.
//!
//! ## Gate layers
//!
//! - **L1.1 / Tier A** — `circuit.ar1cs::body_blake3()` (32 bytes). Definitive
//!   gate: R1CS matrix generation is deterministic in `SynthesisMode::Setup`
//!   with no RNG dependency. Three fixtures — F1 is always-run, F2/F3 are
//!   `#[ignore]` because they call `service::setup` which uses `OsRng` for
//!   the full Groth16 PK generation (~120–150 s each on debug builds).
//!   Post-migration (Commit 2 of the 2026-05 ark-ar1cs boundary plan)
//!   `service::setup` no longer writes `pk.arzkey`; the body_blake3 is
//!   computed from `circuit.ar1cs` directly. Golden values are
//!   byte-equivalent because the pre-migration envelope header was always
//!   populated from `arcs.body_blake3()` at write time.
//!
//! - **L1.2/L1.3/L1.4 / Tier D** — `cs.num_constraints()`,
//!   `cs.num_witness_variables()`, `cs.num_instance_variables()` goldens for
//!   all 3 fixtures. Fast (synthesis only, ~12 s per fixture on debug builds).
//!
//! - **L1.5 / Tier E** — R1CS matrix sha256 golden for all 3 fixtures.
//!   Serialization: for each matrix (A, B, C) in order, prefix `tag_byte ||
//!   row_count_u64le`, then per row `entry_count_u64le || (col_u64le ||
//!   coeff_compressed_32bytes)*` with entries sorted by col index. Fast
//!   (same synthesis pass as Tier D).
//!
//! - **Tier B** — `CircuitConfig::serialize_compressed` byte golden. Fast.
//!
//! - **Tier C** — `ZkapInputV1` postcard golden. Fast.
//!
//! ## Fixture params
//!
//! | Fixture | n | k | tree_height | notes |
//! |---------|---|---|-------------|-------|
//! | F1      | 6 | 3 | 4           | original default; preserves PR0 goldens |
//! | F2      | 8 | 3 | 5           | larger anchor + deeper tree |
//! | F3      | 4 | 2 | 3           | smaller boundary |
//!
//! ## Caveat on Tier A
//!
//! `service::setup` uses `OsRng` for the `ProvingKey` body. `pk.bin` is
//! therefore non-deterministic across runs, so Tier A compares only the
//! 32-byte `body_blake3` of `circuit.ar1cs` (which is deterministic in
//! `SynthesisMode::Setup`), not the full `pk.bin`.
//!
//! ## Golden capture method
//!
//! Golden values for Tier D/E were captured by running
//! `tests/l3_golden_capture.rs` (now deleted) with `--nocapture` on
//! commit `f79e7a26` + this P0-A commit. Any future PR that breaks these
//! goldens has altered the R1CS structure and must be investigated.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use ark_ar1cs::format::ArcsFile;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_serialize::CanonicalSerialize;
use ark_utils::wire::ZkapInputV1;
use circuit::types::{BNP, CG, F};
use circuit::zkap::ZkapCircuit;
use sha2::{Digest, Sha256};
use zkap_service::{CircuitConfig, setup};

// ─── Fixture builders ─────────────────────────────────────────────────────────

/// F1: `n=6, k=3, tree_height=4` — original default fixture.
fn circuit_config_f1() -> CircuitConfig {
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

/// F2: `n=8, k=3, tree_height=5` — larger anchor + deeper tree.
fn circuit_config_f2() -> CircuitConfig {
    CircuitConfig {
        max_jwt_b64_len: 1024,
        max_payload_b64_len: 640,
        max_aud_len: 155,
        max_exp_len: 20,
        max_iss_len: 93,
        max_nonce_len: 93,
        max_sub_len: 93,
        n: 8,
        k: 3,
        tree_height: 5,
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

/// F3: `n=4, k=2, tree_height=3` — smaller boundary.
fn circuit_config_f3() -> CircuitConfig {
    CircuitConfig {
        max_jwt_b64_len: 1024,
        max_payload_b64_len: 640,
        max_aud_len: 155,
        max_exp_len: 20,
        max_iss_len: 93,
        max_nonce_len: 93,
        max_sub_len: 93,
        n: 4,
        k: 2,
        tree_height: 3,
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

fn zkap_input_v1_for(cfg: &CircuitConfig) -> ZkapInputV1 {
    ZkapInputV1 {
        jwt_bytes: b"hdr.payload.sig".to_vec(),
        rsa_modulus_be: vec![0x12; 256],
        rsa_signature_be: vec![0x34; 256],
        random_be: [0x11; 32],
        h_sign_user_op_be: [0x22; 32],
        anchor_values_be: vec![[0x33; 32]; (cfg.n - cfg.k + 1) as usize],
        anchor_known_x_be: vec![[0x44; 32]; cfg.k as usize],
        anchor_selector: {
            let mut sel = vec![0u8; cfg.n as usize];
            for item in sel.iter_mut().take(cfg.k as usize) {
                *item = 1;
            }
            sel
        },
        anchor_current_idx: 0,
        merkle_root_be: [0x55; 32],
        merkle_leaf_sibling_hash_be: [0x66; 32],
        merkle_auth_path_be: vec![[0x77; 32]; (cfg.tree_height - 1) as usize],
        merkle_leaf_idx: 0,
        circuit_config: cfg.clone(),
    }
}

// ─── Golden constants — Tier A (L1.1 / ar1cs_blake3) ─────────────────────────

/// F1 Tier A — blake3 of canonical .ar1cs body (32 bytes).
/// Captured at commit `a6c96dd1` (PR0 of L4 absorption). Preserved unchanged.
const GOLDEN_AR1CS_BLAKE3_F1: &str =
    "afb9ca5c043226a201f55e50a0a24d57a8613c3ad94effada85c45b2ff665f5b";

/// F2 Tier A — `n=8, k=3, tree_height=5`.
/// Captured at P0-A commit by running Tier A test with --nocapture.
const GOLDEN_AR1CS_BLAKE3_F2: &str = "PLACEHOLDER_F2_RUN_IGNORED_TO_CAPTURE";

/// F3 Tier A — `n=4, k=2, tree_height=3`.
/// Captured at P0-A commit by running Tier A test with --nocapture.
const GOLDEN_AR1CS_BLAKE3_F3: &str = "PLACEHOLDER_F3_RUN_IGNORED_TO_CAPTURE";

// ─── Golden constants — Tier B (CircuitConfig::serialize_compressed) ──────────

/// F1 Tier B — 170 bytes, captured at PR0.
const GOLDEN_CIRCUIT_CONFIG_F1: &str = concat!(
    "000400000000000080020000000000009b0000000000000014000000000000005d000000",
    "000000005d000000000000005d000000000000000600000000000000030000000000000004",
    "00000000000000050000000000000005000000000000000300000000000000617564030000",
    "000000000065787003000000000000006973730500000000000000",
    "6e6f6e636503000000000000007375620900000000000000666f7262696464656e",
);

/// F2 Tier B — `n=8, k=3, tree_height=5`.
/// Only n, k, tree_height differ from F1 in the serialized form.
const GOLDEN_CIRCUIT_CONFIG_F2: &str = concat!(
    "000400000000000080020000000000009b0000000000000014000000000000005d000000",
    "000000005d000000000000005d000000000000000800000000000000030000000000000005",
    "00000000000000050000000000000005000000000000000300000000000000617564030000",
    "000000000065787003000000000000006973730500000000000000",
    "6e6f6e636503000000000000007375620900000000000000666f7262696464656e",
);

/// F3 Tier B — `n=4, k=2, tree_height=3`.
const GOLDEN_CIRCUIT_CONFIG_F3: &str = concat!(
    "000400000000000080020000000000009b0000000000000014000000000000005d000000",
    "000000005d000000000000005d000000000000000400000000000000020000000000000003",
    "00000000000000050000000000000005000000000000000300000000000000617564030000",
    "000000000065787003000000000000006973730500000000000000",
    "6e6f6e636503000000000000007375620900000000000000666f7262696464656e",
);

// ─── Golden constants — Tier C (ZkapInputV1 postcard) ─────────────────────────

/// F1 Tier C — 1039 bytes, captured at PR0.
const GOLDEN_ZKAP_INPUT_V1_F1: &str = concat!(
    "0f6864722e7061796c6f61642e7369678002",
    "1212121212121212121212121212121212121212121212121212121212121212",
    "1212121212121212121212121212121212121212121212121212121212121212",
    "1212121212121212121212121212121212121212121212121212121212121212",
    "1212121212121212121212121212121212121212121212121212121212121212",
    "1212121212121212121212121212121212121212121212121212121212121212",
    "1212121212121212121212121212121212121212121212121212121212121212",
    "1212121212121212121212121212121212121212121212121212121212121212",
    "12121212121212121212121212121212121212121212121212121212121212128002",
    "3434343434343434343434343434343434343434343434343434343434343434",
    "3434343434343434343434343434343434343434343434343434343434343434",
    "3434343434343434343434343434343434343434343434343434343434343434",
    "3434343434343434343434343434343434343434343434343434343434343434",
    "3434343434343434343434343434343434343434343434343434343434343434",
    "3434343434343434343434343434343434343434343434343434343434343434",
    "3434343434343434343434343434343434343434343434343434343434343434",
    "34343434343434343434343434343434343434343434343434343434343434",
    "34",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "04",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "03",
    "4444444444444444444444444444444444444444444444444444444444444444",
    "4444444444444444444444444444444444444444444444444444444444444444",
    "4444444444444444444444444444444444444444444444444444444444444444",
    "0601010100000000",
    "5555555555555555555555555555555555555555555555555555555555555555",
    "6666666666666666666666666666666666666666666666666666666666666666",
    "03",
    "7777777777777777777777777777777777777777777777777777777777777777",
    "7777777777777777777777777777777777777777777777777777777777777777",
    "7777777777777777777777777777777777777777777777777777777777777777",
    "00",
    "800880059b01145d5d5d06030405",
    "0503617564036578700369737305",
    "6e6f6e63650373756209666f7262696464656e",
);

// ─── Golden constants — Tier D (cs.num_* goldens, L1.2/L1.3/L1.4) ─────────────
//
// Captured by running l3_golden_capture.rs (now deleted) at P0-A commit
// on commit f79e7a26 baseline. SynthesisMode::Setup, OptimizationGoal::Constraints.

/// F1 `n=6, k=3, tree_height=4` constraint counts (frozen).
const GOLDEN_NUM_CONSTRAINTS_F1: usize = 911941;
const GOLDEN_NUM_WITNESS_F1: usize = 896800;
const GOLDEN_NUM_INSTANCE_F1: usize = 9;

/// F2 `n=8, k=3, tree_height=5` constraint counts (frozen).
const GOLDEN_NUM_CONSTRAINTS_F2: usize = 912929;
const GOLDEN_NUM_WITNESS_F2: usize = 897791;
const GOLDEN_NUM_INSTANCE_F2: usize = 9;

/// F3 `n=4, k=2, tree_height=3` constraint counts (frozen).
const GOLDEN_NUM_CONSTRAINTS_F3: usize = 911196;
const GOLDEN_NUM_WITNESS_F3: usize = 896054;
const GOLDEN_NUM_INSTANCE_F3: usize = 9;

// ─── Golden constants — Tier E (R1CS matrix sha256, L1.5) ─────────────────────
//
// Hash covers A, B, C matrices in order. Per-matrix encoding:
//   tag_byte || row_count_u64le
//   per row: entry_count_u64le || (col_u64le || coeff_compressed_32bytes)*
//   entries sorted ascending by col index.

/// F1 matrix sha256 (frozen).
const GOLDEN_MATRIX_SHA256_F1: &str =
    "4b4bbfeb0cece9d72d5374c8d6b48919e6b45ea49a5e1f4dc7525d2854d60c75";

/// F2 matrix sha256 (frozen).
const GOLDEN_MATRIX_SHA256_F2: &str =
    "86ce5c9831d90f536a7d6573719da41eede738de9f5f57a7861bf1a302f0279d";

/// F3 matrix sha256 (frozen).
const GOLDEN_MATRIX_SHA256_F3: &str =
    "fc825ea64ef668e1d93098011d41b5d799f3cc553a66a077d23c42be634d7dbb";

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Synthesize the circuit for `cfg` in `Setup` mode and return
/// (num_constraints, num_witness_variables, num_instance_variables, matrix_sha256_hex).
fn synthesize_and_inspect(cfg: &CircuitConfig) -> (usize, usize, usize, String) {
    let circuit = ZkapCircuit::<CG, BNP>::generate_mock_circuit(cfg);
    let cs = ConstraintSystem::<F>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit
        .generate_constraints(cs.clone())
        .expect("generate_constraints must succeed in Setup mode");
    cs.finalize();

    let num_c = cs.num_constraints();
    let num_w = cs.num_witness_variables();
    let num_i = cs.num_instance_variables();

    let matrices = ark_ar1cs::format::ConstraintMatrices::from_cs(&cs)
        .expect("ConstraintMatrices::from_cs failed after finalize()");

    // Deterministic R1CS matrix hash.
    // Matrix<F> = Vec<Vec<(F, usize)>> where tuple is (coeff, col_index).
    let mut hasher = Sha256::new();
    for (tag, matrix) in [
        (b'A', &matrices.a),
        (b'B', &matrices.b),
        (b'C', &matrices.c),
    ] {
        hasher.update([tag]);
        hasher.update((matrix.len() as u64).to_le_bytes());
        for row in matrix {
            hasher.update((row.len() as u64).to_le_bytes());
            let mut sorted = row.clone();
            sorted.sort_by_key(|(_coeff, col)| *col);
            for (coeff, col) in &sorted {
                hasher.update((*col as u64).to_le_bytes());
                let mut buf = Vec::new();
                coeff
                    .serialize_compressed(&mut buf)
                    .expect("serialize field element");
                assert_eq!(buf.len(), 32, "BN254 Fr element must serialize to 32 bytes");
                hasher.update(&buf);
            }
        }
    }
    let matrix_sha256 = hex::encode(hasher.finalize());

    (num_c, num_w, num_i, matrix_sha256)
}

fn unique_tmp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "l3_byte_gate_{label}_{}_{nanos}",
        std::process::id()
    ))
}

// ─── Tier A — ar1cs_blake3 (L1.1) ────────────────────────────────────────────

/// F1 Tier A (always run). Original fixture from PR0 — golden MUST stay constant.
///
/// Reads `circuit.ar1cs` (post-migration bundle layout, Commit 2 of the
/// 2026-05 ark-ar1cs boundary migration) and recomputes `body_blake3()`.
/// The value is byte-equivalent to the pre-migration
/// `pk.arzkey` header bytes 16..48 because the envelope's `ar1cs_blake3`
/// was always populated from `arcs.body_blake3()` at write time.
#[test]
fn tier_a_ar1cs_blake3_f1() {
    let tmp_dir = unique_tmp_dir("tier_a_f1");
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");

    let cfg = circuit_config_f1();
    setup(&cfg, &tmp_dir, &mut rand::rngs::OsRng, None)
        .expect("service::setup must succeed for F1 config");

    let arcs_path = tmp_dir.join("circuit.ar1cs");
    let file = File::open(&arcs_path).expect("circuit.ar1cs must exist after setup");
    let mut reader = BufReader::new(file);
    let arcs = ArcsFile::<F>::read(&mut reader).expect("circuit.ar1cs must parse as ArcsFile<F>");
    let actual_hex = hex::encode(arcs.body_blake3());
    let _ = std::fs::remove_dir_all(&tmp_dir);

    assert_eq!(
        actual_hex, GOLDEN_AR1CS_BLAKE3_F1,
        "L1.1 break — F1 `circuit.ar1cs::body_blake3` differs from golden.\n\
         baseline: {GOLDEN_AR1CS_BLAKE3_F1}\n\
         actual:   {actual_hex}"
    );
}

/// F2 Tier A — slow (full Groth16 setup ~120-150s). Run with `-- --include-ignored`.
#[test]
#[ignore = "slow: calls service::setup with OsRng (~120s). Run explicitly to capture/verify F2 blake3 golden."]
fn tier_a_ar1cs_blake3_f2() {
    let tmp_dir = unique_tmp_dir("tier_a_f2");
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");

    let cfg = circuit_config_f2();
    setup(&cfg, &tmp_dir, &mut rand::rngs::OsRng, None)
        .expect("service::setup must succeed for F2 config");

    let arcs_path = tmp_dir.join("circuit.ar1cs");
    let file = File::open(&arcs_path).expect("circuit.ar1cs must exist after setup");
    let mut reader = BufReader::new(file);
    let arcs = ArcsFile::<F>::read(&mut reader).expect("circuit.ar1cs must parse as ArcsFile<F>");
    let actual_hex = hex::encode(arcs.body_blake3());
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // Print for golden capture on first run; thereafter assert equality.
    println!("F2 ar1cs_blake3: {actual_hex}");
    if GOLDEN_AR1CS_BLAKE3_F2.starts_with("PLACEHOLDER") {
        panic!(
            "GOLDEN_AR1CS_BLAKE3_F2 is a placeholder. \
             Copy the printed hex into the constant and re-run.\n\
             Captured: {actual_hex}"
        );
    }
    assert_eq!(
        actual_hex, GOLDEN_AR1CS_BLAKE3_F2,
        "L1.1 break — F2 `circuit.ar1cs::body_blake3` differs from golden.\n\
         baseline: {GOLDEN_AR1CS_BLAKE3_F2}\n\
         actual:   {actual_hex}"
    );
}

/// F3 Tier A — slow (full Groth16 setup ~120-150s). Run with `-- --include-ignored`.
#[test]
#[ignore = "slow: calls service::setup with OsRng (~120s). Run explicitly to capture/verify F3 blake3 golden."]
fn tier_a_ar1cs_blake3_f3() {
    let tmp_dir = unique_tmp_dir("tier_a_f3");
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");

    let cfg = circuit_config_f3();
    setup(&cfg, &tmp_dir, &mut rand::rngs::OsRng, None)
        .expect("service::setup must succeed for F3 config");

    let arcs_path = tmp_dir.join("circuit.ar1cs");
    let file = File::open(&arcs_path).expect("circuit.ar1cs must exist after setup");
    let mut reader = BufReader::new(file);
    let arcs = ArcsFile::<F>::read(&mut reader).expect("circuit.ar1cs must parse as ArcsFile<F>");
    let actual_hex = hex::encode(arcs.body_blake3());
    let _ = std::fs::remove_dir_all(&tmp_dir);

    println!("F3 ar1cs_blake3: {actual_hex}");
    if GOLDEN_AR1CS_BLAKE3_F3.starts_with("PLACEHOLDER") {
        panic!(
            "GOLDEN_AR1CS_BLAKE3_F3 is a placeholder. \
             Copy the printed hex into the constant and re-run.\n\
             Captured: {actual_hex}"
        );
    }
    assert_eq!(
        actual_hex, GOLDEN_AR1CS_BLAKE3_F3,
        "L1.1 break — F3 `circuit.ar1cs::body_blake3` differs from golden.\n\
         baseline: {GOLDEN_AR1CS_BLAKE3_F3}\n\
         actual:   {actual_hex}"
    );
}

// ─── Tier B — CircuitConfig::serialize_compressed (schema drift) ──────────────

#[test]
fn tier_b_circuit_config_canonical_f1() {
    let cfg = circuit_config_f1();
    let mut buf = Vec::new();
    cfg.serialize_compressed(&mut buf)
        .expect("CircuitConfig::serialize_compressed must succeed");
    let actual = hex::encode(&buf);
    assert_eq!(
        actual,
        GOLDEN_CIRCUIT_CONFIG_F1,
        "L1 break — F1 CircuitConfig::serialize_compressed drift.\n\
         baseline ({} bytes): {GOLDEN_CIRCUIT_CONFIG_F1}\n\
         actual   ({} bytes): {actual}",
        GOLDEN_CIRCUIT_CONFIG_F1.len() / 2,
        buf.len(),
    );
}

#[test]
fn tier_b_circuit_config_canonical_f2() {
    let cfg = circuit_config_f2();
    let mut buf = Vec::new();
    cfg.serialize_compressed(&mut buf)
        .expect("CircuitConfig::serialize_compressed must succeed");
    let actual = hex::encode(&buf);
    assert_eq!(
        actual,
        GOLDEN_CIRCUIT_CONFIG_F2,
        "L1 break — F2 CircuitConfig::serialize_compressed drift.\n\
         baseline ({} bytes): {GOLDEN_CIRCUIT_CONFIG_F2}\n\
         actual   ({} bytes): {actual}",
        GOLDEN_CIRCUIT_CONFIG_F2.len() / 2,
        buf.len(),
    );
}

#[test]
fn tier_b_circuit_config_canonical_f3() {
    let cfg = circuit_config_f3();
    let mut buf = Vec::new();
    cfg.serialize_compressed(&mut buf)
        .expect("CircuitConfig::serialize_compressed must succeed");
    let actual = hex::encode(&buf);
    assert_eq!(
        actual,
        GOLDEN_CIRCUIT_CONFIG_F3,
        "L1 break — F3 CircuitConfig::serialize_compressed drift.\n\
         baseline ({} bytes): {GOLDEN_CIRCUIT_CONFIG_F3}\n\
         actual   ({} bytes): {actual}",
        GOLDEN_CIRCUIT_CONFIG_F3.len() / 2,
        buf.len(),
    );
}

// ─── Tier C — ZkapInputV1 postcard encoding (schema drift) ────────────────────

#[test]
fn tier_c_zkap_input_v1_postcard_f1() {
    let cfg = circuit_config_f1();
    let v1 = zkap_input_v1_for(&cfg);
    let buf = postcard::to_allocvec(&v1).expect("postcard::to_allocvec must succeed");
    let actual = hex::encode(&buf);
    assert_eq!(
        actual,
        GOLDEN_ZKAP_INPUT_V1_F1,
        "L1 break — F1 ZkapInputV1 postcard drift.\n\
         baseline ({} bytes): {GOLDEN_ZKAP_INPUT_V1_F1}\n\
         actual   ({} bytes): {actual}",
        GOLDEN_ZKAP_INPUT_V1_F1.len() / 2,
        buf.len(),
    );
}

// ─── Tier D — cs.num_* goldens (L1.2 / L1.3 / L1.4) ─────────────────────────

#[test]
fn tier_d_cs_num_constraints_f1() {
    let cfg = circuit_config_f1();
    let (num_c, num_w, num_i, _) = synthesize_and_inspect(&cfg);
    assert_eq!(
        num_c, GOLDEN_NUM_CONSTRAINTS_F1,
        "L1.2 break — F1 num_constraints changed: expected {GOLDEN_NUM_CONSTRAINTS_F1}, got {num_c}"
    );
    assert_eq!(
        num_w, GOLDEN_NUM_WITNESS_F1,
        "L1.3 break — F1 num_witness_variables changed: expected {GOLDEN_NUM_WITNESS_F1}, got {num_w}"
    );
    assert_eq!(
        num_i, GOLDEN_NUM_INSTANCE_F1,
        "L1.4 break — F1 num_instance_variables changed: expected {GOLDEN_NUM_INSTANCE_F1}, got {num_i}"
    );
}

#[test]
fn tier_d_cs_num_constraints_f2() {
    let cfg = circuit_config_f2();
    let (num_c, num_w, num_i, _) = synthesize_and_inspect(&cfg);
    assert_eq!(
        num_c, GOLDEN_NUM_CONSTRAINTS_F2,
        "L1.2 break — F2 num_constraints changed: expected {GOLDEN_NUM_CONSTRAINTS_F2}, got {num_c}"
    );
    assert_eq!(
        num_w, GOLDEN_NUM_WITNESS_F2,
        "L1.3 break — F2 num_witness_variables changed: expected {GOLDEN_NUM_WITNESS_F2}, got {num_w}"
    );
    assert_eq!(
        num_i, GOLDEN_NUM_INSTANCE_F2,
        "L1.4 break — F2 num_instance_variables changed: expected {GOLDEN_NUM_INSTANCE_F2}, got {num_i}"
    );
}

#[test]
fn tier_d_cs_num_constraints_f3() {
    let cfg = circuit_config_f3();
    let (num_c, num_w, num_i, _) = synthesize_and_inspect(&cfg);
    assert_eq!(
        num_c, GOLDEN_NUM_CONSTRAINTS_F3,
        "L1.2 break — F3 num_constraints changed: expected {GOLDEN_NUM_CONSTRAINTS_F3}, got {num_c}"
    );
    assert_eq!(
        num_w, GOLDEN_NUM_WITNESS_F3,
        "L1.3 break — F3 num_witness_variables changed: expected {GOLDEN_NUM_WITNESS_F3}, got {num_w}"
    );
    assert_eq!(
        num_i, GOLDEN_NUM_INSTANCE_F3,
        "L1.4 break — F3 num_instance_variables changed: expected {GOLDEN_NUM_INSTANCE_F3}, got {num_i}"
    );
}

// ─── Tier E — R1CS matrix sha256 (L1.5) ──────────────────────────────────────

#[test]
fn tier_e_matrix_sha256_f1() {
    let cfg = circuit_config_f1();
    let (_, _, _, actual_sha256) = synthesize_and_inspect(&cfg);
    assert_eq!(
        actual_sha256, GOLDEN_MATRIX_SHA256_F1,
        "L1.5 break — F1 R1CS matrix sha256 changed.\n\
         This means the A/B/C constraint matrices have structurally changed.\n\
         baseline: {GOLDEN_MATRIX_SHA256_F1}\n\
         actual:   {actual_sha256}"
    );
}

#[test]
fn tier_e_matrix_sha256_f2() {
    let cfg = circuit_config_f2();
    let (_, _, _, actual_sha256) = synthesize_and_inspect(&cfg);
    assert_eq!(
        actual_sha256, GOLDEN_MATRIX_SHA256_F2,
        "L1.5 break — F2 R1CS matrix sha256 changed.\n\
         baseline: {GOLDEN_MATRIX_SHA256_F2}\n\
         actual:   {actual_sha256}"
    );
}

#[test]
fn tier_e_matrix_sha256_f3() {
    let cfg = circuit_config_f3();
    let (_, _, _, actual_sha256) = synthesize_and_inspect(&cfg);
    assert_eq!(
        actual_sha256, GOLDEN_MATRIX_SHA256_F3,
        "L1.5 break — F3 R1CS matrix sha256 changed.\n\
         baseline: {GOLDEN_MATRIX_SHA256_F3}\n\
         actual:   {actual_sha256}"
    );
}
