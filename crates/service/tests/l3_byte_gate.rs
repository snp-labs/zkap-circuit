//! L3 byte-equality gate fixture (PR0 of L4 zkap-input-types absorption).
//!
//! Plan: `.omc/plans/2026-05-07-l4-zkap-input-types-absorption.md` §6.1 PR0.
//!
//! Three deterministic tiers freeze byte-level invariants that the L4
//! crate-absorption refactor MUST preserve:
//!
//! - **Tier A** — `arzkey.header.ar1cs_blake3` (32 bytes, header offset
//!   16..48, definition `ark-ar1cs-zkey/src/header.rs:41`). This is the
//!   blake3 of the canonical `.ar1cs` body and is the **definitive L3
//!   gate**: R1CS matrix generation in `service::setup` runs in
//!   `SynthesisMode::Setup` with no RNG dependency, so this 32-byte
//!   field is deterministic across runs and across the absorption.
//!
//! - **Tier B** — `CircuitConfig::serialize_compressed` full hex.
//!   Detects derive-macro re-evaluation drift on the V1 wire schema.
//!
//! - **Tier C** — `ZkapInputV1` postcard `to_allocvec` full hex.
//!   Detects schema drift on the host→wasm payload type.
//!
//! Caveat: `service::setup` uses `OsRng` for the `ProvingKey` body
//! (`crates/service/src/proof/mod.rs:60`). The PK region of `.arzkey`
//! is therefore non-deterministic, so this fixture compares only the
//! 32-byte header field, not the full file.
//!
//! After capturing golden hex in PR0, the same 3 tiers must continue to
//! match at PR1 head (post-absorption). A mismatch indicates an L3 break.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use ark_ar1cs_zkey::ArzkeyHeader;
use ark_serialize::CanonicalSerialize;
use ark_utils::wire::ZkapInputV1;
use zkap_service::{setup, CircuitConfig};

// ─── Fixture inputs (frozen) ──────────────────────────────────────────

fn fixed_circuit_config() -> CircuitConfig {
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

fn fixed_zkap_input_v1(cfg: &CircuitConfig) -> ZkapInputV1 {
    ZkapInputV1 {
        jwt_bytes: b"hdr.payload.sig".to_vec(),
        rsa_modulus_be: vec![0x12; 256],
        rsa_signature_be: vec![0x34; 256],
        random_be: [0x11; 32],
        h_sign_user_op_be: [0x22; 32],
        anchor_values_be: vec![[0x33; 32]; (cfg.n - cfg.k + 1) as usize],
        anchor_known_x_be: vec![[0x44; 32]; cfg.k as usize],
        anchor_selector: vec![1, 1, 1, 0, 0, 0],
        anchor_current_idx: 0,
        merkle_root_be: [0x55; 32],
        merkle_leaf_sibling_hash_be: [0x66; 32],
        merkle_auth_path_be: vec![[0x77; 32]; (cfg.tree_height - 1) as usize],
        merkle_leaf_idx: 0,
        circuit_config: cfg.clone(),
    }
}

// ─── Golden hex (frozen in PR0; must match PR1 post-absorption) ───────

/// Tier A — blake3 of canonical .ar1cs body (32 bytes).
/// Captured from `service::setup(&fixed_circuit_config(), ...)` at
/// branch `refactor/dto-consolidation-pr1` (commit 053e58b2).
const GOLDEN_AR1CS_BLAKE3_HEX: &str =
    "afb9ca5c043226a201f55e50a0a24d57a8613c3ad94effada85c45b2ff665f5b";

/// Tier B — `CircuitConfig::serialize_compressed` full output (170 bytes).
const GOLDEN_CIRCUIT_CONFIG_HEX: &str = concat!(
    "000400000000000080020000000000009b0000000000000014000000000000005d000000",
    "000000005d000000000000005d000000000000000600000000000000030000000000000004",
    "00000000000000050000000000000005000000000000000300000000000000617564030000",
    "000000000065787003000000000000006973730500000000000000",
    "6e6f6e636503000000000000007375620900000000000000666f7262696464656e",
);

/// Tier C — `ZkapInputV1` postcard `to_allocvec` full output (1039 bytes).
const GOLDEN_ZKAP_INPUT_V1_POSTCARD_HEX: &str = concat!(
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

// ─── Tier A ───────────────────────────────────────────────────────────

#[test]
fn tier_a_ar1cs_blake3() {
    // Setup writes pk.arzkey to a temp directory. We re-open it and
    // read only the 32-byte ar1cs_blake3 field from the header.
    let tmp_dir = unique_tmp_dir("tier_a");
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");

    let cfg = fixed_circuit_config();
    setup(&cfg, &tmp_dir).expect("service::setup must succeed for fixed config");

    let arzkey_path = tmp_dir.join("pk.arzkey");
    let file = File::open(&arzkey_path).expect("pk.arzkey must exist after setup");
    let mut reader = BufReader::new(file);
    let header = ArzkeyHeader::read(&mut reader).expect("ArzkeyHeader must parse");

    let actual_hex = hex::encode(header.ar1cs_blake3);

    // Cleanup temp directory regardless of assertion outcome.
    let _ = std::fs::remove_dir_all(&tmp_dir);

    assert_eq!(
        actual_hex, GOLDEN_AR1CS_BLAKE3_HEX,
        "L3 break — `arzkey.header.ar1cs_blake3` (32 bytes, header offset 16..48) \
         differs from the golden hex captured in PR0. \
         R1CS constraint generation has shifted; .arzkey artifacts produced \
         from this branch will NOT verify against pre-existing artifacts. \
         Investigate before merging.\n\
         baseline: {GOLDEN_AR1CS_BLAKE3_HEX}\n\
         actual:   {actual_hex}"
    );
}

// ─── Tier B ───────────────────────────────────────────────────────────

#[test]
fn tier_b_circuit_config_canonical() {
    let cfg = fixed_circuit_config();
    let mut buf = Vec::new();
    cfg.serialize_compressed(&mut buf)
        .expect("CircuitConfig::serialize_compressed must succeed");
    let actual_hex = hex::encode(&buf);

    assert_eq!(
        actual_hex, GOLDEN_CIRCUIT_CONFIG_HEX,
        "L3 break — `CircuitConfig::serialize_compressed` byte output \
         differs from the golden hex captured in PR0. \
         derive(CanonicalSerialize) macro re-evaluation has shifted layout.\n\
         baseline ({} bytes): {GOLDEN_CIRCUIT_CONFIG_HEX}\n\
         actual   ({} bytes): {actual_hex}",
        GOLDEN_CIRCUIT_CONFIG_HEX.len() / 2,
        buf.len(),
    );
}

// ─── Tier C ───────────────────────────────────────────────────────────

#[test]
fn tier_c_zkap_input_v1_postcard() {
    let cfg = fixed_circuit_config();
    let v1 = fixed_zkap_input_v1(&cfg);
    let buf = postcard::to_allocvec(&v1).expect("postcard::to_allocvec must succeed");
    let actual_hex = hex::encode(&buf);

    assert_eq!(
        actual_hex, GOLDEN_ZKAP_INPUT_V1_POSTCARD_HEX,
        "L3 break — `ZkapInputV1` postcard byte output differs from \
         the golden hex captured in PR0. \
         Schema drift on the host→wasm payload type.\n\
         baseline ({} bytes): {GOLDEN_ZKAP_INPUT_V1_POSTCARD_HEX}\n\
         actual   ({} bytes): {actual_hex}",
        GOLDEN_ZKAP_INPUT_V1_POSTCARD_HEX.len() / 2,
        buf.len(),
    );
}

// ─── Helpers ──────────────────────────────────────────────────────────

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
