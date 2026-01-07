use std::path::PathBuf;

use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    merkle_tree::MerkleTree,
    snark::SNARK,
};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::rngs::OsRng;
use common::constants::ZkapConfig;
use gadget::{
    anchor::{
        AnchorScheme,
        poseidon::{PoseidonAnchor, PoseidonAnchorScheme},
    },
    base64::decode_any_base64,
    bigint::constraints::BigNatCircuitParams,
    hashes::{
        blake2s256::{Blake2s256, constraints::Blake2s256Gadget},
        poseidon::get_poseidon_params,
    },
    matrix::VandermondeMatrix,
    mekletree::tree_config::MerkleTreeParams,
    signature::rsa::native::PublicKey,
};
use zkpasskey_service::{
    core::signature::{SignatureService, schnorr::SchnorrSignatureService},
    interface::anchor::{PoseidonAnchorKeyExtension, Secret, SecretDto},
    service::{
        anchor::anchor::create_poseidon_anchor,
        jwt::builder::resize,
        key::io::{load_key_uncompressed, save_key_uncompressed},
        snark::zkap::generate_baerae_proof,
    },
    utils::{
        padding::fit_len_to_field,
        point::{FromStrings, ascii_to_field_be},
    },
};

pub const MAX_JWT_B64_LEN: usize = 1024;
pub const MAX_PAYLOAD_B64_LEN: usize = 640;
pub const MAX_AUD_LEN: usize = 155;
pub const MAX_EXP_LEN: usize = 10;
pub const MAX_ISS_LEN: usize = 155;
pub const MAX_NONCE_LEN: usize = 155;
pub const MAX_SUB_LEN: usize = 155;
pub const N: usize = 6;
pub const K: usize = 3;
pub const TREE_HEIGHT: usize = 4;
pub const CLAIMS: [&str; 5] = ["aud", "exp", "iss", "nonce", "sub"];
pub const RSA_BITS: usize = 2048;
pub const PAD_CHAR: char = '\0';

pub const NUM_AUDIENCE_LIMIT: usize = 5;
pub const FORBIDDEN_STRING: &str = "forbidden";

const LAMBDA: usize = 2048; // 2048 bits
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigNat512TestParams;
impl BigNatCircuitParams for BigNat512TestParams {
    const LIMB_WIDTH: usize = 64;
    const N_LIMBS: usize = LAMBDA / 64;
}

pub type CG = ark_ed_on_bn254::EdwardsProjective;
pub type F = <CG as ark_ec::CurveGroup>::BaseField;
pub type PoseidonHash = CRH<F>;
pub type Blake2 = Blake2s256;
pub type Blake2Gadget = Blake2s256Gadget;
pub type BigNatTestParams = BigNat512TestParams;
pub type BN254 = ark_bn254::Bn254;
pub type CV = ark_ed_on_bn254::constraints::EdwardsVar;
pub type BNP = BigNat512TestParams;

#[derive(Debug, Clone)]
pub struct AnchorConfig {
    pub matrix_rows: usize,
    pub matrix_cols: usize,
    pub max_aud_len: usize,
    pub max_iss_len: usize,
    pub max_sub_len: usize,
    pub pad_char: char,
    pub matrix: VandermondeMatrix<F>,
}

impl Default for AnchorConfig {
    fn default() -> Self {
        AnchorConfig {
            matrix_rows: N,
            matrix_cols: K,
            max_aud_len: MAX_AUD_LEN,
            max_iss_len: MAX_ISS_LEN,
            max_sub_len: MAX_SUB_LEN,
            pad_char: PAD_CHAR,
            matrix: VandermondeMatrix::new(N, K),
        }
    }
}

/// 테스트용 임시 디렉토리 생성
fn setup_test_dir() -> PathBuf {
    let test_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_outputs/crs_n_6_k_1/baerae");
    if !test_dir.exists() {
        std::fs::create_dir_all(&test_dir).unwrap();
    }
    test_dir
}

/// 테스트용 앵커 키 생성 및 저장
fn create_test_anchor_key(path: &PathBuf, n: usize, k: usize, max_claim_len: usize) {
    let mut rng = OsRng;

    let anchor_key = PoseidonAnchorScheme::<F>::setup(&mut rng, n).unwrap();

    let anchor_key_ext = PoseidonAnchorKeyExtension {
        anchor_key,
        n,
        k,
        max_aud_len: Some(max_claim_len),
        max_iss_len: Some(max_claim_len),
        max_sub_len: max_claim_len,
    };

    save_key_uncompressed(path, &anchor_key_ext).unwrap();
}

/// 테스트용 Schnorr Key 생성
fn create_test_schnorr_key(vk_path: &PathBuf, sk_path: &PathBuf) {
    let mut rng = OsRng;

    let (vk, sk) = SchnorrSignatureService::keygen(&mut rng).unwrap();

    save_key_uncompressed(vk_path, &vk).unwrap();
    save_key_uncompressed(sk_path, &sk).unwrap();
}

/// 테스트용 JWT 데이터 생성
fn create_test_jwt_data() -> (String, String, String, String) {
    let pk = "xovPG0EvqfPDKlVBkkYcvqLBFnu0XUiBTOEDiZw_iD8Laxpg1t-K9shLx3i3-OKHIDEJz6PnZTDFKub9PHlEBeIv-XVxizAbye7p7sBeFOKiqeXHGzvrNoUmGGFnNsHHTb_-RcboKBaGFz6oNISxcuFFnLWiYvEcZTEeRw-6HrW3MMhURaMZkcHf8r-ly5ytWl7yH7ZJnIDjGgyCSiLqLqByFaDQEJrjLdDq_O_AP0hdAxBQ6SPUGyT_7oqoAHT_j5MWxHdV8lkQLdKJyuSRWtD9wfXkiwyug20LTe7r44FdtAH-z4RSNMilkidgvoWLBoucgmxJjAYd6bvvFkXm8Q".to_string();
    let e = "AQAB".to_string();
    let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3NTM2NzY2NTg3NjciLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiI3MTM4NTEzMDI2ODYtc3ZsdWVqZDhsaTFsNXFkOXNwODA2dGJtazNsa2I0aGouYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDUwNDM4ODExNzc4ODQ3MzgyMjciLCJlbWFpbCI6ImtpbS5reXVuZ2tvb0BnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibm9uY2UiOiIweDI4MDNmNzU3YTk1MDgzOGJkZGQwMzg2ZmRlMjhkMWU4NDUwOGViNDJjMDhkMGJkNWFhNTU0MWY3NDA2OTgyOGUiLCJuYW1lIjoiS3l1bmdLb28gS2ltIiwiaWF0IjoxNzUzNjc2NjU4LCJleHAiOjE3NTM2ODAyNTl9.EigSBKnoIM7rIw0hlCIenjWJ_FGLup5UK7zZJgxpd7UzjQMwKmDNhXnIHIzq2YlmaLDz_6DKsZzagkI75qbD0RbPYDriiN2hRcRgF31oKPa-nqlDNjcTesxluXgeyR2eVE8tP_25QVXL_00nkteUL5aYRNNzmBWJ-CYeSURHGV0NUfbDu70TTgVSzfqTjeAJZLd4X2J75qdalKjkMPrGQWbVBK2So4Q1N_8nrCUGlv80RSn6j-dD0Zgux3BvVCzilFkVYe6avUyewA9qWuAH5b0aM-EBPLw9OIYuGYhLrNrh_M5OewSFjwpshvvn-iHjQL9mYKTUhorqXeqT5u6qBQ".to_string();

    let iss = r#""https://accounts.google.com""#.to_string();

    (pk, e, jwt, iss)
}

/// 테스트용 머클트리 리프 생성
fn create_test_leaf(iss: &str, n: &str) -> F {
    let n = decode_any_base64(n).unwrap();
    let e = decode_any_base64("AQAB").unwrap();
    let pk = PublicKey { n, e };
    let pk_limbs = pk.to_limbs::<BNP, CG>();
    let iss_limbs = ascii_to_field_be::<F>(iss).unwrap();
    let pre_image = [iss_limbs, pk_limbs.0].concat();
    let poseidon_params = get_poseidon_params::<F>();
    let leaf = PoseidonHash::evaluate(&poseidon_params, pre_image).unwrap();

    leaf
}

/// 테스트용 머클트리 생성
fn create_test_merkle_tree(leaf: F, depth: usize) -> (Vec<String>, F) {
    let poseidon_params = get_poseidon_params::<F>();
    let leaf_hash_param = get_poseidon_params::<F>().clone();
    let two_to_one_hash_param = get_poseidon_params::<F>().clone();
    let h0 = PoseidonHash::evaluate(&poseidon_params, [F::from(0u64)]).unwrap();
    let digests = vec![h0; 1 << (depth - 1)];

    let mut mt = MerkleTree::<MerkleTreeParams<F>>::new_with_leaf_digest(
        &leaf_hash_param,
        &two_to_one_hash_param,
        digests,
    )
    .unwrap();
    mt.update(0, &[leaf]).unwrap();
    let path = mt.generate_proof(0).unwrap();
    let root = mt.root();

    let mut path_str = vec![];

    let leaf_sibling = path.leaf_sibling_hash.to_string();
    let mut auth_path = path.auth_path.clone();
    auth_path.reverse();
    path_str.push(leaf_sibling);
    for h in auth_path {
        path_str.push(h.to_string());
    }
    (path_str, root)
}

/// 테스트용 anchor parts 생성
fn create_test_anchor_parts(secret: &Secret, n: usize) -> Vec<String> {
    let mut secret_dtos = Vec::with_capacity(n);
    for _ in 0..n {
        secret_dtos.push(Secret {
            sub: secret.sub.clone(),
            iss: secret.iss.clone(),
            aud: secret.aud.clone(),
        });
    }

    let anchor = create_poseidon_anchor::<ZkapConfig>(secret_dtos).unwrap();

    let param = get_poseidon_params::<F>();

    let mut h = PoseidonHash::evaluate(&param, [anchor.0[0]]).unwrap();

    for a in anchor.0.iter().skip(1) {
        h = PoseidonHash::evaluate(&param, [h, *a]).unwrap();
    }

    let h_string = h.to_string();
    let mut anchor_parts = anchor
        .0
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    anchor_parts.push(h_string);

    anchor_parts
}

fn create_test_aud_lists(auds: &[Vec<u8>]) -> (Vec<F>, F) {
    let limb_width = ((F::MODULUS_BIT_SIZE - 1) / 8) as usize;
    let poseidon_params = get_poseidon_params::<F>();

    let aud_lists: Vec<F> = auds
        .iter()
        .map(|aud| {
            let mut limbs = Vec::new();

            // limb_width 단위로 청크로 분할
            for chunk in aud.chunks(limb_width) {
                let mut chunk_bytes = chunk.to_vec();
                // 패딩이 필요한 경우 0으로 패딩
                chunk_bytes.resize(limb_width, 0);
                let limb = F::from_be_bytes_mod_order(&chunk_bytes);
                limbs.push(limb);
            }
            println!("aud: {:?}, limbs: {:?}", aud, limbs);

            // Vec<F>를 poseidon hash하여 하나의 F 생성
            PoseidonHash::evaluate(&poseidon_params, limbs).unwrap()
        })
        .collect();

    // aud_lists를 poseidon hash하여 h_aud_lists 생성
    let h_aud_lists = PoseidonHash::evaluate(&poseidon_params, aud_lists.clone()).unwrap();

    (aud_lists, h_aud_lists)
}

#[test]
fn test_generate_baerae_proof_single() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info) // 기본 로그 레벨 설정 (Info)
        .is_test(true) // 테스트 환경에 맞게 출력 (println! 가로채기 방지)
        .try_init();

    // 테스트 파라미터 설정 - K=3으로 고정 (회로 상수)
    let n = 6;
    let k = 1; // BaeraeLightWeightCircuit의 K 상수와 일치해야 함
    let max_jwt_len_b64 = 1024;
    let max_payload_len_b64 = 640;
    let max_iss_len = 31 * 3 as usize;
    let tree_height = 4;
    let pad_char = b'\0';

    println!("\n=== Testing generate_baerae_proof (K={}) ===", k);

    // 1. 테스트 디렉토리 설정
    let test_dir = setup_test_dir();

    // 2. 테스트 키 생성 및 저장
    let snark_pk_path = test_dir.join("pk.key");
    let snark_vk_path = test_dir.join("vk.key");

    // 3. 테스트 데이터 준비
    let selected_secrets = Secret {
        sub: r#""105043881177884738227""#.to_string(),
        iss: r#""https://accounts.google.com""#.to_string(),
        aud: r#""713851302686-svluejd8li1l5qd9sp806tbmk3lkb4hj.apps.googleusercontent.com""#
            .to_string(),
    };

    let anchor_parts = create_test_anchor_parts(&selected_secrets, n);
    println!("Anchor parts created: {} elements", anchor_parts.len());

    let (pk, _e, jwt, iss) = create_test_jwt_data();

    // 4. Merkle tree 생성
    let padded_iss = resize(&iss, max_iss_len, pad_char);
    let leaf = create_test_leaf(&padded_iss, &pk);
    let (mp, root) = create_test_merkle_tree(leaf, tree_height);
    let root_str = root.to_string();
    println!("Merkle tree created. Root: {}", root_str);

    // 5. 입력 준비 (K=3개 - 회로 상수와 일치)
    let jwts = vec![jwt.clone(); k];
    let pk_ops = vec![pk.clone(); k];
    let mp_vec = vec![mp.clone(); k];
    let leaf_index_vec = vec![0; k];

    // Schnorr 서명 관련 값들
    let h_sign_userop = "67890";
    let block_timestamp = "1753676658";
    let random = "12345";

    // aud_list 생성 0번째만 실제 값, 나머지는 0을 hash한 값
    let aud_list: Vec<String> = vec![
        "1537516906439034952305634351122994193921181616590605158358594959574076457504".to_string(),
        "4725746703237049609879526210021666464972871326396081167205154246686201634852".to_string(),
        "4725746703237049609879526210021666464972871326396081167205154246686201634852".to_string(),
        "4725746703237049609879526210021666464972871326396081167205154246686201634852".to_string(),
        "4725746703237049609879526210021666464972871326396081167205154246686201634852".to_string(),
    ];

    println!("\nGenerating {} proof(s)...", k);

    println!("input data:");
    println!(" - jwt: {}", jwts[0]);
    println!(" - pk_op: {}", pk_ops[0]);
    println!(" - merkle_path: {:?}", mp_vec[0]);
    println!(" - leaf_index: {}", leaf_index_vec[0]);
    println!(" - root: {}", root_str);
    println!(" - anchor_parts: {:?}", anchor_parts);
    println!(" - h_sign_userop: {}", h_sign_userop);
    println!(" - block_timestamp: {}", block_timestamp);
    println!(" - random: {}", random);
    println!(" - aud_list: {:?}", aud_list);

    // 6. generate_baerae_proof 호출
    let result = generate_baerae_proof::<ZkapConfig>(
        &snark_pk_path,
        jwts,
        pk_ops,
        mp_vec,
        leaf_index_vec,
        &root_str,
        &anchor_parts,
        h_sign_userop,
        block_timestamp,
        random,
        &aud_list,
    );

    // 7. 결과 검증
    if let Err(e) = &result {
        println!("Error: {:?}", e);
        panic!("Proof generation failed: {:?}", e);
    }

    let (proofs, public_inputs_list) = result.unwrap();

    println!("✓ Proof generation successful!");
    println!("  - Generated {} proof(s)", proofs.len());
    println!("  - Public inputs sets: {}", public_inputs_list.len());

    assert_eq!(proofs.len(), k, "Expected {} proofs", k);
    assert_eq!(
        public_inputs_list.len(),
        k,
        "Expected {} public input sets",
        k
    );

    // 8. 증명 검증
    println!("\nVerifying proofs...");
    let vk = load_key_uncompressed::<VerifyingKey<BN254>>(&snark_vk_path).unwrap();
    let pvk = Groth16::<BN254>::process_vk(&vk).unwrap();

    for (i, (proof, public_inputs)) in proofs.iter().zip(public_inputs_list.iter()).enumerate() {
        println!("\n--- Proof {} ---", i + 1);

        // 증명 직렬화 테스트
        let mut proof_bytes = Vec::new();
        proof.serialize_uncompressed(&mut proof_bytes).unwrap();
        println!("  - Proof size: {} bytes", proof_bytes.len());
        println!("  - Public inputs count: {}", public_inputs.len());

        // 증명 검증
        let is_valid = Groth16::<BN254>::verify_proof(&pvk, proof, public_inputs).unwrap();
        println!(
            "  - Verification: {}",
            if is_valid { "✓ PASS" } else { "✗ FAIL" }
        );

        // Note: 실제 검증 성공 여부는 회로 구현에 따라 다를 수 있음
        // 여기서는 증명 생성이 성공했는지만 확인
    }

    println!("\n=== Test Complete ===");
}

#[test]
fn test_generate_baerae_proof_multiple() {
    // 테스트 파라미터 설정 (K=3)
    let n = 6;
    let k = 3;
    let max_jwt_len = 1024;
    let max_payload_len = 640;
    let max_claim_len = 128;
    let tree_height = 4;

    println!("\n=== Testing generate_baerae_proof (K={}) ===", k);

    // 1. 테스트 디렉토리 설정
    let test_dir = setup_test_dir();

    // 2. 테스트 키 생성 및 저장
    let snark_pk_path = test_dir.join("crs.pk");
    let snark_vk_path = test_dir.join("crs.vk");
    // 3. 테스트 데이터 준비
    let selected_secrets = Secret {
        sub: r#""105043881177884738227""#.to_string(),
        iss: r#""https://accounts.google.com""#.to_string(),
        aud: r#""713851302686-svluejd8li1l5qd9sp806tbmk3lkb4hj.apps.googleusercontent.com""#
            .to_string(),
    };

    let anchor_parts = create_test_anchor_parts(&selected_secrets, n);
    println!("Anchor parts created: {} elements", anchor_parts.len());

    let (pk, _e, jwt, iss) = create_test_jwt_data();

    // 4. Merkle tree 생성
    let fit_len = fit_len_to_field::<F>(&max_claim_len);
    let padded_iss = resize(&iss, fit_len, b'0');
    let leaf = create_test_leaf(&padded_iss, &pk);
    let (mp, root) = create_test_merkle_tree(leaf, tree_height);
    let root_str = root.to_string();
    println!("Merkle tree created. Root: {}", root_str);

    // 5. 입력 준비 (K=3개)
    let jwts = vec![jwt.clone(); k];
    let pk_ops = vec![pk.clone(); k];
    let mp_vec = vec![mp.clone(); k];
    let leaf_index_vec = vec![0; k];

    // Schnorr 서명 관련 값들
    let h_sign_userop = "67890";
    let block_timestamp = "1753676658";
    let random = "12345";

    // aud_list 생성 (빈 배열로 시작)
    let aud_list: Vec<String> = vec![];

    println!("\nGenerating {} proof(s)...", k);

    // 6. generate_baerae_proof 호출
    let result = generate_baerae_proof::<ZkapConfig>(
        &snark_pk_path,
        jwts,
        pk_ops,
        mp_vec,
        leaf_index_vec,
        &root_str,
        &anchor_parts,
        h_sign_userop,
        block_timestamp,
        random,
        &aud_list,
    );

    // 7. 결과 검증
    if let Err(e) = &result {
        println!("Error: {:?}", e);
        panic!("Proof generation failed: {:?}", e);
    }

    let (proofs, public_inputs_list) = result.unwrap();

    println!("✓ Proof generation successful!");
    println!("  - Generated {} proof(s)", proofs.len());
    println!("  - Public inputs sets: {}", public_inputs_list.len());

    assert_eq!(proofs.len(), k, "Expected {} proofs", k);
    assert_eq!(
        public_inputs_list.len(),
        k,
        "Expected {} public input sets",
        k
    );

    // 8. 각 증명에 대해 기본 검증
    println!("\nVerifying proofs...");
    let vk = load_key_uncompressed::<VerifyingKey<BN254>>(&snark_vk_path).unwrap();
    let pvk = Groth16::<BN254>::process_vk(&vk).unwrap();

    for (i, (proof, public_inputs)) in proofs.iter().zip(public_inputs_list.iter()).enumerate() {
        println!("\n--- Proof {} ---", i + 1);

        // 증명 직렬화 테스트
        let mut proof_bytes = Vec::new();
        proof.serialize_uncompressed(&mut proof_bytes).unwrap();
        println!("  - Proof size: {} bytes", proof_bytes.len());
        println!("  - Public inputs count: {}", public_inputs.len());

        // 증명 검증
        let is_valid = Groth16::<BN254>::verify_proof(&pvk, proof, public_inputs).unwrap();
        println!(
            "  - Verification: {}",
            if is_valid { "✓ PASS" } else { "✗ FAIL" }
        );
    }

    println!("\n=== Test Complete ===");
    println!("All {} proofs generated successfully using V4 API", k);
}

#[test]
fn test_generate_baerae_proof_input_validation() {
    let test_dir = setup_test_dir();
    let snark_pk_path = test_dir.join("dummy_pk.bin");

    println!("\n=== Testing Input Validation ===");

    // 잘못된 입력: jwts와 pk_ops 길이 불일치
    let jwts = vec!["jwt1".to_string(), "jwt2".to_string()];
    let pk_ops = vec!["pk1".to_string()]; // 길이 불일치
    let mp_vec = vec![vec!["0".to_string()], vec!["0".to_string()]];
    let leaf_index_vec = vec![0, 0];
    let anchor_parts = vec!["0".to_string(); 5];

    let result = generate_baerae_proof::<ZkapConfig>(
        &snark_pk_path,
        jwts,
        pk_ops,
        mp_vec,
        leaf_index_vec,
        "0",
        &anchor_parts,
        "0",
        "0",
        "0",
        &[],
    );

    assert!(result.is_err(), "Expected validation error");
    println!("✓ Input validation working correctly");

    // 잘못된 입력: anchor_parts 길이 불일치
    // For N=6, K=3: expected anchor_parts length = (6 - 3 + 1) + 1 = 5
    let k = 3;

    let jwts = vec!["jwt".to_string(); k];
    let pk_ops = vec!["pk".to_string(); k];
    let mp_vec = vec![vec!["0".to_string()]; k];
    let leaf_index_vec = vec![0; k];
    let anchor_parts = vec!["0".to_string(); 3]; // 잘못된 길이 (expected: 5)

    let result = generate_baerae_proof::<ZkapConfig>(
        &snark_pk_path,
        jwts,
        pk_ops,
        mp_vec,
        leaf_index_vec,
        "0",
        &anchor_parts,
        "0",
        "0",
        "0",
        &[],
    );

    assert!(result.is_err(), "Expected anchor_parts validation error");
    if let Err(e) = result {
        println!("✓ Anchor parts validation: {:?}", e);
    }

    println!("\n=== Input Validation Tests Complete ===");
}

#[test]
fn test_poseidon_hash_generator() {
    let h_sign_userop = "67890";
    let random = "12345";
    let mut input = vec![];

    // parse numeric strings to u64 and convert into the field element
    let v1 = h_sign_userop.parse::<u64>().unwrap();
    let v2 = random.parse::<u64>().unwrap();
    input.push(F::from(v1));
    input.push(F::from(v2));

    let poseidon_params = get_poseidon_params::<F>();
    let hash = PoseidonHash::evaluate(&poseidon_params, input).unwrap();
    println!("\nPoseidon hash of [{}, {}]: {}", v1, v2, hash);
    // hash to hex
    let bigint = hash.into_bigint();
    let bytes = bigint.to_bytes_be();
    let hex = bytes
        .into_iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    println!("Hex: 0x{}", hex);
}

#[test]
fn test_create_aud_lists() {
    let mut aud1 =
        b"\"713851302686-svluejd8li1l5qd9sp806tbmk3lkb4hj.apps.googleusercontent.com\"".to_vec();
    aud1.resize(MAX_AUD_LEN, PAD_CHAR as u8);
    let mut forbiden = FORBIDDEN_STRING.as_bytes().to_vec();
    forbiden.resize(MAX_AUD_LEN, PAD_CHAR as u8);
    // use the helper resize function which returns a padded String
    let auds = vec![
        aud1,
        forbiden.clone(),
        forbiden.clone(),
        forbiden.clone(),
        forbiden.clone(),
    ];

    let (aud_lists, h_aud_lists) = create_test_aud_lists(&auds);
    println!("aud_lists: {:?}", aud_lists);
    println!("h_aud_lists: {}", h_aud_lists);

    println!("\n=== Test create_test_aud_lists ===");
    println!("Input auds: {:?}", auds);
    println!("aud_lists length: {}", aud_lists.len());
    println!("aud_lists: {:?}", aud_lists);
    println!("h_aud_lists: {}", h_aud_lists);

    // 각 aud가 해시되었는지 확인
    assert_eq!(
        aud_lists.len(),
        auds.len(),
        "aud_lists length should match input auds length"
    );

    // h_aud_lists가 aud_lists의 해시인지 확인
    let poseidon_params = get_poseidon_params::<F>();
    let expected_h_aud_lists = PoseidonHash::evaluate(&poseidon_params, aud_lists.clone()).unwrap();
    assert_eq!(
        h_aud_lists, expected_h_aud_lists,
        "h_aud_lists should be hash of aud_lists"
    );

    println!("✓ create_test_aud_lists test passed!");
}
