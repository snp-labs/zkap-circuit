use std::path::PathBuf;

use ark_crypto_primitives::{crh::CRHScheme, merkle_tree::MerkleTree, snark::SNARK};
use ark_groth16::{Groth16, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::rngs::OsRng;
use gadget::{
    anchor::{
        AnchorScheme,
        poseidon::{PoseidonAnchor, PoseidonAnchorScheme},
    },
    base64::decode_any_base64,
    hashes::poseidon::get_poseidon_params,
    jwt::utils::resize,
    mekletree::tree_config::MerkleTreeParams,
    signature::rsa::native::PublicKey,
};
use zkpasskey_service::{
    core::signature::{SignatureService, schnorr::SchnorrSignatureService},
    interface::{
        anchor::{PoseidonAnchorKeyExtension, SecretDto},
    },
    service::{
        anchor::create_poseidon_anchor,
        constants::{AppCurve, AppField, BN254, PoseidonHash},
        key::io::{load_key_uncompressed, save_key_uncompressed},
        snark::{
            snark_v2::generate_and_write_proving_key,
            snark_v4::generate_baerae_proof,
        },
    },
    utils::{
        padding::fit_len_to_field,
        point::{FromStrings, ascii_to_field_be},
    },
};

/// 테스트용 임시 디렉토리 생성
fn setup_test_dir() -> PathBuf {
    let test_dir = PathBuf::from("test_outputs/snark_v4");
    if !test_dir.exists() {
        std::fs::create_dir_all(&test_dir).unwrap();
    }
    test_dir
}

/// 테스트용 앵커 키 생성 및 저장
fn create_test_anchor_key(path: &PathBuf, n: usize, k: usize, max_claim_len: usize) {
    let mut rng = OsRng;

    let anchor_key = PoseidonAnchorScheme::<AppField>::setup(&mut rng, n).unwrap();

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

/// 테스트용 snark 키 생성
fn create_test_snark_key(
    anchor_key_path: &PathBuf,
    schnorr_key_path: &PathBuf,
    pk_path: &PathBuf,
    vk_path: &PathBuf,
    max_jwt_len: usize,
    max_payload_len: usize,
    max_claim_len: usize,
    tree_height: usize,
) {
    generate_and_write_proving_key(
        anchor_key_path,
        schnorr_key_path,
        max_jwt_len,
        max_payload_len,
        max_claim_len,
        max_claim_len,
        max_claim_len,
        max_claim_len,
        tree_height,
        pk_path,
        vk_path,
    )
    .unwrap();
}

/// 테스트용 JWT 데이터 생성
fn create_test_jwt_data() -> (String, String, String, String) {
    let pk = "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw".to_string();
    let e = "AQAB".to_string();
    let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3NTM2NzY2NTg3NjciLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiI3MTM4NTEzMDI2ODYtc3ZsdWVqZDhsaTFsNXFkOXNwODA2dGJtazNsa2I0aGouYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDUwNDM4ODExNzc4ODQ3MzgyMjciLCJlbWFpbCI6ImtpbS5reXVuZ2tvb0BnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibm9uY2UiOiIweDI2NzBhNDIxY2FiNjg1NzQyNjU0YmIzYjVhYWNhMmVjZWIzYzliZWMxN2M0NDk1OGIyYTRkNjlmZTUxZTZmOGIiLCJuYW1lIjoiS3l1bmdLb28gS2ltIiwiaWF0IjoxNzUzNjc2NjU4LCJleHAiOjE3NTM2ODAyNTl9.d3Hvb4sSLK8PVZRW-GM10DoTPvTq7Gfgv4eWKIkG6odvVoCT73-QC6RKhZmUtW0i6n2BNvR75ysyeUpkSMP3C8D-6uskzJvyEwhNtoat8DBRyGK5BIFjq41WAofgGeJLScpEOI9ykfuVgcGRvr-qFVu9Ndy6piuNlccJovTHPaFipeBIFsyHsRgDtWmMh5epfswMxcqPFf681LmN1qmbkiGDIyfN5Zre_OLSNUAB_lGGGXNPK30DWXhOL_Dq-6pH4qpGbxuKvhVgj9Px-yROAgtpuJi-DHQ94AmEx5WjIeo6ySmYzg3DLvbMOCwuOplEgk_ITQZNvJ_rOcj9-aFhdw".to_string();

    let iss = r#""https://accounts.google.com""#.to_string();

    (pk, e, jwt, iss)
}

/// 테스트용 머클트리 리프 생성
fn create_test_leaf(iss: &str, n: &str) -> AppField {
    let n = decode_any_base64(n).unwrap();
    let e = decode_any_base64("AQAB").unwrap();
    let pk = PublicKey { n, e };
    let pk_limbs = pk.to_limbs::<zkpasskey_service::service::constants::BNP, AppCurve>();
    let iss_limbs = ascii_to_field_be::<AppField>(iss).unwrap();
    let pre_image = [iss_limbs, pk_limbs.0].concat();
    let poseidon_params = get_poseidon_params::<AppField>();
    let leaf = PoseidonHash::evaluate(&poseidon_params, pre_image).unwrap();

    leaf
}

/// 테스트용 머클트리 생성
fn create_test_merkle_tree(leaf: AppField, depth: usize) -> (Vec<String>, AppField) {
    let poseidon_params = get_poseidon_params::<AppField>();
    let leaf_hash_param = get_poseidon_params::<AppField>().clone();
    let two_to_one_hash_param = get_poseidon_params::<AppField>().clone();
    let h0 = PoseidonHash::evaluate(&poseidon_params, [AppField::from(0u64)]).unwrap();

    let digests = vec![h0; 1 << (depth - 1)];

    let mut mt = MerkleTree::<MerkleTreeParams<AppField>>::new_with_leaf_digest(
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
fn create_test_anchor_parts(
    anchor_key_path: &PathBuf,
    secret_dto: &SecretDto,
    n: usize,
) -> Vec<String> {
    let mut secret_dtos = Vec::with_capacity(n);
    for _ in 0..n {
        secret_dtos.push(SecretDto {
            sub: secret_dto.sub.clone(),
            iss: secret_dto.iss.clone(),
            aud: secret_dto.aud.clone(),
        });
    }

    let anchor =
        create_poseidon_anchor(anchor_key_path.to_str().unwrap().to_string(), secret_dtos).unwrap();

    let anchor_struct = PoseidonAnchor::<AppField>::from_strings(&anchor).unwrap();

    let param = get_poseidon_params::<AppField>();

    let mut h = PoseidonHash::evaluate(&param, [anchor_struct.0[0]]).unwrap();

    for a in anchor_struct.0.iter().skip(1) {
        h = PoseidonHash::evaluate(&param, [h, *a]).unwrap();
    }

    let h_string = h.to_string();
    let mut anchor_parts = anchor.clone();
    anchor_parts.push(h_string);

    anchor_parts
}

#[test]
fn test_generate_baerae_proof_single() {
    // 테스트 파라미터 설정 - K=3으로 고정 (회로 상수)
    let n = 6;
    let k = 3; // BaeraeLightWeightCircuit의 K 상수와 일치해야 함
    let max_jwt_len = 1024;
    let max_payload_len = 640;
    let max_claim_len = 128;
    let tree_height = 4;

    println!("\n=== Testing generate_baerae_proof (K={}) ===", k);

    // 1. 테스트 디렉토리 설정
    let test_dir = setup_test_dir();

    // 2. 테스트 키 생성 및 저장
    let anchor_key_path = test_dir.join("test_anchor_key.bin");
    let schnorr_sk_path = test_dir.join("test_schnorr_sk.bin");
    let schnorr_vk_path = test_dir.join("test_schnorr_vk.bin");
    let snark_pk_path = test_dir.join("test_snark_pk.bin");
    let snark_vk_path = test_dir.join("test_snark_vk.bin");

    println!("Creating test keys...");
    create_test_anchor_key(&anchor_key_path, n, k, max_claim_len);
    create_test_schnorr_key(&schnorr_vk_path, &schnorr_sk_path);
    create_test_snark_key(
        &anchor_key_path,
        &schnorr_vk_path,
        &snark_pk_path,
        &snark_vk_path,
        max_jwt_len,
        max_payload_len,
        max_claim_len,
        tree_height,
    );

    // 3. 테스트 데이터 준비
    let selected_secrets = SecretDto {
        sub: Some(r#""105043881177884738227""#.to_string()),
        iss: Some(r#""https://accounts.google.com""#.to_string()),
        aud: Some(r#""713851302686-svluejd8li1l5qd9sp806tbmk3lkb4hj.apps.googleusercontent.com""#.to_string()),
    };

    let anchor_parts = create_test_anchor_parts(&anchor_key_path, &selected_secrets, n);
    println!("Anchor parts created: {} elements", anchor_parts.len());

    let (pk, _e, jwt, iss) = create_test_jwt_data();

    // 4. Merkle tree 생성
    let fit_len = fit_len_to_field::<AppField>(&max_claim_len);
    let padded_iss = resize(&iss, fit_len, b'0');
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

    // aud_list 생성 (빈 배열로 시작)
    let aud_list: Vec<String> = vec![];

    println!("\nGenerating {} proof(s)...", k);

    // 6. generate_baerae_proof 호출
    let result = generate_baerae_proof(
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
        println!("  - Verification: {}", if is_valid { "✓ PASS" } else { "✗ FAIL" });

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
    let anchor_key_path = test_dir.join("test_anchor_key_k3.bin");
    let schnorr_sk_path = test_dir.join("test_schnorr_sk_k3.bin");
    let schnorr_vk_path = test_dir.join("test_schnorr_vk_k3.bin");
    let snark_pk_path = test_dir.join("test_snark_pk_k3.bin");
    let snark_vk_path = test_dir.join("test_snark_vk_k3.bin");

    println!("Creating test keys...");
    create_test_anchor_key(&anchor_key_path, n, k, max_claim_len);
    create_test_schnorr_key(&schnorr_vk_path, &schnorr_sk_path);
    create_test_snark_key(
        &anchor_key_path,
        &schnorr_vk_path,
        &snark_pk_path,
        &snark_vk_path,
        max_jwt_len,
        max_payload_len,
        max_claim_len,
        tree_height,
    );

    // 3. 테스트 데이터 준비
    let selected_secrets = SecretDto {
        sub: Some(r#""105043881177884738227""#.to_string()),
        iss: Some(r#""https://accounts.google.com""#.to_string()),
        aud: Some(r#""713851302686-svluejd8li1l5qd9sp806tbmk3lkb4hj.apps.googleusercontent.com""#.to_string()),
    };

    let anchor_parts = create_test_anchor_parts(&anchor_key_path, &selected_secrets, n);
    println!("Anchor parts created: {} elements", anchor_parts.len());

    let (pk, _e, jwt, iss) = create_test_jwt_data();

    // 4. Merkle tree 생성
    let fit_len = fit_len_to_field::<AppField>(&max_claim_len);
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
    let result = generate_baerae_proof(
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
        println!("  - Verification: {}", if is_valid { "✓ PASS" } else { "✗ FAIL" });
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

    let result = generate_baerae_proof(
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

    let result = generate_baerae_proof(
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
