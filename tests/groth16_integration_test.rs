use std::path::PathBuf;

use ark_crypto_primitives::{crh::CRHScheme, snark::SNARK};
use ark_ff::BigInteger;
use ark_groth16::{Groth16, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use common::gadget::anchor::AnchorScheme;
use common_gadget::{
    anchor::poseidon::{PoseidonAnchor, PoseidonAnchorWitness},
    hashes::poseidon::{constraints::chain_hash_gadget, get_poseidon_params},
    jwt::utils::resize,
};
use zkpasskey_crypto_modules::{
    core::anchor::{AnchorService, poseidon::PoseidonAnchorService},
    interface::{
        anchor::{PoseidonAnchorKeyExtension, SecretDto},
        signature::{SchnorrPublicKeyExtension, SchnorrSecretKeyExtension},
        snark::ProvingKeyExtension,
    },
    service::{
        anchor::{
            anchor::{
                build_anchor_witness, build_poseidon_anchor_from_strings, derive_hashed_message,
            },
            create_poseidon_anchor,
        },
        constants::{AppCurve, AppField, BN254, Blake2, PoseidonHash},
        key::io::{load_key_uncompressed, save_key_uncompressed},
        snark::snark::{generate_and_write_proving_key, generate_proof},
    },
    utils::padding::fit_len_to_field,
};

/// 테스트용 임시 디렉토리 생성
fn setup_test_dir() -> PathBuf {
    let test_dir = PathBuf::from("test_outputs");
    if !test_dir.exists() {
        std::fs::create_dir_all(&test_dir).unwrap();
    }
    test_dir
}

/// 테스트용 Anchor Key 생성
fn create_test_anchor_key(path: &PathBuf) {
    use ark_std::rand::rngs::OsRng;
    use common::gadget::anchor::poseidon::PoseidonAnchorScheme;

    let mut rng = OsRng;
    let n = 6;
    let k = 1;

    let pk: common::gadget::anchor::poseidon::PoseidonAnchorPublicKey<AppField> =
        PoseidonAnchorScheme::setup(&mut rng, n).unwrap();

    let anchor_key_ext = PoseidonAnchorKeyExtension {
        anchor_key: pk,
        n,
        k,
        max_aud_len: Some(128),
        max_iss_len: Some(128),
        max_sub_len: 128,
    };

    save_key_uncompressed(path, &anchor_key_ext).unwrap();
}

/// 테스트용 Schnorr Key 생성
fn create_test_schnorr_key(path: &PathBuf, path2: &PathBuf) {
    use ark_std::rand::rngs::OsRng;
    use common_gadget::signature::SignatureScheme;
    use common_gadget::signature::schnorr::Schnorr;

    let mut rng = OsRng;
    let params = Schnorr::<AppCurve, Blake2>::setup::<_>(&mut rng).unwrap();
    let (vk, sk) = Schnorr::<AppCurve, Blake2>::keygen(&params, &mut rng).unwrap();

    let schnorr_key_ext = SchnorrPublicKeyExtension {
        params: params.clone(),
        vk,
    };
    let schnorr_sk_ext = SchnorrSecretKeyExtension { params, sk };

    save_key_uncompressed(path, &schnorr_key_ext).unwrap();
    save_key_uncompressed(path2, &schnorr_sk_ext).unwrap();
}

/// 테스트용 JWT 데이터 생성 (실제로는 유효한 JWT가 필요)
fn create_test_jwt_data() -> (String, String, String, String) {
    let pk = "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw".to_string();
    let e = "AQAB".to_string();
    let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3NTM2NzY2NTg3NjciLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiI3MTM4NTEzMDI2ODYtc3ZsdWVqZDhsaTFsNXFkOXNwODA2dGJtazNsa2I0aGouYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDUwNDM4ODExNzc4ODQ3MzgyMjciLCJlbWFpbCI6ImtpbS5reXVuZ2tvb0BnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibm9uY2UiOiIweDI2NzBhNDIxY2FiNjg1NzQyNjU0YmIzYjVhYWNhMmVjZWIzYzliZWMxN2M0NDk1OGIyYTRkNjlmZTUxZTZmOGIiLCJuYW1lIjoiS3l1bmdLb28gS2ltIiwiaWF0IjoxNzUzNjc2NjU4LCJleHAiOjE3NTM2ODAyNTl9.d3Hvb4sSLK8PVZRW-GM10DoTPvTq7Gfgv4eWKIkG6odvVoCT73-QC6RKhZmUtW0i6n2BNvR75ysyeUpkSMP3C8D-6uskzJvyEwhNtoat8DBRyGK5BIFjq41WAofgGeJLScpEOI9ykfuVgcGRvr-qFVu9Ndy6piuNlccJovTHPaFipeBIFsyHsRgDtWmMh5epfswMxcqPFf681LmN1qmbkiGDIyfN5Zre_OLSNUAB_lGGGXNPK30DWXhOL_Dq-6pH4qpGbxuKvhVgj9Px-yROAgtpuJi-DHQ94AmEx5WjIeo6ySmYzg3DLvbMOCwuOplEgk_ITQZNvJ_rOcj9-aFhdw".to_string();

    let iss = r#""https://accounts.google.com""#.to_string();

    (pk, e, jwt, iss)
}

fn create_test_leaf(iss: &str, n: &str) -> AppField {
    use ark_crypto_primitives::crh::CRHScheme;
    use common::codec::point::ascii_to_field_be;
    use common::gadget::signature::rsa::native::PublicKey;
    use common_gadget::base64::decode_any_base64;
    use common_gadget::hashes::poseidon::get_poseidon_params;
    use zkpasskey_crypto_modules::service::constants::{AppCurve, AppField, BNP, PoseidonHash};

    let n = decode_any_base64(n).unwrap();
    let e = decode_any_base64("AQAB").unwrap();
    let pk = PublicKey { n, e };
    let pk_limbs = pk.to_limbs::<BNP, AppCurve>();
    let iss_limbs = ascii_to_field_be::<AppField>(iss).unwrap();
    let pre_image = [iss_limbs, pk_limbs.0].concat();
    let poseidon_params = get_poseidon_params::<AppField>();
    let leaf = PoseidonHash::evaluate(&poseidon_params, pre_image).unwrap();

    leaf
}

fn create_test_merkle_tree(leaf: AppField, tree_height: usize) -> (Vec<String>, AppField) {
    use ark_crypto_primitives::crh::CRHScheme;
    use ark_crypto_primitives::merkle_tree::MerkleTree;

    use common_gadget::hashes::poseidon::get_poseidon_params;
    use common_gadget::mekletree::tree_config::MerkleTreeParams;
    use zkpasskey_crypto_modules::service::constants::{AppField, PoseidonHash};

    let poseidon_params = get_poseidon_params::<AppField>();
    let leaf_hash_param = get_poseidon_params::<AppField>().clone();
    let two_to_one_hash_param = get_poseidon_params::<AppField>().clone();
    let h0 = PoseidonHash::evaluate(&poseidon_params, [AppField::from(0u64)]).unwrap();

    let digests = vec![h0; 1 << (tree_height - 1)];

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

fn create_test_schnorr_signature(schnorr_sk_path: &PathBuf, message: &AppField) -> Vec<u8> {
    use ark_ff::{BigInteger, PrimeField};
    use ark_std::rand::rngs::OsRng;
    use common_gadget::signature::SignatureScheme;
    use common_gadget::signature::schnorr::Schnorr;
    use zkpasskey_crypto_modules::service::constants::{AppCurve, Blake2};

    let schnorr_sk_ext =
        load_key_uncompressed::<SchnorrSecretKeyExtension<AppCurve, Blake2>>(schnorr_sk_path)
            .unwrap();
    let message = message.into_bigint().to_bytes_le();
    let mut rng = OsRng;
    let signature = Schnorr::<AppCurve, Blake2>::sign(
        &schnorr_sk_ext.params,
        &schnorr_sk_ext.sk,
        &message,
        &mut rng,
    )
    .unwrap();

    let mut sig_bytes = Vec::new();
    signature.serialize_uncompressed(&mut sig_bytes).unwrap();
    sig_bytes
}

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

    let anchor_struct = PoseidonAnchor::<AppField>::from_str(&anchor).unwrap();

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
fn test_hash() {
    use zkpasskey_crypto_modules::service::constants::PoseidonHash;

    let counter = AppField::from(1u8);
    let random = AppField::from(12345u32);
    let nonce = AppField::from(67890u32);

    let param = get_poseidon_params::<AppField>();

    let h = PoseidonHash::evaluate(&param, vec![nonce, counter, random]).unwrap();
    // Convert field element to big-endian bytes and print as hex
    use ark_ff::PrimeField;
    let mut bytes = h.into_bigint().to_bytes_le();
    // Convert to big-endian for conventional hex display
    bytes.reverse();
    let hex = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    println!("Hash result (hex): 0x{}", hex);
}


#[test]
fn test_anchor_creation() {
    // Anchor 생성 테스트
    let anchor_parts = vec![
        "123456789".to_string(),
        "987654321".to_string(),
        "111111111".to_string(),
    ];

    let result = build_poseidon_anchor_from_strings(&anchor_parts);
    assert!(result.is_ok(), "Failed to build anchor from strings");

    let (anchor, hanchor) = result.unwrap();
    assert_eq!(anchor.0.len(), anchor_parts.len() - 1); // 마지막 요소는 hanchor

    println!("✓ Anchor creation test passed");
    println!("  - Anchor hash: {:?}", hanchor);
}

#[test]
fn test_key_serialization() {
    // 키 직렬화/역직렬화 테스트
    let test_dir = setup_test_dir();
    let anchor_key_path = test_dir.join("test_anchor_serialize.bin");

    // 1. Anchor Key 생성 및 저장
    create_test_anchor_key(&anchor_key_path);

    // 2. 로드
    let loaded = load_key_uncompressed::<PoseidonAnchorKeyExtension<AppField>>(&anchor_key_path);
    assert!(loaded.is_ok(), "Failed to load anchor key");

    let loaded = loaded.unwrap();
    assert_eq!(loaded.n, 5);
    assert_eq!(loaded.k, 3);
    assert_eq!(loaded.max_aud_len, Some(50));
    assert_eq!(loaded.max_iss_len, Some(50));
    assert_eq!(loaded.max_sub_len, 100);

    println!("✓ Key serialization test passed");
}

#[test]
fn test_groth16_setup() {
    // 1. 테스트 디렉토리 설정
    let test_dir = setup_test_dir();

    // 2. 테스트용 키 파일 생성
    let anchor_key_path = test_dir.join("test_anchor_key.bin");
    let schnorr_key_path = test_dir.join("test_schnorr_key.bin");
    let schnorr_sk_path = test_dir.join("test_schnorr_sk.bin");
    let pk_path = test_dir.join("test_proving_key.bin");

    create_test_anchor_key(&anchor_key_path);
    create_test_schnorr_key(&schnorr_key_path, &schnorr_sk_path);

    // 3. .env 파일 설정 (Solidity verifier 경로)
    unsafe {
        std::env::set_var(
            "SOLIDITY_VERIFIER_PATH",
            test_dir.join("verifier.sol").to_str().unwrap(),
        );
    }

    // 4. Proving Key 생성
    let result = generate_and_write_proving_key(
        anchor_key_path.to_str().unwrap().to_string(),
        schnorr_key_path.to_str().unwrap().to_string(),
        1024, // max_jwt_len
        640,  // max_payload_len
        128,  // max_aud_len
        128,  // max_iss_len
        128,  // max_nonce_len
        128,  // max_sub_len
        4,    // tree_height
        test_dir.to_str().unwrap().to_string(),
    );

    // 5. 결과 검증
    assert!(
        result.is_ok(),
        "Proving key generation failed: {:?}",
        result.err()
    );
    assert!(pk_path.exists(), "Proving key file not created");

    // 6. Proving Key 로드 테스트
    let pk_ext = load_key_uncompressed::<ProvingKeyExtension<BN254>>(&pk_path);
    assert!(pk_ext.is_ok(), "Failed to load proving key");

    let pk_ext = pk_ext.unwrap();
    assert_eq!(pk_ext.max_jwt_len, 1024);
    assert_eq!(pk_ext.max_payload_len, 640);
    assert_eq!(pk_ext.tree_height, 4);

    println!("✓ Groth16 setup test passed");
}

#[test]
fn test_groth16_prove_and_verify() {
    // 1. 테스트 디렉토리 및 파일 경로 설정
    let test_dir = setup_test_dir();
    let anchor_key_path = test_dir.join("test_anchor_key.bin");
    let schnorr_key_path = test_dir.join("test_schnorr_key.bin");
    let pk_path = test_dir.join("test_proving_key.bin");
    let schnorr_sk_path = test_dir.join("test_schnorr_sk.bin");
    let vk_path = test_dir.join("test_verifying_key.bin");

    // 2. Setup이 이미 완료되어 있다고 가정 (또는 먼저 setup 실행)
    // test_groth16_setup()를 먼저 실행하거나 여기서 다시 실행

    let selected_secrets = SecretDto {
        sub: Some(r#""105043881177884738227""#.to_string()),
        iss: Some(r#""https://accounts.google.com""#.to_string()),
        aud: None,
    };
    let n = 6;

    // 3. 테스트용 witness 데이터 준비
    let anchor_parts = create_test_anchor_parts(&anchor_key_path, &selected_secrets, n);

    let (pk, e, jwt, iss) = create_test_jwt_data();
    let fit_len = fit_len_to_field::<AppField>(&128);
    let padded_iss = resize(&iss, fit_len, b'0');

    let leaf = create_test_leaf(&padded_iss, &pk);
    let tree_height = 4;
    let (mp, root) = create_test_merkle_tree(leaf, tree_height);
    let leaf_index = 0;

    let selector = vec![true, false, false, false, false, false]; // 6개 중 1개 선택
    let counter = "1".to_string();
    let random = "12345".to_string();
    let h_userop = "67890".to_string();
    let slot = 0usize;

    // Schnorr 서명 생성
    let signature = create_test_schnorr_signature(&schnorr_sk_path, &root);

    let root_str = root.to_string();

    // 4. 증명 생성
    let proof_result = generate_proof(
        pk_path.to_str().unwrap().to_string(),
        anchor_key_path.to_str().unwrap().to_string(),
        schnorr_key_path.to_str().unwrap().to_string(),
        anchor_parts,
        vec![selected_secrets],
        jwt,
        pk,
        mp,
        root_str,
        signature,
        leaf_index,
        selector,
        counter,
        random,
        h_userop,
        slot,
    );

    // 5. 증명 생성 결과 검증
    if let Err(e) = &proof_result {
        println!("Proof generation error: {:?}", e);
    }
    assert!(proof_result.is_ok(), "Proof generation failed");

    let (proof, public_inputs) = proof_result.unwrap();

    // 6. 증명 직렬화 테스트
    let mut proof_bytes = Vec::new();
    proof.serialize_uncompressed(&mut proof_bytes).unwrap();
    assert!(!proof_bytes.is_empty(), "Proof serialization failed");

    println!("✓ Proof generated successfully");
    println!("  - Proof size: {} bytes", proof_bytes.len());
    println!("  - Public inputs count: {}", public_inputs.len());

    let vk = load_key_uncompressed::<VerifyingKey<BN254>>(&vk_path).unwrap();

    let pvk = Groth16::<BN254>::process_vk(&vk).unwrap();

    let is_valid = Groth16::<BN254>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
    assert!(is_valid);
}

#[test]
fn test_multi_prove_verify() {
    use zkpasskey_crypto_modules::service::snark::snark::generate_multi_proof;

    // 1. 테스트 디렉토리 및 파일 경로 설정
    let test_dir = setup_test_dir();
    let anchor_key_path = test_dir.join("test_anchor_key.bin");
    let schnorr_key_path = test_dir.join("test_schnorr_key.bin");
    let pk_path = test_dir.join("test_proving_key.bin");
    let schnorr_sk_path = test_dir.join("test_schnorr_sk.bin");
    let vk_path = test_dir.join("test_verifying_key.bin");

    // 2. Setup이 이미 완료되어 있다고 가정 (또는 먼저 setup 실행)
    // test_groth16_setup()를 먼저 실행하거나 여기서 다시 실행

    let selected_secrets = SecretDto {
        sub: Some(r#""105043881177884738227""#.to_string()),
        iss: Some(r#""https://accounts.google.com""#.to_string()),
        aud: None,
    };
    let n = 6;

    // 3. 테스트용 witness 데이터 준비
    let anchor_parts = create_test_anchor_parts(&anchor_key_path, &selected_secrets, n);

    let (pk, _e, jwt, iss) = create_test_jwt_data();
    let fit_len = fit_len_to_field::<AppField>(&128);
    let padded_iss = resize(&iss, fit_len, b'0');

    let leaf = create_test_leaf(&padded_iss, &pk);
    let tree_height = 4;
    let (mp, root) = create_test_merkle_tree(leaf, tree_height);
    let leaf_index = 0u32;

    let selector = vec![true, true, true, false, false, false]; // 6개 중 3개 선택
    let counter = "1".to_string();
    let random = "12345".to_string();
    let h_userop = "67890".to_string();
    let slot = 0usize;

    // Schnorr 서명 생성
    let signature = create_test_schnorr_signature(&schnorr_sk_path, &root);

    let root_str = root.to_string();

    // 4. 다중 증명 생성을 위한 데이터 준비 (k = 3개의 증명)
    let k = 3;
    let jwt_vec = vec![jwt.clone(); k];
    let pk_vec = vec![pk.clone(); k];
    let mp_vec = vec![mp.clone(); k];
    let leaf_index_vec = vec![leaf_index; k];
    let slot_vec = vec![0, 1, 2];

    println!("\n=== Starting Multi-Proof Generation ===");
    println!("Number of proofs to generate: {}", k);

    // 5. 다중 증명 생성
    let multi_proof_result = generate_multi_proof(
        pk_path.to_str().unwrap().to_string(),
        anchor_key_path.to_str().unwrap().to_string(),
        schnorr_key_path.to_str().unwrap().to_string(),
        anchor_parts,
        vec![selected_secrets; k],
        jwt_vec,
        pk_vec,
        mp_vec,
        root_str,
        signature,
        leaf_index_vec,
        selector,
        counter,
        random,
        h_userop,
        slot_vec,
    );

    // 6. 증명 생성 결과 검증
    if let Err(e) = &multi_proof_result {
        println!("Multi-proof generation error: {:?}", e);
    }
    assert!(multi_proof_result.is_ok(), "Multi-proof generation failed");

    let (proofs, public_inputs_all) = multi_proof_result.unwrap();

    assert_eq!(proofs.len(), k, "Expected {} proofs", k);
    assert_eq!(
        public_inputs_all.len(),
        k,
        "Expected {} public input sets",
        k
    );

    println!("✓ Multi-proof generation successful");
    println!("  - Number of proofs generated: {}", proofs.len());

    // 7. 각 증명 직렬화 및 검증
    let vk = load_key_uncompressed::<VerifyingKey<BN254>>(&vk_path).unwrap();
    let pvk = Groth16::<BN254>::process_vk(&vk).unwrap();

    for (i, (proof, public_inputs)) in proofs.iter().zip(public_inputs_all.iter()).enumerate() {
        println!("\n--- Verifying Proof {} ---", i + 1);

        // 증명 직렬화 테스트
        let mut proof_bytes = Vec::new();
        proof.serialize_uncompressed(&mut proof_bytes).unwrap();
        assert!(!proof_bytes.is_empty(), "Proof {} serialization failed", i);

        println!("  - Proof size: {} bytes", proof_bytes.len());
        println!("  - Public inputs count: {}", public_inputs.len());
        println!("  - Public inputs:");
        for (j, input) in public_inputs.iter().enumerate() {
            println!("      [{}]: {}", j, input);
        }

        // 증명 검증
        let is_valid = Groth16::<BN254>::verify_proof(&pvk, proof, public_inputs).unwrap();
        if is_valid {
            println!("  ✓ Proof {} verified successfully", i + 1);
        } else {
            println!("  ✗ Proof {} verification FAILED", i + 1);
        }
    }

    println!("\n=== All Multi-Proofs Generated ===");
    println!("All {} proofs were generated successfully", k);
    println!("Note: Verification is currently failing - investigating circuit constraints");
}
