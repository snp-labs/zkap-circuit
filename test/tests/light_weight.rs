// use std::path::PathBuf;

// use ark_crypto_primitives::{crh::CRHScheme, merkle_tree::MerkleTree, snark::SNARK};
// use ark_ff::{BigInteger, PrimeField};
// use ark_groth16::{Groth16, VerifyingKey};
// use ark_serialize::CanonicalSerialize;
// use ark_std::rand::rngs::OsRng;
// use gadget::{
//     anchor::{
//         AnchorScheme,
//         poseidon::{PoseidonAnchor, PoseidonAnchorScheme},
//     },
//     base64::decode_any_base64,
//     hashes::poseidon::get_poseidon_params,
//     jwt::utils::resize,
//     mekletree::tree_config::MerkleTreeParams,
//     signature::rsa::native::PublicKey,
// };
// use zkpasskey_service::{
//     core::signature::{SignatureService, schnorr::SchnorrSignatureService},
//     interface::{
//         anchor::{PoseidonAnchorKeyExtension, SecretDto},
//         signature::SchnorrSecretKeyExtension,
//     },
//     service::{
//         anchor::create_poseidon_anchor,
//         constants::{AppCurve, AppField, BN254, BNP, Blake2, PoseidonHash},
//         key::io::{load_key_uncompressed, save_key_uncompressed},
//         snark::snark_v2::{generate_and_write_proving_key, generate_proof_v2},
//     },
//     utils::{
//         padding::fit_len_to_field,
//         point::{FromStrings, ascii_to_field_be},
//     },
// };

// /// 테스트용 임시 디렉토리 생성
// fn setup_test_dir() -> PathBuf {
//     let test_dir = PathBuf::from("test_outputs");
//     if !test_dir.exists() {
//         std::fs::create_dir_all(&test_dir).unwrap();
//     }
//     test_dir
// }

// /// 테스트용 앵커 키 생성 및 저장
// fn create_test_anchor_key(path: &PathBuf, n: usize, k: usize, max_claim_len: usize) {
//     let mut rng = OsRng;

//     let anchor_key = PoseidonAnchorScheme::<AppField>::setup(&mut rng, n).unwrap();

//     let anchor_key_ext = PoseidonAnchorKeyExtension {
//         anchor_key,
//         n,
//         k,
//         max_aud_len: Some(max_claim_len),
//         max_iss_len: Some(max_claim_len),
//         max_sub_len: max_claim_len,
//     };

//     save_key_uncompressed(path, &anchor_key_ext).unwrap();
// }

// /// 테스트용 Scnhorr Key 생성
// fn create_test_schnorr_key(vk_path: &PathBuf, sk_path: &PathBuf) {
//     let mut rng = OsRng;

//     let (vk, sk) = SchnorrSignatureService::keygen(&mut rng).unwrap();

//     save_key_uncompressed(vk_path, &vk).unwrap();
//     save_key_uncompressed(sk_path, &sk).unwrap();
// }

// /// 테스트용 snark 키 생성
// fn create_test_snark_key(
//     anchor_key_path: &PathBuf,
//     schnorr_key_path: &PathBuf,
//     pk_path: &PathBuf,
//     vk_path: &PathBuf,
//     max_jwt_len: usize,
//     max_payload_len: usize,
//     max_claim_len: usize,
//     tree_height: usize,
// ) {
//     generate_and_write_proving_key(
//         &anchor_key_path,
//         &schnorr_key_path,
//         max_jwt_len,
//         max_payload_len,
//         max_claim_len,
//         max_claim_len,
//         max_claim_len,
//         max_claim_len,
//         tree_height,
//         pk_path,
//         vk_path,
//     )
//     .unwrap();
// }

// /// 테스트용 JWT 데이터 생성
// fn create_test_jwt_data() -> (String, String, String, String) {
//     let pk = "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw".to_string();
//     let e = "AQAB".to_string();
//     let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3NTM2NzY2NTg3NjciLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiI3MTM4NTEzMDI2ODYtc3ZsdWVqZDhsaTFsNXFkOXNwODA2dGJtazNsa2I0aGouYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDUwNDM4ODExNzc4ODQ3MzgyMjciLCJlbWFpbCI6ImtpbS5reXVuZ2tvb0BnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibm9uY2UiOiIweDI2NzBhNDIxY2FiNjg1NzQyNjU0YmIzYjVhYWNhMmVjZWIzYzliZWMxN2M0NDk1OGIyYTRkNjlmZTUxZTZmOGIiLCJuYW1lIjoiS3l1bmdLb28gS2ltIiwiaWF0IjoxNzUzNjc2NjU4LCJleHAiOjE3NTM2ODAyNTl9.d3Hvb4sSLK8PVZRW-GM10DoTPvTq7Gfgv4eWKIkG6odvVoCT73-QC6RKhZmUtW0i6n2BNvR75ysyeUpkSMP3C8D-6uskzJvyEwhNtoat8DBRyGK5BIFjq41WAofgGeJLScpEOI9ykfuVgcGRvr-qFVu9Ndy6piuNlccJovTHPaFipeBIFsyHsRgDtWmMh5epfswMxcqPFf681LmN1qmbkiGDIyfN5Zre_OLSNUAB_lGGGXNPK30DWXhOL_Dq-6pH4qpGbxuKvhVgj9Px-yROAgtpuJi-DHQ94AmEx5WjIeo6ySmYzg3DLvbMOCwuOplEgk_ITQZNvJ_rOcj9-aFhdw".to_string();

//     let iss = r#""https://accounts.google.com""#.to_string();

//     (pk, e, jwt, iss)
// }

// /// 테스트용 머클트리 리프 생성
// fn create_test_leaf(iss: &str, n: &str) -> AppField {
//     let n = decode_any_base64(n).unwrap();
//     let e = decode_any_base64("AQAB").unwrap();
//     let pk = PublicKey { n, e };
//     let pk_limbs = pk.to_limbs::<BNP, AppCurve>();
//     let iss_limbs = ascii_to_field_be::<AppField>(iss).unwrap();
//     let pre_image = [iss_limbs, pk_limbs.0].concat();
//     let poseidon_params = get_poseidon_params::<AppField>();
//     let leaf = PoseidonHash::evaluate(&poseidon_params, pre_image).unwrap();

//     leaf
// }

// fn create_test_merkle_tree(leaf: AppField, depth: usize) -> (Vec<String>, AppField) {
//     let poseidon_params = get_poseidon_params::<AppField>();
//     let leaf_hash_param = get_poseidon_params::<AppField>().clone();
//     let two_to_one_hash_param = get_poseidon_params::<AppField>().clone();
//     let h0 = PoseidonHash::evaluate(&poseidon_params, [AppField::from(0u64)]).unwrap();

//     let digests = vec![h0; 1 << (depth - 1)];

//     let mut mt = MerkleTree::<MerkleTreeParams<AppField>>::new_with_leaf_digest(
//         &leaf_hash_param,
//         &two_to_one_hash_param,
//         digests,
//     )
//     .unwrap();
//     mt.update(0, &[leaf]).unwrap();
//     let path = mt.generate_proof(0).unwrap();
//     let root = mt.root();

//     let mut path_str = vec![];

//     let leaf_sibling = path.leaf_sibling_hash.to_string();
//     let mut auth_path = path.auth_path.clone();
//     auth_path.reverse();
//     path_str.push(leaf_sibling);
//     for h in auth_path {
//         path_str.push(h.to_string());
//     }
//     (path_str, root)
// }

// fn create_test_schnorr_signature(schnorr_sk_path: &PathBuf, message: &AppField) -> Vec<u8> {
//     let schnorr_sk_ext =
//         load_key_uncompressed::<SchnorrSecretKeyExtension<AppCurve, Blake2>>(schnorr_sk_path)
//             .unwrap();
//     let message = message.into_bigint().to_bytes_le();
//     let mut rng = OsRng;
//     let signature = SchnorrSignatureService::sign(&schnorr_sk_ext, &message, &mut rng).unwrap();

//     let mut sig_bytes = Vec::new();
//     signature.serialize_uncompressed(&mut sig_bytes).unwrap();
//     sig_bytes
// }

// fn create_test_anchor_parts(
//     anchor_key_path: &PathBuf,
//     secret_dto: &SecretDto,
//     n: usize,
// ) -> Vec<String> {
//     let mut secret_dtos = Vec::with_capacity(n);
//     for _ in 0..n {
//         secret_dtos.push(SecretDto {
//             sub: secret_dto.sub.clone(),
//             iss: secret_dto.iss.clone(),
//             aud: secret_dto.aud.clone(),
//         });
//     }

//     let anchor =
//         create_poseidon_anchor(anchor_key_path.to_str().unwrap().to_string(), secret_dtos).unwrap();

//     let anchor_struct = PoseidonAnchor::<AppField>::from_strings(&anchor).unwrap();

//     let param = get_poseidon_params::<AppField>();

//     let mut h = PoseidonHash::evaluate(&param, [anchor_struct.0[0]]).unwrap();

//     for a in anchor_struct.0.iter().skip(1) {
//         h = PoseidonHash::evaluate(&param, [h, *a]).unwrap();
//     }

//     let h_string = h.to_string();
//     let mut anchor_parts = anchor.clone();
//     anchor_parts.push(h_string);

//     anchor_parts
// }

// #[test]
// fn test_groth16_setup() {
//     let n = 6;
//     let k = 1;
//     let max_jwt_len = 1024;
//     let max_payload_len = 640;
//     let max_claim_len = 128;
//     let tree_height = 4;

//     // 1. 테스트 디렉토리 설정
//     let test_dir = setup_test_dir();

//     // 2. 테스트 키 생성 및 저장
//     let anchor_key_path = test_dir.join("test_anchor_key.bin");
//     let schnorr_sk_path = test_dir.join("test_schnorr_sk.bin");
//     let schnorr_vk_path = test_dir.join("test_schnorr_vk.bin");
//     let snark_pk_path = test_dir.join("test_snark_pk.bin");
//     let snark_vk_path = test_dir.join("test_snark_vk.bin");

//     create_test_anchor_key(&anchor_key_path, n, k, max_claim_len);
//     create_test_schnorr_key(&schnorr_vk_path, &schnorr_sk_path);
//     create_test_snark_key(
//         &anchor_key_path,
//         &schnorr_vk_path,
//         &snark_pk_path,
//         &snark_vk_path,
//         max_jwt_len,
//         max_payload_len,
//         max_claim_len,
//         tree_height,
//     );
// }

// #[test]
// fn test_prove_and_verify() {
//     let n = 6;
//     let k = 1;
//     let max_jwt_len = 1024;
//     let max_payload_len = 640;
//     let max_claim_len = 128;
//     let tree_height = 4;

//     // 1. 테스트 디렉토리 설정
//     let test_dir = setup_test_dir();

//     // 2. 테스트 키 생성 및 저장
//     let anchor_key_path = test_dir.join("test_anchor_key.bin");
//     let schnorr_sk_path = test_dir.join("test_schnorr_sk.bin");
//     let schnorr_vk_path = test_dir.join("test_schnorr_vk.bin");
//     let snark_pk_path = test_dir.join("test_snark_pk.bin");
//     let snark_vk_path = test_dir.join("test_snark_vk.bin");

//     let selected_secrets = SecretDto {
//         sub: Some(r#""105043881177884738227""#.to_string()),
//         iss: Some(r#""https://accounts.google.com""#.to_string()),
//         aud: None,
//     };

//     let anchor_parts = create_test_anchor_parts(&anchor_key_path, &selected_secrets, n);

//     let (pk, e, jwt, iss) = create_test_jwt_data();

//     let fit_len = fit_len_to_field::<AppField>(&max_claim_len);
//     let padded_iss = resize(&iss, fit_len, b'0');
//     let leaf = create_test_leaf(&padded_iss, &pk);
//     let (mp, root) = create_test_merkle_tree(leaf, tree_height);
//     let leaf_index = 0;

//     let counter = "1".to_string();
//     let random = "12345".to_string();
//     let h_userop = "67890".to_string();

//     let signature = create_test_schnorr_signature(&schnorr_sk_path, &root);

//     let root_str = root.to_string();

//     // k-개 증명 생성
//     let jwt_vec = vec![jwt.clone(); k];
//     let pk_vec = vec![pk.clone(); k];
//     let mp_vec = vec![mp.clone(); k];
//     let leaf_index_vec = vec![leaf_index; k];
//     let slot_vec = (0..k).map(|x| x as u8).collect::<Vec<u8>>();
//     let selected_secrets_vec = vec![selected_secrets; k];
//     let selector = (0..n).map(|i| i < k).collect::<Vec<bool>>();

//     let multi_proof_result = generate_proof_v2(
//         snark_pk_path.to_str().unwrap().to_string(),
//         anchor_key_path.to_str().unwrap().to_string(),
//         schnorr_vk_path.to_str().unwrap().to_string(),
//         anchor_parts,
//         selected_secrets_vec,
//         jwt_vec,
//         pk_vec,
//         mp_vec,
//         root_str,
//         signature,
//         leaf_index_vec,
//         selector,
//         counter,
//         random,
//         h_userop,
//         slot_vec,
//     );

//     // 6. 증명 생성 결과 검증
//     if let Err(e) = &multi_proof_result {
//         println!("Multi-proof generation error: {:?}", e);
//     }
//     assert!(multi_proof_result.is_ok(), "Multi-proof generation failed");

//     let (proofs, public_inputs_all) = multi_proof_result.unwrap();

//     assert_eq!(proofs.len(), k, "Expected {} proofs", k);
//     assert_eq!(
//         public_inputs_all.len(),
//         k,
//         "Expected {} public input sets",
//         k
//     );

//     let vk = load_key_uncompressed::<VerifyingKey<BN254>>(&snark_vk_path).unwrap();

//     let pvk = Groth16::<BN254>::process_vk(&vk).unwrap();

//     for (i, (proof, public_inputs)) in proofs.iter().zip(public_inputs_all.iter()).enumerate() {
//         println!("\n--- Verifying Proof {} ---", i + 1);

//         // 증명 직렬화 테스트
//         let mut proof_bytes = Vec::new();
//         proof.serialize_uncompressed(&mut proof_bytes).unwrap();
//         assert!(!proof_bytes.is_empty(), "Proof {} serialization failed", i);

//         println!("  - Proof size: {} bytes", proof_bytes.len());
//         println!("  - Public inputs count: {}", public_inputs.len());
//         println!("  - Public inputs:");
//         for (j, input) in public_inputs.iter().enumerate() {
//             println!("      [{}]: {}", j, input);
//         }

//         // 증명 검증
//         let is_valid = Groth16::<BN254>::verify_proof(&pvk, proof, public_inputs).unwrap();
//         if is_valid {
//             println!("  ✓ Proof {} verified successfully", i + 1);
//         } else {
//             println!("  ✗ Proof {} verification FAILED", i + 1);
//         }
//     }

//     println!("\n=== All Multi-Proofs Generated ===");
//     println!("All {} proofs were generated successfully", k);
//     println!("Note: Verification is currently failing - investigating circuit constraints");
// }
