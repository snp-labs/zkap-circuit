use std::path::PathBuf;

use ark_crypto_primitives::{crh::CRHScheme, snark::CircuitSpecificSetupSNARK};
use ark_groth16::{Groth16, Proof};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::rngs::OsRng;

use circuit::zkpasskey::{
    base::{BaseCircuitArgs, CircuitOps},
    opt_hash::{OptHashArgs, OptHashCircuit},
};
use gadget::{
    base64::get_base64_table, hashes::poseidon::get_poseidon_params, jwt::utils::find_claim_value,
    mekletree::MerkleCircuitInput, signature::schnorr::Signature,
};

use crate::{
    error::error::ApplicationError,
    interface::{
        anchor::{PoseidonAnchorKeyExtension, SecretDto},
        signature::SchnorrPublicKeyExtension,
        snark::{ProvingKeyExtension, ZkpasskeySetupRequestDto},
    },
    service::{
        anchor::anchor::{
            build_anchor_witness, build_poseidon_anchor_from_strings, derive_hashed_message,
        },
        constants::{AppCurve, AppField, BN254, BNP, Blake2, Blake2Gadget, CV, PoseidonHash},
        jwt::builder::{TokenBuilder, build_merkle_proof, build_slot_indices_and_h_slot_and_z},
        key::io::{load_key_uncompressed, save_key_uncompressed},
    },
    utils::{
        generator::SolidityContractGenerator,
        padding::{fit_len_to_field, pad_str}, point::str_to_field,
    },
};

/// Groth16 Proving Key 생성 및 저장
///
/// # Arguments
/// * `anchor_key_path` - Anchor Key 파일 경로
/// * `schnorr_key_path` - Schnorr Key 파일 경로
/// * `max_jwt_len` - JWT의 최대 길이
/// * `max_payload_len` - Payload의 최대 길이
/// * `max_aud_len` - Audience의 최대 길이
/// * `max_iss_len` - Issuer의 최대 길이
/// * `max_sub_len` - Subject의 최대 길이
/// * `tree_height` - Merkle tree 높이
/// * `out_path` - Proving Key를 저장할 경로
///
/// # Returns
/// * `Ok(())` - 성공 시
/// * `Err(ApplicationError)` - 실패 시
pub fn generate_and_write_proving_key(
    anchor_key_path: String,
    schnorr_key_path: String,
    max_jwt_len: usize,
    max_payload_len: usize,
    max_aud_len: usize,
    max_iss_len: usize,
    max_nonce_len: usize,
    max_sub_len: usize,
    tree_height: usize,
    out_path: String,
) -> Result<(), ApplicationError> {
    let mut rng = OsRng;

    // Anchor Key와 Schnorr Key 로드
    let anchor_key_ext = load_key_uncompressed::<PoseidonAnchorKeyExtension<AppField>>(
        &PathBuf::from(&anchor_key_path),
    )?;

    let schnorr_key_ext = load_key_uncompressed::<SchnorrPublicKeyExtension<AppCurve, Blake2>>(
        &PathBuf::from(&schnorr_key_path),
    )?;

    let num_per_block = 16;
    let poseidon_param = get_poseidon_params::<AppField>();
    let base64_table = get_base64_table();
    let keys = vec!["iss".to_string(), "nonce".to_string(), "sub".to_string()];

    let fit_max_aud_len = fit_len_to_field::<AppField>(&max_aud_len);
    let fit_max_iss_len = fit_len_to_field::<AppField>(&max_iss_len);
    let fit_max_sub_len = fit_len_to_field::<AppField>(&max_sub_len);

    let circuit_config = OptHashArgs::<AppCurve, Blake2> {
        base: BaseCircuitArgs::<AppCurve, Blake2> {
            n: anchor_key_ext.n,
            k: anchor_key_ext.k,
            num_per_block,
            max_jwt_len,
            max_payload_len,
            max_aud_len: fit_max_aud_len,
            max_iss_len: fit_max_iss_len,
            max_nonce_len,
            max_sub_len: fit_max_sub_len,
            tree_height,
            schnorr_param: schnorr_key_ext.params,
            schnorr_vk: schnorr_key_ext.vk,
            poseidon_param,
            base64_table,
            keys_len: keys.len(),
        },
        anchor_key: anchor_key_ext.anchor_key,
    };

    let circuit = OptHashCircuit::<AppCurve, Blake2, CV, Blake2Gadget, BNP>::empty(circuit_config);

    // Groth16 setup 수행
    let (pk, vk) = Groth16::<BN254>::setup(circuit.clone(), &mut rng)
        .map_err(|e| ApplicationError::SetupFailed(format!("Groth16 setup failed: {}", e)))?;

    println!("number of constraints: {}", circuit.get_constraints());

    // Proving Key Extension 생성
    let pk_ext = ProvingKeyExtension {
        pk,
        max_jwt_len,
        max_payload_len,
        max_aud_len,
        max_iss_len,
        max_nonce_len,
        max_sub_len,
        tree_height,
    };

    // Proving Key 저장
    let path = PathBuf::from(out_path.clone()).join("test_proving_key.bin");
    save_key_uncompressed(&path, &pk_ext)?;

    // .env 파일에서 Solidity Verifier 경로 읽기
    dotenv::dotenv().ok();
    let solidity_path = std::env::var("SOLIDITY_VERIFIER_PATH")
        .map_err(|_| ApplicationError::EnvVarNotFound("SOLIDITY_VERIFIER_PATH".to_string()))?;

    // Verifying Key를 Solidity 컨트랙트로 저장
    vk.generate_solidity(PathBuf::from(solidity_path));

    // Verifying Key 저장
    // Save the verifying key next to the proving key with a fixed name so tests
    // and consumers can find it (e.g. test_outputs/test_verifying_key.bin).
    let vk_path = PathBuf::from(out_path).join("test_verifying_key.bin");
    save_key_uncompressed(&vk_path, &vk)?;

    Ok(())
}

pub fn generate_multi_proof(
    pk_path: String,
    anchor_key_path: String,
    schnorr_key_path: String,
    anchor_parts: Vec<String>,
    selected_secrets: Vec<SecretDto>, // k개의 선택된 시크릿.
    jwt: Vec<String>,                 // k개의 jwt
    pk: Vec<String>,                  // k개의 pk
    mp: Vec<Vec<String>>,             // k개의 merkle path
    root: String,
    signature: Vec<u8>,
    leaf_index: Vec<u32>, // k개의 leaf index
    selector: Vec<bool>,  // [true, false, true, ...] 형태
    counter: String,
    random: String,
    h_userop: String,
    slot: Vec<usize>,
) -> Result<(Vec<Proof<BN254>>, Vec<Vec<AppField>>), ApplicationError> {
    // 기본 길이 검증
    let k = jwt.len();
    if k == 0 {
        return Err(ApplicationError::InvalidFormat(
            "No JWTs provided for multi-proof generation".to_string(),
        ));
    }

    if pk.len() != k || mp.len() != k || leaf_index.len() != k || slot.len() != k {
        return Err(ApplicationError::InvalidFormat(
            "Mismatched input lengths for multi-proof generation".to_string(),
        ));
    }

    let pk_ext = load_key_uncompressed::<ProvingKeyExtension<BN254>>(&PathBuf::from(&pk_path))?;
    let anchor_key_ext = load_key_uncompressed::<PoseidonAnchorKeyExtension<AppField>>(
        &PathBuf::from(&anchor_key_path),
    )?;
    let schnorr_key_ext = load_key_uncompressed::<SchnorrPublicKeyExtension<AppCurve, Blake2>>(
        &PathBuf::from(&schnorr_key_path),
    )?;

    let mut proofs: Vec<Proof<BN254>> = Vec::with_capacity(k);
    let mut public_inputs_all: Vec<Vec<AppField>> = Vec::with_capacity(k);

    for i in 0..k {
        let (proof, public_inputs) = generate_proof_internal(
            &pk_ext,
            &anchor_key_ext,
            &schnorr_key_ext,
            &anchor_parts,
            &selected_secrets,
            &jwt[i],
            &pk[i],
            &mp[i],
            &root,
            &signature,
            leaf_index[i],
            &selector,
            &counter,
            &random,
            &h_userop,
            slot[i],
        )?;
        proofs.push(proof);
        public_inputs_all.push(public_inputs);
    }

    Ok((proofs, public_inputs_all))
}

/// Groth16 증명 생성
///
/// 메모리 최적화를 위해 파일 경로를 직접 받아 필요할 때만 키를 로드합니다.
/// 모바일 환경에서는 Proving Key가 매우 크므로 메모리에 상주시키지 않고
/// 증명 생성 시에만 로드하여 사용 후 자동으로 해제됩니다.
///
/// # Arguments
/// * `pk_path` - Proving Key 파일 경로
/// * `anchor_key_path` - Anchor Key 파일 경로 (circuit constant 구성용)
/// * `schnorr_key_path` - Schnorr Key 파일 경로 (circuit constant 구성용)
/// * `witness` - 증명할 witness 데이터 (JWT, signature 등)
///
/// # Returns
/// * `Ok(Vec<u8>)` - 직렬화된 증명
/// * `Err(ApplicationError)` - 실패 시
///
/// # 메모리 최적화
/// - 파일에서 직접 로드하므로 KeyManager 캐시를 사용하지 않음
/// - 증명 생성 후 자동으로 메모리에서 해제
/// - 모바일 환경의 제한된 메모리에 적합
pub fn generate_proof(
    pk_path: String,
    anchor_key_path: String,
    schnorr_key_path: String,
    anchor_parts: Vec<String>,
    selected_secrets: Vec<SecretDto>, // k개의 선택된 시크릿.
    jwt: String,
    pk: String,
    mp: Vec<String>,
    root: String,
    signature: Vec<u8>,
    leaf_index: u32,
    selector: Vec<bool>, // [true, false, true, ...] 형태
    counter: String,
    random: String,
    h_userop: String,
    slot: usize,
) -> Result<(Proof<BN254>, Vec<AppField>), ApplicationError> {
    let pk_ext = load_key_uncompressed::<ProvingKeyExtension<BN254>>(&PathBuf::from(&pk_path))?;

    let anchor_key_ext = load_key_uncompressed::<PoseidonAnchorKeyExtension<AppField>>(
        &PathBuf::from(&anchor_key_path),
    )?;

    let schnorr_key_ext = load_key_uncompressed::<SchnorrPublicKeyExtension<AppCurve, Blake2>>(
        &PathBuf::from(&schnorr_key_path),
    )?;

    generate_proof_internal(
        &pk_ext,
        &anchor_key_ext,
        &schnorr_key_ext,
        &anchor_parts,
        &selected_secrets,
        &jwt,
        &pk,
        &mp,
        &root,
        &signature,
        leaf_index,
        &selector,
        &counter,
        &random,
        &h_userop,
        slot,
    )

    // let mut rng = OsRng;

    // // 키 파일들을 직접 로드 (캐싱하지 않음)
    // let pk_ext = load_key_uncompressed::<ProvingKeyExtension<BN254>>(&PathBuf::from(&pk_path))?;

    // let anchor_key_ext = load_key_uncompressed::<PoseidonAnchorKeyExtension<AppField>>(
    //     &PathBuf::from(&anchor_key_path),
    // )?;

    // let schnorr_key_ext = load_key_uncompressed::<SchnorrPublicKeyExtension<AppCurve, Blake2>>(
    //     &PathBuf::from(&schnorr_key_path),
    // )?;

    // // Circuit constant 구성
    // let num_per_block = 16;
    // let poseidon_param = get_poseidon_params::<AppField>();
    // let base64_table = get_base64_table();
    // let keys = vec!["iss".to_string(), "nonce".to_string(), "sub".to_string()];

    // let (anchor, hanchor) = build_poseidon_anchor_from_strings(&anchor_parts)?;

    // let root = str_to_field::<AppField>(&root)
    //     .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to parse root: {}", e)))?;

    // let h_userop = str_to_field::<AppField>(&h_userop)
    //     .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to parse h_userop: {}", e)))?;

    // let counter = str_to_field::<AppField>(&counter)
    //     .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to parse counter: {}", e)))?;

    // let random = str_to_field::<AppField>(&random)
    //     .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to parse random: {}", e)))?;

    // let slot_field = str_to_field::<AppField>(&slot.to_string())
    //     .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to parse slot: {}", e)))?;

    // let mut builder = TokenBuilder::new(&jwt, &pk).add_claims(keys.clone());

    // let token_claims = builder.build_claim_indices_v2().map_err(|e| {
    //     ApplicationError::InvalidFormat(format!("Failed to parse token claims: {}", e))
    // })?;

    // let token_sig = builder.build_token_sig().map_err(|e| {
    //     ApplicationError::InvalidFormat(format!("Failed to parse token signature: {}", e))
    // })?;

    // let token_payload = builder
    //     .build_token_payload_b64(pk_ext.max_jwt_len, pk_ext.max_payload_len)
    //     .map_err(|e| {
    //         ApplicationError::InvalidFormat(format!("Failed to parse token payload: {}", e))
    //     })?;

    // let hashed_messages = derive_hashed_message(
    //     &selected_secrets,
    //     Some(pk_ext.max_aud_len),
    //     Some(pk_ext.max_iss_len),
    //     pk_ext.max_sub_len,
    // )?;

    // let anchor_witness = build_anchor_witness(
    //     anchor_key_ext.n,
    //     anchor_key_ext.k,
    //     &hashed_messages,
    //     &selector,
    // )?;

    // let mut inp = vec![];
    // inp.extend(anchor_witness.placed_secrets.iter());
    // inp.push(random);
    // let h_x = PoseidonHash::evaluate(&poseidon_param, inp).map_err(|e| {
    //     ApplicationError::InvalidFormat(format!("Failed to evaluate h_x: {:?}", e.to_string()))
    // })?;

    // // Signature 디코딩 (바이트 배열에서 Signature 구조체로)
    // let schnorr_signature = Signature::<AppCurve>::deserialize_uncompressed(&signature[..])
    //     .map_err(|e| {
    //         ApplicationError::InvalidFormat(format!("Failed to deserialize signature: {}", e))
    //     })?;

    // let merkle_proof: MerkleCircuitInput<AppField> = {
    //     let pad_char = b'0';
    //     let claims = builder.build_claims().map_err(|e| {
    //         ApplicationError::InvalidFormat(format!("Failed to build claims: {}", e))
    //     })?;
    //     let iss = find_claim_value(&claims, "iss").map_err(|e| {
    //         ApplicationError::InvalidFormat(format!("Failed to find 'iss' claim: {}", e))
    //     })?;
    //     let fit_len = fit_len_to_field::<AppField>(&pk_ext.max_iss_len);
    //     let iss_padded = pad_str(iss, fit_len, pad_char);
    //     let e = "AQAB".to_string();
    //     build_merkle_proof(
    //         &poseidon_param,
    //         leaf_index as usize,
    //         &mp,
    //         &iss_padded,
    //         &pk,
    //         &e,
    //     )?
    // };

    // let (slot_indices, h_slot, z) =
    //     build_slot_indices_and_h_slot_and_z(&poseidon_param, &slot, &selector, &random)?;

    // let fit_max_aud_len = fit_len_to_field::<AppField>(&pk_ext.max_aud_len);
    // let fit_max_iss_len = fit_len_to_field::<AppField>(&pk_ext.max_iss_len);
    // let fit_max_sub_len = fit_len_to_field::<AppField>(&pk_ext.max_sub_len);

    // let circuit_args = OptHashArgs::<AppCurve, Blake2> {
    //     base: BaseCircuitArgs::<AppCurve, Blake2> {
    //         n: anchor_key_ext.n,
    //         k: anchor_key_ext.k,
    //         num_per_block,
    //         max_jwt_len: pk_ext.max_jwt_len,
    //         max_payload_len: pk_ext.max_payload_len,
    //         max_aud_len: fit_max_aud_len,
    //         max_iss_len: fit_max_iss_len,
    //         max_nonce_len: pk_ext.max_nonce_len,
    //         max_sub_len: fit_max_sub_len,
    //         tree_height: pk_ext.tree_height,
    //         schnorr_param: schnorr_key_ext.params,
    //         schnorr_vk: schnorr_key_ext.vk,
    //         poseidon_param,
    //         base64_table,
    //         keys_len: keys.len(),
    //     },
    //     anchor_key: anchor_key_ext.anchor_key,
    // };

    // // Circuit 구성
    // let circuit = OptHashCircuit::<AppCurve, Blake2, CV, Blake2Gadget, BNP>::empty(circuit_args)
    //     .with_hanchor(hanchor)
    //     .with_root(root)
    //     .with_nonce(h_userop)
    //     .with_counter(counter)
    //     .with_h_x(h_x)
    //     .with_slot(slot_field)
    //     .with_h_slot(h_slot)
    //     .with_signature(schnorr_signature)
    //     .with_random(random)
    //     .with_merkle_path(merkle_proof)
    //     .with_anchor(anchor)
    //     .with_anchor_witness(anchor_witness)
    //     .with_token_claim(token_claims)
    //     .with_token_payload(token_payload)
    //     .with_token_sig(token_sig)
    //     .with_z(z)
    //     .with_slot_indices(slot_indices);

    // // Circuit 검증
    // circuit.validate().map_err(|e| {
    //     ApplicationError::InvalidFormat(format!("Circuit validation failed: {}", e))
    // })?;

    // // Public inputs 추출
    // let public_inputs = circuit.get_public_inputs();

    // // Groth16 증명 생성
    // use ark_crypto_primitives::snark::SNARK;
    // let proof = Groth16::<BN254>::prove(&pk_ext.pk, circuit, &mut rng).map_err(|e| {
    //     ApplicationError::ProofGenerationFailed(format!("Proof generation failed: {}", e))
    // })?;

    // Ok((proof, public_inputs))
}

fn generate_proof_internal(
    pk_ext: &ProvingKeyExtension<BN254>,
    anchor_key_ext: &PoseidonAnchorKeyExtension<AppField>,
    schnorr_key_ext: &SchnorrPublicKeyExtension<AppCurve, Blake2>,
    anchor_parts: &[String],
    selected_secrets: &[SecretDto],
    jwt: &str,
    pk: &str,
    mp: &[String],
    root: &str,
    signature: &[u8],
    leaf_index: u32,
    selector: &[bool],
    counter: &str,
    random: &str,
    h_userop: &str,
    slot: usize,
) -> Result<(Proof<BN254>, Vec<AppField>), ApplicationError> {
    let mut rng = OsRng;

    // Circuit constant 구성
    let num_per_block = 16;
    let poseidon_param = get_poseidon_params::<AppField>();
    let base64_table = get_base64_table();
    let keys = vec!["iss".to_string(), "nonce".to_string(), "sub".to_string()];

    let (anchor, hanchor) = build_poseidon_anchor_from_strings(&anchor_parts)?;

    let root = str_to_field::<AppField>(&root)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to parse root: {}", e)))?;

    let h_userop = str_to_field::<AppField>(&h_userop)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to parse h_userop: {}", e)))?;

    let counter = str_to_field::<AppField>(&counter)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to parse counter: {}", e)))?;

    let random = str_to_field::<AppField>(&random)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to parse random: {}", e)))?;

    let slot_field = str_to_field::<AppField>(&slot.to_string())
        .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to parse slot: {}", e)))?;

    let mut builder = TokenBuilder::new(jwt, pk).add_claims(keys.clone());

    let token_claims = builder.build_claim_indices_v2().map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to parse token claims: {}", e))
    })?;

    let token_sig = builder.build_token_sig().map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to parse token signature: {}", e))
    })?;

    let token_payload = builder
        .build_token_payload_b64(pk_ext.max_jwt_len, pk_ext.max_payload_len)
        .map_err(|e| {
            ApplicationError::InvalidFormat(format!("Failed to parse token payload: {}", e))
        })?;

    let hashed_messages = derive_hashed_message(
        &selected_secrets,
        Some(pk_ext.max_aud_len),
        Some(pk_ext.max_iss_len),
        pk_ext.max_sub_len,
    )?;

    let anchor_witness = build_anchor_witness(
        anchor_key_ext.n,
        anchor_key_ext.k,
        &hashed_messages,
        &selector,
    )?;

    let mut inp = vec![];
    inp.extend(anchor_witness.placed_secrets.iter());
    inp.push(random);
    let h_x = PoseidonHash::evaluate(&poseidon_param, inp).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to evaluate h_x: {:?}", e.to_string()))
    })?;

    // Signature 디코딩 (바이트 배열에서 Signature 구조체로)
    let schnorr_signature = Signature::<AppCurve>::deserialize_uncompressed(&signature[..])
        .map_err(|e| {
            ApplicationError::InvalidFormat(format!("Failed to deserialize signature: {}", e))
        })?;

    let merkle_proof: MerkleCircuitInput<AppField> = {
        let pad_char = b'0';
        let claims = builder.build_claims().map_err(|e| {
            ApplicationError::InvalidFormat(format!("Failed to build claims: {}", e))
        })?;
        let iss = find_claim_value(&claims, "iss").map_err(|e| {
            ApplicationError::InvalidFormat(format!("Failed to find 'iss' claim: {}", e))
        })?;
        let fit_len = fit_len_to_field::<AppField>(&pk_ext.max_iss_len);
        let iss_padded = pad_str(iss, fit_len, pad_char);
        let e = "AQAB".to_string();
        build_merkle_proof(
            &poseidon_param,
            leaf_index as usize,
            mp,
            &iss_padded,
            pk,
            &e,
        )?
    };

    let (slot_indices, h_slot, z) =
        build_slot_indices_and_h_slot_and_z(&poseidon_param, &slot, selector, &random)?;

    let fit_max_aud_len = fit_len_to_field::<AppField>(&pk_ext.max_aud_len);
    let fit_max_iss_len = fit_len_to_field::<AppField>(&pk_ext.max_iss_len);
    let fit_max_sub_len = fit_len_to_field::<AppField>(&pk_ext.max_sub_len);

    let circuit_args = OptHashArgs::<AppCurve, Blake2> {
        base: BaseCircuitArgs::<AppCurve, Blake2> {
            n: anchor_key_ext.n,
            k: anchor_key_ext.k,
            num_per_block,
            max_jwt_len: pk_ext.max_jwt_len,
            max_payload_len: pk_ext.max_payload_len,
            max_aud_len: fit_max_aud_len,
            max_iss_len: fit_max_iss_len,
            max_nonce_len: pk_ext.max_nonce_len,
            max_sub_len: fit_max_sub_len,
            tree_height: pk_ext.tree_height,
            schnorr_param: schnorr_key_ext.params.clone(),
            schnorr_vk: schnorr_key_ext.vk,
            poseidon_param,
            base64_table,
            keys_len: keys.len(),
        },
        anchor_key: anchor_key_ext.anchor_key.clone(),
    };

    // Circuit 구성
    let circuit = OptHashCircuit::<AppCurve, Blake2, CV, Blake2Gadget, BNP>::empty(circuit_args)
        .with_hanchor(hanchor)
        .with_root(root)
        .with_nonce(h_userop)
        .with_counter(counter)
        .with_h_x(h_x)
        .with_slot(slot_field)
        .with_h_slot(h_slot)
        .with_signature(schnorr_signature)
        .with_random(random)
        .with_merkle_path(merkle_proof)
        .with_anchor(anchor)
        .with_anchor_witness(anchor_witness)
        .with_token_claim(token_claims)
        .with_token_payload(token_payload)
        .with_token_sig(token_sig)
        .with_z(z)
        .with_slot_indices(slot_indices);

    // Circuit 검증
    circuit.validate().map_err(|e| {
        ApplicationError::InvalidFormat(format!("Circuit validation failed: {}", e))
    })?;

    // Public inputs 추출
    let public_inputs = circuit.get_public_inputs();

    println!("number of constraints: {}", circuit.get_constraints());

    // Groth16 증명 생성
    use ark_crypto_primitives::snark::SNARK;
    let proof = Groth16::<BN254>::prove(&pk_ext.pk, circuit, &mut rng).map_err(|e| {
        ApplicationError::ProofGenerationFailed(format!("Proof generation failed: {}", e))
    })?;

    Ok((proof, public_inputs))
}

/// Groth16 증명 검증
///
/// # Arguments
/// * `vk_bytes` - 직렬화된 Verifying Key
/// * `proof_bytes` - 직렬화된 증명
/// * `public_inputs` - 공개 입력
///
/// # Returns
/// * `Ok(bool)` - 검증 결과 (true: 성공, false: 실패)
/// * `Err(ApplicationError)` - 오류 발생 시
pub fn verify_proof(
    vk_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    public_inputs: Vec<String>,
) -> Result<bool, ApplicationError> {
    // TODO: Verifying Key 역직렬화
    // let vk = deserialize_vk(&vk_bytes)?;

    // TODO: 증명 역직렬화
    // let proof = deserialize_proof(&proof_bytes)?;

    // TODO: 공개 입력 파싱
    // let inputs = parse_public_inputs(&public_inputs)?;

    // TODO: 증명 검증
    // let result = Groth16::<AppPairing>::verify(&vk, &inputs, &proof)?;

    // Ok(result)
    unimplemented!("Proof verification not yet implemented")
}

/// Setup 요청으로부터 키 생성 (Proving Key와 Verifying Key 동시 생성)
///
/// # Arguments
/// * `req` - Setup 요청 정보
/// * `pk_out_path` - Proving Key 저장 경로
/// * `vk_out_path` - Verifying Key 저장 경로
///
/// # Returns
/// * `Ok(())` - 성공 시
/// * `Err(ApplicationError)` - 실패 시
pub fn setup_keys(
    req: ZkpasskeySetupRequestDto,
    pk_out_path: String,
    vk_out_path: String,
) -> Result<(), ApplicationError> {
    let mut rng = OsRng;

    // TODO: Anchor Key와 Schnorr Key 로드
    // let anchor_key = load_key_uncompressed(&PathBuf::from(&req.anchor_key_path))?;
    // let schnorr_key = load_key_uncompressed(&PathBuf::from(&req.schnorr_key_path))?;

    // TODO: Circuit을 정의하고 setup을 수행
    // let circuit = YourCircuit::new(
    //     anchor_key,
    //     schnorr_key,
    //     req.max_jwt_len,
    //     req.max_payload_len,
    //     req.max_aud_len,
    //     req.max_iss_len,
    //     req.max_sub_len,
    //     req.tree_height,
    // );

    // let (pk, vk) = Groth16::<AppPairing>::setup(circuit, &mut rng)?;

    // TODO: Proving Key 저장
    // let pk_ext = ProvingKeyExtension {
    //     pk,
    //     max_jwt_len: req.max_jwt_len,
    //     max_payload_len: req.max_payload_len,
    //     max_aud_len: req.max_aud_len,
    //     max_iss_len: req.max_iss_len,
    //     max_sub_len: req.max_sub_len,
    //     tree_height: req.tree_height,
    // };
    // save_key_uncompressed(&PathBuf::from(pk_out_path), &pk_ext)?;

    // TODO: Verifying Key 저장
    // save_key_uncompressed(&PathBuf::from(vk_out_path), &vk)?;

    // Ok(())
    unimplemented!("Key setup not yet implemented")
}
