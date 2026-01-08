use std::path::PathBuf;

use ark_crypto_primitives::{crh::CRHScheme, merkle_tree::Path, sponge::poseidon::PoseidonConfig};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_std::UniformRand;
use circuit::{ExposesPublicInputs, baerae::BaeraeLightWeightCircuit};
use common::{
    constants::{AnchorConfig, BN254, BNP, CG, F, PoseidonHash, ZkPasskeyConfig},
    field_parser::hex_decimal_to_field, io::load_key_uncompressed,
};
use gadget::{
    anchor::{
        AnchorUtils,
        poseidon::{
            PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorScheme, PoseidonAnchorSecret,
            build_anchor_witness,
        },
    },
    base64::{Base64Table, get_base64_table},
    hashes::poseidon::get_poseidon_params,
    matrix::VandermondeMatrix,
    mekletree::tree_config::MerkleTreeParams,
    utils::str_to_limbs,
};
use log;
use rand::rngs::OsRng;

use crate::{
    app::{
        anchor::anchor::{
            build_poseidon_anchor_from_strings_v3, derive_hashed_message_v2,
            derive_selector_from_secret_and_anchor,
        },
        jwt::builder::TokenBuilder,
    },
    error::ApplicationError,
    types::Secret,
};

#[derive(Clone)]
struct CommonInputs {
    root: F,
    h_sign_userop: F,
    block_timestamp: F,
    random: F,
    aud_list: Vec<F>,
}

/// Anchor 관련 계산 결과를 담는 컨텍스트
#[derive(Clone)]
struct AnchorContextV3 {
    poseidon_params: PoseidonConfig<F>,
    base64_table: Base64Table,
    h_ctx: F,
    lhs: F,
    h_aud_list: F,
    anchor: PoseidonAnchor<F>,
    hanchor: F,
    a: Vec<F>,
    partial_rhs_list: Vec<F>,
    current_idx_list: Vec<usize>,
    selectors: Vec<u8>,
    aud_list: Vec<F>,
}

pub fn generate_baerae_proof<Config: ZkPasskeyConfig>(
    pk_path: &PathBuf,
    jwts: Vec<String>,
    pk_ops: Vec<String>,
    mp: Vec<Vec<String>>,
    leaf_index: Vec<usize>,
    root: &str,
    anchor_parts: &[String],
    h_sign_userop: &str,
    block_timestamp: &str,
    random: &str,
    aud_list: &[String],
) -> Result<(Vec<Proof<BN254>>, Vec<Vec<F>>), ApplicationError> {
    log::info!("[ZKAP] Starting ZK proof generation (Optimized Split Flow)...");

    // 1. 입력 검증
    log::info!("[ZKAP] Step 1: Validating inputs...");
    validate_inputs::<Config>(&jwts, &pk_ops, &mp, &leaf_index, anchor_parts)?;
    log::info!("[ZKAP] Step 1 completed: Input validation passed");

    // [최적화] Step 2: Proving Key 로딩을 나중으로 미룸
    log::info!("[ZKAP] Step 2: Skipped PK loading for memory optimization");

    // 3. 공통 입력 파싱
    log::info!("[ZKAP] Step 3: Parsing common inputs...");
    let common_inputs =
        parse_common_inputs(root, h_sign_userop, block_timestamp, random, aud_list)?;
    log::info!("[ZKAP] Step 3 completed: Common inputs parsed");

    // 4. TokenBuilder 일괄 생성
    log::info!(
        "[ZKAP] Step 4: Creating TokenBuilders for {} JWTs...",
        jwts.len()
    );
    let builders: Vec<TokenBuilder> = jwts
        .iter()
        .map(|jwt| {
            TokenBuilder::new(jwt, Config::CLAIMS.to_vec())
                .map_err(|e| ApplicationError::InvalidFormat(format!("JWT parsing failed: {}", e)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    log::info!(
        "[ZKAP] Step 4 completed: {} TokenBuilders created",
        builders.len()
    );

    // 5. Anchor 컨텍스트 계산
    log::info!("[ZKAP] Step 5: Computing anchor context...");
    let anchor_ctx = compute_anchor_context::<Config>(
        anchor_parts,
        &builders,
        common_inputs.random,
        &common_inputs.aud_list,
    )?;
    log::info!("[ZKAP] Step 5 completed: Anchor context computed");

    // =========================================================================
    // Phase A: Witness & H Generation (PK 없이 수행)
    // =========================================================================
    log::info!("[ZKAP] Phase A: Generating Witnesses and H polynomials...");

    // 중간 결과를 저장할 구조체: (H, Instance, Witness)
    let mut intermediate_results = Vec::with_capacity(Config::K);
    let mut public_inputs_list = Vec::with_capacity(Config::K);

    for i in 0..Config::K {
        log::info!(
            "[ZKAP] Phase A.{}: Processing circuit for JWT {}...",
            i + 1,
            i
        );

        // 회로 생성에 필요한 데이터 준비
        let witness_data = builders[i].build::<Config>(&pk_ops[i]).map_err(|e| {
            ApplicationError::InvalidFormat(format!("Failed to build circuit witness: {}", e))
        })?;
        let li = leaf_index[i];
        let path = build_mp(&mp[i], li)?;

        // 클로저로 회로 팩토리 생성 (캡처된 데이터 사용)
        // Clone이 필요한 데이터들을 미리 복제
        let matrix = VandermondeMatrix::<F>::new(Config::N, Config::K);
        let anchor = PoseidonAnchor(anchor_ctx.anchor.0.clone());
        let ctx_clone = anchor_ctx.clone();
        let common_clone = common_inputs.clone();

        let circuit_factory = move || {
            BaeraeLightWeightCircuit::<CG, BNP, Config>::new(
                matrix.clone(),
                ctx_clone.poseidon_params.clone(),
                ctx_clone.base64_table.clone(),
                ctx_clone.hanchor,
                ctx_clone.h_ctx,
                common_clone.root,
                common_clone.h_sign_userop,
                common_clone.block_timestamp,
                ctx_clone.partial_rhs_list[i],
                ctx_clone.lhs,
                ctx_clone.h_aud_list,
                common_clone.random,
                li,
                path.clone(),
                anchor.clone(),
                witness_data.state.clone(),
                witness_data.nblocks,
                witness_data.claim_indices.clone(),
                witness_data.pay_offset_b64,
                witness_data.pay_len_b64,
                witness_data.sha_pad_payload_b64.clone(),
                witness_data.index_bits.clone(),
                witness_data.pk.clone(),
                witness_data.sig.clone(),
                ctx_clone.a.clone(),
                ctx_clone.selectors.clone(),
                ctx_clone.current_idx_list[i],
                ctx_clone.aud_list.clone(),
            )
        };

        // **핵심**: PK 없이 Part 1 실행
        #[cfg(feature = "use-optimized")]
        let (h, instance, witness) =
            Groth16::<BN254>::create_proof_part1_witness_h(circuit_factory)
                .map_err(|e| ApplicationError::InvalidFormat(format!("Part 1 failed: {}", e)))?;

        // Optimized가 아닐 경우를 위한 폴백 (일반 실행) - 이 경우 PK가 필요하므로 여기서는 에러처리하거나
        // 기존 로직을 타야하지만, 요청하신 맥락상 use-optimized가 활성화된 것으로 가정합니다.
        #[cfg(not(feature = "use-optimized"))]
        return Err(ApplicationError::InvalidFormat(
            "Split execution requires 'use-optimized' feature".into(),
        ));

        // Public Inputs 추출 (Instance의 1번째 요소부터)
        let public_inputs = instance[1..].to_vec();

        intermediate_results.push((h, instance, witness));
        public_inputs_list.push(public_inputs);

        log::info!(
            "[ZKAP] Phase A.{}: H & Witness generated. CS Dropped.",
            i + 1
        );
    }

    // =========================================================================
    // Phase B: Load PK & Generate Proofs (MSM)
    // =========================================================================
    log::info!("[ZKAP] Phase B: Loading Proving Key...");
    // CS가 모두 해제된 상태에서 PK 로드 (메모리 피크 방지)
    let pk = load_key_uncompressed::<ProvingKey<BN254>>(pk_path).map_err(|e| {
        log::error!("[ZKAP] Failed to load proving key: {}", e);
        ApplicationError::InvalidFormat(format!("Failed to load proving key: {}", e))
    })?;
    log::info!("[ZKAP] Proving Key loaded. Starting MSM...");

    let mut proofs = Vec::with_capacity(Config::K);
    let mut rng = OsRng;

    for (i, (h, instance, witness)) in intermediate_results.iter().enumerate() {
        log::info!("[ZKAP] Phase B.{}: Generating Proof (MSM)...", i + 1);

        let r = F::rand(&mut rng);
        let s = F::rand(&mut rng);

        // Part 2 실행
        let proof = Groth16::<BN254>::create_proof_part2_msm(&pk, r, s, h, instance, witness)
            .map_err(|e| ApplicationError::InvalidFormat(format!("Part 2 failed: {}", e)))?;

        proofs.push(proof);
        log::info!("[ZKAP] Phase B.{} completed.", i + 1);
    }

    log::info!(
        "[ZKAP] All steps completed successfully! Generated {} proofs",
        proofs.len()
    );
    Ok((proofs, public_inputs_list))
}

/// 단일 회로에 대한 증명 생성
#[allow(dead_code)]
fn generate_proof_internal<Config: ZkPasskeyConfig>(
    pk: &ProvingKey<BN254>,
    common: &CommonInputs,
    anchor_ctx: &AnchorContextV3,
    builder: &TokenBuilder,
    pk_op_str: &str,
    mp: &[String],
    leaf_index: usize,
    proof_idx: usize,
) -> Result<(Proof<BN254>, Vec<F>), ApplicationError> {
    log::info!("[ZKAP] Proof {}: Building witness...", proof_idx);

    // 1. Witness 생성 (builder.build() 호출)
    let witness = builder.build::<Config>(pk_op_str).map_err(|e| {
        log::error!(
            "[ZKAP] Proof {} failed: Failed to build circuit witness: {}",
            proof_idx,
            e
        );
        ApplicationError::InvalidFormat(format!("Failed to build circuit witness: {}", e))
    })?;
    log::info!("[ZKAP] Proof {}: Witness built successfully", proof_idx);

    // 2. Merkle Path 파싱
    log::info!("[ZKAP] Proof {}: Parsing Merkle path...", proof_idx);
    let path = build_mp(mp, leaf_index)?;
    log::info!("[ZKAP] Proof {}: Merkle path parsed", proof_idx);

    let matrix = VandermondeMatrix::<F>::new(Config::N, Config::K);
    let anchor = PoseidonAnchor(anchor_ctx.anchor.0.clone());

    // 4. 회로 생성
    log::info!("[ZKAP] Proof {}: Creating circuit...", proof_idx);
    let circuit = BaeraeLightWeightCircuit::<CG, BNP, Config>::new(
        matrix,
        anchor_ctx.poseidon_params.clone(),
        anchor_ctx.base64_table.clone(),
        anchor_ctx.hanchor,
        anchor_ctx.h_ctx,
        common.root,
        common.h_sign_userop,
        common.block_timestamp,
        anchor_ctx.partial_rhs_list[proof_idx],
        anchor_ctx.lhs,
        anchor_ctx.h_aud_list,
        common.random,
        leaf_index,
        path,
        anchor,
        witness.state,
        witness.nblocks,
        witness.claim_indices,
        witness.pay_offset_b64,
        witness.pay_len_b64,
        witness.sha_pad_payload_b64,
        witness.index_bits,
        witness.pk,
        witness.sig,
        anchor_ctx.a.clone(),
        anchor_ctx.selectors.clone(),
        anchor_ctx.current_idx_list[proof_idx],
        anchor_ctx.aud_list.clone(),
    );

    let public_inputs = circuit.public_inputs();

    // 5. 증명 생성 실행
    log::info!("[ZKAP] Proof {}: Generating proof...", proof_idx);
    let mut rng = OsRng;
    #[cfg(feature = "use-optimized")]
    let proof = Groth16::<BN254>::create_random_proof_two_pass(|| circuit.clone(), pk, &mut rng)
        .map_err(|e| {
            log::error!(
                "[ZKAP] Proof {} failed: Failed to create optimized proof: {}",
                proof_idx,
                e
            );
            ApplicationError::InvalidFormat(format!("Failed to create proof: {}", e))
        })?;
    log::info!(
        "[ZKAP] Proof {}: Optimized proof generated successfully",
        proof_idx
    );

    #[cfg(not(feature = "use-optimized"))]
    let proof = Groth16::<BN254>::prove(pk, circuit, &mut rng).map_err(|e| {
        log::error!(
            "[ZKAP] Proof {} failed: Failed to create standard proof: {}",
            proof_idx,
            e
        );
        ApplicationError::InvalidFormat(format!("Failed to create proof: {}", e))
    })?;
    log::info!(
        "[ZKAP] Proof {}: Standard proof generated successfully",
        proof_idx
    );

    log::info!("[ZKAP] Proof {} completed successfully", proof_idx);
    Ok((proof, public_inputs))
}

fn compute_anchor_context<Config: ZkPasskeyConfig>(
    anchor_parts: &[String],
    builders: &[TokenBuilder],
    random: F,
    aud_list: &[F],
) -> Result<AnchorContextV3, ApplicationError> {
    let poseidon_params = get_poseidon_params::<F>();
    let vandermonde_matrix = VandermondeMatrix::<F>::new(Config::N, Config::K);
    let base64_table = get_base64_table();

    let (anchor, hanchor) = build_poseidon_anchor_from_strings_v3(anchor_parts)?;

    // 1. Secret 추출
    // TokenBuilderV3.new에서 CLAIMS 순서대로 claims 벡터를 채웠으므로,
    // CLAIMS[i]가 "sub", "iss", "aud" 인지 확인하여 값을 매핑합니다.
    let secrets: Vec<Secret> = builders
        .iter()
        .map(|builder| {
            let mut sub = None;
            let mut iss = None;
            let mut aud = None;

            for (idx, key) in Config::CLAIMS.iter().enumerate() {
                // builder.claims[idx]는 CLAIMS[idx]에 해당하는 Claim 객체입니다.
                // Claim 객체의 `value` 필드에 파싱된 문자열 값이 들어있다고 가정합니다.
                let value = builder.claims[idx].value.clone();
                match *key {
                    "sub" => sub = Some(value),
                    "iss" => iss = Some(value),
                    "aud" => aud = Some(value),
                    _ => {} // 다른 claim은 anchor 해싱에 사용되지 않음
                }
            }

            // 필수 필드가 누락되었는지 확인
            let sub = sub.ok_or_else(|| {
                ApplicationError::InvalidFormat(
                    "Missing required claim 'sub' for anchor generation".to_string(),
                )
            })?;
            let iss = iss.ok_or_else(|| {
                ApplicationError::InvalidFormat(
                    "Missing required claim 'iss' for anchor generation".to_string(),
                )
            })?;
            let aud = aud.ok_or_else(|| {
                ApplicationError::InvalidFormat(
                    "Missing required claim 'aud' for anchor generation".to_string(),
                )
            })?;

            Ok::<Secret, ApplicationError>(Secret { sub, iss, aud })
        })
        .collect::<Result<Vec<Secret>, _>>()?;

    // 2. 해시된 메시지 생성
    let ctx = AnchorConfig::from_config::<Config>();
    let hashed_messages =
        derive_hashed_message_v2::<F, PoseidonHash>(&secrets, &poseidon_params, &ctx).map_err(
            |e| ApplicationError::InvalidFormat(format!("Failed to derive hashed messages: {}", e)),
        )?;

    // 3. Anchor Witness 생성
    let poseidon_key = PoseidonAnchorPublicKey {
        params: poseidon_params.clone(),
    };

    // hashed_messages를 복사하여 사용 (나중에 h_known 구성에 필요)
    let hashed_messages_clone = hashed_messages.clone();
    let secret_obj = PoseidonAnchorSecret(hashed_messages);

    // derive_selector_from_secret_and_anchor는 selector 벡터를 반환
    // 예: [1, 0, 1, 0, 1, 0] - 0번, 2번, 4번 위치에 시크릿이 있음
    let selectors = derive_selector_from_secret_and_anchor(
        &poseidon_key,
        &secret_obj.0,
        &anchor,
        &vandermonde_matrix,
    )?;

    // generate_witness를 호출하되, hashed_messages를 회로와 동일한 방식으로 해싱
    // 회로에서는 H(index, H(aud, iss, sub)) 형태로 계산하므로 동일하게 맞춰야 함
    let anchor_witness = build_anchor_witness(
        &poseidon_params,
        &hashed_messages_clone,
        &selectors,
        &vandermonde_matrix,
    )
    .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to build witness: {}", e)))?;

    // 4. Poseidon Hash 계산 (h_ctx, nullifier, etc)
    let mut h_ctx_inputs = anchor_witness.a.clone();
    h_ctx_inputs.push(random);
    let h_ctx = PoseidonHash::evaluate(&poseidon_params, h_ctx_inputs.as_slice())
        .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to compute h_ctx: {}", e)))?;

    let lhs = PoseidonAnchorScheme::<F>::inner_product(&anchor_witness.a, &anchor.0)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to compute lhs: {}", e)))?;
    let lhs = lhs * random;

    let mut aud_list_inputs = vec![];
    aud_list_inputs.extend_from_slice(aud_list);
    if aud_list.len() < Config::NUM_AUDIENCE_LIMIT {
        // aud_list가 부족한 경우 패딩 추가
        let padding_count = Config::NUM_AUDIENCE_LIMIT - aud_list.len();
        let forbidden_limbs = str_to_limbs::<F>(
            Config::FORBIDDEN_STRING,
            Config::MAX_AUD_LEN,
            Config::PAD_CHAR as u8,
        );
        let h_forbidden =
            PoseidonHash::evaluate(&poseidon_params, &*forbidden_limbs).map_err(|e| {
                ApplicationError::InvalidFormat(format!(
                    "Failed to compute forbidden aud hash: {}",
                    e
                ))
            })?;
        aud_list_inputs.extend_from_slice(&vec![h_forbidden; padding_count]);
    }

    let h_aud_list =
        PoseidonHash::evaluate(&poseidon_params, aud_list_inputs.as_slice()).map_err(|e| {
            ApplicationError::InvalidFormat(format!("Failed to compute h_aud_list: {}", e))
        })?;

    // 5. Partial RHS 계산
    let partial_rhs_all = anchor_witness.compute_partial_rhs();
    let partial_rhs_list: Vec<F> = partial_rhs_all
        .into_iter()
        .filter(|&x| x != F::from(0u8))
        .map(|x| x * random)
        .collect();

    let current_idx_list: Vec<usize> = selectors
        .iter()
        .enumerate()
        .filter_map(|(i, &sel)| if sel == 1 { Some(i) } else { None })
        .collect();

    Ok(AnchorContextV3 {
        poseidon_params,
        base64_table,
        h_ctx,
        lhs,
        h_aud_list,
        anchor,
        hanchor,
        a: anchor_witness.a,
        partial_rhs_list,
        current_idx_list,
        selectors,
        aud_list: aud_list_inputs,
    })
}

fn validate_inputs<Config: ZkPasskeyConfig>(
    jwts: &[String],
    pk_ops: &[String],
    mp: &[Vec<String>],
    leaf_index: &[usize],
    anchor_parts: &[String],
) -> Result<(), ApplicationError> {
    if jwts.len() != Config::K
        || pk_ops.len() != Config::K
        || mp.len() != Config::K
        || leaf_index.len() != Config::K
    {
        return Err(ApplicationError::InvalidFormat(format!(
            "All input vectors must have length K={}, got: jwts={}, pk_ops={}, mp={}, leaf_index={}",
            Config::K,
            jwts.len(),
            pk_ops.len(),
            mp.len(),
            leaf_index.len()
        )));
    }
    if anchor_parts.len() != (Config::N - Config::K + 1) + 1 {
        return Err(ApplicationError::InvalidFormat(
            "Invalid anchor_parts length".to_string(),
        ));
    }
    Ok(())
}

fn parse_common_inputs(
    root: &str,
    h_sign_userop: &str,
    block_timestamp: &str,
    random: &str,
    aud_list: &[String],
) -> Result<CommonInputs, ApplicationError> {
    Ok(CommonInputs {
        root: hex_decimal_to_field(root)
            .map_err(|_| ApplicationError::InvalidFormat("root".into()))?,
        h_sign_userop: hex_decimal_to_field(h_sign_userop)
            .map_err(|_| ApplicationError::InvalidFormat("h_sign_userop".into()))?,
        block_timestamp: hex_decimal_to_field(block_timestamp)
            .map_err(|_| ApplicationError::InvalidFormat("block_timestamp".into()))?,
        random: hex_decimal_to_field(random)
            .map_err(|_| ApplicationError::InvalidFormat("random".into()))?,
        aud_list: aud_list
            .iter()
            .map(|s| {
                hex_decimal_to_field(s)
                    .map_err(|_| ApplicationError::InvalidFormat("aud_list element".into()))
            })
            .collect::<Result<_, _>>()?,
    })
}

fn build_mp(
    path: &[String],
    leaf_idx: usize,
) -> Result<Path<MerkleTreeParams<F>>, ApplicationError> {
    let path_field: Vec<F> = path
        .iter()
        .map(|p_str| {
            hex_decimal_to_field(p_str)
                .map_err(|e| ApplicationError::InvalidFormat(format!("{:?}", e)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (leaf_sibling_hash, auth_path_slice) = path_field
        .split_first()
        .ok_or_else(|| ApplicationError::InvalidFormat("Empty merkle path".to_string()))?;

    Ok(Path {
        leaf_sibling_hash: *leaf_sibling_hash,
        auth_path: auth_path_slice.iter().rev().copied().collect(),
        leaf_index: leaf_idx,
    })
}
