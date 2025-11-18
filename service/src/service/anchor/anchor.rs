use ark_crypto_primitives::{crh::CRHScheme, sponge::Absorb};
use ark_ff::PrimeField;

use crate::{
    config::AnchorConfig,
    error::error::ApplicationError,
    interface::anchor::Secret,
    service::{anchor::PoseidonAnchorService, constants::{AppField, PoseidonHash}},
    utils::point::str_to_field,
};

use gadget::{anchor::{AnchorScheme, error::AnchorError, poseidon::{PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorScheme, PoseidonAnchorSecret}}, matrix::VandermondeMatrix};

pub fn create_poseidon_anchor(secrets: Vec<Secret>) -> Result<Vec<String>, ApplicationError> {
    let ctx = AnchorConfig::default();

    let anchor_key = PoseidonAnchorService::setup();

    let hased_message =
        derive_hashed_message_v2::<AppField, PoseidonHash>(&secrets, &anchor_key.params, &ctx)?;

    let anchor_secret = PoseidonAnchorSecret(hased_message.into());

    let anchor = PoseidonAnchorService::generate_anchor(&anchor_key, &anchor_secret, &ctx.matrix)
        .map_err(|e| {
            ApplicationError::InvalidFormat(format!("Failed to generate anchor: {}", e))
        })?;
    let out = anchor.0.iter().map(|x| x.to_string()).collect();

    Ok(out)
}

/// Anchor를 문자열 배열로부터 빌드하는 최적화된 함수 V3
///
/// # Arguments
/// * `anchor_parts` - Anchor 값들과 hanchor를 포함하는 문자열 배열
///                    마지막 요소가 hanchor, 나머지가 anchor 값들
///
/// # Returns
/// (PoseidonAnchor, hanchor) 튜플
///
/// # 개선사항
/// - 더 명확한 에러 메시지
/// - 타입 안전성 향상
/// - 메모리 할당 최적화
pub fn build_poseidon_anchor_from_strings_v3<F: PrimeField>(
    anchor_parts: &[String],
) -> Result<(PoseidonAnchor<F>, F), ApplicationError> {
    if anchor_parts.is_empty() {
        return Err(ApplicationError::InvalidFormat(
            "Anchor parts cannot be empty".to_string(),
        ));
    }

    // 마지막 요소를 hanchor로 분리
    let (hanchor_str, anchor_strings) = anchor_parts.split_last().ok_or_else(|| {
        ApplicationError::InvalidFormat("Failed to split anchor parts".to_string())
    })?;

    // hanchor 파싱
    let hanchor = str_to_field::<F>(hanchor_str).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to parse hanchor '{}': {}", hanchor_str, e))
    })?;

    // anchor 값들 파싱
    let anchor_values: Result<Vec<F>, _> = anchor_strings
        .iter()
        .enumerate()
        .map(|(i, s)| {
            str_to_field::<F>(s).map_err(|e| {
                ApplicationError::InvalidFormat(format!(
                    "Failed to parse anchor value at index {}: '{}'- {}",
                    i, s, e
                ))
            })
        })
        .collect();

    let anchor = PoseidonAnchor::new(anchor_values?);

    Ok((anchor, hanchor))
}

/// secret을 기반으로 selector 벡터 생성
/// /// # Arguments
/// * secret - 시크릿 벡터
/// * anchor - 앵커 벡터
/// * matrix - Vandermonde 행렬
/// # Returns
/// 선택된 인덱스들의 벡터
pub fn derive_selector_from_secret_and_anchor<F: PrimeField + Absorb>(
    pk: &PoseidonAnchorPublicKey<F>,
    known_secrets: &[F],
    anchor: &PoseidonAnchor<F>,
    matrix: &VandermondeMatrix<F>,
) -> Result<Vec<usize>, ApplicationError> {
    let (m, n) = matrix.dimensions();
    let k = n - m + 1;

    // 사용자가 알고 있는 시크릿의 수가 k와 일치하는지 확인
    if known_secrets.len() != k {
        Err(AnchorError::DimensionMismatch(
            "Number of known secrets must match k".to_string(),
        ))
        .map_err(|e| ApplicationError::InvalidFormat(format!("{}", e)))?
    }

    // 1. n개의 위치 중 k개를 선택하는 모든 인덱스 조합을 생성합니다.
    // 예: n=6, k=3 -> [[0,1,2], [0,1,3], ...]
    let index_combinations = combinations(n, k);

    // 2. 각 인덱스 조합에 대해 순열을 생성하고 검증을 시도합니다.
    for index_combo in index_combinations {
        // `known_secrets`의 모든 순열을 생성합니다.
        // 예: k=3 -> [[s0,s1,s2], [s0,s2,s1], [s1,s0,s2], ...]
        let secret_permutations = permute(&known_secrets);

        for secret_perm in &secret_permutations {
            // 3. 현재의 인덱스 조합과 시크릿 순열로 전체 시크릿 벡터를 재구성합니다.
            let mut temp_secrets = vec![F::zero(); n];
            let mut selector = vec![0; n];

            for i in 0..k {
                let secret_val = secret_perm[i];
                let position = index_combo[i];
                temp_secrets[position] = secret_val;
                selector[position] = 1;
            }

            // 4. 재구성된 시크릿으로 witness를 생성하고 검증을 시도합니다.
            let temp_secret = PoseidonAnchorSecret(temp_secrets);
            let witness =
                PoseidonAnchorScheme::generate_witness(pk, &temp_secret, &selector, matrix)
                    .map_err(|_| {
                        ApplicationError::InvalidFormat(
                            "Failed to compute anchor witness".to_string(),
                        )
                    })?;
            if PoseidonAnchorScheme::verify(anchor, &witness).is_ok() {
                return Ok(index_combo);
            }
        }
    }

    // 모든 조합을 시도했지만 실패한 경우
    Err(AnchorError::InvalidParameters(
        "No valid selector found".to_string(),
    ))
    .map_err(|e| ApplicationError::InvalidFormat(format!("{}", e)))
}

pub fn derive_hashed_message_v2<F, CRH>(
    secrets: &[Secret],
    hash_params: &CRH::Parameters,
    ctx: &AnchorConfig,
) -> Result<Vec<F>, ApplicationError>
where
    F: PrimeField + Absorb,
    CRH: CRHScheme<Input = [F], Output = F>,
{
    secrets
        .iter()
        .map(|s| {
            let padded_message = s.concatenate(
                ctx.max_aud_len,
                ctx.max_iss_len,
                ctx.max_sub_len,
                ctx.pad_char,
            )?;
            let hashed = hash_single_message::<F, CRH>(&padded_message, hash_params)?;
            Ok(hashed)
        })
        .collect::<Result<Vec<F>, ApplicationError>>()
}

fn hash_single_message<F, CRH>(
    message: &str,
    hash_params: &CRH::Parameters,
) -> Result<F, ApplicationError>
where
    F: PrimeField + Absorb,
    CRH: CRHScheme<Input = [F], Output = F>,
{
    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;

    if message.len() % limb_width != 0 {
        return Err(ApplicationError::InvalidFormat(format!(
            "String length must be a multiple of limb width: {} % {} != 0",
            message.len(),
            limb_width
        )));
    }

    let num_limbs = message.len() / limb_width;
    let mut limbs = Vec::with_capacity(num_limbs);

    for chunk in message.as_bytes().chunks_exact(limb_width) {
        limbs.push(F::from_be_bytes_mod_order(chunk));
    }

    CRH::evaluate(hash_params, limbs).map_err(|e| ApplicationError::Other(e.to_string()))
}

// nCk 조합 생성기
fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    if k == 0 || k > n {
        return result;
    }
    let mut indices: Vec<usize> = (0..k).collect();
    loop {
        result.push(indices.clone());
        let mut i = k;
        while i > 0 {
            i -= 1;
            if indices[i] != i + n - k {
                break;
            }
        }
        if indices[0] == n - k {
            break;
        }
        indices[i] += 1;
        for j in i + 1..k {
            indices[j] = indices[j - 1] + 1;
        }
    }
    result
}

/// k개의 원소에 대한 모든 순열을 생성하는 헬퍼 함수
fn permute<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.is_empty() {
        return vec![vec![]];
    }
    let mut result = Vec::new();
    let n = items.len();
    let mut p: Vec<usize> = (0..=n).collect();
    let mut items_clone = items.to_vec();

    result.push(items_clone.clone());

    let mut i = 1;
    while i < n {
        p[i] -= 1;
        let j = if i % 2 == 1 { p[i] } else { 0 };
        items_clone.swap(i, j);
        result.push(items_clone.clone());
        i = 1;
        while i < n && p[i] == 0 {
            p[i] = i;
            i += 1;
        }
    }
    result
}
