use ark_crypto_primitives::{crh::CRHScheme, sponge::Absorb};
use ark_ff::PrimeField;
use common::constants::{AnchorConfig, F, PoseidonHash, ZkPasskeyConfig};

use crate::{
    error::error::ApplicationError, interface::anchor::Secret,
    service::anchor::PoseidonAnchorService, utils::point::hex_decimal_to_field,
};

use gadget::{
    anchor::{
        AnchorScheme,
        error::AnchorError,
        poseidon::{
            PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorScheme, PoseidonAnchorSecret,
            build_anchor_witness,
        },
    },
    matrix::VandermondeMatrix,
};

pub fn create_poseidon_anchor<Config: ZkPasskeyConfig>(
    secrets: Vec<Secret>,
) -> Result<PoseidonAnchor<F>, ApplicationError> {
    let ctx = AnchorConfig::from_config::<Config>();

    let anchor_key = PoseidonAnchorService::setup();

    let hased_message =
        derive_hashed_message_v2::<F, PoseidonHash>(&secrets, &anchor_key.params, &ctx)?;

    let anchor_secret = PoseidonAnchorSecret(hased_message.into());

    let anchor = PoseidonAnchorService::generate_anchor(&anchor_key, &anchor_secret, &ctx.matrix)
        .map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to generate anchor: {}", e))
    })?;

    Ok(anchor)
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
    let hanchor = hex_decimal_to_field::<F>(hanchor_str).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to parse hanchor '{}': {}", hanchor_str, e))
    })?;

    // anchor 값들 파싱
    let anchor_values: Result<Vec<F>, _> = anchor_strings
        .iter()
        .enumerate()
        .map(|(i, s)| {
            hex_decimal_to_field::<F>(s).map_err(|e| {
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
) -> Result<Vec<u8>, ApplicationError> {
    let (_m, n) = matrix.dimensions();
    let k = matrix.k;

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

    // 2. 각 인덱스 조합에 대해 검증을 시도합니다.
    for index_combo in index_combinations {
        // 호출자가 제공한 시크릿 순서(known_secrets[i])가
        // 선택된 인덱스 순서(index_combo[i])와 1:1로 매핑된다고 가정합니다.

        // 3. selector 생성
        let mut selector = vec![0u8; n];
        for &position in &index_combo {
            selector[position] = 1;
        }

        // 4. witness를 구성하여 검증
        // known_secrets를 그대로 전달하여,
        // Anchor[index_combo[i]] == known_secrets[i] 인지 확인하게 됩니다.
        let witness =
            build_anchor_witness(&pk.params, known_secrets, &selector, matrix).map_err(|e| {
                ApplicationError::InvalidFormat(format!("Failed to build witness: {}", e))
            })?;

        if PoseidonAnchorScheme::verify(anchor, &witness).is_ok() {
            return Ok(selector);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::thread_rng;
    use gadget::anchor::poseidon::PoseidonAnchorScheme;

    type F = ark_bn254::Fr;

    #[test]
    fn test_derive_selector_from_secret_and_anchor() {
        let mut rng = thread_rng();
        let n = 6;
        let k = 2;

        // Setup
        let pk = PoseidonAnchorScheme::<F>::setup(&mut rng, n).unwrap();
        let matrix = VandermondeMatrix::<F>::new(n, k);

        // Create full secrets
        let all_secrets = vec![
            F::from(100u64),
            F::from(200u64),
            F::from(300u64),
            F::from(400u64),
            F::from(500u64),
            F::from(600u64),
        ];
        let secrets = PoseidonAnchorSecret(all_secrets.clone());

        // Generate anchor
        let anchor = PoseidonAnchorScheme::<F>::generate_anchor(&pk, &secrets, &matrix).unwrap();

        // Test case 1: known secrets at positions [1, 3, 4]
        let known_indices = vec![1, 3];
        let known_secrets: Vec<F> = known_indices.iter().map(|&i| all_secrets[i]).collect();

        let result = derive_selector_from_secret_and_anchor(&pk, &known_secrets, &anchor, &matrix);
        assert!(result.is_ok(), "Should find valid selector");

        let selector = result.unwrap();
        println!("Found selector: {:?}", selector);

        // Verify the selector matches expected indices
        let expected_selector = vec![0, 1, 0, 1, 0, 0];
        assert_eq!(
            selector, expected_selector,
            "Selector should match expected positions"
        );

        // Verify with witness generation
        // selector에 따라 선택된 시크릿만 추출
        let selected_secrets: Vec<F> = selector
            .iter()
            .enumerate()
            .filter_map(|(i, &s)| if s == 1 { Some(all_secrets[i]) } else { None })
            .collect();
        let selected_secrets_obj = PoseidonAnchorSecret(selected_secrets);
        let witness = PoseidonAnchorScheme::<F>::generate_witness(
            &pk,
            &selected_secrets_obj,
            &selector,
            &matrix,
        )
        .unwrap();
        assert!(
            PoseidonAnchorScheme::<F>::verify(&anchor, &witness).is_ok(),
            "Verification should succeed"
        );
    }

    #[test]
    fn test_derive_selector_from_secret_and_anchor_different_positions() {
        let mut rng = thread_rng();
        let n = 6;
        let k = 3;

        // Setup
        let pk = PoseidonAnchorScheme::<F>::setup(&mut rng, n).unwrap();
        let matrix = VandermondeMatrix::<F>::new(n, k);

        // Create full secrets
        let all_secrets = vec![
            F::from(111u64),
            F::from(222u64),
            F::from(333u64),
            F::from(444u64),
            F::from(555u64),
            F::from(666u64),
        ];
        let secrets = PoseidonAnchorSecret(all_secrets.clone());

        // Generate anchor
        let anchor = PoseidonAnchorScheme::<F>::generate_anchor(&pk, &secrets, &matrix).unwrap();

        // Test case 2: known secrets at positions [0, 2, 5]
        let known_indices = vec![0, 2, 5];
        let known_secrets: Vec<F> = known_indices.iter().map(|&i| all_secrets[i]).collect();

        let result = derive_selector_from_secret_and_anchor(&pk, &known_secrets, &anchor, &matrix);
        assert!(result.is_ok(), "Should find valid selector");

        let selector = result.unwrap();
        println!("Found selector: {:?}", selector);

        // Verify the selector matches expected indices
        let expected_selector = vec![1, 0, 1, 0, 0, 1];
        assert_eq!(
            selector, expected_selector,
            "Selector should match expected positions"
        );

        // Verify with witness generation
        // selector에 따라 선택된 시크릿만 추출
        let selected_secrets: Vec<F> = selector
            .iter()
            .enumerate()
            .filter_map(|(i, &s)| if s == 1 { Some(all_secrets[i]) } else { None })
            .collect();
        let selected_secrets_obj = PoseidonAnchorSecret(selected_secrets);
        let witness = PoseidonAnchorScheme::<F>::generate_witness(
            &pk,
            &selected_secrets_obj,
            &selector,
            &matrix,
        )
        .unwrap();
        assert!(
            PoseidonAnchorScheme::<F>::verify(&anchor, &witness).is_ok(),
            "Verification should succeed"
        );
    }

    #[test]
    fn test_derive_selector_from_secret_and_anchor_wrong_length() {
        let mut rng = thread_rng();
        let n = 6;
        let k = 3;

        // Setup
        let pk = PoseidonAnchorScheme::<F>::setup(&mut rng, n).unwrap();
        let matrix = VandermondeMatrix::<F>::new(n, k);

        // Create dummy anchor
        let dummy_anchor = PoseidonAnchor::new(vec![F::from(0u64); n - k + 1]);

        // Test with wrong number of known secrets (should fail)
        let wrong_known_secrets = vec![F::from(100u64), F::from(200u64)]; // Only 2 instead of 3

        let result = derive_selector_from_secret_and_anchor(
            &pk,
            &wrong_known_secrets,
            &dummy_anchor,
            &matrix,
        );
        assert!(
            result.is_err(),
            "Should fail with wrong number of known secrets"
        );
    }

    #[test]
    fn test_derive_selector_from_secret_and_anchor_no_match() {
        let mut rng = thread_rng();
        let n = 6;
        let k = 3;

        // Setup
        let pk = PoseidonAnchorScheme::<F>::setup(&mut rng, n).unwrap();
        let matrix = VandermondeMatrix::<F>::new(n, k);

        // Create full secrets
        let all_secrets = vec![
            F::from(100u64),
            F::from(200u64),
            F::from(300u64),
            F::from(400u64),
            F::from(500u64),
            F::from(600u64),
        ];
        let secrets = PoseidonAnchorSecret(all_secrets.clone());

        // Generate anchor
        let anchor = PoseidonAnchorScheme::<F>::generate_anchor(&pk, &secrets, &matrix).unwrap();

        // Test with completely wrong known secrets
        let wrong_known_secrets = vec![F::from(999u64), F::from(888u64), F::from(777u64)];

        let result =
            derive_selector_from_secret_and_anchor(&pk, &wrong_known_secrets, &anchor, &matrix);
        assert!(result.is_err(), "Should fail with no matching secrets");
    }
}
