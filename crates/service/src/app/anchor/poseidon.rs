use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use common::constants::{AnchorConfig, F, PoseidonHash, ZkPasskeyConfig};

use crate::{app::anchor::utils::derive_x_from_secret, error::ApplicationError, types::Secret};

use gadget::{
    anchor::{
        AnchorScheme,
        error::AnchorError,
        poseidon::{
            PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorScheme, PoseidonAnchorSecret,
            build_anchor_witness,
        },
    },
    hashes::poseidon::get_poseidon_params,
    matrix::VandermondeMatrix,
};

pub fn create_poseidon_anchor<Config: ZkPasskeyConfig>(
    secrets: Vec<Secret>,
) -> Result<PoseidonAnchor<F>, ApplicationError> {
    let ctx = AnchorConfig::from_config::<Config>();

    let anchor_key = PoseidonAnchorPublicKey {
        params: get_poseidon_params::<F>(),
    };

    let x_list: Vec<F> = secrets
        .iter()
        .map(|s| derive_x_from_secret::<F, PoseidonHash>(s, &anchor_key.params, &ctx))
        .collect::<Result<Vec<F>, ApplicationError>>()?;

    let anchor_secret = PoseidonAnchorSecret(x_list.into());

    let anchor = PoseidonAnchorScheme::generate_anchor(&anchor_key, &anchor_secret, &ctx.matrix)?;

    Ok(anchor)
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
