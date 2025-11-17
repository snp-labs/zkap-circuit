use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    sponge::{
        Absorb, CryptographicSponge,
        poseidon::{PoseidonConfig, PoseidonSponge},
    },
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;

use crate::{
    anchor::{error::AnchorError, utils::{combinations, permute}, AnchorScheme},
    hashes::poseidon::get_poseidon_params,
    matrix::Matrix,
};

pub mod constraints;

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchor<F: PrimeField>(pub Vec<F>);

impl<F: PrimeField> PoseidonAnchor<F> {
    pub fn empty(n: usize) -> Self {
        PoseidonAnchor(vec![F::zero(); n])
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorPublicKey<F: PrimeField> {
    pub params: PoseidonConfig<F>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorSecret<F: PrimeField>(pub Vec<F>);

impl<F: PrimeField> From<Vec<F>> for PoseidonAnchorSecret<F> {
    fn from(value: Vec<F>) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorWitness<F: PrimeField> {
    pub u: Vec<F>,
    pub ut: Vec<F>,
    pub placed_secrets: Vec<F>,
    pub placed_indices: Vec<usize>,
}

impl<F> PoseidonAnchorWitness<F>
where
    F: PrimeField,
{
    pub fn empty(n: usize, k: usize) -> Self {
        Self {
            u: vec![F::zero(); n - k + 1],
            ut: vec![F::zero(); n],
            placed_secrets: vec![F::zero(); n],
            placed_indices: vec![1; k].into_iter().chain(vec![0; n - k]).collect(),
        }
    }
}

pub struct PoseidonAnchorScheme<F: PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F> PoseidonAnchorScheme<F>
where
    F: PrimeField + Absorb,
{
    fn aggregate(base: &[F], material: &[F]) -> Result<F, AnchorError> {
        if base.len() != material.len() {
            return Err(AnchorError::DimensionMismatch(
                "Base and material lengths must match".to_string(),
            ));
        }

        let result = inner_product(base, material)?;

        Ok(result)
    }
}

fn inner_product<F: PrimeField>(a: &[F], b: &[F]) -> Result<F, AnchorError> {
    if a.len() != b.len() {
        return Err(AnchorError::DimensionMismatch(
            "Inner product vectors must have the same length".to_string(),
        ));
    }
    Ok(a.iter().zip(b.iter()).map(|(x, y)| *x * *y).sum())
}

fn matrix_vector_mul<F: PrimeField>(
    matrix: &[Vec<F>],
    vector: &[F],
) -> Result<Vec<F>, AnchorError> {
    if !matrix.is_empty() && matrix[0].len() != vector.len() {
        return Err(AnchorError::DimensionMismatch(
            "Matrix and vector dimensions are incompatible".to_string(),
        ));
    }
    Ok(matrix
        .iter()
        .map(|row| inner_product(row, vector).unwrap_or_default())
        .collect())
}

fn hash_secret<F: PrimeField + Absorb>(params: &PoseidonConfig<F>, secret: F, index: usize) -> F {
    let mut sponge = PoseidonSponge::new(params);
    let inputs = vec![F::from(index as u64), secret];
    sponge.absorb(&inputs);
    let res = sponge.squeeze_field_elements::<F>(1);
    res[0]
}

impl<F: PrimeField + Absorb> AnchorScheme for PoseidonAnchorScheme<F> {
    type Scalar = F;
    type PublicKey = PoseidonAnchorPublicKey<F>;
    type Secret = PoseidonAnchorSecret<F>;
    type Anchor = PoseidonAnchor<F>;
    type Witness = PoseidonAnchorWitness<F>;

    fn setup<R: Rng>(_rng: &mut R, _n: usize) -> Result<Self::PublicKey, AnchorError> {
        let params = get_poseidon_params();
        Ok(PoseidonAnchorPublicKey { params })
    }

    fn generate_anchor(
        pk: &Self::PublicKey,
        secrets: &Self::Secret,
        matrix: &Matrix<Self::Scalar>,
    ) -> Result<Self::Anchor, AnchorError> {
        if secrets.0.len() != matrix.n {
            return Err(AnchorError::DimensionMismatch(
                "Secrets length must match matrix.n".to_string(),
            ));
        }
        let h: Vec<F> = secrets
            .0
            .iter()
            .enumerate()
            .map(|(i, s)| hash_secret(&pk.params, *s, i))
            .collect();
        matrix_vector_mul(&matrix.t_matrix, &h).map(PoseidonAnchor)
    }

    fn generate_witness(
        secrets: &Self::Secret,
        selector: &[usize],
        matrix: &Matrix<Self::Scalar>,
    ) -> Result<Self::Witness, AnchorError> {
        let (u, ut) = matrix.solution(&selector).map_err(|e| {
            AnchorError::CryptoError(format!("Failed to solve linear system: {:?}", e))
        })?;

        let poseidon_param = get_poseidon_params();

        let mut placed_secrets = vec![F::zero(); selector.len()];
        for (i, &sel) in selector.iter().enumerate() {
            if sel == 1 {
                let idx_field = F::from(i as u64);
                placed_secrets[i] =
                    CRH::<F>::evaluate(&poseidon_param, [idx_field, secrets.0[i]]).unwrap();
            }
        }

        Ok(PoseidonAnchorWitness {
            u,
            ut,
            placed_secrets,
            placed_indices: selector.to_vec(),
        })
    }

    fn verify(
        _pk: &Self::PublicKey,
        anchor: &Self::Anchor,
        witness: &Self::Witness,
    ) -> Result<(), AnchorError> {
        let lhs = Self::aggregate(&witness.u, &anchor.0)?;

        let mut h_known = vec![F::zero(); witness.ut.len()];
        // `witness.placed_secrets`에는 이미 해싱된 값이 들어 있습니다.
        for (i, pre_hashed_secret) in witness.placed_secrets.iter().enumerate() {
            let is_selected = witness.placed_indices[i];
            if is_selected == 1 {
                // ✅ 수정된 코드: 이미 해싱된 값을 그대로 사용합니다.
                h_known[i] = *pre_hashed_secret;
            }
        }

        let rhs = Self::aggregate(&witness.ut, &h_known)?;

        if lhs == rhs {
            Ok(())
        } else {
            Err(AnchorError::VerificationFailed(
                "LHS and RHS do not match".to_string(),
            ))
        }
    }

    /// ## 수정된 `get_indices` 함수
    /// 주어진 anchor와 k개의 secrets를 사용하여 원래의 위치(selector)를 찾습니다.
    fn get_indices(
        pk: &Self::PublicKey,
        anchor: &Self::Anchor,
        // 이 secrets는 사용자가 알고 있는 k개의 시크릿 값입니다.
        known_secrets: &Self::Secret,
        matrix: &Matrix<Self::Scalar>,
    ) -> Result<Vec<usize>, AnchorError> {
        let n = matrix.n;
        let k = matrix.k;

        // 사용자가 알고 있는 시크릿의 수가 k와 일치하는지 확인
        if known_secrets.0.len() != k {
            Err(AnchorError::DimensionMismatch(
                "Number of known secrets must match k".to_string(),
            ))?;
        }

        // 1. n개의 위치 중 k개를 선택하는 모든 인덱스 조합을 생성합니다.
        // 예: n=6, k=3 -> [[0,1,2], [0,1,3], ...]
        let index_combinations = combinations(n, k);

        // 2. 각 인덱스 조합에 대해 순열을 생성하고 검증을 시도합니다.
        for index_combo in index_combinations {
            // `known_secrets`의 모든 순열을 생성합니다.
            // 예: k=3 -> [[s0,s1,s2], [s0,s2,s1], [s1,s0,s2], ...]
            let secret_permutations = permute(&known_secrets.0);

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
                if let Ok(witness) = PoseidonAnchorScheme::generate_witness(
                    &PoseidonAnchorSecret(temp_secrets),
                    &selector,
                    matrix,
                ) {
                    if PoseidonAnchorScheme::verify(pk, anchor, &witness).is_ok() {
                        // 5. 검증에 성공하면, 올바른 위치 조합(selector)을 반환합니다.
                        return Ok(selector);
                    }
                }
            }
        }

        // 모든 조합을 시도했지만 실패한 경우
        Err(AnchorError::InvalidParameters(
            "No valid selector found".to_string(),
        ))
    }
}

pub fn hash_poseidon_anchor<F>(
    poseidon_param: &PoseidonConfig<F>,
    anchor: &Vec<F>,
) -> Result<F, AnchorError>
where
    F: PrimeField + Absorb,
{
    let mut h = CRH::<F>::evaluate(&poseidon_param, [anchor[0]])
        .map_err(|e| AnchorError::CryptoError(format!("Failed to hash anchor: {:?}", e)))?;
    for i in 1..anchor.len() {
        h = CRH::<F>::evaluate(&poseidon_param, [h, anchor[i]])
            .map_err(|e| AnchorError::CryptoError(format!("Failed to hash anchor: {:?}", e)))?;
    }
    Ok(h)
}

// --- 테스트 코드 ---
#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_std::{UniformRand, test_rng};

    use crate::{
        anchor::{
            AnchorScheme,
            error::AnchorError,
            poseidon::{PoseidonAnchorScheme, PoseidonAnchorSecret, PoseidonAnchorWitness},
        },
        matrix::Matrix,
    };

    #[test]
    fn test_poseidon_anchor_scheme_with_real_matrix() {
        let mut rng = test_rng();
        const N: usize = 6;
        const K: usize = 3;

        // 1. Setup
        let pk = PoseidonAnchorScheme::<Fr>::setup(&mut rng, N).unwrap();

        // 2. 비밀 값 및 실제 Matrix 생성
        let secrets: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();
        let secrets = PoseidonAnchorSecret(secrets);
        let matrix = Matrix::<Fr>::new(N, K).unwrap();

        // 3. Anchor 생성
        let anchor = PoseidonAnchorScheme::generate_anchor(&pk, &secrets, &matrix).unwrap();
        assert_eq!(anchor.0.len(), N - K + 1);

        // 4. Witness 생성 (실제 solution 메소드 사용)
        // k=3개 선택. n-k = 3개의 0이 있어야 함. m-1 = 4-1=3.
        let selector: Vec<usize> = vec![1, 1, 1, 0, 0, 0];
        assert_eq!(selector.iter().sum::<usize>(), K as usize);

        let witness = PoseidonAnchorScheme::generate_witness(&secrets, &selector, &matrix).unwrap();
        assert_eq!(witness.u.len(), N - K + 1);
        assert_eq!(witness.ut.len(), N);

        // 5. 검증
        let verification_result = PoseidonAnchorScheme::verify(&pk, &anchor, &witness);
        assert!(verification_result.is_ok());

        // 6. 실패 케이스 테스트 (잘못된 비밀 값)
        let mut wrong_witness = PoseidonAnchorWitness {
            u: witness.u.clone(),
            ut: witness.ut.clone(),
            placed_secrets: witness.placed_secrets.clone(),
            placed_indices: witness.placed_indices.clone(),
        };
        wrong_witness.placed_secrets[0] = Fr::rand(&mut rng); // 비밀 값 하나를 변경

        let failed_result = PoseidonAnchorScheme::verify(&pk, &anchor, &wrong_witness);
        assert!(failed_result.is_err());
        assert_eq!(
            failed_result.unwrap_err(),
            AnchorError::VerificationFailed("LHS and RHS do not match".to_string())
        );
    }

    // known_secrets의 순서가 원래 순서와 동일할 때 selector를 성공적으로 찾는지 확인
    #[test]
    fn test_get_indices_success() {
        let mut rng = test_rng();
        const N: usize = 6;
        const K: usize = 3;

        // 1. 공통 설정
        let pk = PoseidonAnchorScheme::<Fr>::setup(&mut rng, N).unwrap();
        let matrix = Matrix::<Fr>::new(N, K).unwrap();

        // 2. 전체 시크릿 벡터와 앵커 생성
        let all_secrets: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();
        let all_secrets = PoseidonAnchorSecret(all_secrets.clone());
        let anchor = PoseidonAnchorScheme::generate_anchor(&pk, &all_secrets, &matrix).unwrap();

        // 3. 실제 위치(selector)와 해당 위치의 시크릿(known_secrets) 정의
        let true_selector = vec![0, 1, 0, 1, 1, 0]; // 예시: 1, 3, 4번 인덱스에 시크릿이 있음
        let mut known_secrets = Vec::new();
        for i in 0..N {
            if true_selector[i] == 1 {
                known_secrets.push(all_secrets.0[i]);
            }
        }
        assert_eq!(known_secrets.len(), K);

        // 4. get_indices 함수 호출
        let found_selector_result = PoseidonAnchorScheme::get_indices(
            &pk,
            &anchor,
            &PoseidonAnchorSecret(known_secrets),
            &matrix,
        );

        // 5. 결과 검증
        assert!(
            found_selector_result.is_ok(),
            "Should find the correct selector"
        );
        assert_eq!(
            found_selector_result.unwrap(),
            true_selector,
            "Found selector should match the true selector"
        );
    }

    // known_secrets의 순서가 바뀌었을 때도 selector를 성공적으로 찾는지 확인
    #[test]
    fn test_get_indices_with_permuted_secrets() {
        let mut rng = test_rng();
        const N: usize = 6;
        const K: usize = 3;

        // 1. 공통 설정
        let pk = PoseidonAnchorScheme::<Fr>::setup(&mut rng, N).unwrap();
        let matrix = Matrix::<Fr>::new(N, K).unwrap();

        // 2. 전체 시크릿 벡터와 앵커 생성
        let all_secrets: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();
        let all_secrets = PoseidonAnchorSecret(all_secrets.clone());
        let anchor = PoseidonAnchorScheme::generate_anchor(&pk, &all_secrets, &matrix).unwrap();

        // 3. 실제 위치 및 시크릿 정의
        let true_selector = vec![1, 0, 1, 0, 0, 1]; // 예시: 0, 2, 5번 인덱스
        let mut original_known_secrets = Vec::new();
        for i in 0..N {
            if true_selector[i] == 1 {
                original_known_secrets.push(all_secrets.0[i]);
            }
        }

        // `known_secrets`의 순서를 일부러 섞음
        let permuted_known_secrets = vec![
            original_known_secrets[2],
            original_known_secrets[0],
            original_known_secrets[1],
        ];

        // 4. 순서가 섞인 시크릿으로 get_indices 함수 호출
        let found_selector_result = PoseidonAnchorScheme::get_indices(
            &pk,
            &anchor,
            &PoseidonAnchorSecret(permuted_known_secrets),
            &matrix,
        );

        // 5. 결과 검증
        assert!(
            found_selector_result.is_ok(),
            "Should find the selector even with permuted secrets"
        );
        assert_eq!(
            found_selector_result.unwrap(),
            true_selector,
            "Found selector should match the true selector"
        );
    }
}
