use std::ops::Mul;

use crate::{
    anchor::{AnchorScheme, error::AnchorError, utils::permute},
    matrix::Matrix,
};
use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use num::BigUint;
use num_integer::Integer;
use sha2::{Digest, Sha256};

pub mod constraints;

// DL 기반 구현체
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DLAnchorPublicKey<C: CurveGroup> {
    pub generators: Vec<C::Affine>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DLAnchor<C: CurveGroup>(pub Vec<C::Affine>);

impl<C: CurveGroup> DLAnchor<C> {
    pub fn empty(n: usize) -> Self {
        DLAnchor(vec![C::Affine::default(); n])
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DLAnchorWitness<C: CurveGroup> {
    pub u: Vec<C::ScalarField>,
    pub ut: Vec<C::ScalarField>,
    pub placed_secrets: Vec<C::ScalarField>,
    pub placed_indices: Vec<C::BaseField>,
    pub quotients: Vec<C::BaseField>,
    pub remainders: Vec<C::BaseField>,
}

impl<C> DLAnchorWitness<C>
where
    C: CurveGroup,
{
    pub fn empty(n: usize, k: usize) -> Self {
        Self {
            u: vec![C::ScalarField::default(); n - k + 1],
            ut: vec![C::ScalarField::default(); n],
            placed_secrets: vec![C::ScalarField::default(); n],
            placed_indices: vec![C::BaseField::from(1u8); k]
                .into_iter()
                .chain(vec![C::BaseField::from(0u8); n - k])
                .collect(),
            quotients: vec![C::BaseField::default(); n],
            remainders: vec![C::BaseField::default(); n],
        }
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DLAnchorSecret<C: CurveGroup>(pub Vec<C::ScalarField>);

impl<C: CurveGroup> From<Vec<C::ScalarField>> for DLAnchorSecret<C> {
    fn from(secrets_vec: Vec<C::ScalarField>) -> Self {
        DLAnchorSecret(secrets_vec)
    }
}

pub struct DLAnchorScheme<C: CurveGroup> {
    _phantom: std::marker::PhantomData<C>,
}

impl<C> DLAnchorScheme<C>
where
    C: CurveGroup,
{
    fn aggregate<B, M>(base: &B, material: &M) -> Result<C::Affine, AnchorError>
    where
        B: AsRef<[C::Affine]>,
        M: AsRef<[C::ScalarField]>,
    {
        let base = base.as_ref();
        let message = material.as_ref();

        if base.len() != message.len() {
            return Err(AnchorError::DimensionMismatch(
                "Base and message lengths must match".to_string(),
            ));
        }

        let bigints: Vec<<C::ScalarField as PrimeField>::BigInt> =
            message.iter().map(|s| s.into_bigint()).collect();
        Ok(C::msm_bigint(base, &bigints[..]).into_affine())
    }
}

impl<C> AnchorScheme for DLAnchorScheme<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
{
    type Scalar = C::ScalarField;
    type PublicKey = DLAnchorPublicKey<C>;
    type Secret = DLAnchorSecret<C>;
    type Anchor = DLAnchor<C>;
    type Witness = DLAnchorWitness<C>;

    /// `n`개의 랜덤한 그룹 생성자(generator)를 생성하여 공개키를 설정합니다.
    fn setup<R: Rng>(_rng: &mut R, n: usize) -> Result<Self::PublicKey, AnchorError> {
        const DST: &[u8] = b"DL_ANCHOR_SCHEME_GENERATORS";
        let generator = C::generator();

        let generators: Vec<C::Affine> = (0..n)
            .map(|i| {
                let mut hasher = Sha256::new();
                hasher.update(DST);
                hasher.update(&i.to_le_bytes());
                let hash_result = hasher.finalize();

                let scalar = C::ScalarField::from_be_bytes_mod_order(&hash_result);
                (generator * scalar).into_affine()
            })
            .collect();

        Ok(DLAnchorPublicKey { generators })
    }

    /// 비밀 값들을 각 생성자에 커밋한 후, MDS 행렬을 이용해 앵커를 생성합니다.
    fn generate_anchor(
        pk: &Self::PublicKey,
        secrets: &Self::Secret,
        matrix: &Matrix<Self::Scalar>,
    ) -> Result<Self::Anchor, AnchorError> {
        if secrets.0.len() != matrix.n || pk.generators.len() != matrix.n {
            return Err(AnchorError::DimensionMismatch(
                "Secrets, generators, and matrix dimensions must match".to_string(),
            ));
        }

        // 1. 각 비밀 값에 대한 개별 커밋먼트 s_g 생성: s_g_i = secret_i * G_i
        let s_g: Vec<C::Affine> = pk
            .generators
            .iter()
            .zip(secrets.0.iter())
            .map(|(g, s)| (*g * *s).into_affine())
            .collect();

        // 2. MDS 행렬을 이용해 앵커 생성: anchor_j = MSM(matrix_row_j, s_g)
        let anchor = matrix
            .t_matrix
            .iter()
            .map(|row| Self::aggregate(&s_g, row))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(DLAnchor(anchor))
    }

    /// `matrix.solution`을 이용해 `u`, `ut`를 계산하여 Witness를 생성합니다.
    fn generate_witness(
        secrets: &Self::Secret,
        selector: &[usize],
        matrix: &Matrix<Self::Scalar>,
    ) -> Result<Self::Witness, AnchorError> {
        let (u, ut) = matrix.solution(&selector).map_err(|e| {
            AnchorError::CryptoError(format!("Failed to solve linear system: {:?}", e))
        })?;

        let mut placed_secrets = vec![C::ScalarField::zero(); selector.len()];
        for (i, &sel) in selector.iter().enumerate() {
            if sel == 1 {
                placed_secrets[i] = secrets.0[i];
            }
        }

        let placed_indices = selector
            .iter()
            .map(|i| C::BaseField::from(*i as u64))
            .collect::<Vec<_>>();
        let (quotients, remainders) = mul_and_divide_by_scalar_modulus::<C>(&placed_secrets, &ut);

        Ok(DLAnchorWitness {
            u,
            ut,
            placed_secrets,
            placed_indices,
            quotients,
            remainders,
        })
    }

    /// MSM을 사용하여 검증 방정식 `MSM(u, anchor) == MSM(ut, c_known)`을 확인합니다.
    fn verify(
        pk: &Self::PublicKey,
        anchor: &Self::Anchor,
        witness: &Self::Witness,
    ) -> Result<(), AnchorError> {
        // 1. 좌변 계산: LHS = MSM(u, anchor)
        let lhs = Self::aggregate(&anchor.0, &witness.u)?;

        // 2. 공개된 비밀 값들로부터 희소 커밋먼트 벡터 c_known 생성

        let c_known: Vec<C::Affine> = pk
            .generators
            .iter()
            .zip(witness.placed_secrets.iter())
            .map(|(g, s)| g.mul(*s).into())
            .collect();

        // 3. 우변 계산: RHS = MSM(ut, c_known)
        let rhs = Self::aggregate(&c_known, &witness.ut)?;

        // 4. 좌변과 우변이 같은지 확인
        if lhs == rhs {
            Ok(())
        } else {
            Err(AnchorError::VerificationFailed(
                "LHS and RHS do not match".to_string(),
            ))
        }
    }

    fn get_indices(
        pk: &Self::PublicKey,
        anchor: &Self::Anchor,
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
        let index_combinations = crate::anchor::utils::combinations(n, k);

        // 2. 각 인덱스 조합에 대해 순열을 생성하고 검증을 시도합니다.
        for index_combo in index_combinations {
            // `known_secrets`의 모든 순열을 생성합니다.
            // 예: k=3 -> [[s0,s1,s2], [s0,s2,s1], [s1,s0,s2], ...]
            let secret_permutations = permute(&known_secrets.0);

            for secret_perm in &secret_permutations {
                // 3. 현재의 인덱스 조합과 시크릿 순열로 전체 시크릿 벡터를 재구성합니다.
                let mut temp_secrets = vec![C::ScalarField::zero(); n];
                let mut selector = vec![0; n];

                for i in 0..k {
                    let secret_val = secret_perm[i];
                    let position = index_combo[i];
                    temp_secrets[position] = secret_val;
                    selector[position] = 1;
                }

                // 4. 재구성된 시크릿으로 witness를 생성하고 검증을 시도합니다.
                if let Ok(witness) = DLAnchorScheme::generate_witness(
                    &DLAnchorSecret(temp_secrets),
                    &selector,
                    matrix,
                ) {
                    if DLAnchorScheme::verify(pk, anchor, &witness).is_ok() {
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

pub fn hash_dl_anchor<C>(
    poseidon_param: &PoseidonConfig<C::BaseField>,
    anchor: &Vec<C::Affine>,
) -> Result<C::BaseField, AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    C::Affine: AffineRepr,
{
    let slice_anchor: Vec<C::BaseField> = anchor
        .iter()
        .map(|affine| {
            affine.xy().ok_or_else(|| {
                AnchorError::CryptoError(
                    "Affine point at infinity found during hashing.".to_string(),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()? // `Result`들을 `Result<Vec<_>>`로 수집합니다.
        .into_iter()
        .flat_map(|(x, y)| vec![x, y])
        .collect();

    let mut h = CRH::<C::BaseField>::evaluate(&poseidon_param, [slice_anchor[0]])
        .map_err(|e| AnchorError::CryptoError(format!("Failed to hash anchor: {:?}", e)))?;
    for i in 1..slice_anchor.len() {
        h = CRH::<C::BaseField>::evaluate(&poseidon_param, [h, slice_anchor[i]])
            .map_err(|e| AnchorError::CryptoError(format!("Failed to hash anchor: {:?}", e)))?;
    }
    Ok(h)
}

fn mul_and_divide_by_scalar_modulus<C: CurveGroup>(
    a: &[C::ScalarField],
    b: &[C::ScalarField],
) -> (Vec<C::BaseField>, Vec<C::BaseField>)
where
    C::BaseField: PrimeField,
{
    let modulus = BigUint::from_bytes_le(&C::ScalarField::MODULUS.to_bytes_le());

    let mut quotients = Vec::new();
    let mut reminders = Vec::new();

    for (a_i, b_i) in a.iter().zip(b.iter()) {
        let a_biguint = BigUint::from_bytes_le(&a_i.into_bigint().to_bytes_le());
        let b_biguint = BigUint::from_bytes_le(&b_i.into_bigint().to_bytes_le());

        let product = a_biguint * b_biguint;
        let (q, r) = product.div_rem(&modulus);

        let q_basefield = C::BaseField::from_le_bytes_mod_order(&q.to_bytes_le());
        let r_basefield = C::BaseField::from_le_bytes_mod_order(&r.to_bytes_le());

        quotients.push(q_basefield);
        reminders.push(r_basefield);
    }

    (quotients, reminders)
}

// --- 테스트 코드 ---
#[cfg(test)]
mod tests {

    type C = ark_ed_on_bn254::EdwardsProjective;
    type Fr = ark_ed_on_bn254::Fr;
    use super::AnchorScheme;
    use super::{AnchorError, DLAnchorScheme, DLAnchorWitness};
    use crate::anchor::dl::DLAnchorSecret;
    use crate::matrix::Matrix;
    use ark_std::{UniformRand, test_rng};

    #[test]
    fn test_dl_anchor_scheme_flow() {
        let mut rng = test_rng();
        const N: usize = 6;
        const K: usize = 3;

        // 1. Setup
        let pk = DLAnchorScheme::<C>::setup(&mut rng, N).unwrap();
        assert_eq!(pk.generators.len(), N);

        // 2. 비밀 값 및 Matrix 생성
        let secrets: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();
        let secrets = DLAnchorSecret(secrets);
        let matrix = Matrix::<Fr>::new(N, K).unwrap();

        // 3. Anchor 생성
        let anchor = DLAnchorScheme::generate_anchor(&pk, &secrets, &matrix).unwrap();
        assert_eq!(anchor.0.len(), N - K + 1);

        // 4. Witness 생성
        let selector: Vec<usize> = vec![1, 1, 0, 0, 1, 0];
        let witness = DLAnchorScheme::generate_witness(&secrets, &selector, &matrix).unwrap();
        assert_eq!(witness.u.len(), N - K + 1);
        assert_eq!(witness.ut.len(), N);

        // 5. 검증 (성공 케이스)
        let verification_result = DLAnchorScheme::verify(&pk, &anchor, &witness);
        assert!(verification_result.is_ok());

        // 6. 실패 케이스 테스트 (잘못된 비밀 값)
        let mut wrong_witness = DLAnchorWitness {
            u: witness.u.clone(),
            ut: witness.ut.clone(),
            placed_secrets: witness.placed_secrets.clone(),
            placed_indices: witness.placed_indices.clone(),
            quotients: witness.quotients.clone(),
            remainders: witness.remainders.clone(),
        };
        wrong_witness.placed_secrets[0] = Fr::rand(&mut rng); // 비밀 값 하나를 의도적으로 변경

        let failed_result = DLAnchorScheme::verify(&pk, &anchor, &wrong_witness);
        assert!(failed_result.is_err());

        // 오류 타입이 VerificationFailed인지 확인
        match failed_result {
            Err(AnchorError::VerificationFailed(_)) => (), // 의도된 오류
            _ => panic!("Expected a VerificationFailed error"),
        }
    }

    #[test]
    fn test_get_indices_success() {
        let mut rng = test_rng();
        const N: usize = 6;
        const K: usize = 3;

        // 1. 공통 설정
        let pk = DLAnchorScheme::<C>::setup(&mut rng, N).unwrap();
        let matrix = Matrix::<Fr>::new(N, K).unwrap();

        // 2. 전체 시크릿 벡터와 앵커 생성
        let all_secrets = DLAnchorSecret((0..N).map(|_| Fr::rand(&mut rng)).collect());

        let anchor = DLAnchorScheme::generate_anchor(&pk, &all_secrets, &matrix).unwrap();

        // 3. 실제 위치(selector)와 해당 위치의 시크릿(known_secrets) 정의
        let true_selector = vec![0, 1, 0, 1, 1, 0]; // 예시: 1, 3, 4번 인덱스
        let mut known_secrets = Vec::new();
        for i in 0..N {
            if true_selector[i] == 1 {
                known_secrets.push(all_secrets.0[i]);
            }
        }
        assert_eq!(known_secrets.len(), K);

        // 4. get_indices 함수 호출
        let found_selector_result =
            DLAnchorScheme::get_indices(&pk, &anchor, &DLAnchorSecret(known_secrets), &matrix);

        // 5. 결과 검증
        assert!(
            found_selector_result.is_ok(),
            "Should find the correct selector. Error: {:?}",
            found_selector_result.err()
        );
        assert_eq!(
            found_selector_result.unwrap(),
            true_selector,
            "Found selector should match the true selector"
        );
    }

    #[test]
    fn test_get_indices_with_permuted_secrets() {
        let mut rng = test_rng();
        // 계산 시간을 줄이기 위해 N과 K를 약간 줄여서 테스트
        const N: usize = 5;
        const K: usize = 3;

        // 1. 공통 설정
        let pk = DLAnchorScheme::<C>::setup(&mut rng, N).unwrap();
        let matrix = Matrix::<Fr>::new(N, K).unwrap();

        // 2. 전체 시크릿 벡터와 앵커 생성
        let all_secrets: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();
        let all_secrets = DLAnchorSecret(all_secrets);
        let anchor = DLAnchorScheme::generate_anchor(&pk, &all_secrets, &matrix).unwrap();

        // 3. 실제 위치 및 시크릿 정의
        let true_selector = vec![1, 0, 1, 0, 1]; // 예시: 0, 2, 4번 인덱스
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
        let found_selector_result = DLAnchorScheme::get_indices(
            &pk,
            &anchor,
            &DLAnchorSecret(permuted_known_secrets),
            &matrix,
        );

        // 5. 결과 검증
        assert!(
            found_selector_result.is_ok(),
            "Should find the selector even with permuted secrets. Error: {:?}",
            found_selector_result.err()
        );
        assert_eq!(
            found_selector_result.unwrap(),
            true_selector,
            "Found selector should match the true selector"
        );
    }
}
