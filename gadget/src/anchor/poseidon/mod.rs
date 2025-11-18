pub mod constraints;

use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;

use crate::{
    anchor::{AnchorScheme, AnchorUtils, error::AnchorError},
    hashes::poseidon::get_poseidon_params,
    matrix::VandermondeMatrix,
};

// ==================== 핵심 데이터 구조 ====================

/// Poseidon Anchor 값 (길이: m = n - k + 1)
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchor<F: PrimeField>(pub Vec<F>);

impl<F: PrimeField> PoseidonAnchor<F> {
    pub fn new(values: Vec<F>) -> Self {
        Self(values)
    }

    pub fn empty(size: usize) -> Self {
        Self(vec![F::zero(); size])
    }
}

/// Poseidon Anchor 공개 키
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorPublicKey<F: PrimeField> {
    pub params: PoseidonConfig<F>,
}

/// Poseidon Anchor 시크릿 (길이: n)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorSecret<F: PrimeField>(pub Vec<F>);

impl<F: PrimeField> From<Vec<F>> for PoseidonAnchorSecret<F> {
    fn from(value: Vec<F>) -> Self {
        Self(value)
    }
}

/// Poseidon Anchor Witness
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorWitness<F: PrimeField> {
    /// 보조 벡터 a (크기: m = n - k + 1)
    pub a: Vec<F>,
    /// 벡터 b = a * Matrix (크기: n)
    pub b: Vec<F>,
    /// 해시된 시크릿 값들 (크기: n)
    /// selector가 1인 위치에만 해시 값, 나머지는 0
    pub h_known: Vec<F>,
}

impl<F: PrimeField> PoseidonAnchorWitness<F> {
    pub fn empty(n: usize, k: usize) -> Self {
        let m = n - k + 1;
        Self {
            a: vec![F::zero(); m],
            b: vec![F::zero(); n],
            h_known: vec![F::zero(); n],
        }
    }

    /// 분할 증명을 위한 부분 RHS 계산
    /// partial_rhs[i] = b[i] * h_known[i]
    pub fn compute_partial_rhs(&self) -> Vec<F> {
        self.b
            .iter()
            .zip(self.h_known.iter())
            .map(|(b_i, h_i)| *b_i * *h_i)
            .collect()
    }
}

// ==================== 해시 캐시 구조체 ====================

/// 시크릿 해싱 결과를 캐시하는 구조체
/// 중복 해싱을 방지하기 위함
#[derive(Clone, Debug)]
pub struct HashedSecretsCache<F: PrimeField> {
    /// 각 인덱스에 대한 해시 값 (H(index || secret))
    pub hashes: Vec<F>,
}

impl<F: PrimeField + Absorb> HashedSecretsCache<F> {
    /// 시크릿 벡터를 한 번에 해싱하여 캐시 생성
    pub fn new(params: &PoseidonConfig<F>, secrets: &[F]) -> Result<Self, AnchorError> {
        let hashes = secrets
            .iter()
            .enumerate()
            .map(|(i, &secret)| {
                let input = vec![F::from(i as u64), secret];
                CRH::<F>::evaluate(params, input)
                    .map_err(|_| AnchorError::CryptoError("Hash failed".to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { hashes })
    }

    /// 특정 인덱스의 해시 값 가져오기
    pub fn get(&self, index: usize) -> Option<F> {
        self.hashes.get(index).copied()
    }

    /// selector에 따라 h_known 벡터 구성
    /// selector가 1인 위치만 해시 값을 채우고 나머지는 0
    pub fn build_h_known(&self, selector: &[usize]) -> Result<Vec<F>, AnchorError> {
        if selector.len() != self.hashes.len() {
            return Err(AnchorError::DimensionMismatch(
                "Selector length must match secrets length".to_string(),
            ));
        }

        Ok(selector
            .iter()
            .enumerate()
            .map(|(i, &s)| if s == 1 { self.hashes[i] } else { F::zero() })
            .collect())
    }

    /// 전체 해시 벡터 반환
    pub fn as_vec(&self) -> &[F] {
        &self.hashes
    }
}

// ==================== Poseidon Anchor Scheme V3 ====================

pub struct PoseidonAnchorScheme<F: PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField + Absorb> AnchorUtils for PoseidonAnchorScheme<F> {
    type Field = F;

    fn inner_product(v1: &[Self::Field], v2: &[Self::Field]) -> Result<Self::Field, AnchorError> {
        if v1.len() != v2.len() {
            return Err(AnchorError::DimensionMismatch(
                "Inner product vectors must have the same length".to_string(),
            ));
        }

        let sum = v1
            .iter()
            .zip(v2.iter())
            .fold(F::zero(), |acc, (a, b)| acc + *a * *b);

        Ok(sum)
    }
}

impl<F: PrimeField + Absorb> AnchorScheme for PoseidonAnchorScheme<F> {
    type Anchor = PoseidonAnchor<F>;
    type PublicKey = PoseidonAnchorPublicKey<F>;
    type Matrix = VandermondeMatrix<F>;
    type Secret = PoseidonAnchorSecret<F>;
    type Witness = PoseidonAnchorWitness<F>;
    fn setup<R: Rng>(_rng: &mut R, _n: usize) -> Result<Self::PublicKey, AnchorError> {
        let params = get_poseidon_params();
        Ok(PoseidonAnchorPublicKey { params })
    }

    fn generate_anchor(
        pk: &Self::PublicKey,
        secrets: &Self::Secret,
        matrix: &Self::Matrix,
    ) -> Result<Self::Anchor, AnchorError> {
        let n = matrix.matrix[0].len();

        if secrets.0.len() != n {
            return Err(AnchorError::DimensionMismatch(format!(
                "Secrets length ({}) must match matrix n ({})",
                secrets.0.len(),
                n
            )));
        }

        // 시크릿 해싱 (한 번만 수행하고 캐시)
        let hashed_cache = HashedSecretsCache::new(&pk.params, &secrets.0)?;

        // 행렬-벡터 곱셈: Anchor = Matrix * h
        let anchor_values = matrix.multiply_vector(hashed_cache.as_vec())?;

        Ok(PoseidonAnchor::new(anchor_values))
    }

    fn generate_witness(
        pk: &Self::PublicKey,
        secrets: &Self::Secret,
        selector: &[usize],
        matrix: &Self::Matrix,
    ) -> Result<Self::Witness, AnchorError> {
        let n = matrix.matrix[0].len();

        if selector.len() != n {
            return Err(AnchorError::DimensionMismatch(format!(
                "Selector length ({}) must match matrix n ({})",
                selector.len(),
                n
            )));
        }

        // 1. 벡터 a 계산
        let vector_a = matrix.calculate_vector_a(selector)?;

        // 2. 벡터 b 계산: b = a * Matrix
        let vector_b = matrix.vector_multiply(&vector_a)?;

        // 3. 시크릿 해싱 및 h_known 벡터 구성 (한 번에 처리)
        let hashed_cache = HashedSecretsCache::new(&pk.params, &secrets.0)?;
        let h_known = hashed_cache.build_h_known(selector)?;

        Ok(PoseidonAnchorWitness {
            a: vector_a,
            b: vector_b,
            h_known,
        })
    }

    fn verify(anchor: &Self::Anchor, witness: &Self::Witness) -> Result<(), AnchorError> {
        // 검증: <a, Anchor> == <b, h_known>
        let lhs = Self::inner_product(&witness.a, &anchor.0)?;
        let rhs = Self::inner_product(&witness.b, &witness.h_known)?;

        if lhs == rhs {
            Ok(())
        } else {
            Err(AnchorError::VerificationFailed2)
        }
    }
}

// ==================== 유틸리티 함수 ====================

/// Anchor에서 올바른 인덱스를 찾는 최적화된 함수
///
/// 기존 get_indices를 별도 함수로 분리하여 책임을 명확히 함
pub fn find_valid_indices<F>(
    pk: &PoseidonAnchorPublicKey<F>,
    anchor: &PoseidonAnchor<F>,
    known_secrets: &PoseidonAnchorSecret<F>,
    matrix: &VandermondeMatrix<F>,
) -> Result<Vec<usize>, AnchorError>
where
    F: PrimeField + Absorb,
{
    let (n, k) = matrix.dimensions();
    // let m = n - k + 1;

    if known_secrets.0.len() != k {
        return Err(AnchorError::DimensionMismatch(format!(
            "Known secrets length ({}) must match k ({})",
            known_secrets.0.len(),
            k
        )));
    }

    // 최적화: 시크릿 해싱을 먼저 수행하여 재사용
    let _hashed_cache = HashedSecretsCache::new(&pk.params, &known_secrets.0)?;

    // n개 중 k개를 선택하는 모든 조합 생성
    let index_combinations = generate_combinations(n, k);

    // 각 조합에 대해 순열을 시도
    for index_combo in index_combinations {
        let secret_permutations = generate_permutations(&known_secrets.0);

        for secret_perm in &secret_permutations {
            // 전체 시크릿 벡터 재구성
            let (temp_secrets, selector) = reconstruct_full_secrets(n, &index_combo, secret_perm);

            // Witness 생성 및 검증
            let temp_secret = PoseidonAnchorSecret(temp_secrets);
            let witness =
                PoseidonAnchorScheme::<F>::generate_witness(pk, &temp_secret, &selector, matrix)?;

            if PoseidonAnchorScheme::<F>::verify(anchor, &witness).is_ok() {
                return Ok(index_combo);
            }
        }
    }

    Err(AnchorError::InvalidParameters(
        "No valid selector found".to_string(),
    ))
}

/// n개 중 k개를 선택하는 모든 조합 생성
fn generate_combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    if k > n {
        return vec![];
    }
    if k == 0 {
        return vec![vec![]];
    }
    if k == n {
        return vec![(0..n).collect()];
    }

    let mut result = Vec::new();
    let mut combination = vec![0; k];
    generate_combinations_helper(0, 0, n, k, &mut combination, &mut result);
    result
}

fn generate_combinations_helper(
    start: usize,
    depth: usize,
    n: usize,
    k: usize,
    combination: &mut Vec<usize>,
    result: &mut Vec<Vec<usize>>,
) {
    if depth == k {
        result.push(combination.clone());
        return;
    }

    for i in start..=(n - k + depth) {
        combination[depth] = i;
        generate_combinations_helper(i + 1, depth + 1, n, k, combination, result);
    }
}

/// 벡터의 모든 순열 생성
fn generate_permutations<F: Clone>(items: &[F]) -> Vec<Vec<F>> {
    if items.is_empty() {
        return vec![vec![]];
    }
    if items.len() == 1 {
        return vec![items.to_vec()];
    }

    let mut result = Vec::new();
    for i in 0..items.len() {
        let mut remaining = items.to_vec();
        let current = remaining.remove(i);

        for mut perm in generate_permutations(&remaining) {
            perm.insert(0, current.clone());
            result.push(perm);
        }
    }
    result
}

/// 인덱스 조합과 시크릿 순열로부터 전체 시크릿 벡터와 selector 재구성
fn reconstruct_full_secrets<F: PrimeField>(
    n: usize,
    indices: &[usize],
    secrets: &[F],
) -> (Vec<F>, Vec<usize>) {
    let mut full_secrets = vec![F::zero(); n];
    let mut selector = vec![0; n];

    for (i, &idx) in indices.iter().enumerate() {
        full_secrets[idx] = secrets[i];
        selector[idx] = 1;
    }

    (full_secrets, selector)
}

#[cfg(test)]
mod tests {
    use crate::matrix::VandermondeMatrix;

    use super::*;
    use ark_std::rand::thread_rng;

    type F = ark_bn254::Fr;
    type PAS = PoseidonAnchorScheme<F>;

    #[test]
    fn test_setup_v3() {
        let mut rng = thread_rng();
        let pk = PAS::setup(&mut rng, 6).unwrap();
        assert!(pk.params.alpha > 0);
    }

    #[test]
    fn test_hashed_secrets_cache() {
        let mut rng = thread_rng();
        let pk = PAS::setup(&mut rng, 6).unwrap();

        let secrets = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
        let cache = HashedSecretsCache::new(&pk.params, &secrets).unwrap();

        assert_eq!(cache.hashes.len(), 3);
        assert_ne!(cache.get(0).unwrap(), F::from(0u64));
    }

    #[test]
    fn test_generate_anchor_v3() {
        let mut rng = thread_rng();
        let n = 6;
        let k = 3;

        let pk = PAS::setup(&mut rng, n).unwrap();
        let matrix = VandermondeMatrix::<F>::new(n, k);

        let secrets = PoseidonAnchorSecret(vec![
            F::from(100u64),
            F::from(200u64),
            F::from(300u64),
            F::from(400u64),
            F::from(500u64),
            F::from(600u64),
        ]);

        let anchor = PAS::generate_anchor(&pk, &secrets, &matrix).unwrap();
        assert_eq!(anchor.0.len(), n - k + 1);
    }

    #[test]
    fn test_generate_witness_and_verify_v3() {
        let mut rng = thread_rng();
        let n = 6;
        let k = 3;

        let pk = PAS::setup(&mut rng, n).unwrap();
        let matrix = VandermondeMatrix::<F>::new(n, k);

        let secrets = PoseidonAnchorSecret(vec![
            F::from(100u64),
            F::from(200u64),
            F::from(300u64),
            F::from(400u64),
            F::from(500u64),
            F::from(600u64),
        ]);

        let anchor = PAS::generate_anchor(&pk, &secrets, &matrix).unwrap();

        // selector: 인덱스 1, 3, 4가 known
        let selector = vec![0, 1, 0, 1, 1, 0];
        let witness = PAS::generate_witness(&pk, &secrets, &selector, &matrix).unwrap();
        // 검증
        assert!(PAS::verify(&anchor, &witness).is_ok());
    }

    #[test]
    fn test_combinations_generation() {
        let combos = generate_combinations(4, 2);
        // C(4,2) = 6
        assert_eq!(combos.len(), 6);

        // 예상 조합들
        assert!(combos.contains(&vec![0, 1]));
        assert!(combos.contains(&vec![2, 3]));
    }

    #[test]
    fn test_permutations_generation() {
        let items = vec![1, 2, 3];
        let perms = generate_permutations(&items);
        // 3! = 6
        assert_eq!(perms.len(), 6);
    }
}
