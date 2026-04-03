use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use num::BigUint;
use num_integer::Integer;

use crate::{anchor::error::AnchorError, utils::str_to_fields};

#[allow(clippy::type_complexity)]
pub fn process_secrets_vec<C, CRH>(
    secrets: &[String],
    hash_param: &<CRH as CRHScheme>::Parameters,
) -> Result<(Vec<C::BaseField>, Vec<C::ScalarField>), AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CRH: CRHScheme<
            Input = [C::BaseField],
            Output = C::BaseField,
            Parameters = PoseidonConfig<C::BaseField>,
        >,
{
    // 1. `iter()`로 벡터의 각 요소에 접근합니다.
    // 2. `map()`으로 각 secret에 대해 `process_secret` 함수를 호출합니다.
    //    이 단계의 결과는 `Result<(Q, R), Error>` 값들을 생성하는 이터레이터입니다.
    let results_iterator = secrets
        .iter()
        .map(|s| process_secret::<C, CRH>(s, hash_param));

    // 3. `collect::<Result<Vec<_>, _>>()`를 사용하여 이터레이터의 모든 Result 값을 하나의 Result로 합칩니다.
    //    - 모든 요소가 Ok이면 `Ok(Vec<(Q, R)>)`이 됩니다.
    //    - 하나라도 Err가 있으면 전체가 그 `Err` 값을 즉시 반환합니다.
    let collected_results: Vec<(C::BaseField, C::ScalarField)> =
        results_iterator.collect::<Result<_, _>>()?;

    // 4. `unzip()`을 사용하여 `Vec<(Q, R)>` 형태의 벡터를 `(Vec<Q>, Vec<R>)` 형태의 튜플로 변환합니다.
    let (q_fields, r_fields): (Vec<_>, Vec<_>) = collected_results.into_iter().unzip();

    Ok((q_fields, r_fields))
}

pub fn process_secret<C, CRH>(
    secret: &str,
    hash_param: &<CRH as CRHScheme>::Parameters,
) -> Result<(C::BaseField, C::ScalarField), AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CRH: CRHScheme<
            Input = [C::BaseField],
            Output = C::BaseField,
            Parameters = PoseidonConfig<C::BaseField>,
        >,
{
    let secret = str_to_fields::<C::BaseField>(secret);
    let (q, r) = hash_and_divide_by_scalar_modulus::<C, CRH>(&secret, hash_param)?;

    let q_field = <C::BaseField as PrimeField>::from_le_bytes_mod_order(&q);
    let r_field = <C::ScalarField as PrimeField>::from_le_bytes_mod_order(&r);

    Ok((q_field, r_field))
}

pub fn process_secrets_poseidon<C>(
    secrets: &[String],
    poseidon_param: &PoseidonConfig<C::BaseField>,
) -> Result<Vec<C::BaseField>, AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    process_no_tk_secrets::<C, CRH<C::BaseField>>(secrets, poseidon_param)
}

pub fn process_no_tk_secrets<C, CRH>(
    secrets: &[String],
    hash_param: &CRH::Parameters,
) -> Result<Vec<C::BaseField>, AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CRH: CRHScheme<Input = [C::BaseField], Output = C::BaseField>,
{
    secrets
        .iter()
        .map(|s| process_no_tk_secret::<C, CRH>(s, hash_param))
        .collect()
}

pub fn process_no_tk_secret<C, CRH>(
    secret: &str,
    hash_param: &CRH::Parameters,
) -> Result<C::BaseField, AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CRH: CRHScheme<Input = [C::BaseField], Output = C::BaseField>,
{
    let secret = str_to_fields::<C::BaseField>(secret);
    let secret = CRH::evaluate(hash_param, &*secret)
        .map_err(|e| AnchorError::CryptoError(format!("Hash failed: {}", e)))?;

    Ok(secret)
}

pub fn divide_by_scalar_modulus<C: CurveGroup>(a: C::BaseField) -> (Vec<u8>, Vec<u8>)
where
    C::BaseField: PrimeField,
{
    let modulus = C::ScalarField::MODULUS;
    let modulus = BigUint::from_bytes_le(&modulus.to_bytes_le());

    let a_bigint = BigUint::from_bytes_le(&a.into_bigint().to_bytes_le());

    let (q, r) = a_bigint.div_rem(&modulus);

    (q.to_bytes_le(), r.to_bytes_le())
}

pub fn hash_and_divide_by_scalar_modulus<C, CRH>(
    elements_to_hash: &[C::BaseField],
    crh_parameters: &CRH::Parameters,
) -> Result<(Vec<u8>, Vec<u8>), AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CRH: CRHScheme<Input = [C::BaseField], Output = C::BaseField>,
{
    // 2. 변환된 원소들을 해시합니다.
    let hash_output = CRH::evaluate(crh_parameters, elements_to_hash)
        .map_err(|e| AnchorError::CryptoError(format!("Hash failed: {}", e)))?;

    // 3. 해시 결과(BaseField)를 최종 목표인 ScalarField 타입으로 변환합니다.
    let (q, r) = divide_by_scalar_modulus::<C>(hash_output);

    // 4. 결과를 반환합니다.
    Ok((q, r))
}

pub fn mul_and_divide_by_scalar_modulus<C: CurveGroup>(
    a: C::ScalarField,
    b: C::ScalarField,
) -> (Vec<u8>, Vec<u8>, Vec<u8>)
where
    C::BaseField: PrimeField,
{
    let modulus = C::ScalarField::MODULUS;
    let modulus = BigUint::from_bytes_le(&modulus.to_bytes_le());

    let a_bigint = BigUint::from_bytes_le(&a.into_bigint().to_bytes_le());
    let b_bigint = BigUint::from_bytes_le(&b.into_bigint().to_bytes_le());

    let product = a_bigint * b_bigint;
    let (q, r) = product.div_rem(&modulus);

    (product.to_bytes_le(), q.to_bytes_le(), r.to_bytes_le())
}

pub fn mul_and_divide_by_scalar_modulus_bytes<C: CurveGroup>(
    a: &[u8],
    b: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>)
where
    C::BaseField: PrimeField,
{
    let a_field = C::ScalarField::from_le_bytes_mod_order(a);
    let b_field = C::ScalarField::from_le_bytes_mod_order(b);
    mul_and_divide_by_scalar_modulus::<C>(a_field, b_field)
}

// nCk 조합 생성기
pub fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
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
pub fn permute<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
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
