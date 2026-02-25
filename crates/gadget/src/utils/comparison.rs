use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldVar, fp::FpVar},
    prelude::Boolean,
};
use ark_relations::r1cs::SynthesisError;

use crate::utils::one_bit_vector;

/// 비트 슬라이스를 비교하여 `a < b`를 반환합니다.
///
/// MSB부터 LSB로 순회하며 두 플래그를 유지합니다:
/// - `less`: `a < b`가 확정되면 true (sticky)
/// - `equal`: 현재까지 모든 비트가 동일하면 true
///
/// 각 비트에서 `less |= equal & !a_bit & b_bit`, `equal &= a_bit XNOR b_bit`를 수행합니다.
pub fn a_lt_b<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<Boolean<F>, SynthesisError> {
    // [ZKAPCIR-003] 비트 길이 불일치 시 zip이 상위 비트를 무시하는 문제 방지
    assert_eq!(
        a_bits.len(),
        b_bits.len(),
        "Bit lengths must be equal for comparison"
    );

    let mut less = Boolean::constant(false);
    let mut equal = Boolean::constant(true);

    for (a_bit, b_bit) in a_bits.iter().rev().zip(b_bits.iter().rev()) {
        let a_lt_b_at_current_bit = &equal & (&!a_bit & b_bit);
        less = &less | a_lt_b_at_current_bit;

        let bits_are_equal_at_current_bit = !(a_bit ^ b_bit);
        equal = &equal & bits_are_equal_at_current_bit;
    }

    Ok(less)
}

/// 비트 슬라이스를 비교하여 `a > b`를 반환합니다.
///
/// MSB부터 LSB로 순회하며 두 플래그를 유지합니다:
/// - `greater`: `a > b`가 확정되면 true (sticky)
/// - `equal`: 현재까지 모든 비트가 동일하면 true
///
/// 각 비트에서 `greater |= equal & a_bit & !b_bit`, `equal &= a_bit XNOR b_bit`를 수행합니다.
pub fn a_gt_b<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<Boolean<F>, SynthesisError> {
    // [ZKAPCIR-003] 비트 길이 불일치 시 zip이 상위 비트를 무시하는 문제 방지
    assert_eq!(
        a_bits.len(),
        b_bits.len(),
        "Bit lengths must be equal for comparison"
    );

    let mut greater = Boolean::constant(false);
    let mut equal = Boolean::constant(true);

    for (a_bit, b_bit) in a_bits.iter().rev().zip(b_bits.iter().rev()) {
        let a_gt_b_at_current_bit = &equal & (a_bit & !b_bit);
        greater = &greater | a_gt_b_at_current_bit;

        let bits_are_equal_at_current_bit = !(a_bit ^ b_bit);
        equal = &equal & bits_are_equal_at_current_bit;
    }

    Ok(greater)
}

/// `i < index`일 때 `out[i] = 1`인 비트 벡터를 생성합니다.
///
/// `index - 1`의 원-핫 벡터를 생성한 후, 접미사 OR 스캔을 수행하여
/// 온도계 인코딩을 구현합니다. 범위 제약: `1 <= index <= n`.
///
/// 예시: `n=5, index=3` → `[1, 1, 1, 0, 0]`
pub fn lt_bit_vector<F: PrimeField>(
    index: &FpVar<F>,
    n: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    if n == 0 {
        return Ok(Vec::new());
    }

    let one = FpVar::<F>::one();
    let index_minus_one = index - one;

    let eq: Vec<FpVar<F>> = one_bit_vector(&index_minus_one, n)?;

    let mut out = eq.clone();
    for i in (0..(n - 1)).rev() {
        out[i] = &out[i] + &out[i + 1];
    }

    // let mut out = vec![FpVar::Constant(F::zero()); n];

    // if n > 0 {
    //     out[n - 1] = eq[n - 1].clone();
    // }

    // if n >= 2 {
    //     for i in (0..=(n - 2)).rev() {
    //         out[i] = eq[i].clone() + &out[i + 1];
    //     }
    // }

    Ok(out)
}

/// `i > index`일 때 `out[i] = 1`인 비트 벡터를 생성합니다.
///
/// `index`의 원-핫 벡터를 생성한 후, 접두사 OR 스캔을 수행하여
/// 온도계 인코딩을 구현합니다. 범위 제약: `0 <= index < n`.
///
/// 예시: `n=5, index=2` → `[0, 0, 0, 1, 1]`
pub fn gt_bit_vector<F>(index: &FpVar<F>, n: usize) -> Result<Vec<FpVar<F>>, SynthesisError>
where
    F: PrimeField,
{
    if n == 0 {
        return Ok(Vec::new());
    }

    let eq: Vec<FpVar<F>> = one_bit_vector(index, n)?;

    let mut out = Vec::with_capacity(n);
    out.push(FpVar::<F>::zero());

    for i in 1..n {
        let next_out = &out[i - 1] + &eq[i - 1];
        out.push(next_out);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{FieldVar, fp::FpVar},
    };
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

    use crate::utils::{gt_bit_vector, lt_bit_vector};

    type F = ark_bn254::Fr;

    fn test_generic_gt_bit_vector(index: usize, n: usize) {
        let cs = ConstraintSystem::<F>::new_ref();

        let index_var = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(index as u64))).unwrap();

        let expected = {
            let mut vec = Vec::with_capacity(n);
            for i in 0..n {
                if i > index {
                    vec.push(FpVar::<F>::one());
                } else {
                    vec.push(FpVar::<F>::zero());
                }
            }
            vec
        };

        let result = gt_bit_vector(&index_var, n).unwrap();
        println!(
            "number of constraints for {}: {}",
            std::any::type_name::<FpVar<F>>(),
            cs.num_constraints()
        );
        expected.enforce_equal(&result).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!(
            "number of constraints for {}: {}",
            std::any::type_name::<FpVar<F>>(),
            cs.num_constraints()
        );
    }

    #[test]
    fn test_gt_bit_vector_as_boolean() {
        test_generic_gt_bit_vector(2, 5);
    }

    #[test]
    fn test_gt_bit_vector_as_fpvar() {
        test_generic_gt_bit_vector(2, 5);
    }

    #[test]
    fn test_lt_bit_vector() {
        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(3))).unwrap();
        let n = 5;
        let expected = vec![
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u8))).unwrap(),
        ];
        let result = lt_bit_vector(&index, n).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("number of constraints: {}", cs.num_constraints());
        expected.enforce_equal(&result).unwrap();
        println!("number of constraints: {}", cs.num_constraints());
    }
}
