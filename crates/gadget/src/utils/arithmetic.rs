use std::ops::Mul;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
};
use ark_relations::r1cs::SynthesisError;

use crate::utils::a_lt_b;

/// 두 벡터의 스칼라 곱(내적)을 계산합니다: `Σ (in1[i] * in2[i])`
///
/// 원-핫 벡터와 함께 사용하여 특정 요소를 선택하는 데 유용합니다.
pub fn scalar_product<F>(in1: &[FpVar<F>], in2: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError>
where
    F: PrimeField,
{
    if in1.len() != in2.len() {
        return Err(SynthesisError::Unsatisfiable);
    }

    // [수정] .sum() 대신 .fold()와 FpVar::zero()를 사용합니다.
    let result = in1
        .iter()
        .zip(in2.iter())
        .map(|(a, b)| a * b) // a, b는 &FpVar<F>
        .fold(FpVar::zero(), |acc, x| acc + x); // T::zero()가 아닌 FpVar::zero()

    Ok(result)
}

/// 두 벡터의 아다마르 곱(Hadamard product)을 계산합니다: 요소별 곱셈.
///
/// # Panics
/// 두 벡터의 길이가 다를 경우 패닉 발생.
pub fn hadamard_product<F, T>(a: &[T], b: &[T]) -> Vec<T>
where
    F: PrimeField,
    T: R1CSVar<F> + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    assert_eq!(
        a.len(),
        b.len(),
        "Vectors must be of the same length for Hadamard product."
    );
    a.iter().zip(b.iter()).map(|(a_i, b_i)| a_i * b_i).collect()
}

/// 정수 관계식 `a = q * m + r`과 `r < m` 조건을 검증합니다.
pub fn verify_integer_relation<F: PrimeField>(
    a: &FpVar<F>,
    q: &FpVar<F>,
    r: &FpVar<F>,
    m: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let rhs = q * m + r;
    a.enforce_equal(&rhs)?;

    let result = a_lt_b(&r.to_bits_le()?, &m.to_bits_le()?)?;
    result.enforce_equal(&Boolean::TRUE)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::{alloc::AllocVar, eq};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_scalar_product_basic() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // [1, 2, 3] · [4, 5, 6] = 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        let in1 = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap(),
        ];

        let in2 = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(4u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(6u64))).unwrap(),
        ];

        let result = scalar_product(&in1, &in2).unwrap();

        result
            .enforce_equal(&FpVar::Constant(Fr::from(32u64)))
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!(
            "Constraints for scalar product basic test: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_scalar_product_empty() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let in1: Vec<FpVar<Fr>> = vec![];
        let in2: Vec<FpVar<Fr>> = vec![];

        let result = scalar_product(&in1, &in2).unwrap();

        result.enforce_equal(&FpVar::zero()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!(
            "Constraints for scalar product empty test: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_scalar_product_single_element() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let in1 = vec![FpVar::new_witness(cs.clone(), || Ok(Fr::from(7u64))).unwrap()];
        let in2 = vec![FpVar::new_witness(cs.clone(), || Ok(Fr::from(8u64))).unwrap()];

        let result = scalar_product(&in1, &in2).unwrap();

        result
            .enforce_equal(&FpVar::Constant(Fr::from(56u64)))
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!(
            "Constraints for scalar product single element test: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_scalar_product_with_zero() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // [1, 0, 3] · [4, 5, 0] = 4 + 0 + 0 = 4
        let in1 = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap(),
            FpVar::zero(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap(),
        ];

        let in2 = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(4u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap(),
            FpVar::zero(),
        ];

        let result = scalar_product(&in1, &in2).unwrap();

        result
            .enforce_equal(&FpVar::Constant(Fr::from(4u64)))
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!(
            "Constraints for scalar product with zero test: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_scalar_product_length_mismatch() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let in1 = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap(),
        ];

        let in2 = vec![FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap()];

        let result = scalar_product(&in1, &in2);
        assert!(result.is_err());
    }

    #[test]
    fn test_hadamard_product_basic() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // [1, 2, 3] ⊙ [4, 5, 6] = [4, 10, 18]
        let a = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap(),
        ];

        let b = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(4u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(6u64))).unwrap(),
        ];
        let assigned_constraints = cs.num_constraints();
        println!(
            "Constraints before hadamard product: {}",
            assigned_constraints
        );

        let result = hadamard_product(&a, &b);
        let hadamard_constraints = cs.num_constraints() - assigned_constraints;
        println!(
            "Constraints for hadamard product operation: {}",
            hadamard_constraints
        );

        assert_eq!(result.len(), 3);
        result[0]
            .enforce_equal(&FpVar::Constant(Fr::from(4u64)))
            .unwrap();
        result[1]
            .enforce_equal(&FpVar::Constant(Fr::from(10u64)))
            .unwrap();
        result[2]
            .enforce_equal(&FpVar::Constant(Fr::from(18u64)))
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
        let equals_constraints =
            cs.num_constraints() - (assigned_constraints + hadamard_constraints);
        println!(
            "Constraints for equality checks in hadamard product test: {}",
            equals_constraints
        );
    }

    #[test]
    fn test_hadamard_product_with_zero() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap(),
            FpVar::zero(),
        ];

        let b = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(7u64))).unwrap(),
        ];

        let result = hadamard_product(&a, &b);

        assert_eq!(result.len(), 2);
        result[0]
            .enforce_equal(&FpVar::Constant(Fr::from(15u64)))
            .unwrap();
        result[1].enforce_equal(&FpVar::zero()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!(
            "Constraints for hadamard product with zero test: {}",
            cs.num_constraints()
        );
    }

    #[test]
    #[should_panic]
    fn test_hadamard_product_length_mismatch() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a = vec![
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap(),
        ];

        let b = vec![FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap()];

        let _ = hadamard_product(&a, &b);
    }

    #[test]
    fn test_verify_integer_relation_valid() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // 17 = 3 * 5 + 2, where 2 < 5
        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(17u64))).unwrap();
        let q = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
        let r = FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap();
        let m = FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap();

        let result = verify_integer_relation(&a, &q, &r, &m);
        assert!(result.is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_verify_integer_relation_zero_quotient() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // 3 = 0 * 5 + 3, where 3 < 5
        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
        let q = FpVar::zero();
        let r = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
        let m = FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap();

        let result = verify_integer_relation(&a, &q, &r, &m);
        assert!(result.is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_verify_integer_relation_zero_remainder() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // 15 = 3 * 5 + 0, where 0 < 5
        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(15u64))).unwrap();
        let q = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
        let r = FpVar::zero();
        let m = FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap();

        let result = verify_integer_relation(&a, &q, &r, &m);
        assert!(result.is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_verify_integer_relation_invalid_equation() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // 17 != 3 * 5 + 3 (should be 18)
        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(17u64))).unwrap();
        let q = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
        let r = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
        let m = FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap();

        let result = verify_integer_relation(&a, &q, &r, &m);
        // 제약 조건 추가는 성공하지만, 회로가 만족되지 않아야 함
        assert!(result.is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_verify_integer_relation_remainder_not_less_than_modulus() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // 17 = 2 * 5 + 7, but 7 >= 5 (invalid remainder)
        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(17u64))).unwrap();
        let q = FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap();
        let r = FpVar::new_witness(cs.clone(), || Ok(Fr::from(7u64))).unwrap();
        let m = FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap();

        let result = verify_integer_relation(&a, &q, &r, &m);
        // 제약 조건 추가는 성공하지만, 회로가 만족되지 않아야 함
        assert!(result.is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_verify_integer_relation_remainder_equal_to_modulus() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // 15 = 2 * 5 + 5, but 5 == 5 (invalid, remainder must be strictly less)
        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(15u64))).unwrap();
        let q = FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap();
        let r = FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap();
        let m = FpVar::new_witness(cs.clone(), || Ok(Fr::from(5u64))).unwrap();

        let result = verify_integer_relation(&a, &q, &r, &m);
        // 제약 조건 추가는 성공하지만, 회로가 만족되지 않아야 함
        assert!(result.is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }
}
