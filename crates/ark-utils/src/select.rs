use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::r1cs::SynthesisError;

/// 2차원 배열에서 `selector` 인덱스에 해당하는 열을 선택합니다.
///
/// 각 행에서 동일한 인덱스의 요소를 선택하여 새로운 벡터를 구성합니다.
///
/// 예시: `[[a,b,c], [d,e,f], [g,h,i]]`, `selector=1` → `[b, e, h]`
pub fn multi_mux<F, T>(inputs: &[Vec<T>], selector: &FpVar<F>) -> Result<Vec<T>, SynthesisError>
where
    F: PrimeField,
    T: R1CSVar<F> + Clone + CondSelectGadget<F>,
{
    let out_len = inputs.len();
    let mut output = Vec::with_capacity(out_len);

    for input_row in inputs {
        // 각 행에 대해 single_multiplexer를 호출합니다.
        let selected = single_multiplexer(input_row, selector)?;
        output.push(selected);
    }

    Ok(output)
}
/// 배열에서 `idx` 인덱스에 해당하는 요소를 선택합니다 (멀티플렉서).
///
/// 원-핫 인코딩과 스칼라 곱을 사용하여 `output = inp[idx]`를 구현합니다.
pub fn single_multiplexer<F, T>(inp: &[T], idx: &FpVar<F>) -> Result<T, SynthesisError>
where
    F: PrimeField,
    T: R1CSVar<F> + Clone + CondSelectGadget<F>,
{
    let n = inp.len();
    let eq_bits = one_bit_vector(idx, n)?;

    assert!(!inp.is_empty(), "inputs cannot be empty");

    let mut res = inp[0].clone();
    for (i, bit) in eq_bits.iter().enumerate().skip(1) {
        res = T::conditionally_select(bit, &inp[i], &res)?;
    }

    Ok(res)
}

/// 인덱스를 원-핫 벡터로 변환하고 범위를 강제합니다.
///
/// `index` 위치만 1이고 나머지는 0인 벡터를 생성합니다.
/// 합이 1이 되도록 강제하여 `0 <= index < n` 범위를 보장합니다.
///
/// 예시: `n=5, index=2` → `[0, 0, 1, 0, 0]`
pub fn one_bit_vector<F, Out>(index: &FpVar<F>, n: usize) -> Result<Vec<Out>, SynthesisError>
where
    F: PrimeField,
    Out: R1CSVar<F> + From<Boolean<F>>,
{
    // [수정] cs 인자 제거
    if n == 0 {
        return Ok(vec![]);
    }

    let mut eq_bits = Vec::with_capacity(n);
    let mut sum_of_bits = FpVar::<F>::zero();

    for i in 0..n {
        let i_const = FpVar::<F>::Constant(F::from(i as u64));
        let is_equal = index.is_eq(&i_const)?;
        sum_of_bits += FpVar::from(is_equal.clone());
        eq_bits.push(Out::from(is_equal));
    }

    // 합이 1임을 강제 (인덱스가 범위 내에 하나만 존재함)
    crate::enforce_eq_internal!("one_bit_vector_sum", sum_of_bits, FpVar::one())?;

    Ok(eq_bits)
}
/// 비트 인덱스를 사용하여 배열에서 요소를 선택합니다 (재귀적 분할).
///
/// 배열을 반으로 나누고 MSB에 따라 왼쪽/오른쪽을 선택하는 방식으로 동작합니다.
pub fn select_array_element<F: PrimeField>(
    input: &[FpVar<F>],
    idx_bits: &[Boolean<F>],
) -> Result<FpVar<F>, SynthesisError> {
    assert!(!input.is_empty());

    assert_eq!(input.len(), 1 << idx_bits.len());

    if input.len() == 1 {
        Ok(input[0].clone())
    } else {
        let mid = input.len() / 2;
        let left = &input[..mid];
        let right = &input[mid..];

        let msb_index = idx_bits.len() - 1;
        let msb = idx_bits[msb_index].clone();
        let remaining_bits = &idx_bits[..msb_index];

        let left_value = select_array_element(left, remaining_bits)?;
        let right_value = select_array_element(right, remaining_bits)?;

        let selected_value = FpVar::conditionally_select(&msb, &right_value, &left_value)?;

        Ok(selected_value)
    }
}

pub fn select_array_element_be<F: PrimeField>(
    input: &[FpVar<F>],
    idx_bits: &[Boolean<F>],
) -> Result<FpVar<F>, SynthesisError> {
    assert!(!input.is_empty());

    assert_eq!(input.len(), 1 << idx_bits.len());

    if input.len() == 1 {
        Ok(input[0].clone())
    } else {
        let mid = input.len() / 2;
        let left = &input[..mid];
        let right = &input[mid..];

        let msb = idx_bits[0].clone();
        let remaining_bits = &idx_bits[1..];

        let left_value = select_array_element_be(left, remaining_bits)?;
        let right_value = select_array_element_be(right, remaining_bits)?;

        let selected_value = FpVar::conditionally_select(&msb, &right_value, &left_value)?;

        Ok(selected_value)
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::{One, Zero};
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::r1cs::ConstraintSystem;

    use crate::{lt_bit_vector, one_bit_vector};

    type F = ark_bn254::Fr;

    #[test]
    fn test_one_bit_vector() {
        let cs = ConstraintSystem::<F>::new_ref();
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(2))).unwrap();
        let n = 5;

        let expected = vec![
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::one()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
        ];

        let result = one_bit_vector(&index, n).unwrap();

        assert!(cs.is_satisfied().unwrap());
        expected.enforce_equal(&result).unwrap();
        println!("number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_lt_bit_vector() {
        let cs = ConstraintSystem::<F>::new_ref();
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(2))).unwrap();
        let n = 5;

        let expected = vec![
            FpVar::<F>::Constant(F::one()),
            FpVar::<F>::Constant(F::one()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
        ];

        let result = lt_bit_vector(&index, n).unwrap();

        assert!(cs.is_satisfied().unwrap());

        expected.enforce_equal(&result).unwrap();
        println!("number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_single_multiplexer_correctness() {
        use super::single_multiplexer;

        let cs = ConstraintSystem::<F>::new_ref();
        let n = 5;

        // 입력 배열: [10, 20, 30, 40, 50]
        let inputs: Vec<FpVar<F>> = (0..n)
            .map(|i| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from((i + 1) as u64 * 10))).unwrap())
            .collect();

        // 인덱스 2 선택 -> 30이 나와야 함
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(2))).unwrap();
        let result = single_multiplexer(&inputs, &index).unwrap();

        assert!(cs.is_satisfied().unwrap());
        result.enforce_equal(&FpVar::Constant(F::from(30))).unwrap();
        println!("Selected value at index 2: should be 30");
        println!("Number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_multi_mux() {
        use super::multi_mux;

        let cs = ConstraintSystem::<F>::new_ref();

        // 2D 배열 생성: [[1,2,3], [4,5,6], [7,8,9]]
        let inputs: Vec<Vec<FpVar<F>>> = (0..3)
            .map(|row| {
                (0..3)
                    .map(|col| {
                        FpVar::<F>::new_witness(cs.clone(), || {
                            Ok(F::from((row * 3 + col + 1) as u64))
                        })
                        .unwrap()
                    })
                    .collect()
            })
            .collect();

        // 인덱스 1 선택 -> [2, 5, 8]이 나와야 함
        let selector = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1))).unwrap();
        let result = multi_mux(&inputs, &selector).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.len(), 3);

        result[0].enforce_equal(&FpVar::Constant(F::from(2))).unwrap();
        result[1].enforce_equal(&FpVar::Constant(F::from(5))).unwrap();
        result[2].enforce_equal(&FpVar::Constant(F::from(8))).unwrap();

        println!("Multi-mux selected column 1: [2, 5, 8]");
        println!("Number of constraints: {}", cs.num_constraints());
    }
}
