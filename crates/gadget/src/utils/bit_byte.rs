use std::borrow::Cow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    uint16::UInt16,
};
use ark_relations::r1cs::SynthesisError;

/// Arkworks 회로 내에서 입력 정수(UInt16)를 2의 p 제곱으로 나눈 몫과 나머지를 계산합니다.
/// 표준 Rust 함수의 Circom DivideMod2Power와 유사한 기능을 회로 내에서 수행합니다.
///
/// # Arguments
/// * `cs`: 제약 조건 시스템 네임스페이스.
/// * `input`: 나눗셈을 수행할 입력 정수 (`UInt16<ConstraintF>` 타입).
/// * `p`: 나눌 값 (2의 p 제곱)을 결정하는 지수 (0 < p < 16).
///        `p`는 회로 외부에서 결정되는 상수 값이어야 합니다.
///
/// # Returns
/// (몫, 나머지)의 튜플 (`UInt16<ConstraintF>`, `UInt16<ConstraintF>`)
///
/// # Panics
/// `p`가 0 이하이거나 16 이상일 경우 패닉이 발생합니다 (컴파일 또는 회로 생성 시점).
///
/// # Errors
/// 제약 조건 생성 중 오류가 발생하면 `SynthesisError`를 반환합니다.
pub fn divide_mod_power_of_2_circuit<F: PrimeField>(
    input: &UInt16<F>,
    p: u32,
) -> Result<(UInt16<F>, UInt16<F>), SynthesisError> {
    // 입력 파라미터 검증 (회로 생성 시점 또는 그 전에 확인)
    // UInt16는 16비트이므로, n은 16으로 고정됩니다.
    assert!(
        p > 0 && p < 16,
        "p must be greater than 0 and less than 16 for UInt16"
    );

    let bits = input.to_bits_le()?;

    // --- 나머지 계산 (하위 p 비트) ---
    // 하위 p개의 비트 (b0 ~ b(p-1))를 가져옵니다.
    let remainder_bits_slice = &bits[0..p as usize];
    // UInt16로 재구성하기 위해 16비트로 만들어야 합니다. 부족한 상위 비트들은 0 (Boolean::FALSE)으로 채웁니다.
    let mut remainder_bits_padded = remainder_bits_slice.to_vec();
    remainder_bits_padded.resize(16, Boolean::FALSE); // 총 16비트로 만들기 위해 뒤에 FALSE 추가
    // 패딩된 비트 벡터로부터 나머지 UInt16 값을 재구성합니다.
    let remainder = UInt16::from_bits_le(&remainder_bits_padded);

    // --- 몫 계산 (상위 16-p 비트, 오른쪽으로 p 시프트) ---
    // 상위 16-p개의 비트 (bp ~ b15)를 가져옵니다. 이것이 몫의 하위 비트가 됩니다.
    let quotient_bits_slice = &bits[p as usize..16];
    // UInt16로 재구성하기 위해 16비트로 만들어야 합니다. 상위 p개의 비트는 0 (Boolean::FALSE)으로 채웁니다.
    let mut quotient_bits_padded = quotient_bits_slice.to_vec();
    quotient_bits_padded.resize(16, Boolean::FALSE); // 총 16비트로 만들기 위해 뒤에 FALSE 추가
    // 패딩된 비트 벡터로부터 몫 UInt16 값을 재구성합니다.
    let quotient = UInt16::from_bits_le(&quotient_bits_padded);

    Ok((quotient, remainder))
}

/// 하나의 `FpVar` 필드 변수를 16개의 바이트(0~255 값)를 나타내는 `FpVar` 벡터로 분해합니다.
///
/// ## 동작 방식
/// 입력 필드 요소(`packed_fp`)의 하위 128비트(16바이트)를 사용합니다.
/// 이 128비트를 **빅 엔디안(Big-Endian) 순서**의 바이트 배열로 변환하여 반환합니다.
/// 즉, 반환된 벡터의 첫 번째 요소(`result[0]`)는 입력값의 가장 의미 있는 바이트(Most Significant Byte, MSB)가 되고,
/// 마지막 요소(`result[15]`)는 가장 덜 의미 있는 바이트(Least Significant Byte, LSB)가 됩니다.
///
/// 만약 입력 필드 요소의 비트 수가 128비트보다 작다면, 부족한 상위 비트들은 0으로 간주하여 처리됩니다.
///
/// # 인자
/// * `cs`: 제약 조건 시스템(Constraint System)에 대한 참조. 회로 내 변수 및 제약 조건 생성을 위해 필요합니다.
/// * `packed_fp`: 분해할 필드 요소 변수(`FpVar`).
///
/// # 반환값
/// * `Ok(Vec<FpVar<F>>)`: 성공 시, 16개의 `FpVar`를 담은 벡터를 반환합니다. 각 `FpVar`는 0에서 255 사이의 값을 나타내는 바이트입니다.
///   벡터의 순서는 `[byte_15, byte_14, ..., byte_0]` (빅 엔디안) 입니다.
/// * `Err(SynthesisError)`: 회로 생성 중 오류가 발생할 경우 반환됩니다.
pub fn unpack_fp_to_byte_fps<F: PrimeField>(
    packed_fp: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // 상수를 정의하여 가독성을 높입니다.
    // 이 함수는 고정적으로 16바이트(128비트)를 처리하도록 설계되었습니다.
    let num_bytes_to_unpack = 16;
    let bits_per_bytes_for_unpack = 8;

    // --- 1. 입력 FpVar를 리틀 엔디안(Little-Endian) 순서의 비트 벡터로 변환 ---
    // to_bits_le()는 필드 요소를 [b_0, b_1, ..., b_n] 형태의 비트(Boolean 변수) 배열로 만듭니다.
    let bits = packed_fp.to_bits_le()?;
    let actual_bits_len = bits.len(); // 실제 변환된 비트의 길이

    // 결과로 반환될 16개의 바이트 FpVar를 저장할 벡터를 초기화합니다.
    let mut byte_fps_result = Vec::with_capacity(num_bytes_to_unpack);

    // --- 2. 16개의 바이트 FpVar를 빅 엔디안 순서로 재구성 ---
    // 바깥쪽 루프는 16번 반복하며 각 바이트를 생성합니다. i는 0부터 15까지 증가합니다.
    for i in 0..num_bytes_to_unpack {
        let mut current_byte_fp = FpVar::<F>::zero(); // 현재 바이트 값을 누적할 변수 (초기값 0)
        let mut power_of_2 = FpVar::<F>::one(); // 2의 거듭제곱을 계산할 변수 (초기값 2^0 = 1)

        // 처리할 비트 묶음의 시작 인덱스를 계산합니다.
        // i=0일 때: (15-0)*8 = 120 -> 120~127번째 비트 (MSB, 최상위 바이트)
        // i=1일 때: (15-1)*8 = 112 -> 112~119번째 비트
        // ...
        // i=15일 때: (15-15)*8 = 0 -> 0~7번째 비트 (LSB, 최하위 바이트)
        let start_bit_idx = ((num_bytes_to_unpack - 1) - i) * bits_per_bytes_for_unpack;
        let end_bit_idx = start_bit_idx + bits_per_bytes_for_unpack;

        // --- 3. 현재 바이트를 구성하는 8개의 비트를 순회하며 FpVar 값 생성 ---
        // 안쪽 루프는 8개의 비트(Boolean)를 정수(FpVar)로 변환합니다.
        for k in start_bit_idx..end_bit_idx {
            // 실제 비트 벡터의 길이를 초과하는 인덱스에 접근하려 할 경우,
            // 해당 비트는 0 (Boolean::FALSE)으로 간주하여 패딩 처리합니다.
            let bit = if k < actual_bits_len {
                bits[k].clone()
            } else {
                Boolean::FALSE
            };

            // 바이트 값 재구성: current_byte_fp = Σ (bit_j * 2^j) for j=0..7
            // Boolean을 FpVar로 변환한 후, 2의 거듭제곱을 곱하여 더해줍니다.
            // Boolean::le_bits_to_fp_var(&[bit.clone()])? 는 비트 하나를 FpVar<F> (0 또는 1)로 변환합니다.
            current_byte_fp += Boolean::le_bits_to_fp(&[bit.clone()])? * &power_of_2;

            // 다음 자릿수를 위해 2의 거듭제곱 값을 업데이트합니다. (power_of_2 = power_of_2 * 2)
            power_of_2 = power_of_2 * FpVar::<F>::Constant(F::from(2u8));
        }
        // 8비트로 구성된 하나의 바이트(0~255 사이의 값을 갖는 FpVar)가 완성되었습니다.
        byte_fps_result.push(current_byte_fp);
    }

    // 최종적으로 16개의 바이트 FpVar가 담긴 벡터를 반환합니다.
    Ok(byte_fps_result)
}

/// Packs a vector of 8-bit FpVar (representing bytes in big-endian order)
/// into a single 128-bit FpVar.
///
/// Assumes the input `byte_fps` contains 16 FpVar elements, where `byte_fps[0]`
/// is the most significant byte and `byte_fps[15]` is the least significant byte.
///
/// # Arguments
/// * `cs`: The constraint system reference (can be ns!(cs, "packing") or similar).
/// * `byte_fps`: A slice of FpVar<F>, expected to have length 16, representing bytes in big-endian order.
///
/// # Returns
/// * `Ok(FpVar<F>)` containing the packed 128-bit value.
/// * `Err(SynthesisError)` if the input slice does not have length 16 or another synthesis error occurs.
pub fn pack_byte_fps_to_fp<F: PrimeField>(
    byte_fps: &[FpVar<F>],
    num_bytes_expected: usize,
) -> Result<FpVar<F>, SynthesisError> {
    let bits_per_byte = 8;

    // 1. Input Validation
    if byte_fps.len() != num_bytes_expected {
        // You might want a more specific error type or message
        assert_eq!(
            byte_fps.len(),
            num_bytes_expected,
            "Expected {} bytes, got {}",
            num_bytes_expected,
            byte_fps.len()
        );
        return Err(SynthesisError::Unsatisfiable);
    }

    // 2. Initialize Result and Multiplier Base
    let mut packed_fp_result = FpVar::<F>::zero();
    // Represents 2^8 = 256. We will use powers of this base.
    let multiplier_base = F::from(1u128 << bits_per_byte); // F::from(256u128)

    // 3. Iterate through bytes in Big-Endian order and combine them
    // byte_fps[0] is MSB, byte_fps[15] is LSB
    for i in 0..num_bytes_expected {
        // Calculate the positional multiplier: 256 ^ (15 - i)
        // This corresponds to shifting the byte `i` to its correct position.
        // Example:
        // i = 0 (MSB): multiplier = 256^15 = 2^(8*15) = 2^120
        // i = 1        : multiplier = 256^14 = 2^(8*14) = 2^112
        // ...
        // i = 15 (LSB): multiplier = 256^0 = 2^0 = 1

        let exponent = (num_bytes_expected - 1 - i) as u64;

        // Calculate multiplier_base ^ exponent within the field F
        let multiplier_val = multiplier_base.pow(&[exponent]); // Assuming pow takes &[u64] for exponent

        // Create a constant FpVar for the multiplier
        let multiplier_fp = FpVar::<F>::Constant(multiplier_val);

        // Get the current byte FpVar
        let current_byte_fp = &byte_fps[i];

        // Multiply the byte by its positional multiplier: byte * (2^8)^(15-i)
        let term = current_byte_fp * multiplier_fp;

        // Add the term to the overall result
        packed_fp_result += term;
    }

    // The final packed_fp_result holds the combined 128-bit value as an FpVar
    Ok(packed_fp_result)
}

pub fn pack_decompose_bytes<F: PrimeField>(
    decompose_bytes: &[FpVar<F>],
    limb_width: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let mut packed_fields = Vec::new();
    for chunk in decompose_bytes.chunks(limb_width) {
        let chunk_with_padding: Cow<[FpVar<F>]> = if chunk.len() < limb_width {
            let mut padded_chunk = chunk.to_vec();
            padded_chunk.resize(limb_width, pad_char.clone());
            Cow::Owned(padded_chunk)
        } else {
            Cow::Borrowed(chunk)
        };
        let packed_field = pack_byte_fps_to_fp(&chunk_with_padding, limb_width)?;
        packed_fields.push(packed_field);
    }
    Ok(packed_fields)
}

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar, fields::fp::FpVar};

    use crate::utils::pack_byte_fps_to_fp;

    type Bn254fr = ark_bn254::Fr;

    #[test]
    fn test_pack_byte_fps_to_fp() {
        let cs = ark_relations::r1cs::ConstraintSystem::<Bn254fr>::new_ref();
        let num_bytes_expected = 16;
        let bytes = "abcdefghijklmnop".as_bytes().to_vec();
        let field = Bn254fr::from_be_bytes_mod_order(&bytes);

        let bytes_var = bytes
            .iter()
            .map(|&b| FpVar::<Bn254fr>::new_witness(cs.clone(), || Ok(Bn254fr::from(b))).unwrap())
            .collect::<Vec<_>>();

        let result = pack_byte_fps_to_fp(&bytes_var, num_bytes_expected).unwrap();
        let expected_result = FpVar::<Bn254fr>::Constant(field);
        assert_eq!(
            result.value().unwrap(),
            expected_result.value().unwrap(),
            "Packed FpVar does not match expected value"
        );
    }
}
