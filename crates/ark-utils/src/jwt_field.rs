use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    uint16::UInt16,
};
use ark_relations::r1cs::SynthesisError;

/// Converts a JWT nonce string of the form `"0x[0-9A-Fa-f]+"` to a field element.
///
/// # Accepted format
/// - Prefix is exactly `"0x`
/// - Followed by 1..=64 hex digits
/// - Followed by a closing quote `"` at `last_quote_index`
///
/// Example:
/// - `"0x1"`
/// - `"0xABCD1234"`
/// - `"0xdeadbeef"`
///
/// # Arguments
/// - `hex_bytes`: padded byte array containing the JWT nonce substring
/// - `last_quote_index`: witness index of the closing `"`
///
/// # Returns
/// - Field element equal to the parsed hex value, accumulated in the field
///
/// # Important note
/// - This function returns the value **in the field**.
/// - If more than the field modulus can represent injectively (for example 64 hex digits in BN254),
///   the result is the natural field reduction of that integer.
///
/// # Constraints
/// 1. `hex_bytes[0..3] == "\"0x"`
/// 2. `last_quote_index` is in the allowed range:
///    - at least 4  (so there is at least 1 hex digit)
///    - at most `min(hex_bytes.len() - 1, 67)`
///      (so there are at most 64 hex digits)
/// 3. At the selected `last_quote_index`, the byte must be `"`
/// 4. Every byte before that quote must be a valid hex character
/// 5. Bytes after `last_quote_index` are ignored by this function
///
/// # Soundness
/// - If this function returns successfully, then the prefix is correct,
///   the selected closing quote is in-range and present,
///   and every character before it is valid hex.
/// - Therefore the returned value is exactly the field accumulation of the parsed hex substring.
///
/// # Completeness
/// - Every input matching the accepted format above is accepted.
pub fn jwt_nonce_hex_to_field<F: PrimeField>(
    hex_bytes: &[FpVar<F>],
    last_quote_index: &UInt16<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let hex_bytes_len = hex_bytes.len();

    // Minimum valid string is: `"0x0"` => 5 bytes
    if hex_bytes_len < 5 {
        return Err(SynthesisError::Unsatisfiable);
    }

    let quote_char = FpVar::<F>::Constant(F::from(b'"'));
    let zero_char = FpVar::<F>::Constant(F::from(b'0'));
    let x_char = FpVar::<F>::Constant(F::from(b'x'));
    let sixteen = FpVar::<F>::Constant(F::from(16u64));
    let zero = FpVar::<F>::zero();

    // Fixed prefix: `"0x`
    quote_char.enforce_equal(&hex_bytes[0])?;
    zero_char.enforce_equal(&hex_bytes[1])?;
    x_char.enforce_equal(&hex_bytes[2])?;

    // The closing quote must appear after at least 1 hex digit and before/at the
    // 64th hex digit position.
    //
    // Prefix occupies indices 0,1,2.
    // Hex digits occupy indices 3..=66 (64 digits max).
    // Closing quote must therefore be in 4..=67, but also within the provided array.
    let max_quote_index = core::cmp::min(hex_bytes_len - 1, 67usize);

    let idx_bits = last_quote_index.to_bits_le()?;
    let lower_exclusive_bits = UInt16::constant(3u16).to_bits_le()?;
    let upper_exclusive_bits = UInt16::constant((max_quote_index as u16) + 1).to_bits_le()?;

    // 3 < last_quote_index < max_quote_index + 1
    // i.e. 4 <= last_quote_index <= max_quote_index
    crate::comparison::enforce_less_than(&lower_exclusive_bits, &idx_bits)?;
    crate::comparison::enforce_less_than(&idx_bits, &upper_exclusive_bits)?;

    let mut accumulated_value = FpVar::<F>::zero();
    let mut found_closing_quote = Boolean::FALSE;

    // Only the first 65 bytes after the prefix can matter:
    // 64 hex digits + 1 closing quote.
    for i in 3..=max_quote_index {
        let current_byte = &hex_bytes[i];
        let current_index = UInt16::constant(i as u16);

        // Is this the selected closing quote position?
        let is_closing_quote_pos = current_index.is_eq(last_quote_index)?;

        // Parse until the selected closing quote.
        let should_parse = &(!&found_closing_quote) & &(!&is_closing_quote_pos);

        // If this is the selected closing-quote position, the byte must be '"'.
        //
        // gate * (current_byte - '"') == 0
        let quote_gate = FpVar::<F>::from(is_closing_quote_pos.clone());
        let quote_diff = current_byte - &quote_char;
        quote_gate.mul_equals(&quote_diff, &zero)?;

        // Convert current byte to hex.
        let (hex_value, is_valid_hex) = hex_char_to_value(current_byte)?;

        // If we are still parsing, the character must be valid hex.
        //
        // should_parse * (1 - is_valid_hex) == 0
        let parse_gate = FpVar::<F>::from(should_parse.clone());
        let invalid_hex = FpVar::<F>::from(!&is_valid_hex);
        parse_gate.mul_equals(&invalid_hex, &zero)?;

        // accumulated = accumulated * 16 + hex_value   (only while parsing)
        let next_value = &accumulated_value * &sixteen + &hex_value;
        accumulated_value = should_parse.select(&next_value, &accumulated_value)?;

        found_closing_quote |= is_closing_quote_pos;
    }

    Ok(accumulated_value)
}

/// Converts a single ASCII hex character to its 0..15 value.
///
/// # Accepted input
/// - '0'..='9'
/// - 'A'..='F'
/// - 'a'..='f'
///
/// # Returns
/// - `(value, is_valid)`
///   - `is_valid == true`  => `value` is the exact hex value in `0..=15`
///   - `is_valid == false` => `value` is unspecified and must be ignored
///
/// # Constraints
/// - Decompose `byte` into 8 bits once and enforce exact reconstruction
/// - Check upper/lower nibble patterns directly with Boolean formulas
/// - Avoid full 4-bit comparators
///
/// # Soundness
/// - 8-bit decomposition + reconstruction guarantees `byte ∈ [0,255]`.
/// - `is_valid` is true iff the byte is one of:
///   - `0x30..=0x39` ('0'..='9')
///   - `0x41..=0x46` ('A'..='F')
///   - `0x61..=0x66` ('a'..='f')
///
/// # Completeness
/// - Every valid hex character above is accepted and mapped to its exact value.
pub fn hex_char_to_value<F: PrimeField>(
    byte: &FpVar<F>,
) -> Result<(FpVar<F>, Boolean<F>), SynthesisError> {
    // Enforce byte ∈ [0,255].
    let (bits, _) = byte.to_bits_le_with_top_bits_zero(8)?;

    // bits[0] = LSB, bits[7] = MSB
    let b0 = bits[0].clone();
    let b1 = bits[1].clone();
    let b2 = bits[2].clone();
    let b3 = bits[3].clone();
    let b4 = bits[4].clone();
    let b5 = bits[5].clone();
    let b6 = bits[6].clone();
    let b7 = bits[7].clone();

    // Lower nibble value = b0 + 2*b1 + 4*b2 + 8*b3
    let lo_value = Boolean::le_bits_to_fp(&bits[0..4])?;

    // ----- Classify '0'..'9' -----
    // High nibble must be 0x3 = 0011 (b7=0,b6=0,b5=1,b4=1)
    let digit_hi = {
        let not_b7 = !&b7;
        let not_b6 = !&b6;
        let hi_top_ok = &not_b7 & &not_b6;
        let hi_low_ok = &b5 & &b4;
        &hi_top_ok & &hi_low_ok
    };

    // Lower nibble <= 9
    // Invalid for 10..15 iff b3 == 1 and (b2 == 1 or b1 == 1)
    let digit_lo_ok = {
        let b2_or_b1 = &b2 | &b1;
        let invalid_10_to_15 = &b3 & &b2_or_b1;
        !invalid_10_to_15
    };

    let is_digit = &digit_hi & &digit_lo_ok;

    // ----- Classify 'A'..'F' or 'a'..'f' -----
    // High nibble must be 0x4 or 0x6:
    // - 'A'..'F' => 0100
    // - 'a'..'f' => 0110
    //
    // Common condition:
    //   b7 = 0, b6 = 1, b4 = 0
    //   b5 is free (0 for uppercase, 1 for lowercase)
    let letter_hi = {
        let not_b7 = !&b7;
        let not_b4 = !&b4;
        let t = &not_b7 & &b6;
        &t & &not_b4
    };

    // Lower nibble must be 1..=6.
    // Equivalent to:
    // - b3 == 0        (exclude 8..15)
    // - at least one of b0,b1,b2 is 1   (exclude 0)
    // - not all of b0,b1,b2 are 1        (exclude 7)
    let letter_lo_ok = {
        let not_b3 = !&b3;

        let any_low = {
            let t = &b0 | &b1;
            &t | &b2
        };

        let all_low = {
            let t = &b0 & &b1;
            &t & &b2
        };

        let not_all_low = !all_low;
        let t = &any_low & &not_all_low;
        &not_b3 & &t
    };

    let is_letter = &letter_hi & &letter_lo_ok;

    // Valid iff digit or letter.
    let is_valid = &is_digit | &is_letter;

    // Value:
    // - '0'..'9' => lo_value
    // - 'A'..'F', 'a'..'f' => lo_value + 9
    //
    // If invalid, the value is unspecified and must be ignored.
    let letter_value = &lo_value + FpVar::<F>::Constant(F::from(9u64));
    let value = is_letter.select(&letter_value, &lo_value)?;

    Ok((value, is_valid))
}

/// Converts a decimal byte array (e.g. JWT exp field) to a field element.
///
/// # Format
/// - Input: `[b'0'..=b'9', 0, 0, ...]` (padded array)
/// - Example: `[49, 50, 51, ...]` = `['1', '2', '3', ...]`
/// - Must always be exactly 10 digits
/// - Digits beyond position 10 must be zero-padded
///
/// # Constraints
/// 1. First 10 bytes must be valid decimal characters (b'0'~b'9')
/// 2. All bytes after position 10 must be 0
/// 3. Result value is in the range 0 ~ 9,999,999,999
///
/// # Arguments
/// * `decimal_bytes` - decimal byte array (exactly 10 digits + padding)
///
/// # Returns
/// * converted field element value
///
/// # Example
/// ```text
/// Input:  [49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 0, 0, ...]
///         ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ...]
/// Output: Field element 1234567890
/// ```
pub fn jwt_exp_to_field<F: PrimeField>(
    decimal_bytes: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    // Minimum length check: 10 digits required
    if decimal_bytes.len() < 10 {
        return Err(SynthesisError::Unsatisfiable);
    }

    let ten = FpVar::Constant(F::from(10u8));
    let zero = FpVar::<F>::Constant(F::zero());

    let mut accumulated_value = FpVar::<F>::zero();

    // --- 1. Parse and validate first 10 digits ---
    for current_byte in decimal_bytes.iter().take(10) {

        // Convert decimal character
        let (digit_value, is_valid_digit) = decimal_byte_to_digit(current_byte)?;

        // Validity check: must be a valid decimal digit
        is_valid_digit.enforce_equal(&Boolean::TRUE)?;

        // Accumulate value: accumulated_value = accumulated_value * 10 + digit_value
        accumulated_value = &accumulated_value * &ten + &digit_value;
    }

    // --- 2. Validate remaining bytes are all zero-padded ---
    for byte in decimal_bytes.iter().skip(10) {
        byte.enforce_equal(&zero)?;
    }

    Ok(accumulated_value)
}

/// Converts a single decimal byte to its 0-9 value and validates it.
///
/// # Arguments
/// * `byte` - ASCII byte (b'0'~b'9', i.e. 48~57)
///
/// # Returns
/// * `(value, is_valid)` - converted value (0-9) and validity flag
///
/// # Constraints
/// - Must match exactly one decimal character
/// - Range: b'0'(48) ~ b'9'(57)
fn decimal_byte_to_digit<F: PrimeField>(
    byte: &FpVar<F>,
) -> Result<(FpVar<F>, Boolean<F>), SynthesisError> {
    let mut result = FpVar::<F>::zero();
    let mut is_valid = Boolean::<F>::FALSE;

    // b'0' = 48, b'1' = 49, ..., b'9' = 57
    for digit in 0..10u8 {
        let byte_value = b'0' + digit; // 48 + digit
        let byte_const = FpVar::<F>::Constant(F::from(byte_value));
        let is_equal = byte.is_eq(&byte_const)?;

        // Accumulate value (digit itself is the value)
        let value_to_add =
            FpVar::from(is_equal.clone()) * FpVar::<F>::Constant(F::from(digit as u64));
        result += &value_to_add;

        // Update validity flag
        is_valid |= is_equal;
    }

    Ok((result, is_valid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;
    use std::str::FromStr;

    type F = ark_bn254::Fr;

    #[test]
    fn test_jwt_nonce_hex_to_field_basic() {
        let cs = ConstraintSystem::<F>::new_ref();

        // Test input: "0x1234"
        let input = b"\"0x1234\"";
        let mut input_bytes = input.to_vec();
        println!("Input bytes: {:?}", &input_bytes[..8]);
        println!(
            "Input string: {}",
            String::from_utf8_lossy(&input_bytes[..8])
        );
        input_bytes.resize(100, b'0'); // padding

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_idx = 7; // closing quote position of "0x1234" (0-indexed)
        println!("Last quote index: {}", last_quote_idx);
        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let result = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();

        if !cs.is_satisfied().unwrap() {
            println!("Constraints not satisfied!");
            println!("Number of constraints: {}", cs.num_constraints());
        }
        assert!(cs.is_satisfied().unwrap());

        let expected = F::from(0x1234u64);
        assert_eq!(result.value().unwrap(), expected);

        println!("Basic test - constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_jwt_nonce_hex_to_field_256bit() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 64 hex digits (256 bits)
        let hex_str = "0e758262e33fe28c37e8612505582e3c341481cbc106e47a617e9471cf5732cc";
        let input = format!("\"0x{}\"", hex_str);
        let mut input_bytes = input.as_bytes().to_vec();

        let expected = F::from_str(
            "6540000879776827511546239914827296250681122647808546265151524760879082451660",
        )
        .unwrap();

        let last_quote_idx = input_bytes.len() - 1;
        input_bytes.resize(200, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let result = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), expected);

        println!("256-bit test - constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_jwt_nonce_hex_uppercase() {
        let cs = ConstraintSystem::<F>::new_ref();

        // Test with uppercase letters
        let input = b"\"0xABCD\"";
        let mut input_bytes = input.to_vec();
        input_bytes.resize(100, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_idx = 7; // closing quote position of "0xABCD"
        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let result = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();

        assert!(cs.is_satisfied().unwrap());

        let expected = F::from(0xABCDu64);
        assert_eq!(result.value().unwrap(), expected);

        println!("Uppercase test - constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_jwt_nonce_hex_with_padding() {
        let cs = ConstraintSystem::<F>::new_ref();
        // 64 hex digits (256 bits)
        let hex_str = "0e758262e33fe28c37e8612505582e3c341481cbc106e47a617e9471cf5732cc";
        let input = format!("\"0x{}\"", hex_str);
        let mut input_bytes = input.as_bytes().to_vec();

        let expected = F::from_str(
            "6540000879776827511546239914827296250681122647808546265151524760879082451660",
        )
        .unwrap();

        let last_quote_idx = input_bytes.len() - 1; // closing quote position
        input_bytes.resize(200, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let result = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), expected);

        println!("256-bit test - constraints: {}", cs.num_constraints());
    }

    #[test]
    #[should_panic]
    fn test_jwt_nonce_invalid_hex() {
        let cs = ConstraintSystem::<F>::new_ref();

        // Contains invalid hex character
        let input = b"\"0x12G4\""; // 'G' is not a valid hex digit
        let mut input_bytes = input.to_vec();
        input_bytes.resize(100, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_idx = 8;
        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let _ = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();

        // Invalid input, so constraints should not be satisfied
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_jwt_exp_to_field_basic() {
        let cs = ConstraintSystem::<F>::new_ref();

        // Test input: 1234567890 (10 digits)
        let input = vec![b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0'];
        let mut input_bytes = input.clone();
        input_bytes.resize(70, 0); // zero-padded

        println!("Input bytes: {:?}", &input_bytes[..15]);
        println!("Expected: 1234567890");

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let result = jwt_exp_to_field(&input_var).unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );

        let expected = F::from(1234567890u64);
        assert_eq!(result.value().unwrap(), expected);

        println!(
            "✓ Basic exp test (1234567890) - constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_jwt_exp_to_field_all_zeros() {
        let cs = ConstraintSystem::<F>::new_ref();

        // Test input: 0000000000 (all 10 digits are 0)
        let input = vec![b'0'; 10];
        let mut input_bytes = input.clone();
        input_bytes.resize(70, 0);

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let result = jwt_exp_to_field(&input_var).unwrap();

        assert!(cs.is_satisfied().unwrap());

        let expected = F::from(0u64);
        assert_eq!(result.value().unwrap(), expected);

        println!("✓ All zeros test - constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_jwt_exp_to_field_max_value() {
        let cs = ConstraintSystem::<F>::new_ref();

        // Test input: 9999999999 (maximum 10-digit value)
        let input = vec![b'9'; 10];
        let mut input_bytes = input.clone();
        input_bytes.resize(70, 0);

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let result = jwt_exp_to_field(&input_var).unwrap();

        assert!(cs.is_satisfied().unwrap());

        let expected = F::from(9999999999u64);
        assert_eq!(result.value().unwrap(), expected);

        println!(
            "✓ Max value test (9999999999) - constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_jwt_exp_to_field_realistic_timestamp() {
        let cs = ConstraintSystem::<F>::new_ref();

        // Real-world timestamp example: 1734000000 (around December 2024)
        let input = b"1734000000";
        let mut input_bytes = input.to_vec();
        input_bytes.resize(70, 0);

        println!("Input: {}", String::from_utf8_lossy(&input_bytes[..10]));

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let result = jwt_exp_to_field(&input_var).unwrap();

        assert!(cs.is_satisfied().unwrap());

        let expected = F::from(1734000000u64);
        assert_eq!(result.value().unwrap(), expected);

        println!(
            "✓ Realistic timestamp test (1734000000) - constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    #[should_panic(expected = "not satisfied")]
    fn test_jwt_exp_to_field_invalid_digit() {
        let cs = ConstraintSystem::<F>::new_ref();

        // Contains invalid character: 123456789a (last character is 'a')
        let mut input_bytes = vec![b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a'];
        input_bytes.resize(70, 0);

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let _result = jwt_exp_to_field(&input_var).unwrap();

        // Invalid input, so constraints should not be satisfied
        if !cs.is_satisfied().unwrap() {
            panic!("Constraints not satisfied - invalid digit detected");
        }
    }

    #[test]
    fn test_jwt_nonce_mixed_case() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = b"\"0xaBcD\"";
        let mut input_bytes = input.to_vec();
        input_bytes.resize(100, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_idx = 7;
        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let result = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), F::from(0xABCDu64));
    }

    #[test]
    fn test_jwt_nonce_wrong_last_quote_index_unsatisfied() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = b"\"0x1234\"";
        let mut input_bytes = input.to_vec();
        input_bytes.resize(100, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        // Wrong index: 5 instead of 7 (closing quote is at 7)
        let wrong_idx = 5u16;
        let last_quote_var = UInt16::<F>::new_witness(cs.clone(), || Ok(wrong_idx)).unwrap();

        let _result = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();
        // Position 5 is '3', not '"', so quote_pos_requirement fails
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_jwt_nonce_tampered_output_unsatisfied() {
        use ark_r1cs_std::eq::EqGadget;

        let cs = ConstraintSystem::<F>::new_ref();
        let input = b"\"0x1234\"";
        let mut input_bytes = input.to_vec();
        input_bytes.resize(100, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_var = UInt16::<F>::new_witness(cs.clone(), || Ok(7u16)).unwrap();

        let result = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();
        assert!(cs.is_satisfied().unwrap());

        // Tamper: enforce result == wrong value
        let wrong = FpVar::new_witness(cs.clone(), || Ok(F::from(9999u64))).unwrap();
        result.enforce_equal(&wrong).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_jwt_exp_tampered_result_unsatisfied() {
        use ark_r1cs_std::eq::EqGadget;

        let cs = ConstraintSystem::<F>::new_ref();
        let mut input_bytes = vec![b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0'];
        input_bytes.resize(70, 0);

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let result = jwt_exp_to_field(&input_var).unwrap();
        assert!(cs.is_satisfied().unwrap());

        // Tamper: enforce result == wrong value
        let wrong = FpVar::new_witness(cs.clone(), || Ok(F::from(42u64))).unwrap();
        result.enforce_equal(&wrong).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    #[should_panic(expected = "not satisfied")]
    fn test_jwt_exp_to_field_non_zero_padding() {
        let cs = ConstraintSystem::<F>::new_ref();

        // Non-zero value after position 10
        let mut input_bytes = vec![b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0'];
        input_bytes.resize(70, 0);
        input_bytes[15] = 1; // non-zero value in padding area

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let _result = jwt_exp_to_field(&input_var).unwrap();

        // Padding is non-zero, so constraints should not be satisfied
        if !cs.is_satisfied().unwrap() {
            panic!("Constraints not satisfied - non-zero padding detected");
        }
    }
}
