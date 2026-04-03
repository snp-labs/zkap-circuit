use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    uint16::UInt16,
};
use ark_relations::r1cs::SynthesisError;

/// Converts a hex string in the JWT nonce field to a field element.
///
/// # Format
/// - Input: `"0x[0-9a-f]+"` (e.g. "0xabcd1234...")
/// - Supports values up to 256 bits
/// - When using the BN254 field, modular reduction is applied automatically if over 254 bits
///
/// # Constraints
/// 1. First 3 bytes must be `"0x` (fixed)
/// 2. All bytes up to `last_quote_index` must be valid hex characters
/// 3. Position `last_quote_index` must be `"`
/// 4. Hex string length must be 1-64 characters (4 bits ~ 256 bits)
///
/// # Arguments
/// * `hex_bytes` - byte array of the JWT nonce value (may include padding)
/// * `last_quote_index` - position of the closing quote `"` (witness)
///
/// # Returns
/// * converted field element value
///
/// # Example
/// ```text
/// Input:  ["0x1234...abcd"000000...]  (padded array)
///          ^             ^
///          |             last_quote_index
///          start
/// Output: Field element representing 0x1234...abcd
/// ```
pub fn jwt_nonce_hex_to_field<F: PrimeField>(
    hex_bytes: &[FpVar<F>],
    last_quote_index: &UInt16<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let hex_bytes_len = hex_bytes.len();

    // Validate minimum length: "0x0" (5 bytes)
    if hex_bytes_len < 5 {
        return Err(SynthesisError::Unsatisfiable);
    }

    // --- Constant definitions ---
    let quote_char = FpVar::<F>::Constant(F::from(b'"'));
    let zero_char = FpVar::<F>::Constant(F::from(b'0'));
    let x_char = FpVar::<F>::Constant(F::from(b'x'));
    let sixteen = FpVar::Constant(F::from(16u8));

    // --- 1. Validate fixed prefix: "0x ---
    crate::enforce_eq_internal!("nonce_prefix_quote", quote_char, hex_bytes[0])?;
    crate::enforce_eq_internal!("nonce_prefix_zero", zero_char, hex_bytes[1])?;
    crate::enforce_eq_internal!("nonce_prefix_x", x_char, hex_bytes[2])?;

    // --- 2. Initialize accumulator variables ---
    let mut accumulated_value = FpVar::<F>::zero();
    let mut found_closing_quote = Boolean::FALSE;
    let mut hex_digit_count = FpVar::<F>::zero(); // hex digit count

    // --- 3. Hex parsing loop (starting from index 3) ---
    for (i, current_byte) in hex_bytes.iter().enumerate().skip(3).take(hex_bytes_len - 3) {
        let current_index = UInt16::constant(i as u16);

        // Is the current position the closing quote position?
        let is_closing_quote_pos = current_index.is_eq(last_quote_index)?;

        // Is the current byte a quote character?
        let is_quote_char = current_byte.is_eq(&quote_char)?;

        // Have we not yet seen the closing quote?
        let is_before_closing_quote = !&found_closing_quote;

        // --- 3.1. Validate closing quote position ---
        // "If this is the closing quote position, the character must be '"'"
        let quote_pos_requirement = !&is_closing_quote_pos | &is_quote_char;
        crate::enforce_true_internal!("nonce_quote_pos", quote_pos_requirement)?;

        // --- 3.2. Hex parsing (only before the closing quote) ---
        let should_parse = &is_before_closing_quote & !&is_closing_quote_pos;

        // Convert hex character
        let (hex_value, is_valid_hex) = hex_char_to_value(current_byte)?;

        // Validity check: "if we must parse, the character must be a valid hex digit"
        let validity_requirement = !&should_parse | &is_valid_hex;
        crate::enforce_true_internal!("nonce_hex_valid", validity_requirement)?;

        // Accumulate value (only when should_parse is true)
        let potential_next_value = &accumulated_value * &sixteen + &hex_value;
        accumulated_value = should_parse.select(&potential_next_value, &accumulated_value)?;

        // Count hex digits
        let should_parse_fp = FpVar::from(should_parse.clone());
        hex_digit_count += &should_parse_fp;

        // --- 3.3. Update state ---
        found_closing_quote |= is_closing_quote_pos;
    }

    // --- 4. Final validation ---
    // 4.1. Must have found the closing quote
    crate::enforce_true_internal!("nonce_closing_quote_found", found_closing_quote)?;

    // 4.2. Hex digit count must be 1~64 (4 bits ~ 256 bits)
    // Minimum 1 digit
    let zero = FpVar::<F>::zero();
    let digit_count_ge_1 = hex_digit_count.is_neq(&zero)?;
    crate::enforce_true_internal!("nonce_digit_count_ge_1", digit_count_ge_1)?;

    // [ZKAPCIR-004] Maximum 64 digits (256 bits) - enforced inside the circuit
    // The previous code did not constrain the comparison result, allowing 65+ digits.
    let max_hex_digits = FpVar::<F>::Constant(F::from(64u64));
    let digit_count_bits = hex_digit_count.to_bits_le()?;
    let max_bits = max_hex_digits.to_bits_le()?;
    let digit_le_max = crate::comparison::is_less_or_equal(&digit_count_bits, &max_bits)?;
    crate::enforce_true_internal!("nonce_digit_le_max", digit_le_max)?;

    Ok(accumulated_value)
}

/// Converts a single hex character to its 0-15 value and validates it.
///
/// # Arguments
/// * `byte` - ASCII byte ('0'-'9', 'a'-'f', 'A'-'F')
///
/// # Returns
/// * `(value, is_valid)` - converted value (0-15) and validity flag
///
/// # Constraints
/// - Decompose byte into 8 bits once, then check 3 ranges via bit patterns
/// - '0'-'9': 0x30..=0x39 → upper 4 bits == 0011, lower 4 bits <= 9
/// - 'A'-'F': 0x41..=0x46 → upper 4 bits == 0100, lower 4 bits <= 5  (bit6=0, bit7=0)
/// - 'a'-'f': 0x61..=0x66 → upper 4 bits == 0110, lower 4 bits <= 5  (bit7=0)
///
/// # Soundness
/// - 8-bit decomposition + enforce_equal on reconstruction guarantees byte in [0, 255]
/// - Upper bit pattern checks implemented as XOR with Boolean constants (near zero cost)
/// - Lower nibble range check implemented as 4-bit is_less_or_equal
fn hex_char_to_value<F: PrimeField>(
    byte: &FpVar<F>,
) -> Result<(FpVar<F>, Boolean<F>), SynthesisError> {
    // Decompose byte into 8-bit witnesses and enforce reconstruction (guarantees byte in [0, 255])
    let cs = byte.cs();
    let byte_val = byte.value().unwrap_or_default();
    let mut b: Vec<Boolean<F>> = Vec::with_capacity(8);
    for i in 0..8usize {
        let bit_val = byte_val.into_bigint().get_bit(i);
        let bit = if cs.is_none() {
            Boolean::constant(bit_val)
        } else {
            Boolean::new_witness(cs.clone(), || Ok(bit_val))?
        };
        b.push(bit);
    }
    // b[0]..b[7]: b[0]=LSB, b[7]=MSB

    // Enforce reconstruction: reconstructed == byte
    let mut reconstructed = FpVar::<F>::zero();
    let mut power = F::one();
    for bit in &b {
        let bit_fp = FpVar::from(bit.clone());
        reconstructed += bit_fp * FpVar::Constant(power);
        power.double_in_place();
    }
    reconstructed.enforce_equal(byte)?;

    // Lower 4 bits (nibble): b[0..4]
    // Upper 4 bits: b[4..8]
    let lo_nibble = &b[0..4]; // bits 0-3
    let hi_nibble = &b[4..8]; // bits 4-7

    // Upper 4-bit pattern checks (all XOR with constant bits → near zero cost)
    // '0'-'9': 0x3? → hi = 0011 (b4=1,b5=1,b6=0,b7=0)
    // 'A'-'F': 0x4? → hi = 0100 (b4=0,b5=0,b6=1,b7=0)  + lower nibble check
    // 'a'-'f': 0x6? → hi = 0110 (b4=0,b5=1,b6=1,b7=0)  + lower nibble check
    //
    // hi_nibble[0]=b4, hi_nibble[1]=b5, hi_nibble[2]=b6, hi_nibble[3]=b7

    // '0'-'9': b7=0, b6=0, b5=1, b4=1
    let hi_is_3 = {
        let b4_eq_1 = hi_nibble[0].clone(); // b4==1
        let b5_eq_1 = hi_nibble[1].clone(); // b5==1
        let b6_eq_0 = !&hi_nibble[2];       // b6==0
        let b7_eq_0 = !&hi_nibble[3];       // b7==0
        &(&b4_eq_1 & &b5_eq_1) & &(&b6_eq_0 & &b7_eq_0)
    };

    // 'A'-'F': b7=0, b6=1, b5=0, b4=0 (0x4?)
    let hi_is_4 = {
        let b4_eq_0 = !&hi_nibble[0];
        let b5_eq_0 = !&hi_nibble[1];
        let b6_eq_1 = hi_nibble[2].clone();
        let b7_eq_0 = !&hi_nibble[3];
        &(&b4_eq_0 & &b5_eq_0) & &(&b6_eq_1 & &b7_eq_0)
    };

    // 'a'-'f': b7=0, b6=1, b5=1, b4=0 (0x6?)
    let hi_is_6 = {
        let b4_eq_0 = !&hi_nibble[0];
        let b5_eq_1 = hi_nibble[1].clone();
        let b6_eq_1 = hi_nibble[2].clone();
        let b7_eq_0 = !&hi_nibble[3];
        &(&b4_eq_0 & &b5_eq_1) & &(&b6_eq_1 & &b7_eq_0)
    };

    // Lower nibble range checks
    // '0'-'9': lo_nibble <= 9 (0x9 = 1001)
    // 'A'-'F': lo_nibble <= 5 (0x5 = 0101) AND lo_nibble >= 1 (0x41='A', lo=1)
    // 'a'-'f': lo_nibble <= 5 AND lo_nibble >= 1 (0x61='a', lo=1)
    //
    // Note: 0x40='@' (lo=0), 0x60='`' (lo=0) are invalid, so lo >= 1 check is required
    let nine_bits: Vec<Boolean<F>> = vec![
        Boolean::constant(true),  // bit0: 1
        Boolean::constant(false), // bit1: 0
        Boolean::constant(false), // bit2: 0
        Boolean::constant(true),  // bit3: 1
    ]; // 9 = 0b1001
    let six_bits: Vec<Boolean<F>> = vec![
        Boolean::constant(false), // bit0: 0
        Boolean::constant(true),  // bit1: 1
        Boolean::constant(true),  // bit2: 1
        Boolean::constant(false), // bit3: 0
    ]; // 6 = 0b0110
    let one_bits: Vec<Boolean<F>> = vec![
        Boolean::constant(true),  // bit0: 1
        Boolean::constant(false), // bit1: 0
        Boolean::constant(false), // bit2: 0
        Boolean::constant(false), // bit3: 0
    ]; // 1 = 0b0001

    let lo_le_9 = crate::comparison::is_less_or_equal(lo_nibble, &nine_bits)?;
    let lo_le_6 = crate::comparison::is_less_or_equal(lo_nibble, &six_bits)?;
    let lo_ge_1 = crate::comparison::is_less_or_equal(&one_bits, lo_nibble)?;

    // Range matching
    let is_digit = &hi_is_3 & &lo_le_9;            // '0'-'9'
    let is_upper = &hi_is_4 & &(&lo_ge_1 & &lo_le_6); // 'A'-'F'
    let is_lower = &hi_is_6 & &(&lo_ge_1 & &lo_le_6); // 'a'-'f'

    // Validity flag
    let is_valid = &is_digit | &(&is_upper | &is_lower);

    // Hex value calculation
    // digit_value = lo_nibble value (0-9) = byte - 0x30
    // upper_value = lo_nibble value - 1 + 10 = lo_nibble + 9 = byte - 0x41 + 10
    // lower_value = lo_nibble value - 1 + 10 = byte - 0x61 + 10
    let ten = FpVar::Constant(F::from(10u64));
    let digit_value = byte - FpVar::Constant(F::from(48u64)); // 0-9
    let upper_value = byte - FpVar::Constant(F::from(55u64)); // 'A'=65 → 65-55=10, 'F'=70 → 70-55=15
    let lower_value = byte - FpVar::Constant(F::from(87u64)); // 'a'=97 → 97-87=10, 'f'=102 → 102-87=15

    // If lo_nibble >= 1 and hi pattern matches, upper/lower value is in range 10-15
    // upper_value = byte - 55 = (0x40 + lo) - 55 = lo + 9, lo in [1,5] → [10,14] ✓
    // lower_value = byte - 87 = (0x60 + lo) - 87 = lo + 9, lo in [1,5] → [10,14] ✓
    // Wait: 'F'=70 → 70-55=15, 'f'=102 → 102-87=15 ✓

    // Conditional select: is_digit → digit value, is_upper → upper value, else → lower value
    let value_if_upper_or_lower = is_upper.select(&upper_value, &lower_value)?;
    let result = is_digit.select(&digit_value, &value_if_upper_or_lower)?;

    // Drop unused variable
    let _ = ten;

    Ok((result, is_valid))
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
        crate::enforce_true_internal!("exp_digit_valid", is_valid_digit)?;

        // Accumulate value: accumulated_value = accumulated_value * 10 + digit_value
        accumulated_value = &accumulated_value * &ten + &digit_value;
    }

    // --- 2. Validate remaining bytes are all zero-padded ---
    for byte in decimal_bytes.iter().skip(10) {
        crate::enforce_eq_internal!("exp_padding_zero", *byte, zero)?;
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
