//! R1CS gadgets for converting JWT field byte strings to field elements.
//!
//! Two domains are covered, each in its own sibling submodule:
//!
//! - **Hex (nonce)**: [`jwt_nonce_hex_to_field`] + [`hex_char_to_value`]
//!   live in [`nonce`]. Parse a `"0x…"` hex string (up to 64 digits) into a
//!   single field element.
//!
//! - **Decimal (expiry)**: [`jwt_exp_to_field`] (with private
//!   `decimal_byte_to_digit`) lives in [`exp`]. Parse a 10-digit decimal
//!   timestamp byte array into a single field element.
//!
//! All functions enforce their parsing constraints in-circuit.  See the
//! individual function doc-comments for the precise soundness/completeness
//! statements.
//!
//! L1 (R1CS-equivalence) note: the production split (nonce / exp) is purely
//! file-organisational — the constraint expressions and their ordering are
//! byte-for-byte identical to the pre-split single file.  See
//! `.omc/plans/2026-05-08-per-crate-refactor/00-cross-cutting-locks.md § L1`.

mod exp;
mod nonce;

pub use exp::jwt_exp_to_field;
pub use nonce::{hex_char_to_value, jwt_nonce_hex_to_field};

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar, fields::fp::FpVar, uint16::UInt16};
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
