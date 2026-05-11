//! Decimal-domain JWT field gadgets.
//!
//! This module hosts the gadgets for JWT expiry parsing — fixed-length
//! 10-digit decimal byte arrays.  It contains the public entry-point
//! [`jwt_exp_to_field`] together with its single-byte decimal classifier
//! `decimal_byte_to_digit`, extracted from the original `jwt_field.rs`
//! so the hex / decimal domains live in sibling files. See the parent
//! module head-doc for the rationale.
//!
//! L1 (R1CS-equivalence) note: every constraint expression and its ordering
//! is byte-for-byte the same as before the split.  Do not re-order, fold,
//! or "simplify" any of the `enforce_*` calls without updating the trusted
//! setup — see
//! `.omc/plans/2026-05-08-per-crate-refactor/00-cross-cutting-locks.md § L1`.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::Boolean,
};
use ark_relations::gr1cs::SynthesisError;

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
