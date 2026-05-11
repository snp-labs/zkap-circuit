//! Hex-domain JWT field gadgets.
//!
//! This module hosts the gadgets for JWT nonce parsing — quoted hex strings
//! of the form `"0x[0-9A-Fa-f]+"`.  It contains the public entry-point
//! [`jwt_nonce_hex_to_field`] together with its single-byte hex classifier
//! [`hex_char_to_value`], extracted from the original `jwt_field.rs` so the
//! hex / decimal domains live in sibling files. See the parent module
//! head-doc for the rationale.
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
    prelude::{Boolean, ToBitsGadget},
    uint16::UInt16,
};
use ark_relations::gr1cs::SynthesisError;

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
    ark_utils::r1cs::comparison::enforce_less_than(&lower_exclusive_bits, &idx_bits)?;
    ark_utils::r1cs::comparison::enforce_less_than(&idx_bits, &upper_exclusive_bits)?;

    let mut accumulated_value = FpVar::<F>::zero();
    let mut found_closing_quote = Boolean::FALSE;

    // Only the first 65 bytes after the prefix can matter:
    // 64 hex digits + 1 closing quote.
    for (i, current_byte) in hex_bytes
        .iter()
        .enumerate()
        .take(max_quote_index + 1)
        .skip(3)
    {
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
