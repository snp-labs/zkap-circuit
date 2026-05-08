//! R1CS gadgets for JWT claim extraction and format verification.
//!
//! # Entry point
//!
//! [`claim_extractor_v2`] — extracts the value bytes of a named claim from a decoded JWT
//! payload and enforces seven format invariants via [`claim_format_verifier_v2`]:
//!
//! 1. `name_len <= colon_idx` (key ends before or at the colon)
//! 2. `colon_idx < value_idx` (colon precedes the value)
//! 3. No non-whitespace between key end and colon
//! 4. No non-whitespace between colon and value start
//! 5. No non-whitespace between value end and claim end
//! 6. Character at `colon_idx` is `':'`
//! 7. Last character of the claim is `','` or `'}'`
//!
//! # r1cs-std 0.5.0 `enforce_cmp` workaround
//!
//! Checks 1 and 2 use `is_less_than` / `is_eq` instead of `enforce_cmp` due to a known bug
//! in `ark-r1cs-std 0.5.0`.  The circuit expression must **not** be reverted to `enforce_cmp`
//! until the upstream bug is confirmed fixed in a version we depend on (L1 lock applies).
//!
//! # Security note
//!
//! The boundary condition in check 5 (`value_end_idx = value_idx + value_len`) is intentional.
//! The off-by-one question raised in an earlier review comment requires a dedicated security
//! audit before any change — see `00-cross-cutting-locks.md § L1`.
//!
//! # Tests
//!
//! Internal correctness tests live in [`crates/circuit/tests/claim_verifier_internal.rs`].
//! They exercise [`claim_extractor_v2`] against hand-crafted JSON payloads and use only
//! the public surface, so no `pub(crate)` widening is needed.

mod format;

use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, uint16::UInt16};
use ark_relations::r1cs::SynthesisError;
use ark_utils::{slice_efficient, slice_from_start};

use crate::token::constraints::ClaimIndicesVar;
use format::claim_format_verifier_v2;

pub fn claim_extractor_v2<F: PrimeField>(
    key: &str,
    payload: &[FpVar<F>],
    pos: &ClaimIndicesVar<F>,
    max_len: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // Wrap key in double quotes to form "key"
    let key_with_quotes = format!(r#""{}""#, key);
    let key_bytes = key_with_quotes
        .bytes()
        .map(|byte| FpVar::<F>::Constant(F::from(byte)))
        .collect::<Vec<_>>();
    let key_len = key_with_quotes.len();
    let key_len_uint = UInt16::constant(key_len as u16);

    // Extract the entire claim from payload (needed for format verification)
    let claim = slice_efficient(payload, &pos.offset, &pos.claim_len, max_len)?;

    // Extract key name from claim using slice_from_start
    // Claim format: "key":value
    // slice_from_start extracts from position 0 with length key_len
    let pad_char = FpVar::<F>::Constant(F::from(b'0'));
    let result_name = slice_from_start(&claim, &key_len_uint.to_fp()?, key_len, &pad_char)?;

    // Extract value directly from payload using absolute offset
    // This eliminates one slice_efficient call (~50k constraints saved)
    // absolute_value_offset = pos.offset + pos.value_idx
    let absolute_value_offset =
        UInt16::<F>::wrapping_add_many(&[pos.offset.clone(), pos.value_idx.clone()])?;
    let result_value = slice_efficient(payload, &absolute_value_offset, &pos.value_len, max_len)?;

    // Verify that extracted name matches the key (with quotes)
    result_name.enforce_equal(&key_bytes)?;

    // Verify claim format
    claim_format_verifier_v2(
        &claim,
        &pos.claim_len,
        &key_len_uint,
        &pos.colon_idx,
        &pos.value_idx,
        &pos.value_len,
        max_len,
    )?;

    Ok(result_value)
}
