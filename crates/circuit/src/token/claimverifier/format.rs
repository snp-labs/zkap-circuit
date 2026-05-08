//! Format-verification helpers for [`super::claim_extractor_v2`].
//!
//! This module contains the seven-invariant claim format check
//! ([`claim_format_verifier_v2`]) plus its private support gadgets
//! ([`enforce_range_is_whitespace_v2`], [`is_whitespace`]). They were split
//! out of `claimverifier.rs` so the entry-point file stays focused on the
//! extraction flow while the format-checker remains together with the
//! whitespace utilities it depends on.
//!
//! L1 (R1CS-equivalence) note: the constraint expressions and their
//! ordering are byte-for-byte the same as before the split. Do not
//! re-order, fold, or "simplify" any of the `enforce_*` calls without
//! updating the trusted setup — see
//! `.omc/plans/2026-05-08-per-crate-refactor/00-cross-cutting-locks.md § L1`.
//!
//! The `enforce_cmp(Ordering::Less, true)` workaround applied at check1
//! and check2 is pinned by
//! `crates/circuit/tests/r1cs_std_enforce_cmp_repro.rs` against
//! ark-r1cs-std 0.5.0. That test is the trigger for revisiting the
//! workaround when the `ark-r1cs-std` pin is bumped — until then the
//! `is_less_than | is_eq` expression below stays as-is.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    select::CondSelectGadget,
    uint16::UInt16,
};
use ark_relations::r1cs::SynthesisError;
use ark_utils::{is_less_than, single_multiplexer};

pub(super) fn claim_format_verifier_v2<F: PrimeField>(
    claim: &[FpVar<F>],
    claim_len: &UInt16<F>,
    name_len: &UInt16<F>,
    colon_idx: &UInt16<F>,
    value_idx: &UInt16<F>,
    value_len: &UInt16<F>,
    max_claim_len: usize,
) -> Result<(), SynthesisError> {
    let value_len = Boolean::le_bits_to_fp(&value_len.to_bits_le()?)?;
    let claim_len = Boolean::le_bits_to_fp(&claim_len.to_bits_le()?)?;

    // check1: name_len <= colon_idx
    // Note: `enforce_cmp` is intentionally not used here.  There is a bug in
    // `ark-r1cs-std 0.5.0` (the version this workspace pins) that produces
    // unsound constraints for `Ordering::Less` with `strict = true`.  The
    // equivalent `is_less_than | is_eq` expression below is correct and must
    // not be reverted to `enforce_cmp` until the upstream fix is verified.
    let name_len_boolean = name_len.to_bits_le()?;
    let colon_idx_boolean = colon_idx.to_bits_le()?;
    let result =
        is_less_than(&name_len_boolean, &colon_idx_boolean)? | name_len.is_eq(colon_idx)?;
    result.enforce_equal(&Boolean::TRUE)?;

    // check2: colon_idx < value_idx  (same enforce_cmp workaround as check1)
    let value_idx_boolean = value_idx.to_bits_le()?;
    let result = is_less_than(&colon_idx_boolean, &value_idx_boolean)?;
    result.enforce_equal(&Boolean::TRUE)?;

    // Compute flags once: 1 if not whitespace, 0 if whitespace.
    let is_not_whitespace_flags = claim
        .iter()
        .map(|byte| Ok(FpVar::from(!is_whitespace(byte)?)))
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    let name_len = name_len.to_fp()?;
    let colon_idx = colon_idx.to_fp()?;
    let value_idx = value_idx.to_fp()?;

    // check3: no non-whitespace characters between key and colon. (name_len-1 < i < colon_idx)
    enforce_range_is_whitespace_v2(
        &(name_len - F::ONE),
        &colon_idx,
        &is_not_whitespace_flags,
        max_claim_len,
    )?;

    // check4: no non-whitespace characters between colon_idx and value_idx. (colon_idx < i < value_idx)
    enforce_range_is_whitespace_v2(
        &colon_idx,
        &value_idx,
        &is_not_whitespace_flags,
        max_claim_len,
    )?;

    // check5: no non-whitespace characters between end of value and end of claim.
    // `value_end_idx = value_idx + value_len` is the first index after the value.
    // `claim_end_idx = claim_len - 1` is the last character index of the claim.
    // The open-interval check in enforce_range_is_whitespace_v2 therefore covers
    // (value_end_idx, claim_end_idx), i.e. the trailing whitespace region.
    //
    // Security note: whether the off-by-one boundary (value_end_idx vs value_end_idx+1)
    // matches the protocol spec requires a dedicated security audit before any change.
    // Do NOT modify the expression below without updating the trusted setup.
    // See .omc/plans/2026-05-08-per-crate-refactor/00-cross-cutting-locks.md § L1.
    let value_end_idx = value_idx + value_len;
    let claim_end_idx = claim_len.clone() - F::ONE; // last character index of claim
    enforce_range_is_whitespace_v2(
        &value_end_idx,
        &claim_end_idx,
        &is_not_whitespace_flags,
        max_claim_len,
    )?;

    // check6: verify that colon is at colon_idx position.
    let colon_var = single_multiplexer(claim, &colon_idx)?;
    colon_var.enforce_equal(&FpVar::<F>::Constant(F::from(b':')))?;

    // check7: last character must be ',' (mid-object claim) or '}' (final claim).
    // The `is_closing_brace | is_comma` boolean OR is cleaner than the product-of-differences
    // trick ((x - ',') * (x - '}') == 0) because it names each case explicitly and avoids
    // the extra field multiplication.
    let last_char_var = single_multiplexer(claim, &(claim_len - F::ONE))?;
    let is_closing_brace = last_char_var.is_eq(&FpVar::constant(F::from(b'}')))?;
    let is_comma = last_char_var.is_eq(&FpVar::constant(F::from(b',')))?;
    (is_closing_brace | is_comma).enforce_equal(&Boolean::TRUE)?;

    Ok(())
}

fn enforce_range_is_whitespace_v2<F: PrimeField>(
    start_idx: &FpVar<F>,
    end_idx: &FpVar<F>,
    is_not_whitespace_flags: &[FpVar<F>],
    max_len: usize,
) -> Result<(), SynthesisError> {
    // Build prefix sums: prefix[i] = sum(is_not_whitespace_flags[0..i])
    // prefix[0] = 0, prefix[1] = flags[0], ..., prefix[max_len] = sum of all flags
    let mut prefix_sums = Vec::with_capacity(max_len + 1);
    prefix_sums.push(FpVar::<F>::zero());
    let mut running_sum = FpVar::<F>::zero();
    for flag in is_not_whitespace_flags.iter().take(max_len) {
        running_sum += flag;
        prefix_sums.push(running_sum.clone());
    }

    // We want sum of flags[i] for i in the open interval (start_idx, end_idx).
    // That equals prefix[end_idx] - prefix[start_idx + 1].
    //
    // When the range is empty (end_idx <= start_idx), we must produce 0.
    // We clamp the lower lookup index: use end_idx instead of start_idx+1 when
    // end_idx <= start_idx, making both lookups identical and the difference 0.
    //
    // Compute: is_nonempty = (start_idx + 1 <= end_idx), i.e., start_idx < end_idx.
    // Then: lookup_start = if is_nonempty { start_idx + 1 } else { end_idx }
    let start_idx_plus_1 = start_idx + FpVar::one();

    // Use 16-bit LE representation (indices fit in 16 bits since max_len <= ~500)
    let start_plus_1_bits = start_idx_plus_1.to_bits_le()?;
    let end_bits = end_idx.to_bits_le()?;
    let bits_16 = 16usize;
    let start_plus_1_bits_16 = &start_plus_1_bits[..bits_16];
    let end_bits_16 = &end_bits[..bits_16];

    // is_nonempty = start_idx + 1 <= end_idx  (equivalently: start_idx + 1 < end_idx OR equal)
    let is_lt = is_less_than(start_plus_1_bits_16, end_bits_16)?;
    let is_eq_end = start_idx_plus_1.is_eq(end_idx)?;
    let is_nonempty = is_lt | is_eq_end;

    // Clamp: if nonempty use start_idx+1, else use end_idx (range sum becomes 0)
    let lookup_start = FpVar::conditionally_select(&is_nonempty, &start_idx_plus_1, end_idx)?;

    let prefix_at_lookup_start = single_multiplexer(&prefix_sums, &lookup_start)?;
    let prefix_at_end = single_multiplexer(&prefix_sums, end_idx)?;

    // range_sum = prefix[end] - prefix[lookup_start]; enforced to be 0
    let range_sum = prefix_at_end - prefix_at_lookup_start;
    range_sum.enforce_equal(&FpVar::zero())?;

    Ok(())
}

fn is_whitespace<F: PrimeField>(byte: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
    let is_tab = byte.is_eq(&FpVar::constant(F::from(0x09u8)))?;
    let is_newline = byte.is_eq(&FpVar::constant(F::from(0x0Au8)))?;
    let is_carriage_return = byte.is_eq(&FpVar::constant(F::from(0x0Du8)))?;
    let is_space = byte.is_eq(&FpVar::constant(F::from(0x20u8)))?;

    Ok(is_tab | is_newline | is_carriage_return | is_space)
}
