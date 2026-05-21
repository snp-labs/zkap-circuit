//! R1CS variable type for JWT claim index positions.
//!
//! [`ClaimIndicesVar`] is the in-circuit counterpart of [`crate::token::ClaimIndices`].
//! It holds five `UInt16` variables that describe where a named claim sits inside the
//! decoded JWT payload (offset, total length, colon position, value start, value length).
//! The [`AllocVar`] impl allocates all five in the requested mode (witness/input/constant).

use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, uint16::UInt16};
use ark_relations::gr1cs::{Namespace, SynthesisError};

use crate::token::ClaimIndices;

/// In-circuit counterpart of [`crate::token::ClaimIndices`] — five
/// `UInt16` allocations describing the location of one named JWT claim
/// inside the decoded payload.
#[derive(Clone)]
pub struct ClaimIndicesVar<F: PrimeField> {
    /// Claim start position (offset of the opening `"` of the claim key).
    pub offset: UInt16<F>,
    /// Total claim length (key + colon + value, including surrounding quotes).
    pub claim_len: UInt16<F>,
    /// Position of the `:` separator between key and value, relative to
    /// the start of the JWT payload.
    pub colon_idx: UInt16<F>,
    /// Value start position (offset of the first byte of the claim value).
    pub value_idx: UInt16<F>,
    /// Value length in bytes, excluding any surrounding quotes.
    pub value_len: UInt16<F>,
}

impl<F> AllocVar<ClaimIndices, F> for ClaimIndicesVar<F>
where
    F: PrimeField,
{
    fn new_variable<T: Borrow<ClaimIndices>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let claim_indices = f()?.borrow().clone();

        // C2.4: replace silent `as u16` truncation with `u16::try_from` so any
        // overflow surfaces as SynthesisError::AssignmentMissing instead of
        // creating an aliased low-bits value.
        let offset = UInt16::new_variable(
            cs.clone(),
            || u16::try_from(claim_indices.offset).map_err(|_| SynthesisError::AssignmentMissing),
            mode,
        )?;
        let claim_len = UInt16::new_variable(
            cs.clone(),
            || {
                u16::try_from(claim_indices.claim_len)
                    .map_err(|_| SynthesisError::AssignmentMissing)
            },
            mode,
        )?;
        let colon_idx = UInt16::new_variable(
            cs.clone(),
            || {
                u16::try_from(claim_indices.colon_idx)
                    .map_err(|_| SynthesisError::AssignmentMissing)
            },
            mode,
        )?;

        let value_idx = UInt16::new_variable(
            cs.clone(),
            || {
                u16::try_from(claim_indices.value_idx)
                    .map_err(|_| SynthesisError::AssignmentMissing)
            },
            mode,
        )?;
        let value_len = UInt16::new_variable(
            cs.clone(),
            || {
                u16::try_from(claim_indices.value_len)
                    .map_err(|_| SynthesisError::AssignmentMissing)
            },
            mode,
        )?;

        Ok(Self {
            offset,
            claim_len,
            colon_idx,
            value_idx,
            value_len,
        })
    }
}

#[cfg(test)]
mod tests {
    //! C2.4 overflow rejection — each field must trigger
    //! `SynthesisError::AssignmentMissing` when its `usize` value exceeds
    //! `u16::MAX`. Prior to AC-4 these would silently truncate to the low
    //! 16 bits, producing an aliased witness that the circuit would happily
    //! accept.
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocationMode;
    use ark_relations::gr1cs::ConstraintSystem;

    const OVERFLOW: usize = u16::MAX as usize + 1; // 65_536

    fn assert_overflow_rejected(ci: ClaimIndices, field: &str) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        // Discard the Ok variant (ClaimIndicesVar doesn't impl Debug) — only
        // the error case needs to be inspectable for the failure message.
        let err = ClaimIndicesVar::<Fr>::new_variable(
            cs,
            || Ok::<_, SynthesisError>(ci),
            AllocationMode::Witness,
        )
        .err();
        assert!(
            matches!(err, Some(SynthesisError::AssignmentMissing)),
            "expected overflow for {field} to map to SynthesisError::AssignmentMissing, got Err = {err:?}",
        );
    }

    #[test]
    fn try_from_rejects_overflow_offset() {
        let ci = ClaimIndices {
            offset: OVERFLOW,
            ..Default::default()
        };
        assert_overflow_rejected(ci, "offset");
    }

    #[test]
    fn try_from_rejects_overflow_claim_len() {
        let ci = ClaimIndices {
            claim_len: OVERFLOW,
            ..Default::default()
        };
        assert_overflow_rejected(ci, "claim_len");
    }

    #[test]
    fn try_from_rejects_overflow_colon_idx() {
        let ci = ClaimIndices {
            colon_idx: OVERFLOW,
            ..Default::default()
        };
        assert_overflow_rejected(ci, "colon_idx");
    }

    #[test]
    fn try_from_rejects_overflow_value_idx() {
        let ci = ClaimIndices {
            value_idx: OVERFLOW,
            ..Default::default()
        };
        assert_overflow_rejected(ci, "value_idx");
    }

    #[test]
    fn try_from_rejects_overflow_value_len() {
        let ci = ClaimIndices {
            value_len: OVERFLOW,
            ..Default::default()
        };
        assert_overflow_rejected(ci, "value_len");
    }
}
