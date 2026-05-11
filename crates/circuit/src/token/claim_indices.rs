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

        let offset = UInt16::new_variable(cs.clone(), || Ok(claim_indices.offset as u16), mode)?;
        let claim_len =
            UInt16::new_variable(cs.clone(), || Ok(claim_indices.claim_len as u16), mode)?;
        let colon_idx =
            UInt16::new_variable(cs.clone(), || Ok(claim_indices.colon_idx as u16), mode)?;

        let value_idx =
            UInt16::new_variable(cs.clone(), || Ok(claim_indices.value_idx as u16), mode)?;
        let value_len =
            UInt16::new_variable(cs.clone(), || Ok(claim_indices.value_len as u16), mode)?;

        Ok(Self {
            offset,
            claim_len,
            colon_idx,
            value_idx,
            value_len,
        })
    }
}
