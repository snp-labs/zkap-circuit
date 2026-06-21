//! Audience allow-list membership constraints.

use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::gr1cs::SynthesisError;

pub(crate) fn enforce_audience_membership_by_equality<F: PrimeField>(
    target_aud: &FpVar<F>,
    aud_list: &[FpVar<F>],
) -> Result<(), SynthesisError> {
    if aud_list.is_empty() {
        return Err(SynthesisError::Unsatisfiable);
    }

    let equality_matches = aud_list
        .iter()
        .map(|valid_aud| target_aud.is_eq(valid_aud))
        .collect::<Result<Vec<_>, _>>()?;

    Boolean::kary_or(&equality_matches)?.enforce_equal(&Boolean::TRUE)
}
