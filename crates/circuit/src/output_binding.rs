//! Output-binding mask helpers for Phase 5 of the ZKAP circuit.

use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget,
        poseidon::constraints::{CRHGadget as PoseidonCRHGadget, CRHParametersVar},
    },
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;

fn output_mask_for_index<F: PrimeField + Absorb>(
    parameters: &CRHParametersVar<F>,
    random: &FpVar<F>,
    index: usize,
) -> Result<FpVar<F>, SynthesisError> {
    PoseidonCRHGadget::<F>::evaluate(
        parameters,
        &[random.clone(), FpVar::Constant(F::from(index as u64))],
    )
}

pub(crate) fn output_masks_for_indices<F: PrimeField + Absorb>(
    parameters: &CRHParametersVar<F>,
    random: &FpVar<F>,
    n: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    (0..n)
        .map(|index| output_mask_for_index(parameters, random, index))
        .collect()
}

pub(crate) fn selected_output_mask_sum<F: PrimeField>(
    indices: &[FpVar<F>],
    output_masks: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    if indices.is_empty() || indices.len() != output_masks.len() {
        return Err(SynthesisError::Unsatisfiable);
    }

    Ok(indices
        .iter()
        .zip(output_masks.iter())
        .fold(FpVar::<F>::Constant(F::zero()), |sum, (selector, mask)| {
            sum + selector * mask
        }))
}
