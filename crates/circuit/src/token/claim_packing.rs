//! Token claim byte packing helpers.
//!
//! These functions preserve the ZKAP claim packing semantics: big-endian
//! field-limb packing at the maximum limb width allowed by the field.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;

pub(crate) fn pack_claim_bytes_to_field_limbs<F: PrimeField>(
    claim_bytes: &[FpVar<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let limb_width = ((F::MODULUS_BIT_SIZE - 1) / 8) as usize;

    if claim_bytes.is_empty() {
        return Ok(Vec::new());
    }

    if !claim_bytes.len().is_multiple_of(limb_width) {
        return Err(SynthesisError::Unsatisfiable);
    }

    claim_bytes
        .chunks_exact(limb_width)
        .map(|chunk| Ok(pack_claim_limb_be_unchecked(chunk)))
        .collect()
}

fn pack_claim_limb_be_unchecked<F: PrimeField>(claim_limb_bytes: &[FpVar<F>]) -> FpVar<F> {
    let base = F::from(256u64);
    let mut powers_of_256 = Vec::with_capacity(claim_limb_bytes.len());

    let mut current_power = F::one();
    for _ in 0..claim_limb_bytes.len() {
        powers_of_256.push(current_power);
        current_power *= base;
    }
    powers_of_256.reverse();

    let mut packed = FpVar::<F>::Constant(F::zero());
    for (byte, power) in claim_limb_bytes.iter().zip(powers_of_256.iter()) {
        packed += byte * FpVar::Constant(*power);
    }

    packed
}
