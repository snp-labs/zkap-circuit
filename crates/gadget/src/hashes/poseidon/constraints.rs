//! R1CS gadgets for sequential Poseidon hash chaining.
//!
//! [`poseidon_chain_hash`] evaluates a sequential Poseidon hash chain over a
//! slice of `FpVar` values, matching the native recipe used by the host-side
//! anchor binding (`service::anchor::poseidon::chain_hash`). The older
//! [`chain_hash_gadget`] surface is kept as a compatibility wrapper.

use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget,
        poseidon::constraints::{CRHGadget, CRHParametersVar},
    },
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

/// Evaluates a sequential Poseidon hash chain over `values` in-circuit:
/// `H(H(…H(H(v[0]), v[1])…), v[n-1])`.
///
/// Matches the native evaluation in [`crate::hashes::poseidon::get_poseidon_params`].
/// Returns `SynthesisError::Unsatisfiable` for empty input.
pub fn chain_hash_gadget<F: PrimeField + Absorb>(
    _cs: ConstraintSystemRef<F>,
    parameters: &CRHParametersVar<F>,
    values: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    poseidon_chain_hash(parameters, values)
}

/// Evaluates a sequential Poseidon hash chain over `values` in-circuit:
/// `H(H(…H(H(v[0]), v[1])…), v[n-1])`.
///
/// Matches the native evaluation in [`crate::hashes::poseidon::get_poseidon_params`].
/// Returns [`SynthesisError::Unsatisfiable`] for empty input.
pub fn poseidon_chain_hash<F: PrimeField + Absorb>(
    parameters: &CRHParametersVar<F>,
    values: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    if values.is_empty() {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut hash = CRHGadget::<F>::evaluate(parameters, &[values[0].clone()])?;
    for value in values.iter().skip(1) {
        hash = CRHGadget::<F>::evaluate(parameters, &[hash, value.clone()])?;
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::crh::{
        CRHScheme,
        poseidon::{CRH, constraints::CRHParametersVar},
    };
    use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use ark_relations::gr1cs::ConstraintSystem;

    type F = ark_bn254::Fr;

    fn get_params() -> ark_crypto_primitives::sponge::poseidon::PoseidonConfig<F> {
        crate::hashes::poseidon::get_poseidon_params::<F>()
    }

    #[test]
    fn test_chain_hash_matches_native() {
        let cs = ConstraintSystem::<F>::new_ref();
        let params = get_params();
        let param_var = CRHParametersVar::<F>::new_constant(cs.clone(), params.clone()).unwrap();

        let vals = [F::from(1u64), F::from(2u64), F::from(3u64)];
        let val_vars: Vec<FpVar<F>> = vals
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect();

        let gadget_result = chain_hash_gadget(cs.clone(), &param_var, &val_vars).unwrap();
        assert!(cs.is_satisfied().unwrap());

        // Native: H(H(1), 2) then H(result, 3)
        let h1 = CRH::evaluate(&params, [vals[0]]).unwrap();
        let h2 = CRH::evaluate(&params, [h1, vals[1]]).unwrap();
        let h3 = CRH::evaluate(&params, [h2, vals[2]]).unwrap();

        assert_eq!(gadget_result.value().unwrap(), h3);
    }

    #[test]
    fn test_chain_hash_wrong_output() {
        let cs = ConstraintSystem::<F>::new_ref();
        let params = get_params();
        let param_var = CRHParametersVar::<F>::new_constant(cs.clone(), params.clone()).unwrap();

        let vals: Vec<FpVar<F>> = (1..=3u64)
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(F::from(v))).unwrap())
            .collect();

        let result = chain_hash_gadget(cs.clone(), &param_var, &vals).unwrap();
        let wrong = FpVar::new_witness(cs.clone(), || Ok(F::from(9999u64))).unwrap();
        result.enforce_equal(&wrong).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_chain_hash_single_element() {
        let cs = ConstraintSystem::<F>::new_ref();
        let params = get_params();
        let param_var = CRHParametersVar::<F>::new_constant(cs.clone(), params.clone()).unwrap();

        let val = F::from(42u64);
        let val_var = FpVar::new_witness(cs.clone(), || Ok(val)).unwrap();

        let gadget_result = chain_hash_gadget(cs.clone(), &param_var, &[val_var]).unwrap();
        assert!(cs.is_satisfied().unwrap());

        let native = CRH::evaluate(&params, [val]).unwrap();
        assert_eq!(gadget_result.value().unwrap(), native);
    }

    #[test]
    fn test_chain_hash_empty_input_errors() {
        let cs = ConstraintSystem::<F>::new_ref();
        let params = get_params();
        let param_var = CRHParametersVar::<F>::new_constant(cs.clone(), params).unwrap();

        let result = chain_hash_gadget(cs, &param_var, &[]);
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }
}
