use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget,
        poseidon::constraints::{CRHGadget, CRHParametersVar},
    },
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    groups::{CurveVar, GroupOpsBounds},
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

pub fn enforce_curve_hanchor<C, CV>(
    cs: ConstraintSystemRef<C::BaseField>,
    poseidon_param: &CRHParametersVar<C::BaseField>,
    anchor: &[CV],
    _hanchor: &FpVar<C::BaseField>,
) -> Result<(), SynthesisError>
where
    C: CurveGroup,
    CV: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField + Absorb,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    let slice_tag = anchor
        .iter()
        .map(|affine| affine.to_constraint_field())
        .collect::<Result<Vec<_>, SynthesisError>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let _reconstructed_hash = chain_hash_gadget(cs.clone(), poseidon_param, &slice_tag)?;

    Ok(())
}

pub fn chain_hash_gadget<F: PrimeField + Absorb>(
    _cs: ConstraintSystemRef<F>,
    parameters: &CRHParametersVar<F>,
    values: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
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
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use ark_relations::r1cs::ConstraintSystem;

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
}
