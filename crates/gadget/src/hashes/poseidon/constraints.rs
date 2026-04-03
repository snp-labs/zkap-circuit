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
