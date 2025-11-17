use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::{FieldVar, fp::FpVar},
    groups::{CurveVar, GroupOpsBounds},
    prelude::{Boolean, EqGadget, ToBitsGadget},
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use crate::{
    anchor::{
        constraints::AnchorSchemeGadget,
        dl::{DLAnchor, DLAnchorPublicKey, DLAnchorScheme, DLAnchorWitness},
    },
    utils::{a_lt_b, single_multiplexer},
};

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Clone)]
pub struct DLAnchorPublicKeyVar<C, CV>
where
    C: CurveGroup,
    CV: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    pub generators: Vec<CV>,
    pub _phantom: std::marker::PhantomData<C>,
}

#[derive(Clone)]
pub struct DLAnchorWitnessVar<C: CurveGroup> {
    pub u: Vec<FpVar<ConstraintF<C>>>,
    pub ut: Vec<FpVar<ConstraintF<C>>>,
    pub placed_secrets: Vec<FpVar<ConstraintF<C>>>,
    pub placed_indices: Vec<FpVar<ConstraintF<C>>>,
    pub quotients: Vec<FpVar<ConstraintF<C>>>,
    pub remainders: Vec<FpVar<ConstraintF<C>>>,
}

impl<C> DLAnchorWitnessVar<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    pub fn enforce_set_equality(
        &self,
        cs: ConstraintSystemRef<ConstraintF<C>>,
        ext_secret: &[FpVar<ConstraintF<C>>],
        k: usize,
    ) -> Result<(), SynthesisError> {
        Self::enforce_k_non_zero(&self, k)?;
        Self::enforce_integer_relation(&self)?;

        let reconstructed = Self::apply_placed_indices(&self, cs.clone(), ext_secret)?;

        reconstructed.enforce_equal(&self.placed_secrets)?;

        Ok(())
    }

    pub fn apply_placed_indices(
        &self,
        _cs: ConstraintSystemRef<ConstraintF<C>>,
        ext_secret: &[FpVar<ConstraintF<C>>],
    ) -> Result<Vec<FpVar<ConstraintF<C>>>, SynthesisError> {
        let mut result = Vec::with_capacity(self.placed_indices.len());
        let mut idx = FpVar::<ConstraintF<C>>::zero();
        let zero = FpVar::<ConstraintF<C>>::zero();

        for sel in self.placed_indices.iter() {
            let is_one = sel.is_eq(&FpVar::one())?;
            let selected = single_multiplexer(ext_secret, &idx)?;

            let value = is_one.select(&selected, &zero)?;
            result.push(value);

            idx += sel;
        }

        Ok(result)
    }

    pub fn enforce_integer_relation(&self) -> Result<(), SynthesisError> {
        let modulus = <C as PrimeGroup>::ScalarField::MODULUS;
        let modulus_bytes = modulus.to_bytes_le();
        let modulus =
            FpVar::<C::BaseField>::Constant(C::BaseField::from_le_bytes_mod_order(&modulus_bytes));
        let modulus_bits = modulus.to_bits_le()?;

        for i in 0..self.placed_secrets.len() {
            let lhs = self.placed_secrets[i].clone() * self.ut[i].clone();

            let rhs = self.quotients[i].clone() * modulus.clone() + self.remainders[i].clone();

            lhs.enforce_equal(&rhs)?;

            let result = a_lt_b(&self.remainders[i].to_bits_le()?, &modulus_bits)?;
            result.enforce_equal(&Boolean::TRUE)?;
        }

        Ok(())
    }

    pub fn enforce_k_non_zero(&self, k: usize) -> Result<(), SynthesisError> {
        // indices는 0 또는 1의 값을 가져야 한다.
        for idx in &self.placed_indices {
            let binary = idx * (FpVar::one() - idx);
            binary.enforce_equal(&FpVar::zero())?;
        }

        // indices의 합이 k와 같아야 한다.
        let indices_sum = self
            .placed_indices
            .iter()
            .fold(FpVar::zero(), |acc, x| acc + x);
        indices_sum.enforce_equal(&FpVar::constant(C::BaseField::from(k as u64)))?;

        // sids[i]가 0이 아닌 경우에만 indices[i]가 1이어야 한다.
        for (sid, idx) in self.placed_secrets.iter().zip(self.placed_indices.iter()) {
            let is_zero = sid * (FpVar::one() - idx);
            is_zero.enforce_equal(&FpVar::zero())?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct DLAnchorVar<C, CV>
where
    C: CurveGroup,
    CV: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    pub anchor: Vec<CV>,
    pub _phantom: PhantomData<C>,
}

#[derive(Clone)]
pub struct DLAnchorSchemeGadget<C: CurveGroup, CV: CurveVar<C, ConstraintF<C>>> {
    pub _phantom: PhantomData<(C, CV)>,
}

impl<C, CV> DLAnchorSchemeGadget<C, CV>
where
    C: CurveGroup,
    CV: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
    C::BaseField: PrimeField,
{
    pub fn aggregate<B>(base: B, scalars: &[FpVar<ConstraintF<C>>]) -> Result<CV, SynthesisError>
    where
        B: AsRef<[CV]>,
    {
        let mut result = CV::zero();
        for (i, scalar) in scalars.iter().enumerate() {
            let term = CurveVar::<C, ConstraintF<C>>::scalar_mul_le(
                &base.as_ref()[i],
                scalar.to_bits_le()?.iter(),
            )?;
            result += term;
        }
        Ok(result)
    }
}

impl<C, CV> AllocVar<DLAnchorPublicKey<C>, ConstraintF<C>> for DLAnchorPublicKeyVar<C, CV>
where
    C: CurveGroup,
    CV: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    fn new_variable<T: Borrow<DLAnchorPublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|val| {
            let generators =
                Vec::<CV>::new_variable(cs, || Ok(val.borrow().generators.clone()), mode)?;
            Ok(DLAnchorPublicKeyVar {
                generators,
                _phantom: std::marker::PhantomData,
            })
        })
    }
}

impl<C> AllocVar<DLAnchorWitness<C>, ConstraintF<C>> for DLAnchorWitnessVar<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
{
    fn new_variable<T: Borrow<DLAnchorWitness<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|val| {
            let u = Vec::<FpVar<ConstraintF<C>>>::new_variable(
                cs.clone(),
                || Ok(convert_scalar_tobase(&val.borrow().u)),
                mode,
            )?;
            let ut = Vec::<FpVar<ConstraintF<C>>>::new_variable(
                cs.clone(),
                || Ok(convert_scalar_tobase(&val.borrow().ut)),
                mode,
            )?;
            let placed_secrets = Vec::<FpVar<ConstraintF<C>>>::new_variable(
                cs.clone(),
                || Ok(convert_scalar_tobase(&val.borrow().placed_secrets)),
                mode,
            )?;
            let placed_indices = Vec::<FpVar<ConstraintF<C>>>::new_variable(
                cs.clone(),
                || Ok(val.borrow().placed_indices.clone()),
                mode,
            )?;
            let quotients = Vec::<FpVar<ConstraintF<C>>>::new_variable(
                cs.clone(),
                || Ok(val.borrow().quotients.clone()),
                mode,
            )?;
            let remainders = Vec::<FpVar<ConstraintF<C>>>::new_variable(
                cs,
                || Ok(val.borrow().remainders.clone()),
                mode,
            )?;
            Ok(Self {
                u,
                ut,
                placed_secrets,
                placed_indices,
                quotients,
                remainders,
            })
        })
    }
}

impl<C, CV> AllocVar<DLAnchor<C>, ConstraintF<C>> for DLAnchorVar<C, CV>
where
    C: CurveGroup,
    CV: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    fn new_variable<T: Borrow<DLAnchor<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|val| {
            let anchor = Vec::<CV>::new_variable(cs, || Ok(val.borrow().0.clone()), mode)?;
            Ok(DLAnchorVar {
                anchor,
                _phantom: std::marker::PhantomData,
            })
        })
    }
}

fn convert_scalar_tobase<SF: PrimeField, BF: PrimeField>(scalar_vec: &[SF]) -> Vec<BF> {
    scalar_vec
        .iter()
        .map(|s| BF::from_le_bytes_mod_order(&s.into_bigint().to_bytes_le()))
        .collect()
}

impl<C, CV> AnchorSchemeGadget<DLAnchorScheme<C>, ConstraintF<C>> for DLAnchorSchemeGadget<C, CV>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CV: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    type PublicKeyVar = DLAnchorPublicKeyVar<C, CV>;
    type AnchorVar = DLAnchorVar<C, CV>;
    type WitnessVar = DLAnchorWitnessVar<C>;

    fn verify(
        pk: &Self::PublicKeyVar,
        anchor: &Self::AnchorVar,
        witness: &Self::WitnessVar,
    ) -> Result<(), SynthesisError> {
        let lhs = Self::aggregate(&anchor.anchor, &witness.u)?;
        let rhs = Self::aggregate(&pk.generators, &witness.remainders)?;

        lhs.enforce_equal(&rhs)?;

        Ok(())
    }
}
