use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget,
        poseidon::constraints::{CRHGadget, CRHParametersVar},
    },
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar, alloc::AllocVar, eq::EqGadget, fields::{FieldVar, fp::FpVar}
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use crate::{
    anchor::{
        constraints::AnchorSchemeGadget,
        poseidon::{
            PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorScheme, PoseidonAnchorWitness,
        },
    },
    utils::single_multiplexer,
};

#[cfg(feature = "r1cs-debug")]
use crate::debug::log_r1cs_eq;

#[derive(Clone)]
pub struct PoseidonAnchorPublicKeyVar<F: PrimeField + Absorb> {
    pub params: CRHParametersVar<F>,
}

#[derive(Clone)]
pub struct PoseidonAnchorWitnessVar<F: PrimeField + Absorb> {
    pub u: Vec<FpVar<F>>,
    pub ut: Vec<FpVar<F>>,
    pub placed_secrets: Vec<FpVar<F>>, // 선택된 시크릿들. k = 3 => [h_1, 0, h_3, 0, h_5] 형태
    pub placed_indices: Vec<FpVar<F>>, // 시크릿 선택 여부를 나타내는 바이너리 벡터. k = 3 => [1,0,1,0,1] 형태
}

impl<F> PoseidonAnchorWitnessVar<F>
where
    F: PrimeField + Absorb,
{
    pub fn enforce_set_equality(
        &self,
        cs: ConstraintSystemRef<F>,
        parameters: &CRHParametersVar<F>,
        ext_secret: &[FpVar<F>],
        k: usize,
    ) -> Result<(), SynthesisError> {
        Self::enforce_k_non_zero(&self, k)?;

        let reconstructed = Self::apply_placed_indices(&self, cs.clone(), parameters, ext_secret)?;

        reconstructed.enforce_equal(&self.placed_secrets)?;

        Ok(())
    }

    // placed_indices가 정확히 k개의 1을 가지고,
    // placed_secrets[i]가 0이 아닌 경우에만 placed_indices[i]가 1임을 강제한다.
    pub fn enforce_k_non_zero(&self, k: usize) -> Result<(), SynthesisError> {
        // indices는 0 또는 1의 값을 가져야 한다.
        for idx in &self.placed_indices {
            let binary = idx * (FpVar::one() - idx);
            #[cfg(feature = "r1cs-debug")]
            log_r1cs_eq(
                "PoseidonAnchorWitnessVar::enforce_k_non_zero - binary check",
                &[binary.clone()],
                &[FpVar::zero()],
            );

            binary.enforce_equal(&FpVar::zero())?;
        }

        // indices의 합이 k와 같아야 한다.
        let indices_sum = self
            .placed_indices
            .iter()
            .fold(FpVar::zero(), |acc, x| acc + x);

        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq(
            "PoseidonAnchorWitnessVar::enforce_k_non_zero - indices_sum",
            &[indices_sum.clone()],
            &[FpVar::constant(F::from(k as u64))],
        );
    
        indices_sum.enforce_equal(&FpVar::constant(F::from(k as u64)))?;

        // sids[i]가 0이 아닌 경우에만 indices[i]가 1이어야 한다.
        for (sid, idx) in self.placed_secrets.iter().zip(self.placed_indices.iter()) {
            let is_zero = sid * (FpVar::one() - idx);
            #[cfg(feature = "r1cs-debug")]
            log_r1cs_eq(
                "PoseidonAnchorWitnessVar::enforce_k_non_zero - sid zero check",
                &[is_zero.clone()],
                &[FpVar::zero()],
            );

            is_zero.enforce_equal(&FpVar::zero())?;
        }

        Ok(())
    }

    pub fn enforce_slot_activation(
        &self,
        slot_indices: &[FpVar<F>],
        slot: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        let index = single_multiplexer(slot_indices, slot)?;
        let is_one = single_multiplexer(&self.placed_indices, &index)?;

        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq("PoseidonAnchorWitnessVar::enforce_slot_activation", &[is_one.clone()], &[FpVar::one()]);

        is_one.enforce_equal(&FpVar::one())?;
        Ok(())
    }

    pub fn apply_placed_indices(
        &self,
        _cs: ConstraintSystemRef<F>,
        parameters: &CRHParametersVar<F>,
        ext_secret: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut result = Vec::with_capacity(self.placed_indices.len());
        let mut idx = FpVar::<F>::zero();
        let zero = FpVar::<F>::zero();

        for (i, sel) in self.placed_indices.iter().enumerate() {
            let i_const = FpVar::<F>::constant(F::from(i as u64));
            let is_one = sel.is_eq(&FpVar::one())?;
            let selected = single_multiplexer(ext_secret, &idx)?;

            let h = CRHGadget::<F>::evaluate(parameters, &[i_const, selected])?;

            let value = is_one.select(&h, &zero)?;
            result.push(value);

            idx += sel;
        }

        Ok(result)
    }

    pub fn enforce_h_i(&self, z: &Vec<FpVar<F>>, h_i: &FpVar<F>) -> Result<(), SynthesisError> {
        let one = vec![FpVar::<F>::one(); z.len()];

        // z_i는 0 또는 1의 값을 가져야 한다.
        for zi in z.iter() {
            let binary = zi * (FpVar::one() - zi);
            #[cfg(feature = "r1cs-debug")]
            log_r1cs_eq(
                "PoseidonAnchorWitnessVar::enforce_h_i - z binary check",
                &[binary.clone()],
                &[FpVar::zero()],
            );

            binary.enforce_equal(&FpVar::zero())?;
        }

        // <z, 1> = 1 이어야한다.
        let sum = z
            .iter()
            .zip(one.iter())
            .map(|(x, y)| x * y)
            .fold(FpVar::zero(), |acc, v| acc + v);
        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq(
            "PoseidonAnchorWitnessVar::enforce_h_i - z sum check",
            &[sum.clone()],
            &[FpVar::one()],
        );

        sum.enforce_equal(&FpVar::one())?;

        // (1 - placed_indices) * z = 0 이어야한다.
        for (zi, pi) in z.iter().zip(self.placed_indices.iter()) {
            let prod = (FpVar::one() - pi) * zi;
            #[cfg(feature = "r1cs-debug")]
            log_r1cs_eq(
                "PoseidonAnchorWitnessVar::enforce_h_i - (1 - placed_indices) * z check",
                &[prod.clone()],
                &[FpVar::zero()],
            );

            prod.enforce_equal(&FpVar::zero())?;
        }

        match z.value() {
            Ok(v) => println!("z vector: {:?}", v.iter().map(|x| x.to_string()).collect::<Vec<_>>()),
            Err(_) => println!("z vector: <missing>"),
        }

        match self.placed_secrets.value() {
            Ok(v) => println!("placed_secrets vector: {:?}", v.iter().map(|x| x.to_string()).collect::<Vec<_>>()),
            Err(_) => println!("placed_secrets vector: <missing>"),
        }

        match h_i.value() {
            Ok(v) => println!("h_i value: {}", v.to_string()),
            Err(_) => println!("h_i value: <missing>"),
        }

        // <z, placed_secrets> = h_i 이어야한다.
        let secret_sum = z
            .iter()
            .zip(self.placed_secrets.iter())
            .map(|(x, y)| x * y)
            .fold(FpVar::zero(), |acc, v| acc + v);
        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq(
            "PoseidonAnchorWitnessVar::enforce_h_i - secret sum check",
            &[secret_sum.clone()],
            &[h_i.clone()],
        );

        secret_sum.enforce_equal(h_i)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct PoseidonAnchorVar<F>
where
    F: PrimeField + Absorb,
{
    pub anchor: Vec<FpVar<F>>,
}

#[derive(Clone)]
pub struct PoseidonAnchorSchemeGadget<F>
where
    F: PrimeField + Absorb,
{
    pub _phantom: PhantomData<F>,
}

impl<F> PoseidonAnchorSchemeGadget<F>
where
    F: PrimeField + Absorb,
{
    pub fn aggregate(base: &[FpVar<F>], scalars: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
        let result = base.iter().zip(scalars.iter()).map(|(b, s)| b * s).sum();
        Ok(result)
    }
}

impl<F> AllocVar<PoseidonAnchorPublicKey<F>, F> for PoseidonAnchorPublicKeyVar<F>
where
    F: PrimeField + Absorb,
{
    fn new_variable<T: Borrow<PoseidonAnchorPublicKey<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|val| {
            let params = CRHParametersVar::new_variable(
                cs.clone(),
                || Ok(val.borrow().params.clone()),
                mode,
            )?;
            Ok(PoseidonAnchorPublicKeyVar { params })
        })
    }
}

impl<F> AllocVar<PoseidonAnchorWitness<F>, F> for PoseidonAnchorWitnessVar<F>
where
    F: PrimeField + Absorb,
{
    fn new_variable<T: Borrow<PoseidonAnchorWitness<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|val| {
            let u = Vec::<FpVar<F>>::new_variable(cs.clone(), || Ok(val.borrow().u.clone()), mode)?;
            let ut =
                Vec::<FpVar<F>>::new_variable(cs.clone(), || Ok(val.borrow().ut.clone()), mode)?;
            let placed_secrets = Vec::<FpVar<F>>::new_variable(
                cs.clone(),
                || Ok(val.borrow().placed_secrets.clone()),
                mode,
            )?;
            let placed_indices_field = val
                .borrow()
                .placed_indices
                .clone()
                .iter()
                .map(|i| F::from(*i as u64))
                .collect::<Vec<_>>();
            let placed_indices =
                Vec::<FpVar<F>>::new_variable(cs.clone(), || Ok(placed_indices_field), mode)?;

            Ok(PoseidonAnchorWitnessVar {
                u,
                ut,
                placed_secrets,
                placed_indices,
            })
        })
    }
}

impl<F> AllocVar<PoseidonAnchor<F>, F> for PoseidonAnchorVar<F>
where
    F: PrimeField + Absorb,
{
    fn new_variable<T: Borrow<PoseidonAnchor<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|val| {
            let anchor =
                Vec::<FpVar<F>>::new_variable(cs.clone(), || Ok(val.borrow().0.clone()), mode)?;
            Ok(PoseidonAnchorVar { anchor })
        })
    }
}

impl<F> AnchorSchemeGadget<PoseidonAnchorScheme<F>, F> for PoseidonAnchorSchemeGadget<F>
where
    F: PrimeField + Absorb,
{
    type AnchorVar = PoseidonAnchorVar<F>;
    type PublicKeyVar = PoseidonAnchorPublicKeyVar<F>;
    type WitnessVar = PoseidonAnchorWitnessVar<F>;

    fn verify(
        _pk: &Self::PublicKeyVar,
        anchor: &Self::AnchorVar,
        witness: &Self::WitnessVar,
    ) -> Result<(), SynthesisError> {
        let lhs = Self::aggregate(&anchor.anchor, &witness.u)?;
        let rhs = Self::aggregate(&witness.placed_secrets, &witness.ut)?;

        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq("PoseidonAnchorSchemeGadget::verify", &[lhs.clone()], &[rhs.clone()]);

        lhs.enforce_equal(&rhs)?;

        Ok(())
    }
}
