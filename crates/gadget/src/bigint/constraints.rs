use core::{
    borrow::Borrow,
    cmp::{max, min},
    marker::PhantomData,
};

use ark_ff::{BitIteratorBE, PrimeField};
use ark_r1cs_std::{
    R1CSVar,
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBytesGadget},
    select::CondSelectGadget,
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use num_integer::Integer;
use num_traits::{One, ToPrimitive};

use std::fmt::Debug;

use crate::bigint::utils::{fe_to_nat, fit_nat_to_limbs, limbs_to_nat, nat_to_fe};

use super::utils::{BigNat, nat_to_limbs};

pub trait BigNatCircuitParams: Clone + Debug + Eq + PartialEq + Send + Sync {
    const LIMB_WIDTH: usize;
    const N_LIMBS: usize;
}

//TODO: Track word_size in number of bits rather than value
#[derive(Clone, Default)]
pub struct BigNatVar<ConstraintF: PrimeField, P: BigNatCircuitParams> {
    pub limbs: Vec<FpVar<ConstraintF>>, // Must be of length P::N_LIMBS
    pub value: BigNat,
    pub word_size: BigNat,
    pub _params: PhantomData<P>,
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> AllocVar<BigNat, ConstraintF>
    for BigNatVar<ConstraintF, P>
{
    fn new_variable<T: Borrow<BigNat>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let f_out = f()?;
        let limbs = nat_to_limbs(f_out.borrow(), P::LIMB_WIDTH, P::N_LIMBS);
        let limb_vars = Vec::<FpVar<ConstraintF>>::new_variable(cs, || Ok(&limbs[..]), mode)?;
        Ok(BigNatVar {
            limbs: limb_vars,
            value: f_out.borrow().clone(),
            word_size: (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one(),
            _params: PhantomData,
        })
    }
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> R1CSVar<ConstraintF>
    for BigNatVar<ConstraintF, P>
{
    type Value = BigNat;

    fn cs(&self) -> ConstraintSystemRef<ConstraintF> {
        self.limbs.as_slice().cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        debug_assert_eq!(self.limbs.len(), P::N_LIMBS);
        let limbs = self
            .limbs
            .iter()
            .map(|f| f.value())
            .collect::<Result<Vec<ConstraintF>, SynthesisError>>()?;
        let value = limbs_to_nat::<ConstraintF>(&limbs, P::LIMB_WIDTH);
        debug_assert_eq!(self.value, value);
        Ok(value)
    }
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> BigNatVar<ConstraintF, P> {
    // Create constant without reference to constraint system
    pub fn constant(nat: &BigNat) -> Result<Self, SynthesisError> {
        let limbs = nat_to_limbs::<ConstraintF>(nat, P::LIMB_WIDTH, P::N_LIMBS);
        let limb_vars = limbs
            .iter()
            .map(|l| <FpVar<ConstraintF>>::constant(l.clone()))
            .collect::<Vec<FpVar<ConstraintF>>>();
        Ok(BigNatVar {
            limbs: limb_vars,
            value: nat.clone(),
            word_size: (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one(),
            _params: PhantomData,
        })
    }

    pub fn reduce(&self) -> Result<Self, SynthesisError> {
        let cs = self.cs();
        if cs != ConstraintSystemRef::None {
            let reduced = Self::new_witness(cs.clone(), || Ok(&self.value))?;
            self.enforce_equal_when_carried(&reduced)?;
            Ok(reduced)
        } else {
            Ok(Self::constant(&self.value)?)
        }
    }

    pub fn add(&self, other: &Self) -> Result<Self, SynthesisError> {
        //TODO: Ensure that word size does not overflow field capacity?
        let word_size = &self.word_size + &other.word_size;
        if word_size.bits() > ((ConstraintF::MODULUS_BIT_SIZE - 1) as u64) {
            self.reduce()?.add(&other.reduce()?)
        } else {
            let limbs = self
                .limbs
                .iter()
                .zip(&other.limbs)
                .map(|(l1, l2)| l1 + l2)
                .collect::<Vec<FpVar<ConstraintF>>>();
            Ok(Self {
                limbs: limbs,
                value: BigNat::from(&self.value + &other.value),
                word_size: word_size,
                _params: PhantomData,
            })
        }
    }

    pub fn sub(&self, other: &Self) -> Result<Self, SynthesisError> {
        let cs = self.cs().or(other.cs());
        //TODO: What to do for constants? ConstraintSystemRef::None?
        //TODO: Check if fits in bits / well-formed?
        //TODO: Optimization: compute diff directly: https://github.com/arkworks-rs/nonnative/blob/master/src/allocated_nonnative_field_var.rs#L181
        let diff = Self::new_witness(cs.clone(), || {
            // CHANGED: BigUint 뺄셈은 패닉을 일으킬 수 있으므로 안전하게 처리
            if self.value >= other.value {
                Ok(&self.value - &other.value)
            } else {
                // 회로에서는 음수를 직접 표현하기보다 보수 등을 사용해야 함.
                // 여기서는 underflow 상황을 어떻게 처리할지 정의가 필요. 일단 0으로 처리.
                Ok(BigNat::ZERO)
            }
        })?;
        let sum = other.add(&diff)?;
        self.enforce_equal_when_carried(&sum)?;
        Ok(diff)
    }

    pub fn mult(&self, other: &Self) -> Result<Self, SynthesisError> {
        let cs = self.cs().or(other.cs());

        // Reduce values so that multiplication doesn't overflow
        debug_assert!(
            2 * (P::LIMB_WIDTH as u32) + log2(P::N_LIMBS) <= (ConstraintF::MODULUS_BIT_SIZE - 1)
        );
        if &self.word_size.bits() + &other.word_size.bits() + log2(P::N_LIMBS) as u64
            > ((ConstraintF::MODULUS_BIT_SIZE - 1) as u64)
        {
            return self.reduce()?.mult(&other.reduce()?);
        }

        // Compute and allocate product
        let product_value = BigNat::from(&self.value * &other.value);
        let product = Self::new_witness(cs.clone(), || Ok(product_value))?;
        let mut padded_product_limbs = product.limbs.clone();
        //padded_product_limbs.resize(2 * P::N_LIMBS - 1, FpVar::new_witness(cs.clone(), || Ok(ConstraintF::zero()))?);
        padded_product_limbs.resize(2 * P::N_LIMBS - 1, FpVar::zero());

        // left (self) * right (other)
        let mut lr_prod_limbs = vec![<FpVar<ConstraintF>>::zero(); 2 * P::N_LIMBS - 1];
        for i in 0..P::N_LIMBS {
            for j in 0..P::N_LIMBS {
                lr_prod_limbs[i + j] = &lr_prod_limbs[i + j] + (&self.limbs[i] * &other.limbs[j]);
            }
        }
        let lr_word_size = &self.word_size + &other.word_size + P::N_LIMBS;

        Self::enforce_limbs_equal_when_carried(
            cs.clone(),
            &lr_prod_limbs,
            &padded_product_limbs,
            &max(lr_word_size, product.word_size.clone()),
        )?;
        Ok(product)
    }

    pub fn mult_mod(&self, other: &Self, modulus: &Self) -> Result<Self, SynthesisError> {
        let cs = self.cs().or(other.cs()).or(modulus.cs());

        // Reduce values so that multiplication doesn't overflow
        debug_assert!(
            2 * (P::LIMB_WIDTH as u32) + log2(P::N_LIMBS) <= (ConstraintF::MODULUS_BIT_SIZE - 1)
        );
        if &self.word_size.bits() + &other.word_size.bits() + log2(P::N_LIMBS) as u64
            > (ConstraintF::MODULUS_BIT_SIZE - 1) as u64
        {
            return self.reduce()?.mult_mod(&other.reduce()?, modulus);
        }

        // todo!("No error");
        // Compute and allocate quotient and remainder
        let (quotient_value, rem_value) = (&self.value * &other.value).div_rem(&modulus.value);
        if cs == ConstraintSystemRef::None {
            //println!("Constant found in mult_mod: {}", rem_value.clone());
            return Ok(Self::constant(&rem_value.clone())?);
        }
        let rem = Self::new_witness(cs.clone(), || Ok(rem_value))?;
        // Since quotient may require more than P::N_LIMBS to allocate, we do not allocate it as a BigNatVar
        // Compute deterministic upper bound on number of quotient limbs and pad to it
        let num_left_bits = P::LIMB_WIDTH * (P::N_LIMBS - 1) + (self.word_size.bits() as usize) + 1; //TODO: +1 differs from bellman-bignat
        let num_right_bits =
            P::LIMB_WIDTH * (P::N_LIMBS - 1) + (other.word_size.bits() as usize) + 1;
        //TODO: Take mod_bits as input
        //let num_mod_bits = modulus.value.significant_bits() as usize;
        //let num_quotient_bits = (num_left_bits + num_right_bits).saturating_sub(num_mod_bits);
        let num_quotient_bits = num_left_bits + num_right_bits;
        let num_quotient_limbs = num_quotient_bits / P::LIMB_WIDTH + 1;
        let mut quotient_value_limbs = fit_nat_to_limbs(&quotient_value, P::LIMB_WIDTH);
        assert!(num_quotient_limbs >= quotient_value_limbs.len());
        quotient_value_limbs.resize(num_quotient_limbs, ConstraintF::zero());
        let quotient_limbs =
            Vec::<FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(&quotient_value_limbs[..]))?;

        // Constrain remainder to appropriate size
        //TODO: Check if fits in bits / well-formed?
        //rem.enforce_fits_in_bits(num_mod_bits)?;

        // left (self) * right (other)
        let mut lr_prod_limbs =
            vec![<FpVar<ConstraintF>>::zero(); P::N_LIMBS + num_quotient_limbs - 1]; // Same length as below
        for i in 0..P::N_LIMBS {
            for j in 0..P::N_LIMBS {
                lr_prod_limbs[i + j] = &lr_prod_limbs[i + j] + (&self.limbs[i] * &other.limbs[j]);
            }
        }
        let lr_word_size =
            BigNat::from(&self.word_size * &other.word_size) * BigNat::from(P::N_LIMBS);

        // mod * quotient + remainder
        debug_assert!(
            2 * (P::LIMB_WIDTH as u32) + log2(num_quotient_limbs) + 1
                <= (ConstraintF::MODULUS_BIT_SIZE - 1)
        );
        let mut mqr_prod_limbs =
            vec![<FpVar<ConstraintF>>::zero(); P::N_LIMBS + num_quotient_limbs - 1];
        for i in 0..P::N_LIMBS {
            for j in 0..num_quotient_limbs {
                mqr_prod_limbs[i + j] =
                    &mqr_prod_limbs[i + j] + (&modulus.limbs[i] * &quotient_limbs[j]);
            }
            mqr_prod_limbs[i] = &mqr_prod_limbs[i] + &rem.limbs[i];
        }
        let mqr_word_size = BigNat::from(&rem.word_size * &modulus.word_size)
            * BigNat::from(num_quotient_limbs)
            + &rem.word_size; // rem and quotient word size is default

        Self::enforce_limbs_equal_when_carried(
            cs.clone(),
            &lr_prod_limbs,
            &mqr_prod_limbs,
            &max(lr_word_size, mqr_word_size),
        )?;
        Ok(rem)
    }

    pub fn pow_mod(
        &self,
        exp: &Self,
        modulus: &Self,
        num_exp_bits: usize,
    ) -> Result<Self, SynthesisError> {
        if exp.word_size >= (BigNat::one() << P::LIMB_WIDTH as u32) {
            return self.pow_mod(&exp.reduce()?, modulus, num_exp_bits);
        }
        let cs = self.cs().or(exp.cs());
        let exp_bits = exp.enforce_fits_in_bits(num_exp_bits)?;

        // Perform a windowed Bauer exponentiation
        // Compute the optimal window size
        let mut k: usize = 1;
        let window_size = loop {
            let fk = k as f64;
            if (num_exp_bits as f64)
                < (fk * (fk + 1.0) * 2f64.powf(2.0 * fk)) / (2f64.powf(fk + 1.0) - fk - 2.0) + 1.0
            {
                break k;
            }
            k += 1;
        };
        //println!("Chosen window size: {}", window_size);

        // Compute base powers
        let base_powers = {
            let mut base_powers =
                vec![Self::new_constant(cs.clone(), BigNat::one())?, self.clone()];
            for _ in 2..(1 << window_size) {
                base_powers.push(base_powers.last().unwrap().mult_mod(self, modulus)?);
            }
            base_powers
        };

        //println!("exp_bits: {:?}", exp_bits.value.clone());
        Self::bauer_power_helper(
            cs.clone(),
            &base_powers,
            exp_bits.chunks(window_size),
            modulus,
        )
    }

    fn bauer_power_helper(
        cs: impl Into<Namespace<ConstraintF>>,
        base_powers: &[Self],
        mut exp_chunks: std::slice::Chunks<Boolean<ConstraintF>>,
        modulus: &Self,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        if let Some(chunk) = exp_chunks.next() {
            let chunk_len = chunk.len();
            //println!("Chunk: {:?}", chunk.iter().map(|b| b.value().unwrap_or_default()).collect::<Vec<bool>>());
            let base_power = select_index(&base_powers[..(1 << chunk_len)], chunk)?;
            if exp_chunks.len() > 0 {
                // If not first chunk, then compute accumulated value
                let mut acc =
                    Self::bauer_power_helper(cs.clone(), base_powers, exp_chunks, modulus)?;
                for _ in 0..chunk_len {
                    // Square for each bit in the chunk
                    acc = acc.mult_mod(&acc, &modulus)?
                }
                Ok(acc.mult_mod(&base_power, &modulus)?)
            } else {
                Ok(base_power)
            }
        } else {
            Ok(Self::new_constant(cs.clone(), BigNat::one())?)
        }
    }

    fn group_limbs(
        limbs: &Vec<FpVar<ConstraintF>>,
        limbs_per_group: usize,
    ) -> Vec<FpVar<ConstraintF>> {
        let mut grouped_limbs = vec![];
        let limb_block =
            <FpVar<ConstraintF>>::constant(nat_to_fe(&(BigNat::one() << (P::LIMB_WIDTH as u32))));
        for limbs_to_group in limbs.as_slice().chunks(limbs_per_group) {
            let mut shift = <FpVar<ConstraintF>>::one();
            let mut grouped_limb = <FpVar<ConstraintF>>::zero();
            for limb in limbs_to_group.iter() {
                grouped_limb += &(limb * shift.clone());
                shift *= &limb_block;
            }
            grouped_limbs.push(grouped_limb);
        }
        grouped_limbs
    }

    pub fn enforce_equal_when_carried(&self, other: &Self) -> Result<(), SynthesisError> {
        let cs = self.cs().or(other.cs());
        let current_word_size = max(&self.word_size, &other.word_size);
        Self::conditional_enforce_limbs_equal_when_carried(
            cs,
            &self.limbs,
            &other.limbs,
            current_word_size,
            &Boolean::TRUE,
        )
    }

    pub fn conditional_enforce_equal_when_carried(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let cs = self.cs().or(other.cs());
        let current_word_size = max(&self.word_size, &other.word_size);
        Self::conditional_enforce_limbs_equal_when_carried(
            cs,
            &self.limbs,
            &other.limbs,
            current_word_size,
            condition,
        )
    }

    fn enforce_limbs_equal_when_carried(
        cs: impl Into<Namespace<ConstraintF>>,
        left_limbs: &Vec<FpVar<ConstraintF>>,
        right_limbs: &Vec<FpVar<ConstraintF>>,
        current_word_size: &BigNat,
    ) -> Result<(), SynthesisError> {
        Self::conditional_enforce_limbs_equal_when_carried(
            cs,
            left_limbs,
            right_limbs,
            current_word_size,
            &Boolean::TRUE,
        )
    }

    fn conditional_enforce_limbs_equal_when_carried(
        cs: impl Into<Namespace<ConstraintF>>,
        left_limbs: &Vec<FpVar<ConstraintF>>,
        right_limbs: &Vec<FpVar<ConstraintF>>,
        current_word_size: &BigNat,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(left_limbs.len(), right_limbs.len());
        assert!(
            current_word_size.clone() < BigNat::one() << (ConstraintF::MODULUS_BIT_SIZE - 1u32)
        );
        let ns = cs.into();
        let cs = ns.cs();
        let current_word_size_f64 = current_word_size
            .to_f64()
            .expect("Failed to convert BigNat to f64");

        let carry_bits =
            (((current_word_size_f64 * 2.0).log2() - P::LIMB_WIDTH as f64).ceil() + 0.1) as usize;
        let carry_bits2 = (current_word_size.bits() as usize - P::LIMB_WIDTH + 1) as usize;
        //TODO: Replace carry_bits with carry_bits2
        assert_eq!(carry_bits, carry_bits2);
        //println!("current_word_size: {}, carry_bits: {}", current_word_size.clone(), carry_bits);

        // Regroup limbs to take advantage of field size and reduce the amount of carrying
        let limbs_per_group =
            ((ConstraintF::MODULUS_BIT_SIZE - 1u32) as usize - carry_bits) / P::LIMB_WIDTH;
        let grouped_base = BigNat::one() << (P::LIMB_WIDTH * limbs_per_group) as u32;
        let grouped_word_size = (0..limbs_per_group).fold(BigNat::ZERO, |mut acc, i| {
            acc.set_bit((i * P::LIMB_WIDTH) as u64, true);
            acc
        }) * current_word_size.clone();
        let grouped_carry_bits =
            (grouped_word_size.bits() as usize - P::LIMB_WIDTH * limbs_per_group + 1) as usize;

        // Propagate carries over grouped limbs.
        let mut carry_in = <FpVar<ConstraintF>>::zero();
        let mut accumulated_extra = BigNat::ZERO;
        for (i, (left_limb, right_limb)) in Self::group_limbs(left_limbs, limbs_per_group)
            .iter()
            .zip(Self::group_limbs(right_limbs, limbs_per_group))
            .enumerate()
        {
            //println!("Round {}:", i);
            let left_limb_value = left_limb.value().unwrap_or_default();
            let right_limb_value = right_limb.value().unwrap_or_default();
            let carry_in_value = carry_in.value().unwrap_or_default();
            //println!("left: {}, right: {}, carry_in: {}", f_to_nat(&left_limb_value), f_to_nat(&right_limb_value), f_to_nat(&carry_in_value));

            let carry_value = nat_to_fe::<ConstraintF>(
                &((fe_to_nat(&left_limb_value)
                    + fe_to_nat(&carry_in_value)
                    + grouped_word_size.clone()
                    - fe_to_nat(&right_limb_value))
                    / grouped_base.clone()),
            );

            //println!("carry: {}", f_to_nat(&carry_value));
            let carry = <FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(carry_value))?;

            accumulated_extra += grouped_word_size.clone();

            let (tmp_accumulated_extra, remainder) = accumulated_extra.div_rem(&grouped_base);
            accumulated_extra = tmp_accumulated_extra;
            //println!("accumulated_extra: {}", accumulated_extra.clone());
            let remainder_limb = nat_to_fe::<ConstraintF>(&remainder);

            let eqn_left: FpVar<ConstraintF> =
                left_limb + &carry_in - right_limb + nat_to_fe::<ConstraintF>(&grouped_word_size);
            let eqn_right = &carry * nat_to_fe::<ConstraintF>(&grouped_base) + remainder_limb;
            //println!("eqn_right: {}, eqn_left: {}, i: {}", f_to_nat(&eqn_right.value().unwrap()), f_to_nat(&eqn_left.value().unwrap()), i);
            eqn_left.conditional_enforce_equal(&eqn_right, condition)?;

            if i < left_limbs.len() - 1 {
                Self::conditional_enforce_limb_fits_in_bits(&carry, grouped_carry_bits, condition)?;
            } else {
                carry.conditional_enforce_equal(
                    &FpVar::<ConstraintF>::Constant(nat_to_fe::<ConstraintF>(&accumulated_extra)),
                    condition,
                )?;
            }

            carry_in = carry.clone();
        }
        Ok(())
    }

    pub fn enforce_fits_in_bits(
        &self,
        n_bits: usize,
    ) -> Result<Vec<Boolean<ConstraintF>>, SynthesisError> {
        let mut bit_vars = vec![];
        let num_limbs = n_bits / P::LIMB_WIDTH;
        for (i, limb) in self.limbs.iter().enumerate() {
            if i < num_limbs {
                bit_vars.append(&mut Self::enforce_limb_fits_in_bits(limb, P::LIMB_WIDTH)?);
            } else if i == num_limbs {
                bit_vars.append(&mut Self::enforce_limb_fits_in_bits(
                    limb,
                    n_bits % P::LIMB_WIDTH,
                )?);
            } else {
                limb.enforce_equal(&<FpVar<ConstraintF>>::zero())?;
            }
        }
        Ok(bit_vars)
    }

    pub fn enforce_limb_fits_in_bits(
        limb: &FpVar<ConstraintF>,
        n_bits: usize,
    ) -> Result<Vec<Boolean<ConstraintF>>, SynthesisError> {
        Self::conditional_enforce_limb_fits_in_bits(limb, n_bits, &Boolean::TRUE)
    }

    pub fn conditional_enforce_limb_fits_in_bits(
        limb: &FpVar<ConstraintF>,
        n_bits: usize,
        condition: &Boolean<ConstraintF>,
    ) -> Result<Vec<Boolean<ConstraintF>>, SynthesisError> {
        let cs = limb.cs();

        let n_bits = min(ConstraintF::MODULUS_BIT_SIZE as usize - 1, n_bits);
        let mut bits = Vec::with_capacity(n_bits);
        let limb_value = limb.value().unwrap_or_default();

        //TODO: find 'REPR_SHAVE_BITS', bls12_381 has 1, ed_on_bn254 has 2
        for b in BitIteratorBE::new(limb_value.into_bigint())
            .skip(2 + ConstraintF::MODULUS_BIT_SIZE as usize - n_bits)
        {
            bits.push(b);
        }

        let mut bit_vars = vec![];
        if cs != ConstraintSystemRef::None {
            for b in bits.iter().rev() {
                // Switch to little-endian
                bit_vars.push(Boolean::<ConstraintF>::new_witness(
                    ark_relations::ns!(cs, "bit"),
                    || Ok(b),
                )?);
            }
            Self::conditional_enforce_limb_equals_bits(limb, &bit_vars, condition)?;
        } else {
            for b in bits.iter().rev() {
                bit_vars.push(Boolean::<ConstraintF>::constant(*b));
            }
        }
        Ok(bit_vars)
    }

    pub fn enforce_equals_bits(&self, bits: &[Boolean<ConstraintF>]) -> Result<(), SynthesisError> {
        self.conditional_enforce_equals_bits(bits, &Boolean::TRUE)
    }

    pub fn conditional_enforce_equals_bits(
        &self,
        bits: &[Boolean<ConstraintF>],
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let num_nonzero_limbs = bits.len() / P::LIMB_WIDTH;
        for (i, limb) in self.limbs.iter().enumerate() {
            if i < num_nonzero_limbs {
                Self::conditional_enforce_limb_equals_bits(
                    limb,
                    &bits[i * P::LIMB_WIDTH..(i + 1) * P::LIMB_WIDTH],
                    condition,
                )?;
            } else if i == num_nonzero_limbs {
                Self::conditional_enforce_limb_equals_bits(
                    limb,
                    &bits[i * P::LIMB_WIDTH..],
                    condition,
                )?;
            } else {
                limb.conditional_enforce_equal(&<FpVar<ConstraintF>>::zero(), condition)?;
            }
        }
        Ok(())
    }

    // fn enforce_limb_equals_bits(
    //     limb: &FpVar<ConstraintF>,
    //     bits: &[Boolean<ConstraintF>],
    // ) -> Result<(), SynthesisError> {
    //     Self::conditional_enforce_limb_equals_bits(limb, bits, &Boolean::TRUE)
    // }

    fn conditional_enforce_limb_equals_bits(
        limb: &FpVar<ConstraintF>,
        bits: &[Boolean<ConstraintF>],
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let cs = limb.cs();
        if cs != ConstraintSystemRef::None {
            limb.conditional_enforce_equal(&Self::limb_from_bits(bits)?, condition)?;
        }
        Ok(())
    }

    pub fn nat_from_bits(bits: &[Boolean<ConstraintF>]) -> Result<Self, SynthesisError> {
        let mut limbs = vec![];
        let num_nonzero_limbs = bits.len() / P::LIMB_WIDTH;
        for i in 0..num_nonzero_limbs {
            limbs.push(Self::limb_from_bits(
                &bits[i * P::LIMB_WIDTH..(i + 1) * P::LIMB_WIDTH],
            )?);
        }
        limbs.push(Self::limb_from_bits(
            &bits[num_nonzero_limbs * P::LIMB_WIDTH..],
        )?);
        limbs.resize(P::N_LIMBS, FpVar::zero());
        let value = limbs_to_nat(
            &limbs
                .iter()
                .map(|f| f.value().unwrap_or_default())
                .collect::<Vec<ConstraintF>>(),
            P::LIMB_WIDTH,
        );
        Ok(BigNatVar {
            limbs,
            value,
            word_size: (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one(),
            _params: PhantomData,
        })
    }

    pub fn limb_from_bits(
        bits: &[Boolean<ConstraintF>],
    ) -> Result<FpVar<ConstraintF>, SynthesisError> {
        let mut bit_sum = FpVar::<ConstraintF>::zero();
        let mut coeff = ConstraintF::one();
        for bit in bits.iter() {
            bit_sum +=
                <FpVar<ConstraintF> as From<Boolean<ConstraintF>>>::from((*bit).clone()) * coeff;
            coeff.double_in_place();
        }
        Ok(bit_sum)
    }

    pub fn min(&self, other: &Self) -> Result<Self, SynthesisError> {
        let cs = self.cs().or(other.cs());
        let is_other_min =
            <Boolean<ConstraintF>>::new_witness(cs.clone(), || Ok(self.value > other.value))?;
        let lesser = Self::conditionally_select(&is_other_min, other, self)?;
        let greater = Self::conditionally_select(&!is_other_min, self, other)?;
        let _diff = greater.sub(&lesser)?;
        Ok(lesser)
    }

    pub fn enforce_coprime(&self, other: &Self) -> Result<(), SynthesisError> {
        self.conditional_enforce_coprime(other, &Boolean::TRUE)
    }

    pub fn conditional_enforce_coprime(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let cs = self.cs().or(other.cs());
        // Compute Bezout coefficient, s: s * self + t * other = 1
        // Add `other` in the case that s is negative
        let bezout_s = BigNatVar::new_witness(cs.clone(), || {
            // self.value와 other.value는 BigUint 타입입니다.
            let a = &self.value;
            let b = &other.value;

            // 1. num_bigint가 제공하는 extended_gcd를 호출합니다.
            //    계수 x와 y는 BigInt 타입으로 반환됩니다.
            let gcd_result = a.extended_gcd(b);
            let s_signed = gcd_result.x; // s*a + t*b = gcd(a,b) 에서의 s (bezout_s)

            // 2. 모듈러 연산을 위해 other.value(b)를 BigInt로 변환합니다.
            let b_signed = b.clone();

            // 3. s를 b로 나눈 나머지를 구하되, 결과가 항상 양수가 되도록 합니다.
            //    (s % b + b) % b 공식은 s가 음수일 때도 올바르게 작동합니다.
            let s_mod_b = (s_signed % &b_signed + &b_signed) % &b_signed;

            // 4. 최종 결과는 BigUint여야 하므로, BigInt를 BigUint로 변환합니다.
            //    모듈러 연산 결과는 항상 0 이상이므로 이 변환은 안전합니다.
            Ok(s_mod_b)
        })?;

        // Check gcd = 1
        Self::constant(&BigNat::one())?
            .conditional_enforce_equal(&self.mult_mod(&bezout_s, other)?, condition)
    }
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> CondSelectGadget<ConstraintF>
    for BigNatVar<ConstraintF, P>
{
    fn conditionally_select(
        cond: &Boolean<ConstraintF>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let selected_limbs = true_value
            .limbs
            .iter()
            .zip(&false_value.limbs)
            .map(|(true_limb, false_limb)| cond.select(true_limb, false_limb))
            .collect::<Result<Vec<FpVar<ConstraintF>>, SynthesisError>>()?;
        let cond_bool = cond.value().unwrap_or_default();
        let selected_nat = if cond_bool { true_value } else { false_value };
        Ok(Self {
            limbs: selected_limbs,
            value: selected_nat.value.clone(),
            word_size: max(true_value.word_size.clone(), false_value.word_size.clone()),
            _params: PhantomData,
        })
    }
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> EqGadget<ConstraintF>
    for BigNatVar<ConstraintF, P>
{
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.limbs.is_eq(&other.limbs)
    }
}

pub fn log2(x: usize) -> u32 {
    if x == 0 {
        0
    } else if x.is_power_of_two() {
        1usize.leading_zeros() - x.leading_zeros()
    } else {
        0usize.leading_zeros() - x.leading_zeros()
    }
}

pub fn select_index<ConstraintF: PrimeField, T: CondSelectGadget<ConstraintF>>(
    v: &[T],
    index_bits: &[Boolean<ConstraintF>],
) -> Result<T, SynthesisError> {
    debug_assert!(index_bits.len() > 0);
    if index_bits.len() == 1 {
        assert_eq!(v.len(), 2);
        T::conditionally_select(&index_bits[0], &v[1], &v[0])
    } else {
        let left = select_index(&v[..(v.len() / 2)], &index_bits[..(index_bits.len() - 1)])?;
        let right = select_index(&v[(v.len() / 2)..], &index_bits[..(index_bits.len() - 1)])?;
        T::conditionally_select(&index_bits.last().unwrap(), &right, &left)
    }
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> ToBytesGadget<ConstraintF>
    for BigNatVar<ConstraintF, P>
{
    fn to_bytes_le(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        let mut bits = self.enforce_fits_in_bits(P::LIMB_WIDTH * P::N_LIMBS)?;
        bits.resize((((bits.len() - 1) / 8) + 1) * 8, Boolean::FALSE);
        Ok(bits
            .chunks(8)
            .map(|byte| UInt8::from_bits_le(byte))
            .collect::<Vec<UInt8<ConstraintF>>>())
    }
}
pub trait BigNatTrait<ConstraintF: PrimeField, P: BigNatCircuitParams> {
    fn alloc_from_u64_limbs(
        cs: impl Into<Namespace<ConstraintF>>,
        u64_limbs: &Vec<u64>,
        word_size: BigNat,
        mode: AllocationMode,
    ) -> Result<BigNatVar<ConstraintF, P>, SynthesisError>;

    fn alloc_from_limbs(
        cs: impl Into<Namespace<ConstraintF>>,
        limbs: &Vec<ConstraintF>,
        word_size: BigNat,
        mode: AllocationMode,
    ) -> Result<BigNatVar<ConstraintF, P>, SynthesisError>;
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> BigNatTrait<ConstraintF, P>
    for BigNatVar<ConstraintF, P>
{
    fn alloc_from_u64_limbs(
        cs: impl Into<Namespace<ConstraintF>>,
        u64_limbs: &Vec<u64>,
        word_size: BigNat,
        mode: AllocationMode,
    ) -> Result<BigNatVar<ConstraintF, P>, SynthesisError> {
        let limbs = u64_limbs
            .iter()
            .rev()
            .map(|int64| ConstraintF::from_bigint(ConstraintF::BigInt::from(*int64)).unwrap())
            .collect::<Vec<ConstraintF>>();
        Self::alloc_from_limbs(cs, &limbs, word_size, mode)
    }

    fn alloc_from_limbs(
        cs: impl Into<Namespace<ConstraintF>>,
        limbs: &Vec<ConstraintF>,
        word_size: BigNat,
        mode: AllocationMode,
    ) -> Result<BigNatVar<ConstraintF, P>, SynthesisError> {
        assert_eq!(limbs.len(), P::N_LIMBS);
        let limb_vars = Vec::<FpVar<ConstraintF>>::new_variable(cs, || Ok(&limbs[..]), mode)?;
        Ok(BigNatVar {
            limbs: limb_vars,
            value: limbs_to_nat::<ConstraintF>(limbs, P::LIMB_WIDTH),
            word_size: word_size,
            _params: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {

    use std::io::Write;

    use ark_ed_on_bn254::Fq;
    use ark_relations::r1cs::ConstraintSystem;

    use super::*;

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNatTestParams;

    impl BigNatCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 3;
        const N_LIMBS: usize = 4;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNat512TestParams;

    impl BigNatCircuitParams for BigNat512TestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 16;
    }

    #[test]
    fn bignat_to_bytes_test() {
        let bignat = BigNat::from(5000u64);
        let cs = ConstraintSystem::<Fq>::new_ref();
        let bignat_var =
            BigNatVar::<Fq, BigNat512TestParams>::new_witness(cs.clone(), || Ok(&bignat)).unwrap();
        let bytes_val = bignat_var
            .to_bytes_le()
            .unwrap()
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<u8>>();
        assert_eq!(bytes_val.len(), 64);
        let mut buffer = [0u8; 64];
        let mut writer = std::io::Cursor::new(&mut buffer[..]);
        let big_vec = bignat.to_bytes_le();
        writer.write_all(&big_vec).unwrap();
        assert_eq!(bytes_val, buffer.to_vec());
    }

    fn carry_over_equal_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        should_satisfy: bool,
    ) {
        println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
        let cs = ConstraintSystem::<Fq>::new_ref();
        let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat1"),
            &vec1,
            BigNat::from(word_size_1),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat2"),
            &vec2,
            BigNat::from(word_size_2),
            AllocationMode::Witness,
        )
        .unwrap();
        nat1var.enforce_equal_when_carried(&nat2var).unwrap();

        if should_satisfy && !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
        assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
    }

    #[test]
    fn carry_over_equal_trivial_test() {
        carry_over_equal_test(vec![2, 1, 4, 7], vec![2, 1, 4, 7], 7, 7, true)
    }

    #[test]
    fn carry_over_equal_1carry_test() {
        carry_over_equal_test(vec![1, 1, 0, 9], vec![1, 1, 1, 1], 14, 7, true)
    }

    #[test]
    fn carry_over_equal_2carry_test() {
        carry_over_equal_test(vec![1, 1, 9, 9], vec![1, 2, 2, 1], 14, 7, true)
    }

    #[test]
    fn carry_over_equal_both_carry_test() {
        carry_over_equal_test(vec![1, 1, 9, 9], vec![1, 0, 18, 1], 14, 21, true)
    }

    #[test]
    fn carry_over_equal_large_word_test() {
        carry_over_equal_test(vec![1, 1, 9, 66], vec![1, 3, 1, 2], 70, 7, true)
    }

    #[test]
    fn carry_over_equal_3carry_test() {
        carry_over_equal_test(vec![1, 12, 7, 12], vec![2, 5, 0, 4], 14, 7, true)
    }

    #[test]
    fn carry_over_equal_3carry_overflow_test() {
        carry_over_equal_test(vec![12, 12, 12, 12], vec![13, 5, 5, 4], 14, 14, true)
    }

    fn add_equal_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        vec3: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        word_size_3: u64,
        should_satisfy: bool,
    ) {
        println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
        let cs = ConstraintSystem::<Fq>::new_ref();
        let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat1"),
            &vec1,
            BigNat::from(word_size_1),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat2"),
            &vec2,
            BigNat::from(word_size_2),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat3var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat3"),
            &vec3,
            BigNat::from(word_size_3),
            AllocationMode::Witness,
        )
        .unwrap();

        let sum = nat1var.add(&nat2var).unwrap();
        nat3var.enforce_equal_when_carried(&sum).unwrap();

        if should_satisfy && !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
        assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
    }

    #[test]
    fn add_equal_trivial_test() {
        add_equal_test(
            vec![1, 1, 1, 1],
            vec![1, 1, 1, 1],
            vec![2, 2, 2, 2],
            7,
            7,
            7,
            true,
        )
    }

    #[test]
    fn add_equal_carryover_test() {
        add_equal_test(
            vec![1, 1, 1, 6],
            vec![1, 1, 1, 6],
            vec![2, 2, 3, 4],
            7,
            7,
            7,
            true,
        )
    }

    fn sub_equal_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        vec3: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        word_size_3: u64,
        should_satisfy: bool,
    ) {
        println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
        let cs = ConstraintSystem::<Fq>::new_ref();
        let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat1"),
            &vec1,
            BigNat::from(word_size_1),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat2"),
            &vec2,
            BigNat::from(word_size_2),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat3var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat3"),
            &vec3,
            BigNat::from(word_size_3),
            AllocationMode::Witness,
        )
        .unwrap();

        let diff = nat1var.sub(&nat2var).unwrap();
        nat3var.enforce_equal_when_carried(&diff).unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        if should_satisfy && !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
        assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
    }

    #[test]
    fn sub_equal_trivial_test() {
        sub_equal_test(
            vec![2, 2, 2, 2],
            vec![1, 1, 1, 1],
            vec![1, 1, 1, 1],
            7,
            7,
            7,
            true,
        )
    }

    #[test]
    fn sub_equal_carryover_test() {
        sub_equal_test(
            vec![2, 0, 18, 2],
            vec![1, 1, 1, 1],
            vec![1, 1, 1, 1],
            21,
            7,
            7,
            true,
        )
    }

    fn mult_mod_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        vec3: Vec<u64>,
        modvec: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        word_size_3: u64,
        mod_word_size: u64,
        should_satisfy: bool,
    ) {
        println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
        let cs = ConstraintSystem::<Fq>::new_ref();
        let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat1"),
            &vec1,
            BigNat::from(word_size_1),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat2"),
            &vec2,
            BigNat::from(word_size_2),
            AllocationMode::Witness,
        )
        .unwrap();
        let nat3var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat3"),
            &vec3,
            BigNat::from(word_size_3),
            AllocationMode::Witness,
        )
        .unwrap();
        let modvar = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "mod"),
            &modvec,
            BigNat::from(mod_word_size),
            AllocationMode::Witness,
        )
        .unwrap();

        let prod = nat1var.mult_mod(&nat2var, &modvar).unwrap();
        nat3var.enforce_equal_when_carried(&prod).unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        if should_satisfy && !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
        assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
    }

    #[test]
    fn mult_mod_trivial_test() {
        mult_mod_test(
            vec![0, 0, 1, 1],
            vec![0, 0, 1, 1],
            vec![0, 1, 2, 1],
            vec![0, 7, 0, 0],
            7,
            7,
            7,
            7,
            true,
        )
    }

    #[test]
    fn mult_mod_prod_overflow_test() {
        mult_mod_test(
            vec![1, 1, 1, 1], // 585
            vec![2, 2, 0, 0], // 1152
            vec![3, 2, 2, 0], // 585 * 1152 = 673920 ; 673920 % 2801 = 1680
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            true,
        )
    }

    #[test]
    fn mult_mod_large_quotient_test() {
        mult_mod_test(
            vec![65, 1, 1, 1], // 33353
            vec![66, 2, 0, 0], // 33920
            vec![2, 6, 6, 1],  // (33353 * 33920) % 2801 = 1457
            vec![5, 3, 6, 1],  // prime mod = 2801
            70,
            70,
            7,
            7,
            true,
        )
    }

    fn pow_mod_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        vec3: Vec<u64>,
        modvec: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        word_size_3: u64,
        mod_word_size: u64,
        num_exp_bits: usize,
        should_satisfy: bool,
    ) {
        println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
        let cs = ConstraintSystem::<Fq>::new_ref();
        let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat1"),
            &vec1,
            BigNat::from(word_size_1),
            AllocationMode::Witness,
        )
        .unwrap();
        println!(
            "vec1: {}",
            limbs_to_nat(
                &nat1var.limbs.value().unwrap(),
                BigNatTestParams::LIMB_WIDTH
            )
        );
        println!("vec1.value: {:?}", nat1var.limbs.value().unwrap());

        let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat2"),
            &vec2,
            BigNat::from(word_size_2),
            AllocationMode::Witness,
        )
        .unwrap();
        println!(
            "vec2: {}",
            limbs_to_nat(
                &nat2var.limbs.value().unwrap(),
                BigNatTestParams::LIMB_WIDTH
            )
        );
        println!("vec2.value: {:?}", nat2var.limbs.value().unwrap());

        let nat3var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "nat3"),
            &vec3,
            BigNat::from(word_size_3),
            AllocationMode::Witness,
        )
        .unwrap();
        println!("vec3.value: {:?}", nat3var.limbs.value().unwrap());

        let modvar = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
            ark_relations::ns!(cs, "mod"),
            &modvec,
            BigNat::from(mod_word_size),
            AllocationMode::Witness,
        )
        .unwrap();
        println!(
            "modvar: {}",
            limbs_to_nat(&modvar.limbs.value().unwrap(), BigNatTestParams::LIMB_WIDTH)
        );

        let result = nat1var.pow_mod(&nat2var, &modvar, num_exp_bits).unwrap();
        println!("POW MOD DONE");
        println!(
            "result: {}",
            limbs_to_nat(&result.limbs.value().unwrap(), BigNatTestParams::LIMB_WIDTH)
        );
        println!(
            "expected: {}",
            limbs_to_nat(
                &nat3var.limbs.value().unwrap(),
                BigNatTestParams::LIMB_WIDTH
            )
        );
        nat3var.enforce_equal_when_carried(&result).unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        if should_satisfy && !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
        assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
    }

    #[test]
    fn pow_mod_trivial1_test() {
        pow_mod_test(
            vec![0, 0, 0, 3], // 3
            vec![0, 0, 0, 6], // 6
            vec![1, 3, 3, 1], // 3^6 = 729
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            3,
            true,
        )
    }

    #[test]
    fn pow_mod_trivial2_test() {
        pow_mod_test(
            vec![0, 0, 0, 3], // 3
            vec![0, 0, 0, 7], // 7
            vec![4, 2, 1, 3], // 3^7 = 2187
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            4,
            true,
        )
    }

    #[test]
    fn pow_mod_zero_test() {
        pow_mod_test(
            vec![1, 1, 1, 1], // 585
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 1],
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            3,
            true,
        )
    }

    #[test]
    fn pow_mod_small_overflow_test() {
        pow_mod_test(
            vec![0, 0, 0, 3], // 3
            vec![0, 0, 1, 0], // 8
            vec![1, 6, 7, 7], // 3^8 % 2801 = 959
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            6,
            true,
        )
    }

    #[test]
    fn pow_mod_full_test() {
        pow_mod_test(
            vec![1, 1, 1, 3], // 587 // 2048 bit의 vec를 만들어주세요
            vec![0, 0, 2, 1], // 17
            vec![0, 5, 7, 0], // (587^17) % 2801 = 376
            vec![5, 3, 6, 1], // prime mod = 2801
            7,
            7,
            7,
            7,
            6,
            true,
        )
    }

    /// BigNat2048TestParams 정의
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNat2048TestParams;

    impl BigNatCircuitParams for BigNat2048TestParams {
        const LIMB_WIDTH: usize = 64;
        const N_LIMBS: usize = 32;
    }

    #[test]
    fn pow_mod_rsa_style_17bit_exp_test() {
        use num_bigint::BigUint;
        use num_traits::One;
        use rand::{RngCore, thread_rng};

        // BigUint를 Big-Endian u64 limb 벡터로 변환하는 헬퍼 함수
        let to_be_limbs = |n: &BigUint| -> Vec<u64> {
            let limb_bytes = BigNat2048TestParams::LIMB_WIDTH / 8;
            let num_bytes = BigNat2048TestParams::N_LIMBS * limb_bytes;
            let bytes = n.to_bytes_be();
            let padding = num_bytes.saturating_sub(bytes.len());
            let mut padded_bytes = vec![0; padding];
            padded_bytes.extend_from_slice(&bytes);
            padded_bytes
                .chunks_exact(limb_bytes)
                .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
                .collect::<Vec<u64>>()
        };

        // 1. 테스트용 RSA 스타일 값 설정
        let mut rng = thread_rng();

        // Exponent (e = 65537, 17비트)
        let exp_val = BigUint::from(65537u32);
        let num_exp_bits = 17;

        // Base (Message, 2048-bit)
        let mut base_bytes = vec![0u8; 2048 / 8];
        rng.fill_bytes(&mut base_bytes);
        let base_val = BigUint::from_bytes_be(&base_bytes);

        // Modulus (N, 2040-bit, 홀수 보장)
        let mut mod_bytes = vec![0u8; 2040 / 8];
        rng.fill_bytes(&mut mod_bytes);
        // last_mut()으로 마지막 요소를 안전하게 가져와 홀수로 만듭니다.
        if let Some(last_byte) = mod_bytes.last_mut() {
            *last_byte |= 1;
        }
        let mod_val = BigUint::from_bytes_be(&mod_bytes);

        // 2. 예상 결과값 계산 (ciphertext = base^exp % mod)
        let expected_res_val = base_val.modpow(&exp_val, &mod_val);

        // BigUint 값들을 회로 입력에 맞는 limb 벡터로 변환
        let base_limbs = to_be_limbs(&base_val);
        let exp_limbs = to_be_limbs(&exp_val);
        let mod_limbs = to_be_limbs(&mod_val);
        let expected_res_limbs = to_be_limbs(&expected_res_val);

        // 3. 제약 조건 시스템 설정
        let cs = ConstraintSystem::<Fq>::new_ref();
        let word_size: BigNat = (BigNat::one() << 64) - BigNat::one();

        // 4. 회로 변수 할당
        let base_var = BigNatVar::<Fq, BigNat2048TestParams>::alloc_from_u64_limbs(
            cs.clone(),
            &base_limbs,
            word_size.clone(),
            AllocationMode::Witness,
        )
        .unwrap();
        let exp_var = BigNatVar::<Fq, BigNat2048TestParams>::alloc_from_u64_limbs(
            cs.clone(),
            &exp_limbs,
            word_size.clone(),
            AllocationMode::Witness,
        )
        .unwrap();
        let mod_var = BigNatVar::<Fq, BigNat2048TestParams>::alloc_from_u64_limbs(
            cs.clone(),
            &mod_limbs,
            word_size.clone(),
            AllocationMode::Witness,
        )
        .unwrap();
        let expected_res_var = BigNatVar::<Fq, BigNat2048TestParams>::alloc_from_u64_limbs(
            cs.clone(),
            &expected_res_limbs,
            word_size.clone(),
            AllocationMode::Witness,
        )
        .unwrap();

        // 5. 회로 내에서 모듈러 거듭제곱 연산 수행
        let res_var = base_var.pow_mod(&exp_var, &mod_var, num_exp_bits).unwrap();

        // 6. 회로 결과와 예상 결과가 같은지 제약 조건 추가
        expected_res_var
            .enforce_equal_when_carried(&res_var)
            .unwrap();

        // 7. 모든 제약 조건이 만족하는지 확인
        println!(
            "RSA 스타일 17-bit pow_mod 제약 조건 수: {}",
            cs.num_constraints()
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "RSA 스타일 17-bit pow_mod 제약 조건을 만족하지 못했습니다."
        );
    }
}
