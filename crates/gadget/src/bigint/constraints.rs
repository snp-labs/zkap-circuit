use core::{borrow::Borrow, cmp::max, marker::PhantomData};

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
use num::Zero;
use num_integer::Integer;
use num_traits::One;

use std::fmt::Debug;

use crate::bigint::utils::{
    fe_to_nat, field_characteristic_to_nat, fit_nat_to_limbs, limbs_to_nat, nat_to_fe,
};

use super::utils::{BigNat, nat_to_limbs};

pub trait BigNatCircuitParams: Clone + Debug + Eq + PartialEq + Send + Sync {
    const LIMB_WIDTH: usize;
    const N_LIMBS: usize;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RangeMode {
    Checked,
    Unchecked,
}

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
    #[inline(always)]
    fn maybe_enforce_limb_range(&self, mode: RangeMode) -> Result<(), SynthesisError> {
        if matches!(mode, RangeMode::Checked) {
            // Only enforce range check for canonical (normalized) representations
            // where word_size > 2^LIMB_WIDTH - 1
            let max_canonical_word_size = (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one();
            if self.word_size <= max_canonical_word_size {
                self.enforce_limb_range_via_bits()?;
            }
        }
        Ok(())
    }

    /// Create constant without reference to constraint system
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

    /// Reduce BigNatVar to a canonical limb representation.
    /// - Range-checks all input limbs
    /// - Adds an equality constraint (carry-aware) between self and the reduced output
    pub fn reduce(&self) -> Result<Self, SynthesisError> {
        // Enforce each limb < 2^w
        self.enforce_limb_range_via_bits()?;

        let cs = self.cs();
        if cs != ConstraintSystemRef::None {
            // Allocate a fresh witness with the same value, enforce canonical form,
            // then constrain self == out via carry-aware equality.
            let reduced = Self::new_witness(cs.clone(), || Ok(&self.value))?;
            reduced.enforce_limb_range_via_bits()?;
            self.enforce_equal_when_carried(&reduced)?;
            Ok(reduced)
        } else {
            // No constraint system — return as constant
            Ok(Self::constant(&self.value)?)
        }
    }

    /// Addition (checked): range-checks input limbs; output is canonical
    pub fn add(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.add_mode(other, RangeMode::Checked)
    }

    /// Addition (unchecked): skips input range-check; output is canonical
    pub fn add_unchecked(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.add_mode(other, RangeMode::Unchecked)
    }

    /// Common addition logic:
    /// - (optional) input range-check
    /// - fails with Unsatisfiable if accumulated word_size exceeds field size (field wrap risk)
    /// - connects tmp=self+other (no carry propagation) to out (canonical witness) via carry-equality
    pub fn add_mode(&self, other: &Self, mode: RangeMode) -> Result<Self, SynthesisError> {
        self.maybe_enforce_limb_range(mode)?;
        other.maybe_enforce_limb_range(mode)?;

        let cs = self.cs().or(other.cs());

        // If the accumulated word bound >= field size, FpVar addition loses integer semantics
        let field_char = field_characteristic_to_nat::<ConstraintF>();
        let max_word_size = &self.word_size + &other.word_size;
        if max_word_size >= field_char {
            return Err(SynthesisError::Unsatisfiable);
        }

        let sum_value = &self.value + &other.value;
        let out = Self::new_witness(cs.clone(), || Ok(sum_value.clone()))?;
        out.enforce_limb_range_via_bits()?; // output is canonical

        // tmp represents the limb-wise sum before carry propagation;
        // constrain tmp == out via carry-aware equality to preserve integer semantics
        let tmp_limbs = self
            .limbs
            .iter()
            .zip(other.limbs.iter())
            .map(|(a, b)| a + b)
            .collect::<Vec<_>>();

        let tmp = Self {
            limbs: tmp_limbs,
            value: sum_value,
            word_size: max_word_size,
            _params: PhantomData,
        };

        tmp.enforce_equal_when_carried(&out)?;
        Ok(out)
    }

    /// Subtraction (checked): range-checks inputs; output is canonical
    pub fn sub(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.sub_mode(other, RangeMode::Checked)
    }

    /// Subtraction (unchecked): skips input range-check; output is canonical
    pub fn sub_unchecked(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.sub_mode(other, RangeMode::Unchecked)
    }

    /// Common subtraction logic:
    /// - (optional) input range-check
    /// - checks word_size bound to prevent field wrap
    /// - allocates diff as a witness and enforces canonical form
    /// - constrains other + diff == self via carry-aware equality (preserving integer semantics)
    pub fn sub_mode(&self, other: &Self, mode: RangeMode) -> Result<Self, SynthesisError> {
        self.maybe_enforce_limb_range(mode)?;
        other.maybe_enforce_limb_range(mode)?;

        let cs = self.cs().or(other.cs());

        let field_char = field_characteristic_to_nat::<ConstraintF>();
        let max_word_size = max(&self.word_size, &other.word_size) + BigNat::one();
        if max_word_size >= field_char {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Compute diff off-circuit (clamped to 0 on underflow);
        // integer semantics are enforced below via the constraint other+diff==self
        let diff_value = if self.value >= other.value {
            &self.value - &other.value
        } else {
            BigNat::zero()
        };

        let diff = Self::new_witness(cs.clone(), || Ok(diff_value.clone()))?;
        diff.enforce_limb_range_via_bits()?; // output is canonical

        // Enforce other + diff == self (carry-aware)
        let sum = other.add_mode(&diff, RangeMode::Unchecked)?;
        self.enforce_equal_when_carried(&sum)?;
        Ok(diff)
    }

    /// Multiplication (checked): range-checks both inputs
    pub fn mult(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.mult_mode(other, RangeMode::Checked)
    }

    /// Multiplication (unchecked): skips input range-check
    pub fn mult_unchecked(&self, other: &Self) -> Result<Self, SynthesisError> {
        self.mult_mode(other, RangeMode::Unchecked)
    }

    /// Common multiplication logic:
    /// - (optional) input range-check
    /// - fails if accumulated word_size exceeds field size (integer semantics would break)
    /// - builds the product limb representation as a (2N-1)-term convolution (no carry propagation)
    pub fn mult_mode(&self, other: &Self, mode: RangeMode) -> Result<Self, SynthesisError> {
        self.maybe_enforce_limb_range(mode)?;
        other.maybe_enforce_limb_range(mode)?;

        let field_char = field_characteristic_to_nat::<ConstraintF>();
        let max_word_size =
            &self.word_size * &other.word_size * BigNat::from(P::N_LIMBS * P::N_LIMBS);
        if max_word_size >= field_char {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Schoolbook long-multiplication convolution (no carry propagation)
        let mut prod_limbs = vec![FpVar::<ConstraintF>::zero(); 2 * P::N_LIMBS - 1];
        for i in 0..P::N_LIMBS {
            for j in 0..P::N_LIMBS {
                prod_limbs[i + j] += &self.limbs[i] * &other.limbs[j];
            }
        }

        let value = &self.value * &other.value;
        Ok(Self {
            limbs: prod_limbs,
            value,
            word_size: max_word_size,
            _params: PhantomData,
        })
    }

    /// Modular multiplication (checked): generic implementation
    pub fn mult_mod(&self, other: &Self, modulus: &Self) -> Result<Self, SynthesisError> {
        self.mult_mod_mode(other, modulus, RangeMode::Checked)
    }

    /// Modular multiplication (unchecked): fast-path entry optimized for RSA2048 signature verification
    pub fn mult_mod_unchecked(&self, other: &Self, modulus: &Self) -> Result<Self, SynthesisError> {
        self.mult_mod_mode(other, modulus, RangeMode::Unchecked)
    }

    /// Dispatch for mult_mod.
    /// - Checked: generic safe implementation (quotient allocated with 2N limbs)
    /// - Unchecked: fast-path for RSA2048 signature verify — skips input range-check and limits quotient to N limbs
    pub fn mult_mod_mode(
        &self,
        other: &Self,
        modulus: &Self,
        mode: RangeMode,
    ) -> Result<Self, SynthesisError> {
        match mode {
            RangeMode::Checked => self.mult_mod_checked_impl(other, modulus),
            RangeMode::Unchecked => self.mult_mod_unchecked_impl(other, modulus),
        }
    }

    /// Generic modular multiplication:
    /// proves rem = self*other mod modulus by allocating quotient/rem as witnesses and
    /// constraining self*other == modulus*quotient + rem and rem < modulus
    fn mult_mod_checked_impl(&self, other: &Self, modulus: &Self) -> Result<Self, SynthesisError> {
        // Only enforce range check for canonical (normalized) representations
        let max_canonical_word_size = (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one();
        if self.word_size <= max_canonical_word_size {
            self.enforce_limb_range_via_bits()?;
        }
        if other.word_size <= max_canonical_word_size {
            other.enforce_limb_range_via_bits()?;
        }
        if modulus.word_size <= max_canonical_word_size {
            modulus.enforce_limb_range_via_bits()?;
        }
        let cs = self.cs().or(other.cs()).or(modulus.cs());

        // Enforce modulus != 0
        if cs != ConstraintSystemRef::None {
            let zero = FpVar::<ConstraintF>::zero();
            let mut all_zero = Boolean::<ConstraintF>::TRUE;
            for l in modulus.limbs.iter() {
                all_zero = all_zero & l.is_eq(&zero)?;
            }
            crate::enforce_eq_internal!("bigint_modulus_nonzero", all_zero, Boolean::FALSE)?;
        }

        // Compute quotient and rem off-circuit; the circuit only verifies the relation
        let left_value = self.value.clone();
        let right_value = other.value.clone();
        let mod_value = modulus.value.clone();

        let (quotient_value, rem_value) = if mod_value.is_zero() {
            (BigNat::zero(), BigNat::zero())
        } else {
            let prod = &left_value * &right_value;
            (&prod / &mod_value, &prod % &mod_value)
        };

        let rem = Self::new_witness(cs.clone(), || Ok(rem_value.clone()))?;
        rem.enforce_limb_range_via_bits()?;

        // Quotient may need up to 2N limbs in the general case; allocate 2N for safety
        let num_quotient_limbs: usize = 2 * P::N_LIMBS;
        let mut quotient_value_limbs = fit_nat_to_limbs(&quotient_value, P::LIMB_WIDTH);
        quotient_value_limbs.resize(num_quotient_limbs, ConstraintF::zero());
        let quotient_limbs =
            Vec::<FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(&quotient_value_limbs[..]))?;
        for q in quotient_limbs.iter() {
            let _ = q.to_bits_le_with_top_bits_zero(P::LIMB_WIDTH)?;
        }
        let quotient = BigNatVar::<ConstraintF, P> {
            limbs: quotient_limbs,
            value: quotient_value.clone(),
            word_size: (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one(),
            _params: PhantomData,
        };

        // STRICT: enforce rem < modulus to ensure uniqueness of the remainder representation
        Self::enforce_lt_strict_borrow_chain(cs.clone(), &rem, modulus)?;

        let lr_len = 2 * P::N_LIMBS - 1;
        let mut lr_prod_limbs = vec![FpVar::<ConstraintF>::zero(); lr_len];
        for i in 0..P::N_LIMBS {
            for j in 0..P::N_LIMBS {
                lr_prod_limbs[i + j] += &self.limbs[i] * &other.limbs[j];
            }
        }

        let mq_len = P::N_LIMBS + (2 * P::N_LIMBS) - 1;
        let mut mq_prod_limbs = vec![FpVar::<ConstraintF>::zero(); mq_len];
        for i in 0..P::N_LIMBS {
            for j in 0..(2 * P::N_LIMBS) {
                mq_prod_limbs[i + j] += &modulus.limbs[i] * &quotient.limbs[j];
            }
        }

        let eq_len = core::cmp::max(lr_len, mq_len);
        let mut lhs_limbs = vec![FpVar::<ConstraintF>::zero(); eq_len];
        for i in 0..lr_len {
            lhs_limbs[i] += &lr_prod_limbs[i];
        }
        let mut rhs_limbs = vec![FpVar::<ConstraintF>::zero(); eq_len];
        for i in 0..mq_len {
            rhs_limbs[i] += &mq_prod_limbs[i];
        }
        for i in 0..P::N_LIMBS {
            rhs_limbs[i] += &rem.limbs[i];
        }

        // Enforce self*other == modulus*quotient + rem via carry-aware equality
        // (carry is propagated internally as a witness)
        let lhs_word_size = BigNat::from(P::N_LIMBS) * &self.word_size * &other.word_size;
        let rhs_word_size =
            BigNat::from(P::N_LIMBS) * &modulus.word_size * &quotient.word_size + &rem.word_size;
        let eq_word_size = max(lhs_word_size, rhs_word_size);

        Self::conditional_enforce_limbs_equal_when_carried(
            cs.clone(),
            &lhs_limbs,
            &rhs_limbs,
            &eq_word_size,
            &Boolean::TRUE,
        )?;
        Ok(rem)
    }

    /// Modular multiplication fast-path: skips input range-checks.
    /// "Unchecked" means input limb range-checks are omitted; rem and quotient still
    /// receive the minimum range-checks needed for relation verification.
    /// Quotient is limited to N_LIMBS (assumes operands < modulus, as in RSA).
    fn mult_mod_unchecked_impl(
        &self,
        other: &Self,
        modulus: &Self,
    ) -> Result<Self, SynthesisError> {
        let cs = self.cs().or(other.cs()).or(modulus.cs());

        let prod_value = &self.value * &other.value;
        let lhs_word_size = BigNat::from(P::N_LIMBS) * &self.word_size * &other.word_size;

        // Full schoolbook multiplication
        let lr_len = 2 * P::N_LIMBS - 1;
        let mut lr_prod_limbs = vec![FpVar::<ConstraintF>::zero(); lr_len];
        for i in 0..P::N_LIMBS {
            for j in 0..P::N_LIMBS {
                lr_prod_limbs[i + j] += &self.limbs[i] * &other.limbs[j];
            }
        }

        Self::verify_mod_relation(cs, &lr_prod_limbs, lr_len, modulus, &prod_value, &lhs_word_size)
    }

    /// Modular squaring (checked): range-checks inputs, then delegates to the core impl
    pub fn square_mod(&self, modulus: &Self) -> Result<Self, SynthesisError> {
        self.square_mod_mode(modulus, RangeMode::Checked)
    }

    /// Modular squaring (unchecked): entry point optimized for RSA2048 signature verification
    pub fn square_mod_unchecked(&self, modulus: &Self) -> Result<Self, SynthesisError> {
        self.square_mod_mode(modulus, RangeMode::Unchecked)
    }

    /// Dispatch for square_mod. Both checked and unchecked modes use the same
    /// core implementation; checked only adds input range checks via maybe_enforce_limb_range.
    pub fn square_mod_mode(&self, modulus: &Self, mode: RangeMode) -> Result<Self, SynthesisError> {
        self.maybe_enforce_limb_range(mode)?;
        modulus.maybe_enforce_limb_range(mode)?;

        self.square_mod_impl(modulus)
    }

    /// Core modular squaring implementation.
    /// Used by both checked and unchecked paths — input range checks are
    /// handled by the caller (square_mod_mode).
    /// Uses symmetric multiplication (upper triangle + doubling) to halve R1CS constraints.
    /// Quotient is limited to N_LIMBS (assumes operands < modulus, as in RSA).
    fn square_mod_impl(&self, modulus: &Self) -> Result<Self, SynthesisError> {
        let cs = self.cs().or(modulus.cs());

        let prod_value = &self.value * &self.value;
        let lhs_word_size = BigNat::from(P::N_LIMBS) * &self.word_size * &self.word_size;

        // Symmetric schoolbook: compute only i<=j terms, double off-diagonal
        let lr_len = 2 * P::N_LIMBS - 1;
        let mut lr_prod_limbs = vec![FpVar::<ConstraintF>::zero(); lr_len];
        for i in 0..P::N_LIMBS {
            for j in i..P::N_LIMBS {
                let k = i + j;
                let term = &self.limbs[i] * &self.limbs[j];
                lr_prod_limbs[k] += &term;
                if i != j {
                    lr_prod_limbs[k] += &term;
                }
            }
        }

        Self::verify_mod_relation(cs, &lr_prod_limbs, lr_len, modulus, &prod_value, &lhs_word_size)
    }

    /// Common verification for modular multiplication/squaring (unchecked path).
    ///
    /// Given lr_prod_limbs representing `a * b` (or `a * a`), verifies:
    ///   lr_prod == modulus * quotient + remainder, where 0 <= remainder < modulus
    ///
    /// Allocates quotient (N_LIMBS) and remainder as witnesses, enforces range checks,
    /// strict rem < modulus, and carry-propagation equality.
    fn verify_mod_relation(
        cs: ConstraintSystemRef<ConstraintF>,
        lr_prod_limbs: &[FpVar<ConstraintF>],
        lr_len: usize,
        modulus: &Self,
        prod_value: &BigNat,
        lhs_word_size: &BigNat,
    ) -> Result<Self, SynthesisError> {
        let mod_value = &modulus.value;
        let (quotient_value, rem_value) = if mod_value.is_zero() {
            (BigNat::zero(), BigNat::zero())
        } else {
            (prod_value / mod_value, prod_value % mod_value)
        };

        // Allocate rem as a witness and enforce canonical form (rem < 2^w)
        let rem = Self::new_witness(cs.clone(), || Ok(rem_value.clone()))?;
        rem.enforce_limb_range_via_bits()?;

        // Fix quotient to N limbs (operands assumed < modulus, so quotient stays small)
        let num_quotient_limbs: usize = P::N_LIMBS;
        let mut quotient_value_limbs = fit_nat_to_limbs(&quotient_value, P::LIMB_WIDTH);
        quotient_value_limbs.resize(num_quotient_limbs, ConstraintF::zero());
        let quotient_limbs =
            Vec::<FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(&quotient_value_limbs[..]))?;
        for q in quotient_limbs.iter() {
            let _ = q.to_bits_le_with_top_bits_zero(P::LIMB_WIDTH)?;
        }
        let quotient = BigNatVar::<ConstraintF, P> {
            limbs: quotient_limbs,
            value: quotient_value.clone(),
            word_size: (BigNat::one() << P::LIMB_WIDTH as u32) - BigNat::one(),
            _params: PhantomData,
        };

        // STRICT: enforce rem < modulus to ensure uniqueness of the remainder
        Self::enforce_lt_strict_borrow_chain(cs.clone(), &rem, modulus)?;

        // Compute modulus * quotient
        let mq_len = P::N_LIMBS + num_quotient_limbs - 1;
        let mut mq_prod_limbs = vec![FpVar::<ConstraintF>::zero(); mq_len];
        for i in 0..P::N_LIMBS {
            for j in 0..num_quotient_limbs {
                mq_prod_limbs[i + j] += &modulus.limbs[i] * &quotient.limbs[j];
            }
        }

        // Build lhs (product) and rhs (mod*quot + rem) limb arrays
        let eq_len = core::cmp::max(lr_len, mq_len);
        let mut lhs_limbs = vec![FpVar::<ConstraintF>::zero(); eq_len];
        for i in 0..lr_len {
            lhs_limbs[i] += &lr_prod_limbs[i];
        }
        let mut rhs_limbs = vec![FpVar::<ConstraintF>::zero(); eq_len];
        for i in 0..mq_len {
            rhs_limbs[i] += &mq_prod_limbs[i];
        }
        for i in 0..P::N_LIMBS {
            rhs_limbs[i] += &rem.limbs[i];
        }

        // Conservative word_size bound for carry propagation
        let rhs_word_size =
            BigNat::from(P::N_LIMBS) * &modulus.word_size * &quotient.word_size + &rem.word_size;
        let eq_word_size = max(lhs_word_size.clone(), rhs_word_size);

        Self::conditional_enforce_limbs_equal_when_carried(
            cs.clone(),
            &lhs_limbs,
            &rhs_limbs,
            &eq_word_size,
            &Boolean::TRUE,
        )?;

        Ok(rem)
    }

    /// Modular exponentiation (checked): generic implementation
    pub fn pow_mod(
        &self,
        exp: &Self,
        modulus: &Self,
        num_exp_bits: usize,
    ) -> Result<Self, SynthesisError> {
        self.pow_mod_mode(exp, modulus, num_exp_bits, RangeMode::Checked)
    }

    /// Modular exponentiation (unchecked): fast-path entry optimized for RSA2048 signature verification
    pub fn pow_mod_unchecked(
        &self,
        exp: &Self,
        modulus: &Self,
        num_exp_bits: usize,
    ) -> Result<Self, SynthesisError> {
        self.pow_mod_mode(exp, modulus, num_exp_bits, RangeMode::Unchecked)
    }

    pub fn pow_mod_mode(
        &self,
        exp: &Self,
        modulus: &Self,
        num_exp_bits: usize,
        mode: RangeMode,
    ) -> Result<Self, SynthesisError> {
        // Unchecked = skip input range-checks only
        self.maybe_enforce_limb_range(mode)?;
        exp.maybe_enforce_limb_range(mode)?;
        modulus.maybe_enforce_limb_range(mode)?;

        // Normalize exp if its word_size is abnormally large
        if exp.word_size >= (BigNat::one() << P::LIMB_WIDTH as u32) {
            // reduce() is checked in nature, but this branch only fires when word_size is out of range,
            // so keeping it is the safe choice.
            return self.pow_mod_mode(&exp.reduce()?, modulus, num_exp_bits, mode);
        }

        let cs = self.cs().or(exp.cs()).or(modulus.cs());

        // Enforcing zero high bits on exp is critical for soundness — always applied regardless of mode
        let exp_bits = exp.enforce_fits_in_bits(num_exp_bits)?;

        let window_size = if num_exp_bits < 8 {
            1
        } else if num_exp_bits < 32 {
            2
        } else if num_exp_bits < 128 {
            3
        } else if num_exp_bits < 512 {
            4
        } else if num_exp_bits < 2048 {
            5
        } else {
            6
        };

        // base_powers must guarantee STRICT rem < modulus.
        // Even in unchecked mode, use mult_mod_checked_impl (only input range-checks are skipped)
        let base_powers = {
            let mut base_powers =
                vec![Self::new_constant(cs.clone(), BigNat::one())?, self.clone()];
            for _ in 2..(1 << window_size) {
                let next = base_powers
                    .last()
                    .unwrap()
                    .mult_mod_checked_impl(self, modulus)?;
                base_powers.push(next);
            }
            base_powers
        };

        Self::bauer_power_helper_mode(
            cs.clone(),
            &base_powers,
            exp_bits.chunks(window_size),
            modulus,
            mode,
        )
    }

    /// Recursive Bauer window exponentiation helper (used internally by pow_mod).
    /// Splits exp bits into windows, selects the corresponding base^k via select_index,
    /// then recursively accumulates: square chunk_len times, then multiply by the selected power.
    /// Uses mult_mod_checked_impl throughout to maintain STRICT rem < modulus (soundness).
    fn bauer_power_helper_mode(
        cs: impl Into<Namespace<ConstraintF>>,
        base_powers: &[Self],
        mut exp_chunks: std::slice::Chunks<Boolean<ConstraintF>>,
        modulus: &Self,
        mode: RangeMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        if let Some(chunk) = exp_chunks.next() {
            let chunk_len = chunk.len();
            let base_power = select_index(&base_powers[..(1 << chunk_len)], chunk)?;

            if exp_chunks.len() > 0 {
                let mut acc = Self::bauer_power_helper_mode(
                    cs.clone(),
                    base_powers,
                    exp_chunks,
                    modulus,
                    mode,
                )?;

                // Square step: square chunk_len times (acc = acc^(2^{chunk_len}))
                for _ in 0..chunk_len {
                    // Always use checked_impl to preserve correctness guarantees
                    acc = acc.mult_mod_checked_impl(&acc, modulus)?;
                }

                // Multiply step: apply the selected base_power to advance the accumulator
                Ok(acc.mult_mod_checked_impl(&base_power, modulus)?)
            } else {
                Ok(base_power)
            }
        } else {
            Ok(Self::new_constant(cs.clone(), BigNat::one())?)
        }
    }

    /// Combine multiple limbs into a single grouped limb.
    /// Processing limbs in groups reduces constraint count during carry propagation verification.
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

    /// Unconditionally enforce carry-aware equality.
    /// Verifies that two BigNats represent the same value, allowing carry propagation across limbs.
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

    /// Internal helper: enforce carry-aware equality over limb arrays.
    /// Verifies that left_limbs and right_limbs represent the same value under carry propagation.
    /// current_word_size: maximum possible value per limb (used to compute carry bounds).
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

        // Carry bound: we need carry < 2^carry_bits.
        // Use an integer-only formula to avoid floating-point rounding issues.
        let carry_bits = (current_word_size.bits() as usize)
            .saturating_add(1)
            .saturating_sub(P::LIMB_WIDTH);

        let limbs_per_group =
            ((ConstraintF::MODULUS_BIT_SIZE - 1u32) as usize - carry_bits) / P::LIMB_WIDTH;

        assert!(limbs_per_group >= 1, "limbs_per_group must be >= 1");

        let grouped_base = BigNat::one() << (P::LIMB_WIDTH * limbs_per_group) as u32;
        let grouped_word_size = (0..limbs_per_group).fold(BigNat::ZERO, |mut acc, i| {
            acc.set_bit((i * P::LIMB_WIDTH) as u64, true);
            acc
        }) * current_word_size.clone();

        let grouped_carry_bits =
            (grouped_word_size.bits() as usize - P::LIMB_WIDTH * limbs_per_group + 1) as usize;

        // Propagate carries over grouped limbs.
        let mut carry_in = FpVar::<ConstraintF>::Constant(ConstraintF::ZERO);
        let mut accumulated_extra = BigNat::ZERO;

        // Group limbs once (avoid recomputation) and iterate over groups.
        let left_grouped = Self::group_limbs(left_limbs, limbs_per_group);
        let right_grouped = Self::group_limbs(right_limbs, limbs_per_group);

        for (i, (left_limb, right_limb)) in
            left_grouped.iter().zip(right_grouped.iter()).enumerate()
        {
            let left_limb_value = left_limb.value().unwrap_or_default();
            let right_limb_value = right_limb.value().unwrap_or_default();
            let carry_in_value = carry_in.value().unwrap_or_default();

            let carry_value = nat_to_fe::<ConstraintF>(
                &((fe_to_nat(&left_limb_value)
                    + fe_to_nat(&carry_in_value)
                    + grouped_word_size.clone()
                    - fe_to_nat(&right_limb_value))
                    / grouped_base.clone()),
            );

            let carry = <FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(carry_value))?;

            accumulated_extra += grouped_word_size.clone();

            let (tmp_accumulated_extra, remainder) = accumulated_extra.div_rem(&grouped_base);
            accumulated_extra = tmp_accumulated_extra;
            let remainder_limb = nat_to_fe::<ConstraintF>(&remainder);

            let eqn_left: FpVar<ConstraintF> =
                left_limb + &carry_in - right_limb + nat_to_fe::<ConstraintF>(&grouped_word_size);
            let eqn_right = &carry * nat_to_fe::<ConstraintF>(&grouped_base) + remainder_limb;

            eqn_left.conditional_enforce_equal(&eqn_right, condition)?;

            // last-iteration check must be based on number of GROUPS, not raw limb length.
            if i + 1 < left_grouped.len() {
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

    /// Enforce that BigNat fits in n_bits and return the bit array.
    /// Upper limbs must be zero; the topmost non-zero limb must fit in n_bits % LIMB_WIDTH bits.
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
                crate::enforce_eq_internal!("bigint_limb_zero", limb.clone(), <FpVar<ConstraintF>>::zero())?;
            }
        }
        Ok(bit_vars)
    }

    /// Unconditionally enforce that a single limb fits in n_bits.
    pub fn enforce_limb_fits_in_bits(
        limb: &FpVar<ConstraintF>,
        n_bits: usize,
    ) -> Result<Vec<Boolean<ConstraintF>>, SynthesisError> {
        Self::conditional_enforce_limb_fits_in_bits(limb, n_bits, &Boolean::TRUE)
    }

    /// Conditionally enforce that a single limb fits in n_bits.
    /// Caps n_bits at modulus_bit_size - 1 to prevent field wrap-around.
    fn conditional_enforce_limb_fits_in_bits(
        limb: &FpVar<ConstraintF>,
        n_bits: usize,
        condition: &Boolean<ConstraintF>,
    ) -> Result<Vec<Boolean<ConstraintF>>, SynthesisError> {
        let cs = limb.cs();

        // Cap at modulus_bit_size - 1 to avoid field wrap-around
        let n_bits = core::cmp::min(ConstraintF::MODULUS_BIT_SIZE as usize - 1, n_bits);

        // Total bit length of the BigInt representation (version-independent)
        let repr_bits = core::mem::size_of::<<ConstraintF as PrimeField>::BigInt>() * 8;

        let limb_value = limb.value().unwrap_or_default();

        // BitIteratorBE iterates all repr_bits (including shaved bits),
        // so skip the top repr_bits - n_bits to retain only the lowest n_bits
        let skip = repr_bits.saturating_sub(n_bits);

        let mut bits_be = Vec::with_capacity(n_bits);
        for b in BitIteratorBE::new(limb_value.into_bigint()).skip(skip) {
            bits_be.push(b);
        }

        // Existing code built LE witnesses via bits.iter().rev() — preserve that ordering
        let mut bit_vars = Vec::with_capacity(n_bits);
        if cs != ConstraintSystemRef::None {
            for b in bits_be.iter().rev() {
                bit_vars.push(Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(*b))?);
            }
            Self::conditional_enforce_limb_equals_bits(limb, &bit_vars, condition)?;
        } else {
            for b in bits_be.iter().rev() {
                bit_vars.push(Boolean::<ConstraintF>::constant(*b));
            }
        }

        Ok(bit_vars)
    }

    /// Unconditionally enforce that BigNat equals the given bit array.
    pub fn enforce_equals_bits(&self, bits: &[Boolean<ConstraintF>]) -> Result<(), SynthesisError> {
        self.conditional_enforce_equals_bits(bits, &Boolean::TRUE)
    }

    /// Conditionally enforce that BigNat equals the given bit array.
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

    /// Internal helper: conditionally enforce that a single limb equals the given bit array.
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

    /// Construct a single limb (FpVar) from a bit array.
    /// Combines bits in little-endian order to produce a field element.
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

    /// Range-check all limbs: enforce each limb fits in LIMB_WIDTH bits.
    /// Decomposes each limb into bits to guarantee canonical form.
    pub fn enforce_limb_range_via_bits(&self) -> Result<(), SynthesisError> {
        for limb in self.limbs.iter() {
            let _ = limb.to_bits_le_with_top_bits_zero(P::LIMB_WIDTH)?;
        }
        Ok(())
    }

    pub fn enforce_lt_strict_borrow_chain(
        cs: ConstraintSystemRef<ConstraintF>,
        a: &BigNatVar<ConstraintF, P>,
        b: &BigNatVar<ConstraintF, P>,
    ) -> Result<(), SynthesisError> {
        // a,b are assumed canonical (limb < 2^w). Caller ensured at allocation time.

        // Base B = 2^LIMB_WIDTH (works even when LIMB_WIDTH >= 64)
        let base_const = ConstraintF::from(2u64).pow([P::LIMB_WIDTH as u64]);
        let base = FpVar::<ConstraintF>::constant(base_const);

        // mask = (1<<w)-1 in BigNat
        let mask = (BigNat::one() << (P::LIMB_WIDTH as u32)) - BigNat::one();

        // Compute diff = b - a and borrow_out[i] off-circuit (per limb)
        // If b < a, we still produce something, but final borrow will force failure.
        let mut borrow_bits: Vec<bool> = Vec::with_capacity(P::N_LIMBS);
        let mut diff_limbs_nat: Vec<BigNat> = Vec::with_capacity(P::N_LIMBS);

        let mut borrow: bool = false;
        for i in 0..P::N_LIMBS {
            let shift = (i * P::LIMB_WIDTH) as u32;

            let a_i = (&a.value >> shift) & &mask;
            let b_i = (&b.value >> shift) & &mask;

            // compute: b_i - a_i - borrow
            // if underflow at this limb => borrow_out = 1 and add base
            let (d_i, borrow_out) = if !borrow {
                if b_i >= a_i {
                    (b_i.clone() - a_i, false)
                } else {
                    ((b_i + (&mask + BigNat::one())) - a_i, true) // +B - a_i
                }
            } else {
                // subtract 1 extra
                if b_i > a_i {
                    (b_i.clone() - a_i - BigNat::one(), false)
                } else if b_i == a_i {
                    ((&mask + BigNat::one()) - BigNat::one(), true) // B-1, borrow continues
                } else {
                    ((b_i + (&mask + BigNat::one())) - a_i - BigNat::one(), true)
                }
            };

            diff_limbs_nat.push(d_i);
            borrow_bits.push(borrow_out);
            borrow = borrow_out;
        }

        // Allocate diff limbs
        let mut diff_limbs_val = diff_limbs_nat
            .iter()
            .map(|x| nat_to_fe::<ConstraintF>(x))
            .collect::<Vec<_>>();
        diff_limbs_val.resize(P::N_LIMBS, ConstraintF::zero());
        let diff_limbs =
            Vec::<FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(&diff_limbs_val[..]))?;

        // Enforce borrow-chain and strictness
        let mut borrow_prev = FpVar::<ConstraintF>::zero();
        let mut any_nonzero = Boolean::<ConstraintF>::FALSE;

        for i in 0..P::N_LIMBS {
            // range-check diff limb (needed to make limb meaning sound)
            let _ = diff_limbs[i].to_bits_le_with_top_bits_zero(P::LIMB_WIDTH)?;

            // witness borrow_out[i]
            let bi = borrow_bits[i];
            let borrow_out = Boolean::<ConstraintF>::new_witness(cs.clone(), || Ok(bi))?;
            let borrow_out_fp =
                borrow_out.select(&FpVar::<ConstraintF>::one(), &FpVar::<ConstraintF>::zero())?;

            // (b_i - a_i - borrow_prev) + borrow_out*B - diff_i == 0
            let lhs =
                &b.limbs[i] - &a.limbs[i] - &borrow_prev + &borrow_out_fp * &base - &diff_limbs[i];
            crate::enforce_eq_internal!("bigint_sub_limb_eq", lhs, FpVar::<ConstraintF>::zero())?;

            // diff != 0  (strict)
            let limb_is_nonzero = diff_limbs[i].is_neq(&FpVar::<ConstraintF>::zero())?;
            any_nonzero = any_nonzero | limb_is_nonzero;

            borrow_prev = borrow_out_fp;
        }

        // final borrow must be 0  => a <= b
        crate::enforce_eq_internal!("bigint_sub_borrow_zero", borrow_prev, FpVar::<ConstraintF>::zero())?;

        // strict: diff != 0 => a != b
        crate::enforce_true_internal!("bigint_sub_nonzero", any_nonzero)?;

        Ok(())
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
// TODO(P4-5): This limb-wise comparison is semantically incorrect for non-canonical representations. Use enforce_equal_when_carried for semantic equality.

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
        let result = BigNatVar {
            limbs: limb_vars,
            value: limbs_to_nat::<ConstraintF>(limbs, P::LIMB_WIDTH),
            word_size: word_size,
            _params: PhantomData,
        };
        Ok(result)
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
            vec![1, 1, 1, 3], // 587
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

    /// BigNat2048TestParams definition
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

        // Helper: convert BigUint to a big-endian u64 limb vector
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

        // 1. Set up RSA-style test values
        let mut rng = thread_rng();

        // Exponent (e = 65537, 17-bit)
        let exp_val = BigUint::from(65537u32);
        let num_exp_bits = 17;

        // Base (message, 2048-bit)
        let mut base_bytes = vec![0u8; 2048 / 8];
        rng.fill_bytes(&mut base_bytes);
        let base_val = BigUint::from_bytes_be(&base_bytes);

        // Modulus (N, 2040-bit, guaranteed odd)
        let mut mod_bytes = vec![0u8; 2040 / 8];
        rng.fill_bytes(&mut mod_bytes);
        // Use last_mut() to safely make the last byte odd
        if let Some(last_byte) = mod_bytes.last_mut() {
            *last_byte |= 1;
        }
        let mod_val = BigUint::from_bytes_be(&mod_bytes);

        // 2. Compute expected result (ciphertext = base^exp % mod)
        let expected_res_val = base_val.modpow(&exp_val, &mod_val);

        // Convert BigUint values to limb vectors for circuit input
        let base_limbs = to_be_limbs(&base_val);
        let exp_limbs = to_be_limbs(&exp_val);
        let mod_limbs = to_be_limbs(&mod_val);
        let expected_res_limbs = to_be_limbs(&expected_res_val);

        // 3. Set up constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let word_size: BigNat = (BigNat::one() << 64) - BigNat::one();

        // 4. Allocate circuit variables
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

        // 5. Compute modular exponentiation in the circuit
        let res_var = base_var.pow_mod(&exp_var, &mod_var, num_exp_bits).unwrap();

        // 6. Add constraint: circuit result equals expected result
        expected_res_var
            .enforce_equal_when_carried(&res_var)
            .unwrap();

        // 7. Verify all constraints are satisfied
        println!(
            "RSA-style 17-bit pow_mod constraint count: {}",
            cs.num_constraints()
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "RSA-style 17-bit pow_mod constraints are not satisfied."
        );
    }
}
