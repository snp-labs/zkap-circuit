use core::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{crh::poseidon::constraints::CRHParametersVar, sponge::Absorb};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::Boolean,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::{
    anchor::{
        constraints::AnchorSchemeGadget,
        poseidon::{
            PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorScheme, PoseidonAnchorWitness,
        },
    },
    matrix::constraints::VandermondeMatrixVar,
};

#[cfg(feature = "constraints-logging")]
use crate::debug::log_r1cs_eq;

#[derive(Clone)]
pub struct PoseidonAnchorPublicKeyVar<F: PrimeField + Absorb> {
    pub params: CRHParametersVar<F>,
}

#[derive(Clone)]
pub struct PoseidonAnchorWitnessVar<F: PrimeField + Absorb> {
    pub a: Vec<FpVar<F>>,
    pub b: Vec<FpVar<F>>,
    pub h_known: Vec<FpVar<F>>,
}

impl<F> PoseidonAnchorWitnessVar<F>
where
    F: PrimeField + Absorb,
{
    /// Verifies Sparsity Consistency between vector b and vector h_known.
    /// For every index i, if b[i] == 0 then h_known[i] must also be 0.
    pub fn verify_sparsity_consistency(&self) -> Result<Boolean<F>, SynthesisError> {
        if self.b.len() != self.h_known.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut is_all_valid = Boolean::constant(true);

        for (b_elem, h_elem) in self.b.iter().zip(self.h_known.iter()) {
            // 1. Check if b[i] is zero (Boolean)
            let b_is_zero = b_elem.is_zero()?;

            // 2. Check if h[i] is zero (Boolean)
            let h_is_zero = h_elem.is_zero()?;

            // 3. Construct logical condition: (b is non-zero) OR (h is zero)
            // - b != 0: (True OR ...) => True (condition satisfied, h doesn't matter)
            // - b == 0: (False OR h_is_zero) => h_is_zero (i.e., h must also be 0 for True)
            let b_is_nonzero = !b_is_zero;
            let current_pair_valid = b_is_nonzero | &h_is_zero;

            // 4. Accumulate with AND across all pairs
            // If any pair is False, the overall result becomes False
            is_all_valid &= &current_pair_valid;
        }

        Ok(is_all_valid)
    }

    /// Verifies that vector a is not the zero vector (All Zeros).
    pub fn is_a_nonzero(&self) -> Result<Boolean<F>, SynthesisError> {
        let mut found_nonzero = Boolean::constant(false);

        for elem in &self.a {
            // 1. Check if the current element is zero
            let is_zero = elem.is_zero()?;

            // 2. Check if the current element is non-zero
            // If is_zero is True, then is_nonzero is False
            let is_nonzero = !is_zero;

            // 3. Accumulate OR
            // If any element so far is non-zero (found_nonzero),
            // or the current element is non-zero (is_nonzero) -> result is True
            found_nonzero |= &is_nonzero;
        }

        Ok(found_nonzero)
    }
}

#[derive(Clone)]
pub struct PoseidonAnchorVar<F: PrimeField + Absorb> {
    pub anchor: Vec<FpVar<F>>,
}

#[derive(Clone)]
pub struct PoseidonAnchorSchemeGadget<F: PrimeField + Absorb> {
    pub _phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> PoseidonAnchorSchemeGadget<F> {
    pub fn inner_product(v1: &[FpVar<F>], v2: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
        if v1.len() != v2.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        let mut sum = FpVar::zero();
        for (a, b) in v1.iter().zip(v2.iter()) {
            sum += a * b;
        }
        Ok(sum)
    }

    /// Function for split-proof.
    /// Verifies that vector a is not the zero vector (All Zeros).
    pub fn is_a_nonzero(a: &[FpVar<F>]) -> Result<Boolean<F>, SynthesisError> {
        let mut found_nonzero = Boolean::constant(false);
        for elem in a {
            let is_zero = elem.is_zero()?;

            let is_nonzero = !is_zero;

            // If any element so far is non-zero (found_nonzero),
            // or the current element is non-zero (is_nonzero) -> result is True
            found_nonzero |= &is_nonzero;
        }

        Ok(found_nonzero)
    }

    /// Function for split-proof.
    /// Verifies that vector b (b = a * A) is zero at all indices not specified by selector.
    /// selector is a bitmask (e.g. [1, 1, 1, 0, 0, 0]): non-zero values only allowed at positions where selector == 1
    pub fn is_b_sparsity(
        b: &[FpVar<F>],
        selector: &[FpVar<F>],
    ) -> Result<Boolean<F>, SynthesisError> {
        if b.is_empty() || selector.is_empty() {
            return Err(SynthesisError::Unsatisfiable);
        }

        if b.len() != selector.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let n = b.len();

        let mut is_all_valid = Boolean::TRUE;

        let zero_var = FpVar::Constant(F::zero());
        let one_var = FpVar::Constant(F::one());

        for j in 0..n {
            // 1. Check if selector[j] is 1 (is_selected)
            let is_selected = selector[j].is_eq(&one_var)?;

            // 2. Check if b[j] is zero (is_zero)
            let is_zero = b[j].is_eq(&zero_var)?;

            // 3. Determine validity for index j
            // Condition: "must be selected (OR) value must be zero"
            // Logic: Valid_j = is_selected OR is_zero
            // - selector[j] == 1 (selected) -> value doesn't matter (True OR X = True) -> pass
            // - selector[j] == 0 (not selected) -> value must be zero (False OR is_zero) -> is_zero must be True to pass
            let is_valid_j = is_selected | &is_zero;

            // 4. Accumulate AND across all results
            is_all_valid &= &is_valid_j;
        }

        Ok(is_all_valid)
    }
}

/// indices[j] ∈ {0,1}  (boolean)
pub fn enforce_boolean_selectors<F: PrimeField>(
    indices: &[FpVar<F>],
) -> Result<(), SynthesisError> {
    let one = FpVar::<F>::one();
    let zero = FpVar::<F>::zero();

    for s in indices {
        // s * (s - 1) == 0  <=> s ∈ {0,1}
        let s_minus_one = s.clone() - one.clone();
        crate::enforce_eq_internal!("anchor_selector_boolean", s.clone() * s_minus_one, zero)?;
    }
    Ok(())
}

pub fn enforce_boolean_selector_debug<F: PrimeField>(
    indices: &[FpVar<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let one = FpVar::<F>::one();
    let zero = FpVar::<F>::zero();
    let mut ok = Boolean::constant(true);

    for s in indices {
        // s * (s - 1) == 0  <=> s ∈ {0,1}
        let s_minus_one = s.clone() - one.clone();
        let is_zero = (s.clone() * s_minus_one).is_eq(&zero)?;
        ok &= is_zero;
    }
    Ok(ok)
}

/// Σ indices[j] == k  (cardinality)
pub fn enforce_selector_cardinality<F: PrimeField>(
    indices: &[FpVar<F>],
    k: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let mut sum = FpVar::<F>::zero();
    for s in indices {
        sum += s.clone();
    }
    crate::enforce_eq_internal!("anchor_selector_cardinality", sum, k.clone())?;
    Ok(())
}

/// Σ indices[j] == k  (cardinality)
pub fn enforce_selector_cardinality_debug<F: PrimeField>(
    indices: &[FpVar<F>],
    k: &FpVar<F>,
) -> Result<Boolean<F>, SynthesisError> {
    let mut sum = FpVar::<F>::zero();
    for s in indices {
        sum += s.clone();
    }
    let is_eq = sum.is_eq(k)?;
    Ok(is_eq)
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
            let a = Vec::<FpVar<F>>::new_variable(cs.clone(), || Ok(val.borrow().a.clone()), mode)?;
            let b = Vec::<FpVar<F>>::new_variable(cs.clone(), || Ok(val.borrow().b.clone()), mode)?;
            let h_known = Vec::<FpVar<F>>::new_variable(
                cs.clone(),
                || Ok(val.borrow().h_known.clone()),
                mode,
            )?;

            Ok(PoseidonAnchorWitnessVar { a, b, h_known })
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

impl<F: PrimeField + Absorb> AnchorSchemeGadget<PoseidonAnchorScheme<F>, F>
    for PoseidonAnchorSchemeGadget<F>
{
    type AnchorVar = PoseidonAnchorVar<F>;
    type MatrixVar = VandermondeMatrixVar<F>;
    type PublicKeyVar = PoseidonAnchorPublicKeyVar<F>;
    type WitnessVar = PoseidonAnchorWitnessVar<F>;

    fn verify_b_consistency(
        witness: &Self::WitnessVar,
        matrix: &Self::MatrixVar,
    ) -> Result<ark_r1cs_std::prelude::Boolean<F>, SynthesisError> {
        let computed_b = matrix.vector_mul_matrix(&witness.a)?;
        let is_equal = computed_b
            .iter()
            .zip(witness.b.iter())
            .map(|(c, w)| c.is_eq(w))
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        Boolean::kary_and(&is_equal)
    }

    fn verify_binding(
        _pk: &Self::PublicKeyVar,
        anchor: &Self::AnchorVar,
        witness: &Self::WitnessVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        let lhs = Self::inner_product(&witness.a, &anchor.anchor)?;
        let rhs = Self::inner_product(&witness.b, &witness.h_known)?;
        lhs.is_eq(&rhs)
    }
}
