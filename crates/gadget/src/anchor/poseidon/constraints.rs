//! R1CS gadgets for the Poseidon anchor scheme.
//!
//! Provides allocator impls for all Poseidon anchor witness types and
//! [`PoseidonAnchorSchemeGadget`], which enforces the anchor equation in-circuit.
//! Key entry points: `inner_product` (dot-product constraint), `enforce_a_nonzero`
//! (at least one selector is active), `enforce_b_sparsity` / `is_b_sparsity`
//! (exactly `k` selectors are set), and `enforce_boolean_selectors`.

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

/// In-circuit representation of [`PoseidonAnchorPublicKey`]: holds the Poseidon
/// parameter constants allocated into the constraint system.
#[derive(Clone)]
pub struct PoseidonAnchorPublicKeyVar<F: PrimeField + Absorb> {
    /// Poseidon round constants and MDS matrix allocated as circuit constants.
    pub params: CRHParametersVar<F>,
}

/// In-circuit representation of [`PoseidonAnchorWitness`]: the three vectors
/// `a`, `b`, and `h_known` allocated as `FpVar` witnesses.
#[derive(Clone)]
pub struct PoseidonAnchorWitnessVar<F: PrimeField + Absorb> {
    /// Auxiliary vector `a` of length `m = n − k + 1`; encodes which linear
    /// combination of the Vandermonde rows collapses to the anchor.
    pub a: Vec<FpVar<F>>,
    /// Product `b = a · Matrix` of length `n`; non-zero only at the `k` selected
    /// positions, enforced by `enforce_b_sparsity`.
    pub b: Vec<FpVar<F>>,
    /// Poseidon hashes of the known secrets at each selected position (`H(i, secret[i])`);
    /// zero at unselected positions.
    pub h_known: Vec<FpVar<F>>,
}

impl<F> PoseidonAnchorWitnessVar<F>
where
    F: PrimeField + Absorb,
{
    /// Verifies Sparsity Consistency between vector `b` and vector `h_known`.
    /// For every index `i`, if `b[i] == 0` then `h_known[i]` must also be 0.
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

/// In-circuit representation of [`PoseidonAnchor`]: the committed anchor vector
/// of length `m = n − k + 1` allocated as `FpVar` public inputs.
#[derive(Clone)]
pub struct PoseidonAnchorVar<F: PrimeField + Absorb> {
    /// The `m` field-element anchor values, typically allocated as public inputs
    /// so the verifier can check them against the on-chain commitment.
    pub anchor: Vec<FpVar<F>>,
}

/// Concrete gadget implementing [`AnchorSchemeGadget`] for the Poseidon-based scheme.
///
/// Stateless — all methods are associated functions parameterised on `F`. The phantom
/// field ensures the correct `PrimeField + Absorb` bound is carried at the type level.
#[derive(Clone)]
pub struct PoseidonAnchorSchemeGadget<F: PrimeField + Absorb> {
    /// Phantom data binding the field type; no runtime storage.
    pub _phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> PoseidonAnchorSchemeGadget<F> {
    /// Computes the dot product `Σ v1[i] · v2[i]` as a single `FpVar` constraint.
    ///
    /// # Precondition
    ///
    /// `v1.len() == v2.len()`. The caller is responsible for enforcing this —
    /// production callers (`circuit::zkap::ZkapCircuit::generate_constraints`
    /// and the same-file [`PoseidonAnchorSchemeGadget::verify_binding`])
    /// derive both slices from the same matrix dimensions before invocation.
    ///
    /// On precondition violation (length mismatch) the function returns
    /// `Err(SynthesisError::Unsatisfiable)`. The `Unsatisfiable` variant is
    /// reused here as a reporting channel because arkworks'
    /// `ark_relations::r1cs::SynthesisError` is the foreign error type
    /// returned by every constraint method in the gadget surface and does
    /// not carry a `LengthMismatch` variant; replacing the return type with
    /// a custom error would cascade through every R1CS-synthesising call
    /// site in `circuit::zkap` (L1 lock — see
    /// `00-cross-cutting-locks.md`). Callers should treat `Unsatisfiable`
    /// from this function as a caller-side precondition bug, not as
    /// evidence that the circuit witness violates a constraint.
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
    pub fn enforce_a_nonzero(a: &[FpVar<F>]) -> Result<(), SynthesisError> {
        let zero = FpVar::<F>::zero();
        let nonzero_bits = a
            .iter()
            .map(|x| x.is_neq(&zero))
            .collect::<Result<Vec<_>, _>>()?;
        Boolean::kary_or(&nonzero_bits)?.enforce_equal(&Boolean::TRUE)?;

        Ok(())
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

    /// Enforces that `b[j] == 0` for every `j` where `selector[j] == 0`.
    ///
    /// Uses: `(1 - selector[j]) * b[j] == 0`, which is 1 constraint per element.
    /// Cost: N constraints vs `is_b_sparsity` + `enforce_true`: ~8N+1 constraints.
    ///
    /// Precondition: `selector[j] ∈ {0,1}` must be enforced separately (via `enforce_boolean_selectors`).
    /// Soundness: `selector[j]=0 → 1*b[j]=0 → b[j]=0`. `selector[j]=1 → 0*b[j]=0` → always holds.
    pub fn enforce_b_sparsity(b: &[FpVar<F>], selector: &[FpVar<F>]) -> Result<(), SynthesisError> {
        if b.is_empty() || selector.is_empty() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if b.len() != selector.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let one = FpVar::<F>::one();
        let zero = FpVar::<F>::zero();

        for j in 0..b.len() {
            // (1 - selector[j]) * b[j] == 0
            let mask = &one - &selector[j];
            mask.mul_equals(&b[j], &zero)?;
        }

        Ok(())
    }
}

/// `indices[j] ∈ {0,1}`  (boolean)
pub fn enforce_boolean_selectors<F: PrimeField>(
    indices: &[FpVar<F>],
) -> Result<(), SynthesisError> {
    let one = FpVar::<F>::one();
    let zero = FpVar::<F>::zero();

    for s in indices {
        // [OPT-5] s × (s - 1) = 0 as single R1CS constraint (was 2 constraints)
        let s_minus_one = s.clone() - one.clone();
        s.mul_equals(&s_minus_one, &zero)?;
    }
    Ok(())
}

/// `Σ indices[j] == k`  (cardinality)
pub fn enforce_selector_cardinality<F: PrimeField>(
    indices: &[FpVar<F>],
    k: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let mut sum = FpVar::<F>::zero();
    for s in indices {
        sum += s.clone();
    }
    sum.enforce_equal(k)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::r1cs::ConstraintSystem;

    type F = ark_bn254::Fr;

    fn fp(cs: &ark_relations::r1cs::ConstraintSystemRef<F>, v: u64) -> FpVar<F> {
        FpVar::new_witness(cs.clone(), || Ok(F::from(v))).unwrap()
    }

    #[test]
    fn test_inner_product_basic() {
        let cs = ConstraintSystem::<F>::new_ref();
        let v1: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 2), fp(&cs, 3)];
        let v2: Vec<FpVar<F>> = vec![fp(&cs, 4), fp(&cs, 5), fp(&cs, 6)];

        let result = PoseidonAnchorSchemeGadget::<F>::inner_product(&v1, &v2).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), F::from(32u64)); // 1*4+2*5+3*6=32
    }

    #[test]
    fn test_inner_product_different_lengths() {
        let cs = ConstraintSystem::<F>::new_ref();
        let v1: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 2)];
        let v2: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 2), fp(&cs, 3)];

        let result = PoseidonAnchorSchemeGadget::<F>::inner_product(&v1, &v2);
        assert!(result.is_err());
    }

    #[test]
    fn test_enforce_a_nonzero_all_nonzero() {
        let cs = ConstraintSystem::<F>::new_ref();
        let a: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 2), fp(&cs, 3)];

        PoseidonAnchorSchemeGadget::<F>::enforce_a_nonzero(&a).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_a_nonzero_all_zero() {
        let cs = ConstraintSystem::<F>::new_ref();
        let a: Vec<FpVar<F>> = vec![fp(&cs, 0), fp(&cs, 0), fp(&cs, 0)];

        PoseidonAnchorSchemeGadget::<F>::enforce_a_nonzero(&a).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_is_b_sparsity_valid() {
        let cs = ConstraintSystem::<F>::new_ref();
        // selector[1]=0, so b[1] must be 0 — and it is
        let b: Vec<FpVar<F>> = vec![fp(&cs, 5), fp(&cs, 0), fp(&cs, 3)];
        let selector: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 0), fp(&cs, 1)];

        let result = PoseidonAnchorSchemeGadget::<F>::is_b_sparsity(&b, &selector).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert!(result.value().unwrap());
    }

    #[test]
    fn test_is_b_sparsity_invalid() {
        let cs = ConstraintSystem::<F>::new_ref();
        // selector[1]=0, but b[1]=7 (nonzero) → invalid
        let b: Vec<FpVar<F>> = vec![fp(&cs, 5), fp(&cs, 7), fp(&cs, 3)];
        let selector: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 0), fp(&cs, 1)];

        let result = PoseidonAnchorSchemeGadget::<F>::is_b_sparsity(&b, &selector).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert!(!result.value().unwrap());
    }

    #[test]
    fn test_enforce_boolean_selectors_valid() {
        let cs = ConstraintSystem::<F>::new_ref();
        let indices: Vec<FpVar<F>> = vec![fp(&cs, 0), fp(&cs, 1), fp(&cs, 1), fp(&cs, 0)];

        enforce_boolean_selectors(&indices).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_boolean_selectors_non_boolean() {
        let cs = ConstraintSystem::<F>::new_ref();
        let indices: Vec<FpVar<F>> = vec![fp(&cs, 0), fp(&cs, 2), fp(&cs, 1), fp(&cs, 0)];

        enforce_boolean_selectors(&indices).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_selector_cardinality_valid() {
        let cs = ConstraintSystem::<F>::new_ref();
        let indices: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 1), fp(&cs, 0), fp(&cs, 0)];
        let k = fp(&cs, 2);

        enforce_selector_cardinality(&indices, &k).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_selector_cardinality_wrong_k() {
        let cs = ConstraintSystem::<F>::new_ref();
        let indices: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 1), fp(&cs, 0), fp(&cs, 0)];
        let k = fp(&cs, 3); // wrong: sum is 2, not 3

        enforce_selector_cardinality(&indices, &k).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_verify_sparsity_consistency_valid() {
        let cs = ConstraintSystem::<F>::new_ref();
        // b[0]=0 → h_known[0] must be 0. b[1]=5 → h_known[1] can be anything
        let witness = PoseidonAnchorWitnessVar {
            a: vec![fp(&cs, 1)],
            b: vec![fp(&cs, 0), fp(&cs, 5)],
            h_known: vec![fp(&cs, 0), fp(&cs, 3)],
        };

        let result = witness.verify_sparsity_consistency().unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert!(result.value().unwrap());
    }

    #[test]
    fn test_single_element_boundary() {
        let cs = ConstraintSystem::<F>::new_ref();
        // n=1, k=1 case
        let indices: Vec<FpVar<F>> = vec![fp(&cs, 1)];
        let k = fp(&cs, 1);

        enforce_boolean_selectors(&indices).unwrap();
        enforce_selector_cardinality(&indices, &k).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    // =========================================================================
    // enforce_a_nonzero tests
    // =========================================================================

    #[test]
    fn test_enforce_a_nonzero_single_nonzero() {
        let cs = ConstraintSystem::<F>::new_ref();
        let a: Vec<FpVar<F>> = vec![fp(&cs, 1)];
        PoseidonAnchorSchemeGadget::<F>::enforce_a_nonzero(&a).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_a_nonzero_single_zero() {
        let cs = ConstraintSystem::<F>::new_ref();
        let a: Vec<FpVar<F>> = vec![fp(&cs, 0)];
        PoseidonAnchorSchemeGadget::<F>::enforce_a_nonzero(&a).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_a_nonzero_one_among_zeros() {
        let cs = ConstraintSystem::<F>::new_ref();
        let a: Vec<FpVar<F>> = vec![fp(&cs, 0), fp(&cs, 0), fp(&cs, 5), fp(&cs, 0)];
        PoseidonAnchorSchemeGadget::<F>::enforce_a_nonzero(&a).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_a_nonzero_last_nonzero() {
        let cs = ConstraintSystem::<F>::new_ref();
        let a: Vec<FpVar<F>> = vec![fp(&cs, 0), fp(&cs, 0), fp(&cs, 0), fp(&cs, 1)];
        PoseidonAnchorSchemeGadget::<F>::enforce_a_nonzero(&a).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_a_nonzero_first_nonzero() {
        let cs = ConstraintSystem::<F>::new_ref();
        let a: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 0), fp(&cs, 0), fp(&cs, 0)];
        PoseidonAnchorSchemeGadget::<F>::enforce_a_nonzero(&a).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_a_nonzero_large_value() {
        let cs = ConstraintSystem::<F>::new_ref();
        let a: Vec<FpVar<F>> = vec![fp(&cs, 0), fp(&cs, 0), fp(&cs, u64::MAX)];
        PoseidonAnchorSchemeGadget::<F>::enforce_a_nonzero(&a).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    // =========================================================================
    // enforce_b_sparsity tests
    // =========================================================================

    #[test]
    fn test_enforce_b_sparsity_valid() {
        let cs = ConstraintSystem::<F>::new_ref();
        let b: Vec<FpVar<F>> = vec![fp(&cs, 5), fp(&cs, 0), fp(&cs, 3)];
        let selector: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 0), fp(&cs, 1)];
        PoseidonAnchorSchemeGadget::<F>::enforce_b_sparsity(&b, &selector).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_b_sparsity_all_selected() {
        let cs = ConstraintSystem::<F>::new_ref();
        let b: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 2), fp(&cs, 3)];
        let selector: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 1), fp(&cs, 1)];
        PoseidonAnchorSchemeGadget::<F>::enforce_b_sparsity(&b, &selector).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_b_sparsity_all_zero_unselected() {
        let cs = ConstraintSystem::<F>::new_ref();
        let b: Vec<FpVar<F>> = vec![fp(&cs, 0), fp(&cs, 0), fp(&cs, 0)];
        let selector: Vec<FpVar<F>> = vec![fp(&cs, 0), fp(&cs, 0), fp(&cs, 0)];
        PoseidonAnchorSchemeGadget::<F>::enforce_b_sparsity(&b, &selector).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_b_sparsity_single_selected() {
        let cs = ConstraintSystem::<F>::new_ref();
        let b: Vec<FpVar<F>> = vec![fp(&cs, 42)];
        let selector: Vec<FpVar<F>> = vec![fp(&cs, 1)];
        PoseidonAnchorSchemeGadget::<F>::enforce_b_sparsity(&b, &selector).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_enforce_b_sparsity_invalid_nonzero_unselected() {
        let cs = ConstraintSystem::<F>::new_ref();
        let b: Vec<FpVar<F>> = vec![fp(&cs, 5), fp(&cs, 7), fp(&cs, 3)];
        let selector: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 0), fp(&cs, 1)];
        PoseidonAnchorSchemeGadget::<F>::enforce_b_sparsity(&b, &selector).unwrap();
        assert!(!cs.is_satisfied().unwrap()); // b[1]=7 but selector[1]=0
    }

    #[test]
    fn test_enforce_b_sparsity_single_unselected_nonzero() {
        let cs = ConstraintSystem::<F>::new_ref();
        let b: Vec<FpVar<F>> = vec![fp(&cs, 5)];
        let selector: Vec<FpVar<F>> = vec![fp(&cs, 0)];
        PoseidonAnchorSchemeGadget::<F>::enforce_b_sparsity(&b, &selector).unwrap();
        assert!(!cs.is_satisfied().unwrap()); // b[0]=5 but selector[0]=0
    }

    #[test]
    fn test_enforce_b_sparsity_last_violates() {
        let cs = ConstraintSystem::<F>::new_ref();
        let b: Vec<FpVar<F>> = vec![fp(&cs, 0), fp(&cs, 0), fp(&cs, 7)];
        let selector: Vec<FpVar<F>> = vec![fp(&cs, 0), fp(&cs, 0), fp(&cs, 0)];
        PoseidonAnchorSchemeGadget::<F>::enforce_b_sparsity(&b, &selector).unwrap();
        assert!(!cs.is_satisfied().unwrap()); // b[2]=7 but selector[2]=0
    }

    #[test]
    fn test_enforce_b_sparsity_first_violates() {
        let cs = ConstraintSystem::<F>::new_ref();
        let b: Vec<FpVar<F>> = vec![fp(&cs, 7), fp(&cs, 0), fp(&cs, 0)];
        let selector: Vec<FpVar<F>> = vec![fp(&cs, 0), fp(&cs, 1), fp(&cs, 1)];
        PoseidonAnchorSchemeGadget::<F>::enforce_b_sparsity(&b, &selector).unwrap();
        assert!(!cs.is_satisfied().unwrap()); // b[0]=7 but selector[0]=0
    }

    #[test]
    fn test_enforce_b_sparsity_empty_errors() {
        let b: Vec<FpVar<F>> = vec![];
        let selector: Vec<FpVar<F>> = vec![];
        let result = PoseidonAnchorSchemeGadget::<F>::enforce_b_sparsity(&b, &selector);
        assert!(result.is_err());
    }

    #[test]
    fn test_enforce_b_sparsity_length_mismatch_errors() {
        let cs = ConstraintSystem::<F>::new_ref();
        let b: Vec<FpVar<F>> = vec![fp(&cs, 1), fp(&cs, 2)];
        let selector: Vec<FpVar<F>> = vec![fp(&cs, 1)];
        let result = PoseidonAnchorSchemeGadget::<F>::enforce_b_sparsity(&b, &selector);
        assert!(result.is_err());
    }
}
