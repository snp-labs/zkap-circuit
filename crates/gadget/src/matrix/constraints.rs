//! R1CS gadget for Vandermonde matrix-vector multiplication.
//!
//! [`VandermondeMatrixVar`] allocates a Vandermonde matrix as a 2D array of `FpVar`
//! field elements and exposes `vector_mul_matrix` for in-circuit dot-product computation.
//! Used by [`crate::anchor::poseidon::constraints`] to enforce the consistency check
//! `b = a · A` as part of the threshold anchor binding proof.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{FieldVar, fp::FpVar},
};

use crate::matrix::VandermondeMatrix;

/// In-circuit witness for a [`VandermondeMatrix`]. Allocated once per
/// proof so the prover can enforce `b = a · A` without re-emitting the
/// (constant) matrix entries on every multiplication.
#[derive(Clone)]
pub struct VandermondeMatrixVar<F: PrimeField> {
    /// Field-element form of the matrix rows; outer `Vec` indexes rows
    /// (length `m`), inner indexes columns (length `n`). Each entry is
    /// a circuit variable, so allocation cost is `m * n` `FpVar`s.
    pub matrix: Vec<Vec<FpVar<F>>>,
}

impl<F: PrimeField> VandermondeMatrixVar<F> {
    /// b = a * M
    pub fn vector_mul_matrix(
        &self,
        a: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, ark_relations::r1cs::SynthesisError> {
        let m = self.matrix.len();
        let n = self.matrix[0].len();

        if a.len() != m {
            return Err(ark_relations::r1cs::SynthesisError::Unsatisfiable);
        }

        let mut result = Vec::with_capacity(n);

        for j in 0..n {
            let mut sum = FpVar::zero();

            // Multiply the i-th element of a by the (i,j) element of M and accumulate
            // 1 constraint per multiplication
            for (i, a_i) in a.iter().enumerate().take(m) {
                sum += a_i * &self.matrix[i][j];
            }
            result.push(sum);
        }

        Ok(result)
    }
}

impl<F: PrimeField> AllocVar<VandermondeMatrix<F>, F> for VandermondeMatrixVar<F> {
    fn new_variable<T: std::borrow::Borrow<VandermondeMatrix<F>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|val| {
            let m = val.borrow().matrix.len();
            let n = val.borrow().matrix[0].len();

            let mut matrix_vars = Vec::with_capacity(m);

            for r in &val.borrow().matrix {
                let mut row_vars = Vec::with_capacity(n);
                for &elem in r {
                    let var = FpVar::new_variable(cs.clone(), || Ok(elem), mode)?;
                    row_vars.push(var);
                }
                matrix_vars.push(row_vars);
            }

            Ok(VandermondeMatrixVar {
                matrix: matrix_vars,
            })
        })
    }
}
