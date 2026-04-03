use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{FieldVar, fp::FpVar},
};

use crate::matrix::VandermondeMatrix;

#[derive(Clone)]
pub struct VandermondeMatrixVar<F: PrimeField> {
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

            // a의 i번째 원소와 M의 (i,j) 요소를 곱하여 더함
            // Mul 한 번 당 Constraint 1개
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
