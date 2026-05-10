//! Vandermonde matrix operations used by the threshold anchor scheme.
//!
//! [`VandermondeMatrix`] supports construction (`new`), dimension queries, submatrix
//! extraction (`create_submatrix`), vector multiplication (`multiply_vector`,
//! `vector_multiply`), and the `calculate_vector_a` helper used in anchor generation.
//! [`solve_linear_system`] solves `Ax = b` over a prime field via Gaussian elimination
//! with partial pivoting. The R1CS gadget for in-circuit matrix-vector products is in
//! [`constraints`].

pub mod constraints;
pub mod error;

use crate::matrix::error::VandermondeMatrixError;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Optimized Vandermonde Matrix V2
///
/// Key improvements:
/// - Reduced unnecessary memory allocations
/// - Clearer method names
/// - Improved error messages
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VandermondeMatrix<F: PrimeField> {
    /// m × n matrix
    /// m = n - k + 1 (number of rows)
    /// n = total number of secrets (number of columns)
    pub matrix: Vec<Vec<F>>,
    pub n: usize,
    pub k: usize,
}

impl<F: PrimeField> VandermondeMatrix<F> {
    /// Create a new Vandermonde matrix
    ///
    /// # Arguments
    /// * `n` - Total number of secrets (number of columns)
    /// * `k` - Number of known secrets
    ///
    /// # Returns
    /// m × n matrix where m = n - k + 1
    pub fn new(n: usize, k: usize) -> Self {
        if k > n {
            panic!("k must be less than or equal to n");
        }

        let m = n - k + 1;
        let mut matrix = vec![vec![F::zero(); n]; m];

        // matrix[i][j] = (i+1)^j
        for (i, row) in matrix.iter_mut().enumerate().take(m) {
            let base = F::from((i + 1) as u64);
            for (j, elem) in row.iter_mut().enumerate().take(n) {
                *elem = base.pow([j as u64]);
            }
        }

        VandermondeMatrix { matrix, n, k }
    }

    /// Return the dimensions of the matrix (m, n)
    pub fn dimensions(&self) -> (usize, usize) {
        let m = self.matrix.len();
        let n = if m > 0 { self.matrix[0].len() } else { 0 };
        (m, n)
    }

    /// Create a submatrix from the specified column indices
    ///
    /// # Arguments
    /// * `column_indices` - Column indices to select (length = m)
    ///
    /// # Returns
    /// Submatrix of size m × m
    pub fn create_submatrix(
        &self,
        column_indices: &[usize],
    ) -> Result<Self, VandermondeMatrixError> {
        let m = self.matrix.len();

        if column_indices.len() != m {
            return Err(VandermondeMatrixError::LengthError(format!(
                "Column indices length ({}) must match matrix row count ({})",
                column_indices.len(),
                m
            )));
        }

        // Validate index range
        for &idx in column_indices {
            if idx >= self.n {
                return Err(VandermondeMatrixError::LengthError(format!(
                    "Column index {} out of bounds (max: {})",
                    idx,
                    self.n - 1
                )));
            }
        }

        // Create submatrix
        let mut submatrix = vec![vec![F::zero(); m]; m];
        for (r, sub_row) in submatrix.iter_mut().enumerate().take(m) {
            for (new_col, &orig_col) in column_indices.iter().enumerate() {
                sub_row[new_col] = self.matrix[r][orig_col];
            }
        }

        Ok(VandermondeMatrix {
            matrix: submatrix,
            n: m,
            k: 1, // submatrix is a square matrix
        })
    }

    /// Compute vector a from a selector
    ///
    /// This function solves a linear system to find vector a:
    /// a * SubMatrix = target (where only the last element of target is 1)
    ///
    /// # Arguments
    /// * `selector` - 0/1 vector (length n), 1 = known index, 0 = unknown index
    ///   The number of 1s must be exactly k
    pub fn calculate_vector_a(&self, selector: &[u8]) -> Result<Vec<F>, VandermondeMatrixError> {
        let (m, n) = self.dimensions();
        let k = self.k;

        if selector.len() != n {
            return Err(VandermondeMatrixError::LengthError(format!(
                "Selector length ({}) must match n ({})",
                selector.len(),
                n
            )));
        }

        // Separate Unknown and Known indices
        let (unknown_indices, known_indices) = partition_indices(selector);

        if known_indices.len() != k {
            return Err(VandermondeMatrixError::LengthError(format!(
                "Number of known indices ({}) must match k ({})",
                known_indices.len(),
                k
            )));
        }

        // Build submatrix columns: [unknown_indices..., first_known_index]
        let mut submatrix_cols = unknown_indices;
        submatrix_cols.push(known_indices[0]);

        // Create m × m submatrix
        let submatrix = self.create_submatrix(&submatrix_cols)?;

        // Target vector: only the last element is 1, rest are 0
        let mut target = vec![F::zero(); m];
        target[m - 1] = F::one();

        // Solve linear system
        solve_linear_system(&submatrix, &target)
    }

    /// Matrix-vector multiplication: y = Matrix * x
    ///
    /// # Arguments
    /// * `vector` - Vector of length n
    ///
    /// # Returns
    /// Result vector of length m
    pub fn multiply_vector(&self, vector: &[F]) -> Result<Vec<F>, VandermondeMatrixError> {
        let (_, n) = self.dimensions();

        if vector.len() != n {
            return Err(VandermondeMatrixError::LengthError(format!(
                "Vector length ({}) must match matrix n ({})",
                vector.len(),
                n
            )));
        }

        let result = self
            .matrix
            .iter()
            .map(|row| {
                row.iter()
                    .zip(vector.iter())
                    .fold(F::zero(), |acc, (m_val, v_val)| acc + *m_val * *v_val)
            })
            .collect();

        Ok(result)
    }

    /// Vector-matrix multiplication: y = x * Matrix
    ///
    /// # Arguments
    /// * `vector` - Vector of length m
    ///
    /// # Returns
    /// Result vector of length n
    pub fn vector_multiply(&self, vector: &[F]) -> Result<Vec<F>, VandermondeMatrixError> {
        let m = self.matrix.len();
        let n = self.n;

        if vector.len() != m {
            return Err(VandermondeMatrixError::LengthError(format!(
                "Vector length ({}) must match matrix m ({})",
                vector.len(),
                m
            )));
        }

        let mut result = vec![F::zero(); n];

        // result[j] = sum_i(vector[i] * matrix[i][j])
        for (col, res_col) in result.iter_mut().enumerate().take(n) {
            for (row, v) in vector.iter().enumerate().take(m) {
                *res_col += *v * self.matrix[row][col];
            }
        }

        Ok(result)
    }
}

// ==================== Helper Functions ====================

/// Partition indices into unknown and known based on selector
fn partition_indices(selector: &[u8]) -> (Vec<usize>, Vec<usize>) {
    let mut unknown = Vec::new();
    let mut known = Vec::new();

    for (i, &s) in selector.iter().enumerate() {
        if s == 0 {
            unknown.push(i);
        } else {
            known.push(i);
        }
    }

    (unknown, known)
}

/// Solve linear system: Matrix^T * x = target
///
/// Uses Gaussian elimination with partial pivoting
fn solve_linear_system<F: PrimeField>(
    matrix: &VandermondeMatrix<F>,
    target: &[F],
) -> Result<Vec<F>, VandermondeMatrixError> {
    let size = target.len();

    if matrix.matrix.len() != size || matrix.matrix[0].len() != size {
        return Err(VandermondeMatrixError::LengthError(
            "Matrix must be square for linear system solving".to_string(),
        ));
    }

    // Create transpose matrix
    let mut m_t = vec![vec![F::zero(); size]; size];
    for (r, row) in m_t.iter_mut().enumerate().take(size) {
        for (c, elem) in row.iter_mut().enumerate().take(size) {
            *elem = matrix.matrix[c][r];
        }
    }

    let mut rhs = target.to_vec();

    // Forward elimination
    for i in 0..size {
        // Pivoting
        let mut pivot = i;
        while pivot < size && m_t[pivot][i].is_zero() {
            pivot += 1;
        }

        if pivot == size {
            return Err(VandermondeMatrixError::SingularMatrix);
        }

        if pivot != i {
            m_t.swap(i, pivot);
            rhs.swap(i, pivot);
        }

        let inv = m_t[i][i]
            .inverse()
            .ok_or(VandermondeMatrixError::NoInverse)?;

        // Eliminate below
        for j in (i + 1)..size {
            let factor = m_t[j][i] * inv;

            // Copy the row to avoid simultaneous mutation issues
            let row_i_copy: Vec<F> = m_t[i].clone();
            let rhs_i_copy = rhs[i];

            for k in i..size {
                m_t[j][k] -= row_i_copy[k] * factor;
            }
            rhs[j] -= rhs_i_copy * factor;
        }
    }

    // Backward substitution
    let mut solution = vec![F::zero(); size];
    for i in (0..size).rev() {
        let mut sum = F::zero();
        for j in (i + 1)..size {
            sum += m_t[i][j] * solution[j];
        }

        let inv = m_t[i][i]
            .inverse()
            .ok_or(VandermondeMatrixError::NoInverse)?;

        solution[i] = (rhs[i] - sum) * inv;
    }

    Ok(solution)
}

#[cfg(test)]
mod tests {
    use super::*;
    type F = ark_bn254::Fr;

    #[test]
    fn test_new_matrix() {
        let matrix = VandermondeMatrix::<F>::new(6, 3);
        assert_eq!(matrix.dimensions(), (4, 6));
        assert_eq!(matrix.n, 6);
        assert_eq!(matrix.k, 3);
    }

    #[test]
    fn test_first_column_all_ones() {
        let matrix = VandermondeMatrix::<F>::new(5, 2);
        for row in &matrix.matrix {
            assert_eq!(row[0], F::from(1u64));
        }
    }

    #[test]
    fn test_create_submatrix() {
        let matrix = VandermondeMatrix::<F>::new(6, 3);
        let submatrix = matrix.create_submatrix(&[0, 2, 3, 5]).unwrap();

        assert_eq!(submatrix.dimensions(), (4, 4));
    }

    #[test]
    fn test_multiply_vector() {
        let matrix = VandermondeMatrix::<F>::new(4, 2);
        let vector = vec![F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

        let result = matrix.multiply_vector(&vector).unwrap();
        assert_eq!(result.len(), 3); // m = 4 - 2 + 1 = 3
    }

    #[test]
    fn test_vector_multiply() {
        let matrix = VandermondeMatrix::<F>::new(4, 2);
        let vector = vec![F::from(1u64), F::from(2u64), F::from(3u64)];

        let result = matrix.vector_multiply(&vector).unwrap();
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_calculate_vector_a() {
        let matrix = VandermondeMatrix::<F>::new(6, 3);
        let selector = vec![0, 1, 0, 1, 1, 0]; // 3 known

        let result = matrix.calculate_vector_a(&selector);
        assert!(result.is_ok());

        let a = result.unwrap();
        assert_eq!(a.len(), 4); // m = 6 - 3 + 1 = 4
    }

    #[test]
    fn test_partition_indices() {
        let selector = vec![0, 1, 0, 1, 1, 0];
        let (unknown, known) = partition_indices(&selector);

        assert_eq!(unknown, vec![0, 2, 5]);
        assert_eq!(known, vec![1, 3, 4]);
    }

    #[test]
    fn test_solve_linear_system_simple() {
        let matrix = VandermondeMatrix::<F>::new(3, 2);
        let submatrix = matrix.create_submatrix(&[0, 1]).unwrap();

        let target = vec![F::from(3u64), F::from(5u64)];
        let solution = solve_linear_system(&submatrix, &target).unwrap();

        assert_eq!(solution.len(), 2);

        // Verify: Matrix * solution = target
        let verification = submatrix.multiply_vector(&solution).unwrap();
        assert_eq!(verification[0], target[0]);
        assert_eq!(verification[1], target[1]);
    }
}
