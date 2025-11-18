use ark_ff::Field;

use crate::matrix::error::LinearSystemError;

#[derive(Clone, Debug)]
pub struct Matrix<F: Field> {
    pub n: usize,
    pub k: usize,
    pub t_matrix: Vec<Vec<F>>,
}

impl<F: Field> Matrix<F> {
    pub fn new(n: usize, k: usize) -> Result<Self, LinearSystemError> {
        if n <= 0 || k <= 0 || k > n {
            return Err(LinearSystemError::InvalidLength(format!(
                "n: {}, k: {}. n must be greater than 0, k must be greater than 0 and less than or equal to n",
                n, k
            )));
        }

        let t_matrix = generate_matrix::<F>(n, k);
        Ok(Matrix { n, k, t_matrix })
    }

    pub fn solution(&self, used_indices: &[usize]) -> Result<(Vec<F>, Vec<F>), LinearSystemError> {
        if used_indices.len() != self.n {
            return Err(LinearSystemError::InvalidLength(format!(
                "used_indices의 길이({})는 반드시 n({})과 같아야 합니다.",
                used_indices.len(),
                self.n
            )));
        }

        let num_used = used_indices.iter().filter(|&&val| val == 1).count();
        if num_used > self.k {
            return Err(LinearSystemError::InvalidLength(format!(
                "사용된 인덱스의 개수({})가 k({})를 초과할 수 없습니다.",
                num_used, self.k
            )));
        }

        let unused_indices: Vec<usize> = used_indices
            .iter()
            .enumerate()
            .filter_map(|(index, &is_used)| if is_used == 0 { Some(index) } else { None })
            .collect();

        let mut t_prime = vec![vec![F::zero(); unused_indices.len()]; self.t_matrix.len()];
        for (c_prime, &c_t) in unused_indices.iter().enumerate() {
            for r in 0..(self.t_matrix.len()) {
                t_prime[r][c_prime] = self.t_matrix[r][c_t];
            }
        }

        let row = t_prime.len();
        if row < 2 {
            return Err(LinearSystemError::InvalidLength(format!(
                "T' must have at least 2 rows, found: {}",
                row
            )));
        }

        let num_eq = row - 1;
        if t_prime.iter().any(|r| r.len() != num_eq) {
            return Err(LinearSystemError::InvalidLength(
                "T' must have the same number of columns in each row".to_string(),
            ));
        }

        let mut a = vec![vec![F::zero(); num_eq]; num_eq];
        let mut b = vec![F::zero(); num_eq];

        // x = [u₂, u₃, ..., uₘ]ᵀ
        // A는 T'의 첫 행을 제외하고 전치한 행렬
        // b는 T'의 첫 행에 -1을 곱한 벡터
        for i in 0..num_eq {
            // 방정식 인덱스 (T'의 열 인덱스)
            b[i] = -t_prime[0][i];
            for j in 0..num_eq {
                // 미지수 인덱스 (u₂, u₃, ...)
                // A_ij는 u_{j+2}의 i번째 방정식에서의 계수
                a[i][j] = t_prime[j + 1][i];
            }
        }

        // Solve the linear system Ax = b
        let solution = solve_square_linear_system::<F>(&a, &b)?;

        // Add u₁ = 1 to the solution
        let mut u = vec![F::one()];
        u.extend(solution);

        // Verify the solution
        verify_solution(&u, &t_prime)?;

        // u * t_mattrix
        let mut result = vec![F::zero(); self.n];
        for j in 0..self.n {
            for i in 0..u.len() {
                result[j] += u[i] * self.t_matrix[i][j];
            }
        }

        Ok((u, result))
    }
}

pub fn solve_square_linear_system<F: Field>(
    matrix: &[Vec<F>],
    vector: &[F],
) -> Result<Vec<F>, LinearSystemError> {
    let row = matrix.len();
    if row == 0 || vector.len() != row {
        return Err(LinearSystemError::InvalidLength(
            "Matrix and vector dimensions do not match".to_string(),
        ));
    }

    let mut a = matrix.to_vec();
    let mut b = vector.to_vec();

    for i in 0..row {
        let pivot_row = (i..row)
            .find(|&r| a[r][i] != F::zero())
            .ok_or(LinearSystemError::SingularMatrix(i))?;

        a.swap(i, pivot_row);
        b.swap(i, pivot_row);

        let pivot_inv = a[i][i]
            .inverse()
            .ok_or(LinearSystemError::SingularMatrix(i))?;

        for j in i..row {
            a[i][j] = a[i][j] * pivot_inv;
        }
        b[i] = b[i] * pivot_inv;

        for k in 0..row {
            if k != i {
                let factor = a[k][i];
                for j in i..row {
                    a[k][j] = a[k][j] - factor * a[i][j];
                }
                b[k] = b[k] - factor * b[i];
            }
        }
    }

    Ok(b)
}

pub fn generate_matrix<F: Field>(n: usize, k: usize) -> Vec<Vec<F>> {
    assert!(n > 0 && k > 0, "n and k must be greater than 0");
    assert!(k <= n, "k cannot be greater than n");

    let num_rows = n - k + 1;
    let num_cols = n;

    let t_matrix: Vec<Vec<F>> = (0..num_rows)
        .map(|i| {
            let mut row = vec![F::zero(); num_cols];

            for j in 0..num_cols {
                if j < k {
                    let base = F::from((i + 1) as u64);
                    row[j] = base.pow(&[j as u64]);
                } else {
                    let selector_col_index = j - k;
                    if i > 0 && (i - 1) == selector_col_index {
                        row[j] = F::one();
                    }
                }
            }
            row
        })
        .collect();

    t_matrix
}

fn verify_solution<F: Field>(solution: &[F], t_matrix: &[Vec<F>]) -> Result<(), LinearSystemError> {
    let m = solution.len();
    let num_eq = t_matrix.len() - 1;

    if m != num_eq + 1 {
        return Err(LinearSystemError::InvalidLength(format!(
            "Solution length {} does not match expected length {}",
            m,
            num_eq + 1
        )));
    }

    let mut expected = vec![F::zero(); num_eq];
    for j in 0..num_eq {
        // T'의 열
        for i in 0..m {
            // T'의 행 (u의 원소)
            expected[j] += solution[i] * t_matrix[i][j];
        }
    }

    if expected.iter().all(|x| x.is_zero()) {
        Ok(())
    } else {
        Err(LinearSystemError::SolutionVerifyFailed)
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field;

    use crate::matrix::mod_v0::Matrix;

    type F = ark_ed_on_bn254::Fq;

    fn test_generate_t_matrix<F: Field>(n: usize, k: usize, expected: &[Vec<F>]) {
        let matrix = Matrix::<F>::new(n, k).unwrap();
        assert_eq!(matrix.n, n);
        assert_eq!(matrix.k, k);
        assert_eq!(matrix.t_matrix.len(), n - k + 1);
        assert_eq!(matrix.t_matrix[0].len(), n);
        assert_eq!(matrix.t_matrix, expected);
    }

    fn test_generate_u_vector<F: Field>(n: usize, k: usize, used_indices: &[usize]) {
        let matrix = Matrix::<F>::new(n, k).unwrap();
        let solution = matrix.solution(used_indices).unwrap();
        assert_eq!(solution.0.len(), n - k + 1);
        assert_eq!(solution.1.len(), n);
    }

    #[test]
    fn test_generate_t_matrix_trivial1() {
        let n = 6;
        let k = 3;
        let expected = matrix_to_field::<F>(&vec![
            vec![1, 1, 1, 0, 0, 0],
            vec![1, 2, 4, 1, 0, 0],
            vec![1, 3, 9, 0, 1, 0],
            vec![1, 4, 16, 0, 0, 1],
        ]);
        test_generate_t_matrix(n, k, &expected);
    }

    #[test]
    fn test_generate_t_matrix_trivial2() {
        let n = 7;
        let k = 2;
        let expected = matrix_to_field::<F>(&vec![
            vec![1, 1, 0, 0, 0, 0, 0],
            vec![1, 2, 1, 0, 0, 0, 0],
            vec![1, 3, 0, 1, 0, 0, 0],
            vec![1, 4, 0, 0, 1, 0, 0],
            vec![1, 5, 0, 0, 0, 1, 0],
            vec![1, 6, 0, 0, 0, 0, 1],
        ]);
        test_generate_t_matrix(n, k, &expected);
    }

    #[test]
    fn test_generate_u_vector_trivial1() {
        let n = 6;
        let k = 3;
        let used_indices = vec![1, 1, 1, 0, 0, 0];
        test_generate_u_vector::<F>(n, k, &used_indices);
    }

    #[test]
    fn test_generate_u_vector_trivial2() {
        let n = 7;
        let k = 2;
        let used_indices = vec![1, 1, 0, 0, 0, 0, 0];
        test_generate_u_vector::<F>(n, k, &used_indices);
    }

    fn matrix_to_field<F: Field>(matrix: &[Vec<u64>]) -> Vec<Vec<F>> {
        matrix
            .iter()
            .map(|row| row.iter().map(|&x| F::from(x)).collect())
            .collect()
    }
}
