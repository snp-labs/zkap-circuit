use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{domain, EvaluationDomain};
use ark_std::{cfg_iter, cfg_iter_mut, vec};

use crate::{FlatMatrix, Vec};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSystemRef, Result as R1CSResult, SynthesisError,
};
use core::ops::{AddAssign, Deref};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[inline]
/// Computes the inner product of `terms` with `assignment`.
pub fn evaluate_constraint<'a, LHS, RHS, R>(terms: &'a [(LHS, usize)], assignment: &'a [RHS]) -> R
where
    LHS: One + Send + Sync + PartialEq,
    RHS: Send + Sync + core::ops::Mul<&'a LHS, Output = RHS> + Copy,
    R: Zero + Send + Sync + AddAssign<RHS> + core::iter::Sum,
{
    // Need to wrap in a closure when using Rayon
    #[cfg(feature = "parallel")]
    let zero = || R::zero();
    #[cfg(not(feature = "parallel"))]
    let zero = R::zero();

    let res = cfg_iter!(terms).fold(zero, |mut sum, (coeff, index)| {
        let val = &assignment[*index];

        if coeff.is_one() {
            sum += *val;
        } else {
            sum += val.mul(coeff);
        }

        sum
    });

    // Need to explicitly call `.sum()` when using Rayon
    #[cfg(feature = "parallel")]
    return res.sum();
    #[cfg(not(feature = "parallel"))]
    return res;
}

#[inline(always)]
fn get_var<F: Copy>(idx: u32, num_inputs: usize, instance: &[F], witness: &[F]) -> F {
    let i = idx as usize;
    if i < num_inputs {
        instance[i]
    } else {
        witness[i - num_inputs]
    }
}

#[inline(always)]
fn eval_row<F: Field + Copy>(
    flat: &FlatMatrix<F>,
    r: usize,
    num_inputs: usize,
    instance: &[F],
    witness: &[F],
) -> F {
    let (s, e) = flat.row_range(r);
    let mut acc = F::zero();
    for k in s..e {
        let v = get_var(flat.col[k], num_inputs, instance, witness);
        acc += flat.val[k] * v;
    }
    acc
}

/// Computes instance and witness reductions from R1CS to
/// Quadratic Arithmetic Programs (QAPs).
pub trait R1CSToQAP {
    /// Computes a QAP instance corresponding to the R1CS instance defined by `cs`.
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError>;

    #[inline]
    /// Computes a QAP witness corresponding to the R1CS witness defined by `cs`.
    fn witness_map<F: PrimeField, D: EvaluationDomain<F>>(
        prover: ConstraintSystemRef<F>,
    ) -> Result<Vec<F>, SynthesisError> {
        let matrices = prover.to_matrices().unwrap();
        let num_inputs = prover.num_instance_variables();
        let num_constraints = prover.num_constraints();

        let cs = prover.borrow().unwrap();
        let prover = cs.deref();

        let full_assignment = [
            prover.instance_assignment.as_slice(),
            prover.witness_assignment.as_slice(),
        ]
        .concat();

        Self::witness_map_from_matrices::<F, D>(
            &matrices,
            num_inputs,
            num_constraints,
            &full_assignment,
        )
    }

    /// Computes a QAP witness corresponding to the R1CS witness defined by `cs`.
    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &ConstraintMatrices<F>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> R1CSResult<Vec<F>>;

    /// Computes the exponents that the generator uses to calculate base
    /// elements which the prover later uses to compute `h(x)t(x)/delta`.
    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        zt: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError>;

    fn witness_map_from_flat_matrices_split<F: PrimeField, D: EvaluationDomain<F>>(
        flat_a: &FlatMatrix<F>,
        flat_b: &FlatMatrix<F>,
        flat_c: &FlatMatrix<F>,
        num_inputs: usize,
        num_constraints: usize,
        instance: &[F],
        witness: &[F],
        domain: D,
    ) -> R1CSResult<Vec<F>>;

    // ✅ 추가: 단일 행렬 처리용 메서드
    fn eval_flat_matrix_on_domain<F: PrimeField, D: EvaluationDomain<F>>(
        flat_matrix: &FlatMatrix<F>,
        num_inputs: usize,
        num_constraints: usize,
        instance: &[F],
        witness: &[F],
        domain: D,
        is_matrix_a: bool, // ✅ 파라미터 추가
    ) -> R1CSResult<Vec<F>>;
}

/// Computes the R1CS-to-QAP reduction defined in [`libsnark`](https://github.com/scipr-lab/libsnark/blob/2af440246fa2c3d0b1b0a425fb6abd8cc8b9c54d/libsnark/reductions/r1cs_to_qap/r1cs_to_qap.tcc).
pub struct LibsnarkReduction;

impl R1CSToQAP for LibsnarkReduction {
    #[inline]
    #[allow(clippy::type_complexity)]
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> R1CSResult<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize)> {
        let matrices = cs.to_matrices().unwrap();
        let domain_size = cs.num_constraints() + cs.num_instance_variables();
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let zt = domain.evaluate_vanishing_polynomial(*t);

        // Evaluate all Lagrange polynomials
        let coefficients_time = start_timer!(|| "Evaluate Lagrange coefficients");
        let u = domain.evaluate_all_lagrange_coefficients(*t);
        end_timer!(coefficients_time);

        let qap_num_variables = (cs.num_instance_variables() - 1) + cs.num_witness_variables();

        let mut a = vec![F::zero(); qap_num_variables + 1];
        let mut b = vec![F::zero(); qap_num_variables + 1];
        let mut c = vec![F::zero(); qap_num_variables + 1];

        {
            let start = 0;
            let end = cs.num_instance_variables();
            let num_constraints = cs.num_constraints();
            a[start..end].copy_from_slice(&u[(start + num_constraints)..(end + num_constraints)]);
        }

        for (i, u_i) in u.iter().enumerate().take(cs.num_constraints()) {
            for &(ref coeff, index) in &matrices.a[i] {
                a[index] += &(*u_i * coeff);
            }
            for &(ref coeff, index) in &matrices.b[i] {
                b[index] += &(*u_i * coeff);
            }
            for &(ref coeff, index) in &matrices.c[i] {
                c[index] += &(*u_i * coeff);
            }
        }

        Ok((a, b, c, zt, qap_num_variables, domain_size))
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &ConstraintMatrices<F>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> R1CSResult<Vec<F>> {
        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        // 1. a, b 벡터 할당 및 계산
        let mut a = vec![F::zero(); domain_size];
        let mut b = vec![F::zero(); domain_size];

        cfg_iter_mut!(a[..num_constraints])
            .zip(cfg_iter_mut!(b[..num_constraints]))
            .zip(cfg_iter!(&matrices.a))
            .zip(cfg_iter!(&matrices.b))
            .for_each(|(((a, b), at_i), bt_i)| {
                *a = evaluate_constraint(&at_i, &full_assignment);
                *b = evaluate_constraint(&bt_i, &full_assignment);
            });

        a[num_constraints..num_constraints + num_inputs]
            .copy_from_slice(&full_assignment[..num_inputs]);

        // In-place FFT로 메모리 절약
        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        let coset_domain = domain.get_coset(F::GENERATOR).unwrap();
        coset_domain.fft_in_place(&mut a);
        coset_domain.fft_in_place(&mut b);

        // 2. a 버퍼를 ab 곱 계산용으로 재사용
        for (a_i, b_i) in a.iter_mut().zip(b.iter()) {
            *a_i *= b_i;
        }
        let mut ab = a; // 변수명만 변경, 실제 메모리 이동 없음

        // 3. b 버퍼를 c 계산용으로 재사용 (추가 할당 방지)
        let mut c = b;
        c.fill(F::zero()); // 기존 b 내용 초기화

        cfg_iter_mut!(c[..num_constraints])
            .enumerate()
            .for_each(|(i, c_val)| {
                *c_val = evaluate_constraint(&matrices.c[i], &full_assignment);
            });

        domain.ifft_in_place(&mut c);
        coset_domain.fft_in_place(&mut c);

        // 4. 최종 결과 계산
        let inv_vanishing_poly = domain
            .evaluate_vanishing_polynomial(F::GENERATOR)
            .inverse()
            .unwrap();
        cfg_iter_mut!(ab).zip(c).for_each(|(ab_i, c_i)| {
            *ab_i -= &c_i;
            *ab_i *= &inv_vanishing_poly;
        });

        coset_domain.ifft_in_place(&mut ab);
        Ok(ab)
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        zt: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        let scalars = cfg_into_iter!(0..max_power)
            .map(|i| zt * &delta_inverse * &t.pow([i as u64]))
            .collect::<Vec<_>>();
        Ok(scalars)
    }

    fn witness_map_from_flat_matrices_split<F: PrimeField, D: EvaluationDomain<F>>(
        flat_a: &FlatMatrix<F>,
        flat_b: &FlatMatrix<F>,
        flat_c: &FlatMatrix<F>,
        num_inputs: usize,
        num_constraints: usize,
        instance: &[F],
        witness: &[F],
        domain: D,
    ) -> R1CSResult<Vec<F>> {
        // Keep semantics identical to `witness_map_from_matrices`, but read rows
        // from flat CSR matrices and use split assignment (instance/witness).
        let domain_size = domain.size();

        // 1) Allocate and compute a, b on the coset domain.
        let mut a = vec![F::zero(); domain_size];
        let mut b = vec![F::zero(); domain_size];

        cfg_iter_mut!(a[..num_constraints])
            .zip(cfg_iter_mut!(b[..num_constraints]))
            .enumerate()
            .for_each(|(i, (a_i, b_i))| {
                *a_i = eval_row(flat_a, i, num_inputs, instance, witness);
                *b_i = eval_row(flat_b, i, num_inputs, instance, witness);
            });

        // a holds the public inputs in the tail, exactly like the original.
        a[num_constraints..num_constraints + num_inputs].copy_from_slice(&instance[..num_inputs]);

        // In-place FFT to reduce allocations.
        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        let coset_domain = domain.get_coset(F::GENERATOR).unwrap();
        coset_domain.fft_in_place(&mut a);
        coset_domain.fft_in_place(&mut b);

        // 2) Reuse `a` as `ab` (point-wise product).
        for (a_i, b_i) in a.iter_mut().zip(b.iter()) {
            *a_i *= b_i;
        }
        let mut ab = a;

        // 3) Reuse `b` buffer to compute c.
        let mut c = b;
        c.fill(F::zero());

        cfg_iter_mut!(c[..num_constraints])
            .enumerate()
            .for_each(|(i, c_val)| {
                *c_val = eval_row(flat_c, i, num_inputs, instance, witness);
            });

        domain.ifft_in_place(&mut c);
        coset_domain.fft_in_place(&mut c);

        // 4) Finalize: (ab - c) / Z on the coset, then IFFT.
        // NOTE: This matches the original implementation's choice of evaluation point.
        let inv_vanishing_poly = domain
            .evaluate_vanishing_polynomial(F::GENERATOR)
            .inverse()
            .unwrap();

        cfg_iter_mut!(ab).zip(c).for_each(|(ab_i, c_i)| {
            *ab_i -= &c_i;
            *ab_i *= &inv_vanishing_poly;
        });

        coset_domain.ifft_in_place(&mut ab);
        Ok(ab)
    }

    // ✅ 추가된 핵심 메서드: 단일 FlatMatrix를 도메인 위에서 평가 (FFT 포함)
fn eval_flat_matrix_on_domain<F: PrimeField, D: EvaluationDomain<F>>(
        flat_matrix: &FlatMatrix<F>,
        num_inputs: usize,
        num_constraints: usize,
        instance: &[F],
        witness: &[F],
        domain: D,
        is_matrix_a: bool, // ✅ 파라미터 추가
    ) -> R1CSResult<Vec<F>> {
        let domain_size = domain.size();
        let mut evals = vec![F::zero(); domain_size];

        // 1. Evaluate row (Lagrange basis)
        cfg_iter_mut!(evals[..num_constraints])
            .enumerate()
            .for_each(|(i, val)| {
                *val = eval_row(flat_matrix, i, num_inputs, instance, witness);
            });
        
        // ✅ Matrix A인 경우 Public Input(Instance) 값을 뒤에 복사
        if is_matrix_a {
            evals[num_constraints..num_constraints + num_inputs]
                .copy_from_slice(&instance[..num_inputs]);
        }

        // 2. IFFT -> FFT (Coset)
        domain.ifft_in_place(&mut evals);
        let coset_domain = domain.get_coset(F::GENERATOR).unwrap();
        coset_domain.fft_in_place(&mut evals);

        Ok(evals)
    }
}
