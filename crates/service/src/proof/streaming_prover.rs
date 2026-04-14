//! Custom Groth16 streaming prover using only standard ark-* 0.5.0 public APIs.
//!
//! Solves Android OOM by separating proof generation into two phases:
//!   Phase A (`witness_and_h`):     compute h polynomial WITHOUT the ProvingKey (~666MB peak)
//!   Phase B (`compute_proof_msm`): load PK and compute MSMs                    (~410MB peak)
//!
//! The standard `Groth16::prove()` peaks at ~1000MB+ (PK + CS + matrices
//! simultaneously). By separating the phases, we keep the maximum below ~666MB.

use std::mem;

use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{FftField, Field, One, PrimeField, Zero};
use ark_groth16::{Proof, ProvingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal,
    Result as R1CSResult, SynthesisError, SynthesisMode,
};

use circuit::constants::F;

// mi_collect is compiled into libzkap_uniffi_bindings.so via the mimalloc
// dependency in zkap-uniffi-bindings.  The linker resolves it at final link
// time within the same .so, so no external symbol lookup is needed.
#[cfg(any(target_os = "android", target_os = "ios"))]
unsafe extern "C" {
    fn mi_collect(force: bool);
}

/// Force freed mimalloc pages back to OS between proof phases.
///
/// `mi_collect(true)` aggressively returns all idle pages to the OS.
/// mimalloc is the global allocator in `zkap-uniffi-bindings`, so this symbol
/// is present in the final `.so` and does not require an external libc lookup.
#[inline(always)]
pub fn gc() {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    // SAFETY: mi_collect is a mimalloc internal function linked into this .so
    unsafe {
        mi_collect(true);
    }
}

/// Phase A: Synthesize the circuit and compute the h polynomial WITHOUT loading
/// the ProvingKey.
///
/// ## Two-pass memory strategy
///
/// **Pass 0** (`Prove { construct_matrices: false }`):
/// - CS holds only witness assignments (~31 MB, no LC data)
/// - `mem::take` extracts instance/witness → `drop(cs)` → `gc()`
///
/// **Pass 1** (`Setup`):
/// - CS builds constraint LC data (~339 MB)
/// - `to_matrices()` converts to sparse format (+~327 MB) → peak ~666 MB
/// - `drop(cs_m)` frees raw LC data (~339 MB) → `gc()`
/// - A, B, C matrices processed sequentially with per-matrix `drop` + `gc()`
/// - h = coset\_IFFT((eval\_a × eval\_b − eval\_c) / Z(generator))
///
/// ## Returns
/// `(h, instance_assignment, witness_assignment)`
pub fn witness_and_h<C>(
    mut circuit_factory: impl FnMut() -> C,
) -> R1CSResult<(Vec<F>, Vec<F>, Vec<F>)>
where
    C: ConstraintSynthesizer<F>,
{
    // ── Pass 0: witness-only synthesis (no LC / matrix data) ─────────────────
    let cs = ConstraintSystem::<F>::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
    });
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit_factory().generate_constraints(cs.clone())?;
    cs.finalize();

    let num_constraints = cs.num_constraints();
    let num_inputs = cs.num_instance_variables();

    let (instance, witness) = {
        let mut inner = cs.borrow_mut().unwrap();
        let inst = mem::take(&mut inner.instance_assignment);
        let wit = mem::take(&mut inner.witness_assignment);
        (inst, wit)
    };
    drop(cs);
    gc();

    let full_assignment: Vec<F> = [instance.as_slice(), witness.as_slice()].concat();

    let domain = GeneralEvaluationDomain::<F>::new(num_constraints + num_inputs)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

    // ── Pass 1: Setup synthesis → constraint matrices ─────────────────────────
    let cs_m = ConstraintSystem::<F>::new_ref();
    cs_m.set_mode(SynthesisMode::Setup);
    cs_m.set_optimization_goal(OptimizationGoal::Constraints);
    circuit_factory().generate_constraints(cs_m.clone())?;
    cs_m.finalize();

    // Peak: raw LC data (~339 MB) + sparse matrices from to_matrices() (~327 MB) ≈ 666 MB
    let matrices = cs_m
        .to_matrices()
        .ok_or(SynthesisError::AssignmentMissing)?;
    drop(cs_m); // Free raw LC data (~339 MB)
    gc();

    // Destructure to allow sequential per-matrix processing and dropping.
    // The `..` fields (metadata integers) are dropped here.
    let ConstraintMatrices {
        a: mat_a,
        b: mat_b,
        c: mat_c,
        ..
    } = matrices;

    // ── A → eval_a (coset evaluation domain) ─────────────────────────────────
    let eval_a = eval_matrix_on_coset(
        mat_a,
        num_constraints,
        num_inputs,
        &full_assignment,
        true,
        &domain,
    );

    // ── B → eval_b (coset evaluation domain) ─────────────────────────────────
    let eval_b = eval_matrix_on_coset(
        mat_b,
        num_constraints,
        num_inputs,
        &full_assignment,
        false,
        &domain,
    );

    // A × B (pointwise, still in coset evaluation domain)
    let mut ab: Vec<F> = eval_a
        .into_iter()
        .zip(eval_b.iter())
        .map(|(a, b)| a * b)
        .collect();
    drop(eval_b);

    // ── C → eval_c (coset evaluation domain) ─────────────────────────────────
    let eval_c = eval_matrix_on_coset(
        mat_c,
        num_constraints,
        num_inputs,
        &full_assignment,
        false,
        &domain,
    );

    // h = (A×B − C) / Z(generator), then coset IFFT → polynomial coefficients
    let coset = domain.get_coset(F::GENERATOR).unwrap();
    let z_inv = domain
        .evaluate_vanishing_polynomial(F::GENERATOR)
        .inverse()
        .unwrap();
    for (ab_i, c_i) in ab.iter_mut().zip(eval_c.iter()) {
        *ab_i = (*ab_i - c_i) * z_inv;
    }
    drop(eval_c);

    coset.ifft_in_place(&mut ab);
    // `ab` is now the h polynomial coefficients (length = domain_size).
    // `pk.h_query` has length domain_size − 1; MSM uses min(bases, scalars) automatically.

    Ok((ab, instance, witness))
}

/// Evaluate a constraint matrix on the coset evaluation domain.
///
/// Consumes `matrix` and **explicitly drops it before FFT** to reclaim ~109 MB,
/// then calls `gc()` to return freed pages to the OS.
fn eval_matrix_on_coset(
    matrix: Vec<Vec<(F, usize)>>,
    num_constraints: usize,
    num_inputs: usize,
    full_assignment: &[F],
    is_matrix_a: bool,
    domain: &GeneralEvaluationDomain<F>,
) -> Vec<F> {
    let domain_size = domain.size();
    let mut eval = vec![F::zero(); domain_size];

    for (i, row) in matrix.iter().enumerate().take(num_constraints) {
        // Mirrors evaluate_constraint from ark_groth16::r1cs_to_qap:
        // skip the field multiplication when the coefficient is 1.
        eval[i] = row
            .iter()
            .map(|(coeff, idx)| {
                if coeff.is_one() {
                    full_assignment[*idx]
                } else {
                    full_assignment[*idx] * coeff
                }
            })
            .sum();
    }

    // Matrix A: identity block — eval[num_constraints..][..num_inputs] = instance values
    if is_matrix_a {
        let start = num_constraints;
        let end = start + num_inputs;
        eval[start..end].clone_from_slice(&full_assignment[..num_inputs]);
    }

    // Drop matrix before FFT to reclaim ~109 MB
    drop(matrix);
    gc();

    domain.ifft_in_place(&mut eval);
    let coset = domain.get_coset(F::GENERATOR).unwrap();
    coset.fft_in_place(&mut eval);
    eval
}

/// Phase B: Compute the Groth16 proof elements via MSM using the ProvingKey.
///
/// Reimplements `create_proof_with_assignment` (private in ark-groth16 0.5.0)
/// using `ProvingKey` public fields.  Follows the standard implementation exactly:
///
/// ```text
/// g_a  = r·δ₁ + a_query[0] + MSM(a_query[1..],    [instance[1..], witness]) + α₁
/// g1_b = s·δ₁ + b_g1[0]    + MSM(b_g1_query[1..], [instance[1..], witness]) + β₁
/// g2_b = s·δ₂ + b_g2[0]    + MSM(b_g2_query[1..], [instance[1..], witness]) + β₂
/// g_c  = s·g_a + r·g1_b − rs·δ₁ + l_aux_acc + h_acc
/// ```
pub fn compute_proof_msm(
    pk: &ProvingKey<Bn254>,
    r: F,
    s: F,
    h: &[F],
    instance_assignment: &[F],
    aux_assignment: &[F],
) -> R1CSResult<Proof<Bn254>> {
    // instance_assignment[0] = 1 (constant); handled by query[0] added unscaled.
    let input_assignment = &instance_assignment[1..];

    let h_bigint: Vec<_> = h.iter().map(|x| x.into_bigint()).collect();
    let aux_bigint: Vec<_> = aux_assignment.iter().map(|x| x.into_bigint()).collect();
    let input_bigint: Vec<_> = input_assignment.iter().map(|x| x.into_bigint()).collect();

    // h_acc = Σ h[i] * h_query[i]  (MSM takes min(h_query.len, h.len) = domain_size−1)
    let h_acc: G1Projective = G1Projective::msm_bigint(&pk.h_query, &h_bigint);
    drop(h_bigint);

    // l_aux_acc = Σ l_query[i] * witness[i]
    let l_aux_acc: G1Projective = G1Projective::msm_bigint(&pk.l_query, &aux_bigint);

    let r_s_delta_g1: G1Projective = (pk.delta_g1 * (r * s)).into();

    // assignment = [instance[1..], witness] as BigInt (no index 0)
    let assignment: Vec<_> = input_bigint
        .iter()
        .chain(aux_bigint.iter())
        .cloned()
        .collect();
    drop(input_bigint);
    drop(aux_bigint);

    let r_g1: G1Projective = (pk.delta_g1 * r).into();
    let g_a: G1Projective = calculate_coeff_g1(r_g1, &pk.a_query, pk.vk.alpha_g1, &assignment);
    let s_g_a: G1Projective = g_a * s;

    let g1_b: G1Projective = if !r.is_zero() {
        let s_g1: G1Projective = (pk.delta_g1 * s).into();
        calculate_coeff_g1(s_g1, &pk.b_g1_query, pk.beta_g1, &assignment)
    } else {
        G1Projective::zero()
    };

    let s_g2: G2Projective = (pk.vk.delta_g2 * s).into();
    let g2_b: G2Projective = calculate_coeff_g2(s_g2, &pk.b_g2_query, pk.vk.beta_g2, &assignment);
    drop(assignment);

    let r_g1_b: G1Projective = g1_b * r;

    let mut g_c = s_g_a;
    g_c += r_g1_b;
    g_c -= r_s_delta_g1;
    g_c += l_aux_acc;
    g_c += h_acc;

    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}

/// Mirrors `calculate_coeff` (private in ark-groth16) for G1 affine queries.
///
/// `query[0]` is added unscaled — it corresponds to the "1" variable (instance[0] = 1).
/// `assignment` = [instance[1..], witness] already converted to `BigInt`.
fn calculate_coeff_g1(
    initial: G1Projective,
    query: &[G1Affine],
    vk_param: G1Affine,
    assignment: &[<F as PrimeField>::BigInt],
) -> G1Projective {
    let acc = G1Projective::msm_bigint(&query[1..], assignment);
    let mut res = initial;
    res += query[0];
    res += acc;
    res += vk_param;
    res
}

/// Mirrors `calculate_coeff` for G2 affine queries.
fn calculate_coeff_g2(
    initial: G2Projective,
    query: &[G2Affine],
    vk_param: G2Affine,
    assignment: &[<F as PrimeField>::BigInt],
) -> G2Projective {
    let acc = G2Projective::msm_bigint(&query[1..], assignment);
    let mut res = initial;
    res += query[0];
    res += acc;
    res += vk_param;
    res
}
