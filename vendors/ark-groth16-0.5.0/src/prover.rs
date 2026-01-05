use std::mem;

use crate::FlatMatrix;
use crate::{r1cs_to_qap::R1CSToQAP, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{FftField, Field, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
    Result as R1CSResult, SynthesisError, SynthesisMode, Variable,
};
use ark_std::rand::Rng;
use ark_std::{
    ops::{AddAssign, Mul},
    vec::Vec,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;
#[cfg(feature = "memory-logging")]
use sysinfo::System;

type D<F> = GeneralEvaluationDomain<F>;
const MSM_CHUNK_SIZE: usize = 4_096;
#[cfg(feature = "memory-logging")]
macro_rules! log_step {
    ($msg:expr) => {
        println!("[rss_kb] {:<40} : {} MB", $msg, rss_kb() / (1024 * 1024));
    };
}

#[cfg(not(feature = "memory-logging"))]
macro_rules! log_step {
    ($msg:expr) => {};
}

// ✅ 행렬 선택을 위한 열거형
enum MatrixTarget {
    A,
    B,
    C,
}

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// ✅ 1. Two-Pass 방식의 진입점 (테스트에서 이 함수를 호출해야 함)
    pub fn create_random_proof_two_pass<C, F>(
        circuit_factory: F, // 변경: Circuit -> Factory Closure
        pk: &ProvingKey<E>,
        rng: &mut impl ark_std::rand::Rng,
    ) -> ark_relations::r1cs::Result<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        F: FnMut() -> C, // 변경: 팩토리 함수 타입 정의
    {
        log_step!("Function Start: create_random_proof_two_pass");
        let r = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);

        // factory를 그대로 하위 함수로 전달
        let res = Self::create_proof_two_pass(circuit_factory, pk, r, s);

        log_step!("Function End: create_random_proof_two_pass");
        res
    }

    /// ✅ 2. Two-Pass 핵심 로직 (메모리 분리 수행)
    // =========================================================================
    // [Core Logic] Two-Pass 핵심 로직
    // =========================================================================
    pub fn create_proof_two_pass<C, F>(
        mut circuit_factory: F, // 변경: Circuit -> Factory Closure
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
    ) -> ark_relations::r1cs::Result<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        F: FnMut() -> C, // 변경: 팩토리 함수 타입 정의
    {
        // =========================================================================
        // [Phase 1] Witness Generation (메모리 가장 적게 먹는 작업 먼저 수행)
        // =========================================================================
        log_step!("Phase 1: Witness Gen Start");

        let cs_witness = ConstraintSystem::new_ref();
        cs_witness.set_mode(SynthesisMode::Prove {
            construct_matrices: false, // 행렬 생성 안 함 (메모리 절약)
        });
        cs_witness.set_optimization_goal(OptimizationGoal::Constraints);

        let circuit_w = circuit_factory();
        circuit_w.generate_constraints(cs_witness.clone())?;
        cs_witness.finalize();
        log_step!("Phase 1: Finalized");

        // Witness와 Instance만 추출하고 CS는 즉시 해제
        let (instance_assignment, witness_assignment) = {
            let mut cs_inner = cs_witness.borrow_mut().unwrap();
            let inst = mem::take(&mut cs_inner.instance_assignment);
            let wit = mem::take(&mut cs_inner.witness_assignment);
            (inst, wit)
        };
        drop(cs_witness);
        log_step!("Phase 1: CS Dropped (Witness Extracted)");

        let num_inputs = instance_assignment.len();

        // =========================================================================
        // [Phase 2] Matrix Generation & Sequential Processing
        // =========================================================================
        log_step!("Phase 2: Matrix Setup Start");

        let cs_matrix = ConstraintSystem::new_ref();
        cs_matrix.set_mode(SynthesisMode::Setup); // Setup 모드 (값 할당 없이 행렬 구조만 생성)
        cs_matrix.set_optimization_goal(OptimizationGoal::Constraints);

        let circuit_m = circuit_factory();
        circuit_m.generate_constraints(cs_matrix.clone())?;
        cs_matrix.finalize();
        log_step!("Phase 2: CS Finalized");

        // ⚠️ 여기서 to_matrices()를 호출하지 않음으로써 메모리 복제를 방지합니다.
        // CS 내부의 constraints 벡터에 직접 접근합니다.
        let num_constraints = cs_matrix.num_constraints();

        let domain = D::<E::ScalarField>::new(num_constraints + num_inputs)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        // [Phase 3] Sequential Evaluation (A -> B -> C 순서로 처리하여 중첩 방지)
        // -------------------------------------------------------------------------

        // --- Step A: Process Matrix A ---
        log_step!("Phase 3: Processing Matrix A");
        let mut eval_a = {
            // CS에서 A 행렬 부분만 추출하여 FlatMatrix 생성
            let flat_a =
                Self::extract_flat_matrix(&cs_matrix, MatrixTarget::A, num_inputs, num_constraints);

            QAP::eval_flat_matrix_on_domain(
                &flat_a,
                num_inputs,
                num_constraints,
                &instance_assignment,
                &witness_assignment,
                domain,
                true,
            )?
        };
        log_step!("Phase 3: Matrix A Done & Dropped");

        // --- Step B: Process Matrix B ---
        log_step!("Phase 3: Processing Matrix B");
        let eval_b = {
            let flat_b =
                Self::extract_flat_matrix(&cs_matrix, MatrixTarget::B, num_inputs, num_constraints);

            QAP::eval_flat_matrix_on_domain(
                &flat_b,
                num_inputs,
                num_constraints,
                &instance_assignment,
                &witness_assignment,
                domain,
                false,
            )?
        };

        // A = A * B (In-place)
        log_step!("Phase 3: Compute A * B");
        for (a, b) in eval_a.iter_mut().zip(eval_b.iter()) {
            *a *= b;
        }
        drop(eval_b); // B 결과 해제
        log_step!("Phase 3: B Eval Dropped");

        // --- Step C: Process Matrix C ---
        log_step!("Phase 3: Processing Matrix C");
        let eval_c = {
            let flat_c =
                Self::extract_flat_matrix(&cs_matrix, MatrixTarget::C, num_inputs, num_constraints);

            QAP::eval_flat_matrix_on_domain(
                &flat_c,
                num_inputs,
                num_constraints,
                &instance_assignment,
                &witness_assignment,
                domain,
                false,
            )?
        };
        log_step!("Phase 3: Matrix C Done & Dropped");

        // A = A - C (In-place)
        log_step!("Phase 3: Compute (AB - C)");

        // Z(x) 역원 계산 (여기서 E::ScalarField::GENERATOR 사용)
        let inv_vanishing_poly = domain
            .evaluate_vanishing_polynomial(E::ScalarField::GENERATOR)
            .inverse()
            .unwrap();

        // (AB - C) / Z
        for (ab, c) in eval_a.iter_mut().zip(eval_c.iter()) {
            *ab -= c;
            *ab *= inv_vanishing_poly;
        }
        drop(eval_c); // C 결과 해제

        // IFFT on Coset
        let coset_domain = domain.get_coset(E::ScalarField::GENERATOR).unwrap();
        coset_domain.ifft_in_place(&mut eval_a);

        let h = eval_a; // 최종 H 다항식
        log_step!("Phase 3: H Calculated");

        // =========================================================================
        // [Phase 4] Proof Generation (MSM)
        // =========================================================================

        let input_assignment = &instance_assignment[1..];
        let aux_assignment = &witness_assignment;

        let proof =
            Self::create_proof_with_assignment(pk, r, s, &h, input_assignment, aux_assignment)?;

        log_step!("Proof Generated");
        Ok(proof)
    }

    fn extract_flat_matrix(
        cs: &ConstraintSystemRef<E::ScalarField>,
        target: MatrixTarget,
        num_inputs: usize,
        num_constraints: usize,
    ) -> FlatMatrix<E::ScalarField> {
        let cs_borrow = cs.borrow().unwrap();

        // 1. 목표 행렬에 해당하는 인덱스 벡터 선택
        // (포크에서 해당 필드들을 pub으로 열어주셔야 접근 가능합니다)
        let indices = match target {
            MatrixTarget::A => &cs_borrow.a_constraints,
            MatrixTarget::B => &cs_borrow.b_constraints,
            MatrixTarget::C => &cs_borrow.c_constraints,
        };

        let mut ptr = Vec::with_capacity(num_constraints + 1);
        let mut col = Vec::new();
        let mut val = Vec::new();

        ptr.push(0);

        // 2. 인덱스를 순회하며 lc_map에서 실제 선형 결합(LC) 데이터를 조회
        for &lc_index in indices {
            if let Some(lc) = cs_borrow.lc_map.get(&lc_index) {
                // (coeff, var) 순서로 이터레이션 (앞선 타입 에러 해결)
                for (coeff, var) in lc.iter() {
                    let idx = match var {
                        Variable::One => 0,
                        Variable::Instance(i) => *i,
                        Variable::Witness(i) => num_inputs + *i,

                        // ✅ 추가됨: Zero 변수는 값이 0이므로 행렬에 추가할 필요 없음 (Sparse 최적화)
                        Variable::Zero => continue,

                        // ✅ 추가됨: SymbolicLc는 Matrix 추출 단계에서 예외 처리
                        // 만약 이 변형이 실제로 사용된다면, 해당 로직에 맞춰 인덱스를 매핑해야 합니다.
                        Variable::SymbolicLc(_) => {
                            panic!("SymbolicLc encountered during matrix extraction! Ensure constraints are flattened.");
                        }
                    };

                    col.push(idx as u32);
                    val.push(*coeff);
                }
            }
            ptr.push(col.len());
        }

        FlatMatrix { ptr, col, val }
    }

    /// ✅ flat matrices + split assignment 버전 (concat 없음)
    #[inline]
    pub fn create_proof_with_reduction_and_flat_matrices_split(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        flat_a: &FlatMatrix<E::ScalarField>,
        flat_b: &FlatMatrix<E::ScalarField>,
        flat_c: &FlatMatrix<E::ScalarField>,
        num_inputs: usize,
        num_constraints: usize,
        instance_assignment: &[E::ScalarField],
        witness_assignment: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        let prover_time = start_timer!(|| "Groth16::Prover");
        log_step!("Groth16::Prover Start");

        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        log_step!("R1CS→QAP witness map Start");

        // ✅ 기존 witness_map_from_matrices와 동일 흐름을 flat + split로 수행
        let domain = D::<E::ScalarField>::new(num_constraints + num_inputs)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let h = QAP::witness_map_from_flat_matrices_split::<E::ScalarField, D<E::ScalarField>>(
            flat_a,
            flat_b,
            flat_c,
            num_inputs,
            num_constraints,
            instance_assignment,
            witness_assignment,
            domain,
        )?;
        log_step!("Witness Map(H) Calculated");
        end_timer!(witness_map_time);

        // ✅ concat 기반 full_assignment slicing 제거
        let input_assignment = &instance_assignment[1..num_inputs]; // [0] = 1
        let aux_assignment = witness_assignment;

        let proof =
            Self::create_proof_with_assignment(pk, r, s, &h, input_assignment, aux_assignment)?;

        drop(h);
        log_step!("H Dropped");

        log_step!("Proof Generated");
        end_timer!(prover_time);

        Ok(proof)
    }

    #[inline]
    fn create_proof_with_assignment(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        h: &[E::ScalarField],
        input_assignment: &[E::ScalarField],
        aux_assignment: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        let c_acc_time = start_timer!(|| "Compute C");
        log_step!("MSM: Compute C Start");

        // 1. H Accumulation (Chunked)
        log_step!("MSM: H_Acc Start");
        let h_acc = Self::msm_bigint_chunked::<E::G1Affine>(&pk.h_query, h, MSM_CHUNK_SIZE);
        log_step!("MSM: H_Acc End");

        // 2. L_Aux Accumulation (Chunked - BigInt 변환 제거됨)
        log_step!("MSM: L_Aux_Acc Start");
        let l_aux_acc =
            Self::msm_bigint_chunked::<E::G1Affine>(&pk.l_query, aux_assignment, MSM_CHUNK_SIZE);
        log_step!("MSM: L_Aux_Acc End");

        let r_s_delta_g1 = pk.delta_g1 * (r * s);
        end_timer!(c_acc_time);

        // Compute A (Chunked)
        let a_acc_time = start_timer!(|| "Compute A");
        log_step!("MSM: Compute A Start");
        let r_g1 = pk.delta_g1.mul(r);

        let g_a = Self::calculate_coeff_split(
            r_g1,
            &pk.a_query,
            pk.vk.alpha_g1,
            input_assignment,
            aux_assignment,
        );
        log_step!("MSM: Compute A End");

        let s_g_a = g_a * &s;
        end_timer!(a_acc_time);

        // Compute B in G1 (Chunked)
        let g1_b = if !r.is_zero() {
            let b_g1_acc_time = start_timer!(|| "Compute B in G1");
            log_step!("MSM: Compute B(G1) Start");
            let s_g1 = pk.delta_g1.mul(s);

            let g1_b = Self::calculate_coeff_split(
                s_g1,
                &pk.b_g1_query,
                pk.beta_g1,
                input_assignment,
                aux_assignment,
            );
            log_step!("MSM: Compute B(G1) End");
            end_timer!(b_g1_acc_time);
            g1_b
        } else {
            E::G1::zero()
        };

        // Compute B in G2 (Chunked)
        let b_g2_acc_time = start_timer!(|| "Compute B in G2");
        log_step!("MSM: Compute B(G2) Start");
        let s_g2 = pk.vk.delta_g2.mul(s);

        let g2_b = Self::calculate_coeff_split(
            s_g2,
            &pk.b_g2_query,
            pk.vk.beta_g2,
            input_assignment,
            aux_assignment,
        );
        log_step!("MSM: Compute B(G2) End");

        let r_g1_b = g1_b * &r;
        end_timer!(b_g2_acc_time);

        let c_time = start_timer!(|| "Finish C");
        let mut g_c = s_g_a;
        g_c += &r_g1_b;
        g_c -= &r_s_delta_g1;
        g_c += &l_aux_acc;
        g_c += &h_acc;
        end_timer!(c_time);
        log_step!("Function End: create_proof_assignment");

        Ok(Proof {
            a: g_a.into_affine(),
            b: g2_b.into_affine(),
            c: g_c.into_affine(),
        })
    }

    /// ScalarField 슬라이스를 받아 Chunk 단위로 BigInt 변환 후 MSM 수행
    #[inline]
    fn calculate_coeff_split<G: AffineRepr>(
        mut acc: G::Group,
        query: &[G],
        vk_param: G,
        assign1: &[G::ScalarField],
        assign2: &[G::ScalarField],
    ) -> G::Group
    where
        G::Group: VariableBaseMSM<MulBase = G>,
    {
        let el0 = query[0];
        let q_rest = &query[1..];

        let (q1, q2) = q_rest.split_at(assign1.len());

        let part1 = Self::msm_bigint_chunked(q1, assign1, MSM_CHUNK_SIZE);
        let part2 = Self::msm_bigint_chunked(q2, assign2, MSM_CHUNK_SIZE);

        acc.add_assign(&el0);
        acc += &part1;
        acc += &part2;
        acc.add_assign(&vk_param);
        acc
    }

    /// 핵심 최적화 함수: 16K 단위로 BigInt 변환 및 연산 후 즉시 메모리 해제
    #[inline]
    fn msm_bigint_chunked<G: AffineRepr>(
        bases: &[G],
        scalars_src: &[G::ScalarField],
        chunk_size: usize,
    ) -> G::Group
    where
        G::Group: VariableBaseMSM<MulBase = G>,
    {
        let mut sum = G::Group::zero();
        let mut i = 0;
        let len = bases.len();

        while i < len {
            let end = core::cmp::min(i + chunk_size, len);

            // Chunk만큼만 BigInt로 변환 (메모리 피크 방지)
            let s_chunk: Vec<<G::ScalarField as PrimeField>::BigInt> = scalars_src[i..end]
                .iter()
                .map(|s| s.into_bigint())
                .collect();

            let part = G::Group::msm_bigint(&bases[i..end], &s_chunk);
            sum += &part;

            // s_chunk는 여기서 drop됨
            i = end;
        }
        sum
    }

    pub fn create_proof_with_reduction_factory<C>(
        mut circuit_factory: impl FnMut() -> C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
    ) -> ark_relations::r1cs::Result<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        println!(
            "[rss_kb] create_proof_with_reduction_factory 시작: {} MB",
            rss_kb() / (1024 * 1024)
        );
        // ---- Pass 1: 회로를 생성해 CS 구성 & 행렬/할당 추출 ----
        let prover_time = start_timer!(|| "Groth16::Prover (factory)");
        let cs = ConstraintSystem::new_ref();

        // 증명 모드에서 행렬도 구성 (witness/instance assignment + matrices 모두 필요)
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        // 회로 인스턴스는 여기서 "한 번" 만들고 사용 후 버려집니다.
        let synthesis_time = start_timer!(|| "Constraint synthesis (factory)");
        let circuit = circuit_factory();
        circuit.generate_constraints(cs.clone())?;
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs (factory)");
        cs.finalize();
        end_timer!(lc_time);

        // 행렬 & 전체 할당 추출
        let matrices = cs
            .to_matrices()
            .expect("matrices must exist in Prove{construct_matrices:true}");
        let num_inputs = cs.num_instance_variables();
        let num_constraints = cs.num_constraints();

        // full_assignment = [instance | witness]
        let cs_borrow = cs.borrow().expect("borrow cs");
        let instance_assignment = cs_borrow.instance_assignment.as_slice();
        let witness_assignment = cs_borrow.witness_assignment.as_slice();
        let full_assignment: Vec<E::ScalarField> =
            [instance_assignment, witness_assignment].concat();
        drop(cs_borrow);
        // 여기서 CS 전체를 메모리에서 내립니다.
        drop(cs);

        // ---- Witness map 계산 (CS 없이 진행) ----
        let witness_map_time = start_timer!(|| "R1CS→QAP witness map (factory)");
        let h = QAP::witness_map_from_matrices::<E::ScalarField, D<E::ScalarField>>(
            &matrices,
            num_inputs,
            num_constraints,
            &full_assignment,
        )?;
        end_timer!(witness_map_time);
        // matrices는 더 이상 불필요하므로 즉시 해제
        drop(matrices);

        // 입력/보조 분리 (full_assignment은 이 시점에만 잠깐 유지)
        let input_assignment = &full_assignment[1..num_inputs];
        let aux_assignment = &full_assignment[num_inputs..];

        // ---- MSM 등 나머지 계산 ----
        let proof =
            Self::create_proof_with_assignment(pk, r, s, &h, input_assignment, aux_assignment)?;

        end_timer!(prover_time);
        println!(
            "[rss_kb] create_proof_with_reduction_factory 종료: {} MB",
            rss_kb() / (1024 * 1024)
        );
        Ok(proof)
    }

    /// Create a Groth16 proof that is zero-knowledge using the provided
    /// R1CS-to-QAP reduction.
    /// This method samples randomness for zero knowledges via `rng`.
    #[inline]
    pub fn create_random_proof_with_reduction<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut impl Rng,
    ) -> R1CSResult<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        println!(
            "[rss_kb] create_random_proof_with_reduction 시작: {} MB",
            rss_kb() / (1024 * 1024)
        );

        let r = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);

        Self::create_proof_with_reduction(circuit, pk, r, s)
    }

    /// Create a Groth16 proof using randomness `r` and `s` and the provided
    /// R1CS-to-QAP reduction.
    #[inline]
    pub fn create_proof_with_reduction<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
    ) -> R1CSResult<Proof<E>>
    where
        E: Pairing,
        C: ConstraintSynthesizer<E::ScalarField>,
        QAP: R1CSToQAP,
    {
        let prover_time = start_timer!(|| "Groth16::Prover");
        println!(
            "[rss_kb] Groth16::Prover 시작: {} MB",
            rss_kb() / (1024 * 1024)
        );
        let cs = ConstraintSystem::new_ref();

        // Set the optimization goal
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);
        println!(
            "[rss_kb] Constraint synthesis 종료: {} MB",
            rss_kb() / (1024 * 1024)
        );

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);
        println!(
            "[rss_kb] Inlining LCs 종료: {} MB",
            rss_kb() / (1024 * 1024)
        );

        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map::<E::ScalarField, D<E::ScalarField>>(cs.clone())?;
        end_timer!(witness_map_time);
        println!("[rss_kb] witness_map 종료: {} MB", rss_kb() / (1024 * 1024));

        let prover = cs.borrow().unwrap();
        let proof = Self::create_proof_with_assignment(
            pk,
            r,
            s,
            &h,
            &prover.instance_assignment[1..],
            &prover.witness_assignment,
        )?;
        println!("[rss_kb] proof 생성 후: {} MB", rss_kb() / (1024 * 1024));

        end_timer!(prover_time);
        println!(
            "[rss_kb] Groth16::Prover 종료: {} MB",
            rss_kb() / (1024 * 1024)
        );

        Ok(proof)
    }

    /// Given a Groth16 proof, returns a fresh proof of the same statement. For a proof π of a
    /// statement S, the output of the non-deterministic procedure `rerandomize_proof(π)` is
    /// statistically indistinguishable from a fresh honest proof of S. For more info, see theorem 3 of
    /// [\[BKSV20\]](https://eprint.iacr.org/2020/811)
    pub fn rerandomize_proof(
        vk: &VerifyingKey<E>,
        proof: &Proof<E>,
        rng: &mut impl Rng,
    ) -> Proof<E> {
        // These are our rerandomization factors. They must be nonzero and uniformly sampled.
        let (mut r1, mut r2) = (E::ScalarField::zero(), E::ScalarField::zero());
        while r1.is_zero() || r2.is_zero() {
            r1 = E::ScalarField::rand(rng);
            r2 = E::ScalarField::rand(rng);
        }

        // See figure 1 in the paper referenced above:
        //   A' = (1/r₁)A
        //   B' = r₁B + r₁r₂(δG₂)
        //   C' = C + r₂A

        // We can unwrap() this because r₁ is guaranteed to be nonzero
        let new_a = proof.a.mul(r1.inverse().unwrap());
        let new_b = proof.b.mul(r1) + &vk.delta_g2.mul(r1 * &r2);
        let new_c = proof.c + proof.a.mul(r2).into_affine();

        Proof {
            a: new_a.into_affine(),
            b: new_b.into_affine(),
            c: new_c.into_affine(),
        }
    }
}

#[cfg(feature = "memory-logging")]
pub fn rss_kb() -> u64 {
    // System은 내부 캐시를 갖습니다. 한 번 만들고 재사용해도 됩니다.
    // 간단히 매번 새로 만들어도 충분히 가벼워요.
    let mut sys = System::new();
    // 현재 프로세스만 갱신
    if let Ok(pid) = sysinfo::get_current_pid() {
        sys.refresh_process(pid);
        if let Some(p) = sys.process(pid) {
            // KiB 단위 (KB 개념으로 취급해도 무방)
            return p.memory();
        }
    }
    0
}

#[cfg(not(feature = "memory-logging"))]
pub fn rss_kb() -> u64 {
    0
}
