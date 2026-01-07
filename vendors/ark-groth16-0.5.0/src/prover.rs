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

use std::sync::atomic::AtomicU64;

use log;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
#[cfg(feature = "memory-logging")]
use sysinfo::System;

type D<F> = GeneralEvaluationDomain<F>;
#[cfg(feature = "memory-logging")]
macro_rules! log_step {
    ($msg:expr) => {
        let (cur, peak) = rss_kb();
        // println!을 사용하여 테스트 환경(--nocapture)에서도 바로 출력되도록 함
        println!(
            "[rss_kb] {:<40} : Cur {} MB / Peak {} MB",
            $msg,
            cur / (1024 * 1024),
            peak / (1024 * 1024)
        );
    };
}

#[cfg(not(feature = "memory-logging"))]
macro_rules! log_step {
    ($msg:expr) => {
        log::info!("[ZKAP] {}", $msg);
    };
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
        // -------------------------------------------------------------------------
        // [Phase 1] Witness Generation
        // -------------------------------------------------------------------------
        log_step!("Phase 1: Witness Gen Start");

        let cs_witness = ConstraintSystem::new_ref();
        cs_witness.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });
        cs_witness.set_optimization_goal(OptimizationGoal::Constraints);

        let circuit_w = circuit_factory();
        circuit_w.generate_constraints(cs_witness.clone())?;
        cs_witness.finalize();

        // ✅ Phase 2를 위해 제약조건 수 미리 캡처
        let num_constraints = cs_witness.num_constraints();
        log_step!("Phase 1: Finalized");

        let (instance_assignment, witness_assignment) = {
            let mut cs_inner = cs_witness.borrow_mut().unwrap();
            let inst = mem::take(&mut cs_inner.instance_assignment);
            let wit = mem::take(&mut cs_inner.witness_assignment);
            (inst, wit)
        };
        drop(cs_witness);
        log_step!("Phase 1: CS Dropped (Witness Extracted)");

        let num_inputs = instance_assignment.len();

        let domain = D::<E::ScalarField>::new(num_constraints + num_inputs)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        // -------------------------------------------------------------------------
        // [Phase 2 & 3] Sequential Matrix Gen & Eval (3-Pass)
        // -------------------------------------------------------------------------
        // 헬퍼 클로저: 회로를 다시 생성하고 특정 행렬(Target)만 추출한 뒤 CS를 즉시 해제함
        // 이를 통해 Peak 메모리를 (CS 1개 + FlatMatrix 1개) 수준으로 억제
        let mut generate_and_extract_one =
            |target: MatrixTarget| -> R1CSResult<FlatMatrix<E::ScalarField>> {
                // log_step!(format!("Phase 2: Generating CS for Matrix {:?}", target)); // Debug 없을시 주석
                log_step!("Phase 2: Re-generating CS for Matrix Extraction");

                let cs_matrix = ConstraintSystem::new_ref();
                cs_matrix.set_mode(SynthesisMode::Setup);
                cs_matrix.set_optimization_goal(OptimizationGoal::Constraints);

                let circuit_m = circuit_factory();
                circuit_m.generate_constraints(cs_matrix.clone())?;
                cs_matrix.finalize();

                // 추출
                let flat =
                    Self::extract_flat_matrix(&cs_matrix, target, num_inputs, num_constraints);

                // ✅ CS 즉시 해제 (메모리 확보)
                drop(cs_matrix);
                log_step!("Phase 2: CS Dropped");

                Ok(flat)
            };

        // --- Step A ---
        log_step!("Phase 3: Processing Matrix A (Pass 1/3)");
        let mut eval_a = {
            let flat_a = generate_and_extract_one(MatrixTarget::A)?;
            let e = QAP::eval_flat_matrix_on_domain(
                &flat_a,
                num_inputs,
                num_constraints,
                &instance_assignment,
                &witness_assignment,
                domain,
                true,
            )?;
            drop(flat_a); // Matrix A 메모리 해제
            e
        };
        log_step!("Phase 3: Matrix A Done");

        // --- Step B ---
        log_step!("Phase 3: Processing Matrix B (Pass 2/3)");
        let eval_b = {
            let flat_b = generate_and_extract_one(MatrixTarget::B)?;
            let e = QAP::eval_flat_matrix_on_domain(
                &flat_b,
                num_inputs,
                num_constraints,
                &instance_assignment,
                &witness_assignment,
                domain,
                false,
            )?;
            drop(flat_b); // Matrix B 메모리 해제
            e
        };
        log_step!("Phase 3: Matrix B Done");

        // A = A * B
        log_step!("Phase 3: Compute A * B");
        for (a, b) in eval_a.iter_mut().zip(eval_b.iter()) {
            *a *= b;
        }
        drop(eval_b); // Eval B 해제

        // --- Step C ---
        log_step!("Phase 3: Processing Matrix C (Pass 3/3)");
        let eval_c = {
            let flat_c = generate_and_extract_one(MatrixTarget::C)?;
            let e = QAP::eval_flat_matrix_on_domain(
                &flat_c,
                num_inputs,
                num_constraints,
                &instance_assignment,
                &witness_assignment,
                domain,
                false,
            )?;
            drop(flat_c); // Matrix C 메모리 해제
            e
        };
        log_step!("Phase 3: Matrix C Done");

        // (AB - C) / Z
        log_step!("Phase 3: Compute (AB - C)");
        let inv_vanishing_poly = domain
            .evaluate_vanishing_polynomial(E::ScalarField::GENERATOR)
            .inverse()
            .unwrap();

        for (ab, c) in eval_a.iter_mut().zip(eval_c.iter()) {
            *ab -= c;
            *ab *= inv_vanishing_poly;
        }
        drop(eval_c);

        // IFFT
        let coset_domain = domain.get_coset(E::ScalarField::GENERATOR).unwrap();
        coset_domain.ifft_in_place(&mut eval_a);
        let h = eval_a;
        log_step!("Phase 3: H Calculated");

        // -------------------------------------------------------------------------
        // [Phase 4] Proof Generation
        // -------------------------------------------------------------------------
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

        let indices = match target {
            MatrixTarget::A => &cs_borrow.a_constraints,
            MatrixTarget::B => &cs_borrow.b_constraints,
            MatrixTarget::C => &cs_borrow.c_constraints,
        };

        // 1. [Optimization] 정확한 크기(Capacity) 계산 (메모리 피크 방지)
        let mut total_non_zeros = 0;
        for &lc_index in indices {
            if let Some(lc) = cs_borrow.lc_map.get(&lc_index) {
                // Zero, SymbolicLc 제외하고 실제 추가될 개수만 카운트
                for (_, var) in lc.iter() {
                    match var {
                        Variable::Zero => continue,
                        Variable::SymbolicLc(_) => continue,
                        _ => total_non_zeros += 1,
                    }
                }
            }
        }

        let mut ptr = Vec::with_capacity(num_constraints + 1);
        let mut col = Vec::with_capacity(total_non_zeros); // 정확한 크기로 할당
        let mut val = Vec::with_capacity(total_non_zeros); // 정확한 크기로 할당

        ptr.push(0);

        // 2. 데이터 채우기
        for &lc_index in indices {
            if let Some(lc) = cs_borrow.lc_map.get(&lc_index) {
                for (coeff, var) in lc.iter() {
                    let idx = match var {
                        Variable::One => 0,
                        Variable::Instance(i) => *i,
                        Variable::Witness(i) => num_inputs + *i,
                        Variable::Zero => continue,
                        Variable::SymbolicLc(_) => {
                            panic!("SymbolicLc encountered during matrix extraction!");
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
        let h_acc = E::G1::msm_bigint(
            &pk.h_query,
            cfg_into_iter!(h)
                .map(|s| s.into_bigint())
                .collect::<Vec<_>>()
                .as_slice(),
        );

        // 2. L_Aux Accumulation (Chunked - BigInt 변환 제거됨)
        log_step!("MSM: L_Aux_Acc Start");
        log_step!(format!("l_query length: {}", pk.l_query.len()));
        log_step!(format!("aux_assignment length: {}", aux_assignment.len()));
        let l_aux_acc = E::G1::msm_bigint(
            &pk.l_query,
            cfg_into_iter!(aux_assignment)
                .map(|s| s.into_bigint())
                .collect::<Vec<_>>()
                .as_slice(),
        );
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

        let part1 = G::Group::msm_bigint(
            q1,
            cfg_into_iter!(assign1)
                .map(|s| s.into_bigint())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let part2 = G::Group::msm_bigint(
            q2,
            cfg_into_iter!(assign2)
                .map(|s| s.into_bigint())
                .collect::<Vec<_>>()
                .as_slice(),
        );

        acc.add_assign(&el0);
        acc += &part1;
        acc += &part2;
        acc.add_assign(&vk_param);
        acc
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
        log_step!("Function Start: create_proof_with_reduction_factory");
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
        log_step!("Groth16::Prover (factory) End");
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
        log_step!("Function Start: create_random_proof_with_reduction");

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

        log_step!("Function Start: create_proof_with_reduction");
        let cs = ConstraintSystem::new_ref();

        // Set the optimization goal
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);
        log_step!("Constraint synthesis End");

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);
        log_step!("Inlining LCs End");

        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map::<E::ScalarField, D<E::ScalarField>>(cs.clone())?;
        end_timer!(witness_map_time);
        log_step!("R1CS to QAP witness map End");

        let prover = cs.borrow().unwrap();
        let proof = Self::create_proof_with_assignment(
            pk,
            r,
            s,
            &h,
            &prover.instance_assignment[1..],
            &prover.witness_assignment,
        )?;
        log_step!("Proof Generated");

        end_timer!(prover_time);
        log_step!("Function End: create_proof_with_reduction");

        Ok(proof)
    }
    // =========================================================================
    // [Optimized] Split Execution API
    // 메모리 최적화를 위해 "Witness/H 계산(PK 불필요)"과 "MSM(PK 필요)"을 분리
    // =========================================================================

    /// [Step 1] ProvingKey 없이 Witness와 H 다항식만 먼저 계산합니다.
    /// 이 함수 실행 중에는 거대한 PK가 메모리에 없어야 최적화 효과가 있습니다.
    pub fn create_proof_part1_witness_h<C, F>(
        mut circuit_factory: F,
    ) -> ark_relations::r1cs::Result<(
        Vec<E::ScalarField>,
        Vec<E::ScalarField>,
        Vec<E::ScalarField>,
    )>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        F: FnMut() -> C,
    {
        // -------------------------------------------------------------------------
        // [Phase 1] Witness Generation
        // -------------------------------------------------------------------------
        log_step!("Step 1: Witness Gen Start");

        let cs_witness = ConstraintSystem::new_ref();
        cs_witness.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });
        cs_witness.set_optimization_goal(OptimizationGoal::Constraints);

        let circuit_w = circuit_factory();
        circuit_w.generate_constraints(cs_witness.clone())?;
        cs_witness.finalize();

        // Phase 2를 위해 제약조건 수 캡처
        let num_constraints = cs_witness.num_constraints();
        log_step!("Step 1: Finalized");

        let (instance_assignment, witness_assignment) = {
            let mut cs_inner = cs_witness.borrow_mut().unwrap();
            let inst = mem::take(&mut cs_inner.instance_assignment);
            let wit = mem::take(&mut cs_inner.witness_assignment);
            (inst, wit)
        };
        drop(cs_witness);
        log_step!("Step 1: CS Dropped (Witness Extracted)");

        let num_inputs = instance_assignment.len();

        let domain = D::<E::ScalarField>::new(num_constraints + num_inputs)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        // -------------------------------------------------------------------------
        // [Phase 2 & 3] Sequential Matrix Gen & Eval (3-Pass)
        // -------------------------------------------------------------------------
        let mut generate_and_extract_one =
            |target: MatrixTarget| -> R1CSResult<FlatMatrix<E::ScalarField>> {
                log_step!("Step 1: Re-generating CS for Matrix Extraction");

                let cs_matrix = ConstraintSystem::new_ref();
                cs_matrix.set_mode(SynthesisMode::Setup);
                cs_matrix.set_optimization_goal(OptimizationGoal::Constraints);

                let circuit_m = circuit_factory();
                circuit_m.generate_constraints(cs_matrix.clone())?;
                cs_matrix.finalize();

                // 추출
                let flat =
                    Self::extract_flat_matrix(&cs_matrix, target, num_inputs, num_constraints);

                // CS 즉시 해제
                drop(cs_matrix);
                log_step!("Step 1: CS Dropped");

                Ok(flat)
            };

        // --- Matrix A ---
        log_step!("Step 1: Processing Matrix A");
        let mut eval_a = {
            let flat_a = generate_and_extract_one(MatrixTarget::A)?;
            let e = QAP::eval_flat_matrix_on_domain(
                &flat_a,
                num_inputs,
                num_constraints,
                &instance_assignment,
                &witness_assignment,
                domain,
                true,
            )?;
            drop(flat_a);
            e
        };

        // --- Matrix B ---
        log_step!("Step 1: Processing Matrix B");
        let eval_b = {
            let flat_b = generate_and_extract_one(MatrixTarget::B)?;
            let e = QAP::eval_flat_matrix_on_domain(
                &flat_b,
                num_inputs,
                num_constraints,
                &instance_assignment,
                &witness_assignment,
                domain,
                false,
            )?;
            drop(flat_b);
            e
        };

        // A = A * B
        for (a, b) in eval_a.iter_mut().zip(eval_b.iter()) {
            *a *= b;
        }
        drop(eval_b);

        // --- Matrix C ---
        log_step!("Step 1: Processing Matrix C");
        let eval_c = {
            let flat_c = generate_and_extract_one(MatrixTarget::C)?;
            let e = QAP::eval_flat_matrix_on_domain(
                &flat_c,
                num_inputs,
                num_constraints,
                &instance_assignment,
                &witness_assignment,
                domain,
                false,
            )?;
            drop(flat_c);
            e
        };

        // (AB - C) / Z
        let inv_vanishing_poly = domain
            .evaluate_vanishing_polynomial(E::ScalarField::GENERATOR)
            .inverse()
            .unwrap();

        for (ab, c) in eval_a.iter_mut().zip(eval_c.iter()) {
            *ab -= c;
            *ab *= inv_vanishing_poly;
        }
        drop(eval_c);

        // IFFT
        let coset_domain = domain.get_coset(E::ScalarField::GENERATOR).unwrap();
        coset_domain.ifft_in_place(&mut eval_a);

        let h = eval_a;
        log_step!("Step 1: H Calculated. Ready for MSM.");

        // H 벡터와 Assignment를 반환
        Ok((h, instance_assignment, witness_assignment))
    }

    /// [Step 2] ProvingKey를 로드하여 최종 증명을 생성합니다.
    /// 이 단계에서만 PK가 메모리에 올라옵니다.
    pub fn create_proof_part2_msm(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        h: &[E::ScalarField],
        instance_assignment: &[E::ScalarField],
        witness_assignment: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        log_step!("Step 2: MSM Start (PK Loaded)");

        let input_assignment = &instance_assignment[1..];
        let aux_assignment = witness_assignment;

        let proof =
            Self::create_proof_with_assignment(pk, r, s, h, input_assignment, aux_assignment)?;

        log_step!("Step 2: Proof Generated");
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

// ✅ 전역 변수로 피크 메모리 저장 (초기값 0)
static PEAK_MEMORY: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "memory-logging")]
pub fn rss_kb() -> (u64, u64) {
    // 반환 타입 변경: (Current, Peak)
    let mut sys = System::new();
    if let Ok(pid) = sysinfo::get_current_pid() {
        sys.refresh_process(pid);
        if let Some(p) = sys.process(pid) {
            let current = p.memory(); // 현재 메모리 (Bytes)

            // 피크 메모리 갱신 (현재 값이 더 크면 업데이트)
            // fetch_max는 이전 값을 반환하므로, 현재 값과 비교하여 더 큰 값을 peak로 사용
            let prev_peak = PEAK_MEMORY.fetch_max(current, Ordering::Relaxed);
            let peak = std::cmp::max(prev_peak, current);

            return (current, peak);
        }
    }
    (0, PEAK_MEMORY.load(Ordering::Relaxed))
}

#[cfg(not(feature = "memory-logging"))]
pub fn rss_kb() -> (u64, u64) {
    (0, 0)
}
