use crate::{r1cs_to_qap::R1CSToQAP, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal,
    Result as R1CSResult, SynthesisMode,
};
use ark_std::rand::Rng;
use ark_std::{
    cfg_iter,
    ops::{AddAssign, Mul},
    vec::Vec,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sysinfo::System;

type D<F> = GeneralEvaluationDomain<F>;

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    pub fn create_random_proof_with_reduction_factory<C>(
        circuit_factory: impl FnMut() -> C,
        pk: &ProvingKey<E>,
        rng: &mut impl ark_std::rand::Rng,
    ) -> ark_relations::r1cs::Result<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        println!(
            "[rss_kb] create_random_proof_with_reduction_factory 시작: {} MB",
            rss_kb() / (1024 * 1024)
        );
        let r = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);
        let result = Self::create_proof_with_reduction_factory(circuit_factory, pk, r, s);
        println!(
            "[rss_kb] create_random_proof_with_reduction_factory 종료: {} MB",
            rss_kb() / (1024 * 1024)
        );
        result
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
    pub fn create_proof_two_pass_with_factory<C, F>(
        mut make_circuit: F,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
    ) -> ark_relations::r1cs::Result<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        F: FnMut() -> C,
    {
        let circuit_setup = make_circuit();
        let circuit_prove = make_circuit();
        Self::create_proof_two_pass_with(circuit_setup, circuit_prove, pk, r, s)
    }

    pub fn create_proof_two_pass_with<C>(
        circuit_for_setup: C,
        circuit_for_prove: C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
    ) -> ark_relations::r1cs::Result<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        // ---- Pass A: 행렬만
        let cs_a = ConstraintSystem::new_ref();
        cs_a.set_mode(SynthesisMode::Setup);
        cs_a.set_optimization_goal(OptimizationGoal::Constraints);
        circuit_for_setup.generate_constraints(cs_a.clone())?;
        cs_a.finalize();
        let matrices = cs_a.to_matrices().expect("matrices in setup");
        let num_inputs = matrices.num_instance_variables;
        let num_constraints = matrices.num_constraints;
        drop(cs_a); // 행렬 외 임시들 해제

        // ---- Pass B: 할당만
        let cs_b = ConstraintSystem::new_ref();
        cs_b.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });
        cs_b.set_optimization_goal(OptimizationGoal::Constraints);
        circuit_for_prove.generate_constraints(cs_b.clone())?;
        cs_b.finalize();

        let cs_b_in = cs_b.borrow().unwrap();
        let full_assignment: Vec<E::ScalarField> = [
            cs_b_in.instance_assignment.as_slice(),
            cs_b_in.witness_assignment.as_slice(),
        ]
        .concat();
        drop(cs_b_in);
        drop(cs_b);

        // ---- 연결
        Self::create_proof_with_reduction_and_matrices(
            pk,
            r,
            s,
            &matrices,
            num_inputs,
            num_constraints,
            &full_assignment,
        )
    }

    pub fn create_random_proof_two_pass<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut impl ark_std::rand::Rng,
    ) -> ark_relations::r1cs::Result<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField> + Clone,
    {
        let r = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);
        Self::create_proof_two_pass(circuit, pk, r, s)
    }

    pub fn create_proof_two_pass<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
    ) -> ark_relations::r1cs::Result<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField> + Clone,
    {
        // ---- Pass A: 행렬만 생성
        let cs_a = ConstraintSystem::new_ref();
        cs_a.set_mode(SynthesisMode::Setup);
        // 메모리 관점에서 두 가지 옵션을 시험해보세요:
        // 1) Constraints (기본): 인라이닝 → 구조 단순, 행렬 길이는 늘 수 있음
        // 2) Weight: 아웃라이닝 → non-zero 수 감소 → 행렬 메모리 감소 가능
        cs_a.set_optimization_goal(OptimizationGoal::Constraints);
        circuit.clone().generate_constraints(cs_a.clone())?;
        cs_a.finalize();
        // 이 시점엔 "할당"이 전혀 없음 → 행렬만 생성
        let matrices = cs_a.to_matrices().expect("matrices in setup");
        // cs_a 드롭으로 LC 맵 등 큰 구조 해제
        drop(cs_a);

        // Pass A에서 필요한 메타 값은 matrices와 아래 값들
        let num_inputs = matrices.num_instance_variables;
        let num_constraints = matrices.num_constraints;

        // ---- Pass B: 할당만 생성(행렬 X)
        let cs_b = ConstraintSystem::new_ref();
        cs_b.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });
        cs_b.set_optimization_goal(OptimizationGoal::Constraints); // 여기선 아웃라이닝 불필요
        circuit.generate_constraints(cs_b.clone())?;
        cs_b.finalize();

        // 풀 어사인먼트 추출 (행렬 없이 메모리 가벼움)
        let cs_b_inner = cs_b.borrow().unwrap();
        let full_assignment: Vec<E::ScalarField> = [
            cs_b_inner.instance_assignment.as_slice(),
            cs_b_inner.witness_assignment.as_slice(),
        ]
        .concat();
        drop(cs_b_inner);
        drop(cs_b);

        // ---- 행렬 + 할당을 연결하여 증명 생성(메모리 중복 없이)
        Self::create_proof_with_reduction_and_matrices(
            pk,
            r,
            s,
            &matrices,
            num_inputs,
            num_constraints,
            &full_assignment,
        )
    }

    /// Create a Groth16 proof using randomness `r` and `s` and
    /// the provided R1CS-to-QAP reduction, using the provided
    /// R1CS constraint matrices.
    #[inline]
    pub fn create_proof_with_reduction_and_matrices(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        matrices: &ConstraintMatrices<E::ScalarField>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        let prover_time = start_timer!(|| "Groth16::Prover");
        println!(
            "[rss_kb] Groth16::Prover 시작: {} MB",
            rss_kb() / (1024 * 1024)
        );
        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        println!("[rss_kb] witness_map 시작: {} MB", rss_kb() / (1024 * 1024));
        let h = QAP::witness_map_from_matrices::<E::ScalarField, D<E::ScalarField>>(
            matrices,
            num_inputs,
            num_constraints,
            full_assignment,
        )?;
        println!("[rss_kb] witness_map 종료: {} MB", rss_kb() / (1024 * 1024));
        end_timer!(witness_map_time);
        let input_assignment = &full_assignment[1..num_inputs];
        let aux_assignment = &full_assignment[num_inputs..];
        println!(
            "[rss_kb] assignment 분리 후: {} MB",
            rss_kb() / (1024 * 1024)
        );
        let proof =
            Self::create_proof_with_assignment(pk, r, s, &h, input_assignment, aux_assignment)?;
        println!("[rss_kb] proof 생성 후: {} MB", rss_kb() / (1024 * 1024));
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
        println!("[rss_kb] Compute C 시작: {} MB", rss_kb() / (1024 * 1024));
        // let h_assignment = cfg_into_iter!(h)
        //     .map(|s| s.into_bigint())
        //     .collect::<Vec<_>>();
        // let h_acc = E::G1::msm_bigint(&pk.h_query, &h_assignment);
        // drop(h_assignment);

        let h_acc = Self::msm_bigint_chunked::<E::G1Affine>(&pk.h_query, h, 16_384);
        println!("[rss_kb] h_acc 계산 후: {} MB", rss_kb() / (1024 * 1024));

        // Compute C
        // let aux_assignment = cfg_iter!(aux_assignment)
        //     .map(|s| s.into_bigint())
        //     .collect::<Vec<_>>();

        // let l_aux_acc = E::G1::msm_bigint(&pk.l_query, &aux_assignment);
        let aux_bigint = cfg_iter!(aux_assignment)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let l_aux_acc = E::G1::msm_bigint(&pk.l_query, &aux_bigint);
        println!(
            "[rss_kb] l_aux_acc 계산 후: {} MB",
            rss_kb() / (1024 * 1024)
        );

        let r_s_delta_g1 = pk.delta_g1 * (r * s);

        end_timer!(c_acc_time);
        println!("[rss_kb] Compute C 종료: {} MB", rss_kb() / (1024 * 1024));

        // let input_assignment = input_assignment
        //     .iter()
        //     .map(|s| s.into_bigint())
        //     .collect::<Vec<_>>();

        // let assignment = [&input_assignment[..], &aux_assignment[..]].concat();
        // drop(aux_assignment);
        let input_bigint = input_assignment
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        println!(
            "[rss_kb] input_bigint 변환 후: {} MB",
            rss_kb() / (1024 * 1024)
        );

        // Compute A
        let a_acc_time = start_timer!(|| "Compute A");
        println!("[rss_kb] Compute A 시작: {} MB", rss_kb() / (1024 * 1024));
        let r_g1 = pk.delta_g1.mul(r);

        // let g_a = Self::calculate_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, &assignment);
        let g_a = Self::calculate_coeff_split(
            r_g1,
            &pk.a_query,
            pk.vk.alpha_g1,
            &input_bigint,
            &aux_bigint,
        );
        println!("[rss_kb] g_a 계산 후: {} MB", rss_kb() / (1024 * 1024));

        let s_g_a = g_a * &s;
        end_timer!(a_acc_time);
        println!("[rss_kb] Compute A 종료: {} MB", rss_kb() / (1024 * 1024));

        // Compute B in G1 if needed
        let g1_b = if !r.is_zero() {
            let b_g1_acc_time = start_timer!(|| "Compute B in G1");
            println!(
                "[rss_kb] Compute B in G1 시작: {} MB",
                rss_kb() / (1024 * 1024)
            );
            let s_g1 = pk.delta_g1.mul(s);
            // let g1_b = Self::calculate_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, &assignment);
            let g1_b = Self::calculate_coeff_split(
                s_g1,
                &pk.b_g1_query,
                pk.beta_g1,
                &input_bigint,
                &aux_bigint,
            );
            println!("[rss_kb] g1_b 계산 후: {} MB", rss_kb() / (1024 * 1024));

            end_timer!(b_g1_acc_time);
            println!(
                "[rss_kb] Compute B in G1 종료: {} MB",
                rss_kb() / (1024 * 1024)
            );

            g1_b
        } else {
            E::G1::zero()
        };

        // Compute B in G2
        let b_g2_acc_time = start_timer!(|| "Compute B in G2");
        println!(
            "[rss_kb] Compute B in G2 시작: {} MB",
            rss_kb() / (1024 * 1024)
        );
        let s_g2 = pk.vk.delta_g2.mul(s);
        // let g2_b = Self::calculate_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, &assignment);
        let g2_b = Self::calculate_coeff_split(
            s_g2,
            &pk.b_g2_query,
            pk.vk.beta_g2,
            &input_bigint,
            &aux_bigint,
        );
        println!("[rss_kb] g2_b 계산 후: {} MB", rss_kb() / (1024 * 1024));
        let r_g1_b = g1_b * &r;
        // drop(assignment);
        drop(input_bigint);
        drop(aux_bigint);

        end_timer!(b_g2_acc_time);
        println!(
            "[rss_kb] Compute B in G2 종료: {} MB",
            rss_kb() / (1024 * 1024)
        );

        let c_time = start_timer!(|| "Finish C");
        println!("[rss_kb] Finish C 시작: {} MB", rss_kb() / (1024 * 1024));
        let mut g_c = s_g_a;
        g_c += &r_g1_b;
        g_c -= &r_s_delta_g1;
        g_c += &l_aux_acc;
        g_c += &h_acc;
        end_timer!(c_time);
        println!("[rss_kb] Finish C 종료: {} MB", rss_kb() / (1024 * 1024));

        Ok(Proof {
            a: g_a.into_affine(),
            b: g2_b.into_affine(),
            c: g_c.into_affine(),
        })
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

    /// Create a Groth16 proof that is *not* zero-knowledge with the provided
    /// R1CS-to-QAP reduction.
    #[inline]
    pub fn create_proof_with_reduction_no_zk<C>(
        circuit: C,
        pk: &ProvingKey<E>,
    ) -> R1CSResult<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        Self::create_proof_with_reduction(
            circuit,
            pk,
            E::ScalarField::zero(),
            E::ScalarField::zero(),
        )
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

    #[inline]
    fn calculate_coeff_split<G: AffineRepr>(
        mut acc: G::Group,
        query: &[G],
        vk_param: G,
        assign1: &[<G::ScalarField as PrimeField>::BigInt],
        assign2: &[<G::ScalarField as PrimeField>::BigInt],
    ) -> G::Group
    where
        G::Group: VariableBaseMSM<MulBase = G>,
    {
        // query[0]는 별도 더하고, 나머지는 assignment에 맞춰 MSM
        let el0 = query[0];
        let q_rest = &query[1..];
        // q_rest는 assign1(len1) + assign2(len2) 에 대응한다고 가정
        let (q1, q2) = q_rest.split_at(assign1.len());
        let part1 = G::Group::msm_bigint(q1, assign1);
        let part2 = G::Group::msm_bigint(q2, assign2);
        acc.add_assign(&el0);
        acc += &part1;
        acc += &part2;
        acc.add_assign(&vk_param);
        acc
    }

    #[inline]
    fn msm_bigint_chunked<G: AffineRepr>(
        bases: &[G],
        scalars_src: &[G::ScalarField],
        chunk: usize,
    ) -> G::Group
    where
        G::Group: VariableBaseMSM<MulBase = G>,
    {
        use ark_std::vec::Vec;
        let mut sum = G::Group::zero();
        let mut i = 0;
        while i < bases.len() {
            let end = core::cmp::min(i + chunk, bases.len());
            // 현 chunk: scalars를 BigInt로 변환
            let s_chunk: Vec<<G::ScalarField as PrimeField>::BigInt> = scalars_src[i..end]
                .iter()
                .map(|s| s.into_bigint())
                .collect();
            let part = G::Group::msm_bigint(&bases[i..end], &s_chunk);
            sum += &part;
            i = end;
        }
        sum
    }
}

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
