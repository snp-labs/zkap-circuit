use std::path::PathBuf;

use ark_crypto_primitives::merkle_tree::Path;
#[cfg(feature = "use-optimized")]
use ark_groth16::Groth16;
use ark_groth16::{Proof, ProvingKey};
use ark_std::UniformRand;
use circuit::baerae::BaeraeLightWeightCircuit;
#[cfg(feature = "use-optimized")]
use common::constants::BN254;
use common::{
    constants::{BNP, CG, F, ZkPasskeyConfig},
    io::load_key_uncompressed,
};
use gadget::mekletree::tree_config::MerkleTreeParams;
use rand::rngs::OsRng;

use crate::{
    app::{
        jwt::builder::{JwtCircuitWitness, TokenBuilder},
        snark::{
            preprocess::build_mp,
            types::{AnchorContext, CircuitContext, Intermediate, ParsedInputs},
        },
    },
    error::ApplicationError,
};

pub(crate) fn make_circuit_factory<Config: ZkPasskeyConfig>(
    circuit_ctx: &CircuitContext<Config>,
    parsed_inputs: &ParsedInputs,
    anchor_ctx: &AnchorContext,
    leaf_idx: usize,
    jwt_circuit_witness: JwtCircuitWitness,
    path: Path<MerkleTreeParams<F>>,
    padded_aud_list: &[F],
    h_aud_list: F,
    proof_i: usize,
) -> impl FnMut() -> BaeraeLightWeightCircuit<CG, BNP, Config> {
    let partial_rhs = anchor_ctx.partial_rhs_list[proof_i];
    let current_idx = anchor_ctx.current_idx_list[proof_i];

    let vm = circuit_ctx.vandermonde_matrix.clone();
    let pp = circuit_ctx.poseidon_params.clone();
    let bt = circuit_ctx.base64_table.clone();

    let hanchor = parsed_inputs.hanchor;
    let root = parsed_inputs.root;
    let h_sign_user_op = parsed_inputs.h_sign_user_op;
    let block_timestamp = parsed_inputs.block_timestamp;
    let random = parsed_inputs.random;
    let anchor = parsed_inputs.anchor.clone();

    let h_ctx = anchor_ctx.h_ctx;
    let lhs = anchor_ctx.lhs;
    let a = anchor_ctx.anchor_witness_a.clone();
    let selector = anchor_ctx.selector.clone();

    let path0 = path;
    let w0 = jwt_circuit_witness;
    let aud0 = padded_aud_list;

    move || {
        let path = path0.clone(); // Path가 Clone이어야 함
        let w = w0.clone(); // JwtCircuitWitness는 Clone (주신 정의에 Clone 있음)
        let aud = aud0;

        BaeraeLightWeightCircuit::<CG, BNP, Config>::new(
            vm.clone(),
            pp.clone(),
            bt.clone(),
            hanchor,
            h_ctx,
            root,
            h_sign_user_op,
            block_timestamp,
            partial_rhs,
            lhs,
            h_aud_list,
            random,
            leaf_idx,
            path,
            anchor.clone(),
            w.state.clone(),
            w.nblocks,
            w.claim_indices.clone(),
            w.pay_offset_b64,
            w.pay_len_b64,
            w.sha_pad_payload_b64.clone(),
            w.index_bits.clone(),
            w.pk.clone(),
            w.sig.clone(),
            a.clone(),
            selector.clone(),
            current_idx,
            aud.to_vec(),
            w.total_len,
            w.pre_hash_block_len,
            w.pad_start_in_suffix,
        )
    }
}

pub(crate) fn phase_a_part1<Config: ZkPasskeyConfig>(
    circuit_ctx: &CircuitContext<Config>,
    builders: &[TokenBuilder],
    raw_pk_ops: &[String],
    raw_merkle_paths: &[Vec<String>],
    raw_leaf_indices: &[usize],
    parsed_inputs: &ParsedInputs,
    anchor_ctx: &AnchorContext,
    padded_aud_list: &[F], // ✅ 변경
    h_aud_list: F,
) -> Result<(Vec<Intermediate>, Vec<Vec<F>>), ApplicationError> {
    let mut intermediate_results = Vec::with_capacity(Config::K);
    let mut public_inputs_list = Vec::with_capacity(Config::K);

    for i in 0..Config::K {
        let witness = builders[i].build::<Config>(&raw_pk_ops[i]).map_err(|e| {
            ApplicationError::InvalidFormat(format!("Failed to build circuit witness: {}", e))
        })?;

        let li = raw_leaf_indices[i];
        let path = build_mp(&raw_merkle_paths[i], li)?;

        // ✅ make_circuit_factory에 slice를 넘김
        let circuit_factory = make_circuit_factory::<Config>(
            circuit_ctx,
            parsed_inputs,
            anchor_ctx,
            li,
            witness,
            path,
            padded_aud_list, // ✅ move 없음
            h_aud_list,
            i,
        );

        #[cfg(feature = "use-optimized")]
        let (h, instance, w) = Groth16::<BN254>::create_proof_part1_witness_h(circuit_factory)
            .map_err(|e| ApplicationError::InvalidFormat(format!("Part 1 failed: {}", e)))?;

        #[cfg(not(feature = "use-optimized"))]
        return Err(ApplicationError::InvalidFormat(
            "Split execution requires 'use-optimized' feature".into(),
        ));

        public_inputs_list.push(instance[1..].to_vec());
        intermediate_results.push(Intermediate {
            h,
            instance,
            witness: w,
        });
    }

    Ok((intermediate_results, public_inputs_list))
}

pub(crate) fn phase_b_part2_msm<Config: ZkPasskeyConfig>(
    pk_path: &PathBuf,
    intermediate_results: &[Intermediate],
) -> Result<Vec<Proof<BN254>>, ApplicationError> {
    // ProvingKey 로드
    let pk = load_key_uncompressed::<ProvingKey<BN254>>(pk_path).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to load proving key: {}", e))
    })?;

    let mut rng = OsRng;
    let mut proofs = Vec::with_capacity(intermediate_results.len());

    for inter in intermediate_results.iter() {
        let r = F::rand(&mut rng);
        let s = F::rand(&mut rng);

        // ✅ Vec<F>를 clone하지 말고 slice로 넘김(함수 시그니처가 &Vec or &[F] 둘 다 OK인 경우가 많음)
        let proof = Groth16::<BN254>::create_proof_part2_msm(
            &pk,
            r,
            s,
            &inter.h,
            &inter.instance,
            &inter.witness,
        )
        .map_err(|e| ApplicationError::InvalidFormat(format!("Part 2 failed: {}", e)))?;

        proofs.push(proof);
    }

    Ok(proofs)
}

pub(crate) fn prove_streaming<Config: ZkPasskeyConfig>(
    pk_path: &PathBuf,
    circuit_ctx: &CircuitContext<Config>,
    builders: &[TokenBuilder],
    raw_pk_ops: &[String],
    raw_merkle_paths: &[Vec<String>],
    raw_leaf_indices: &[usize],
    parsed_inputs: &ParsedInputs,
    anchor_ctx: &AnchorContext,
    padded_aud_list: &[F],
    h_aud_list: F,
) -> Result<(Vec<Proof<BN254>>, Vec<Vec<F>>), ApplicationError> {
    // ✅ PK는 한 번만 로드
    let pk = load_key_uncompressed::<ProvingKey<BN254>>(pk_path)
        .map_err(|e| ApplicationError::InvalidFormat(e.to_string()))?;

    let mut rng = OsRng;
    let mut proofs = Vec::with_capacity(Config::K);
    let mut public_inputs = Vec::with_capacity(Config::K);

    for i in 0..Config::K {
        // ---------------------------
        // Phase A(i): witness + h
        // ---------------------------
        let witness = builders[i]
            .build::<Config>(&raw_pk_ops[i])
            .map_err(|e| ApplicationError::InvalidFormat(e.to_string()))?;

        let leaf_idx = raw_leaf_indices[i];
        let path = build_mp(&raw_merkle_paths[i], leaf_idx)?;

        let circuit_factory = make_circuit_factory::<Config>(
            circuit_ctx,
            parsed_inputs,
            anchor_ctx,
            leaf_idx,
            witness,
            path,
            padded_aud_list,
            h_aud_list,
            i,
        );

        let (h, instance, w) = Groth16::<BN254>::create_proof_part1_witness_h(circuit_factory)
            .map_err(|e| ApplicationError::InvalidFormat(e.to_string()))?;

        // public input은 보존
        public_inputs.push(instance[1..].to_vec());

        // ---------------------------
        // Phase B(i): MSM
        // ---------------------------
        let r = F::rand(&mut rng);
        let s = F::rand(&mut rng);

        let proof = Groth16::<BN254>::create_proof_part2_msm(&pk, r, s, &h, &instance, &w)
            .map_err(|e| ApplicationError::InvalidFormat(e.to_string()))?;

        proofs.push(proof);

        // ✅ 여기서 h / w는 스코프 종료로 drop
    }

    Ok((proofs, public_inputs))
}
