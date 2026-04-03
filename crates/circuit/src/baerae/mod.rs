#![allow(unused_variables)]
#![allow(unused_mut)]

pub mod input;

use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget,
        poseidon::{self, constraints::CRHGadget as PoseidonCRHGadget},
    },
    merkle_tree::{Path, constraints::PathVar},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{Boolean, ToBitsGadget, ToBytesGadget},
    uint8::UInt8,
    uint16::UInt16,
};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::*;
use std::marker::PhantomData;

use crate::{
    ExposesPublicInputs,
    token::{
        ClaimIndices,
        claimverifier::claim_extractor_v2,
        constraints::{ClaimIndicesVar, RSA2048VerifyGadget},
    },
};
use crate::constants::ZkPasskeyConfig;
use gadget::{
    anchor::poseidon::{
        PoseidonAnchor,
        constraints::{
            PoseidonAnchorSchemeGadget, PoseidonAnchorVar, enforce_boolean_selector_debug,
            enforce_selector_cardinality_debug,
        },
    },
    base64::{
        Base64TableVar,
        constraints::{Base64DecoderGadget, IndexBitsVar},
        get_base64_table,
        IndexBits,
    },
    bigint::{
        constraints::{BigNatCircuitParams, BigNatVar},
        utils::BigNat,
    },
    hashes::{
        poseidon::{constraints::chain_hash_gadget, get_poseidon_params},
        sha256::constraints::SHA256Gadget,
    },
    matrix::{VandermondeMatrix, constraints::VandermondeMatrixVar},
    merkletree::tree_config::{Empty, MerkleTreeParams, MerkleTreeParamsVar},
    signature::rsa::{
        PublicKey, Signature,
        constraints::{PublicKeyVar, SignatureVar},
    },
    utils::{
        bit_bytes::pack_decompose_bytes_unchecked,
        comparison::is_less_than,
        single_multiplexer, slice_v2,
        string_v2::{jwt_exp_to_field, jwt_nonce_hex_to_field},
    },
};

/// ZK-Passkey circuit (Baerae Lightweight)
///
/// Fields organized by logical group:
/// - `constants`: circuit constants (Vandermonde, Poseidon, Base64)
/// - `public_inputs`: inputs exposed to the verifier
/// - `jwt`: JWT-related witness (SHA256, Base64, RSA)
/// - `anchor`: Threshold anchor witness
/// - `merkle`: Merkle tree witness
/// - `audience`: Audience list witness
/// - `misc`: miscellaneous witness (random)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct BaeraeLightWeightCircuit<C, BNP, Config>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
    Config: ZkPasskeyConfig + Send + Sync,
{
    /// Circuit constants (determined at setup time)
    pub constants: input::CircuitConstants<C::BaseField>,
    /// Public inputs (exposed to the verifier)
    pub public_inputs: input::CircuitPublicInputs<C::BaseField>,
    /// JWT-related witness
    pub jwt: input::JwtWitness,
    /// Anchor/Threshold witness
    pub anchor: input::AnchorWitness<C::BaseField>,
    /// Merkle tree witness
    pub merkle: input::MerkleWitness<C::BaseField>,
    /// Audience witness
    pub audience: input::AudienceWitness<C::BaseField>,
    /// Miscellaneous witness
    pub misc: input::MiscWitness<C::BaseField>,
    /// Phantom data for type parameters
    _phantom: PhantomData<(BNP, Config)>,
}

impl<C, BNP, Config> ConstraintSynthesizer<C::BaseField>
    for BaeraeLightWeightCircuit<C, BNP, Config>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
    Config: ZkPasskeyConfig + Send + Sync,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>,
    ) -> ark_relations::r1cs::Result<()> {
        assert!(self.anchor.selector.len() == Config::N);
        // Implement the constraint generation logic here

        let initial_constraints = cs.num_constraints();
        let mut cs_last = initial_constraints;

        // ============ Constants ============
        let vandermonde_matrix = VandermondeMatrixVar::<C::BaseField>::new_constant(
            cs.clone(),
            self.constants.vandermonde_matrix,
        )?;

        let poseidon_param = poseidon::constraints::CRHParametersVar::<C::BaseField>::new_constant(
            cs.clone(),
            self.constants.poseidon_param,
        )?;

        let base64_table =
            Base64TableVar::<C::BaseField>::new_constant(cs.clone(), self.constants.base64_table)?;

        // ============ Public Inputs ============
        let hanchor = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.hanchor))?;

        let h_a = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.h_a))?;

        let root = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.root))?;

        let h_sign_user_op =
            FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.h_sign_user_op))?;

        let jwt_exp = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.jwt_exp))?;

        let partial_rhs = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.partial_rhs))?;

        let lhs = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.lhs))?;

        let h_aud_list = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.h_aud_list))?;

        // ============ Misc Witness ============
        let random = FpVar::<C::BaseField>::new_witness(cs.clone(), || Ok(self.misc.random))?;

        // ============ Merkle Witness ============
        let leaf_idx =
            UInt16::<C::BaseField>::new_witness(cs.clone(), || Ok(self.merkle.leaf_idx as u16))?;

        let mut path = PathVar::<
            MerkleTreeParams<C::BaseField>,
            C::BaseField,
            MerkleTreeParamsVar<C::BaseField>,
        >::new_witness(cs.clone(), || Ok(self.merkle.path))?;

        // ============ Anchor Witness ============
        let anchor =
            PoseidonAnchorVar::<C::BaseField>::new_witness(cs.clone(), || Ok(self.anchor.anchor))?;

        let a = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || Ok(self.anchor.a))?;

        let indices = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || {
            Ok(self
                .anchor.selector
                .iter()
                .map(|&i| C::BaseField::from(i as u64))
                .collect::<Vec<C::BaseField>>())
        })?;

        let current_idx = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(C::BaseField::from(self.anchor.current_idx as u64))
        })?;

        // ============ JWT Witness ============
        let nblocks = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(C::BaseField::from(self.jwt.nblocks as u64))
        })?;

        let token_claim =
            Vec::<ClaimIndicesVar<C::BaseField>>::new_witness(cs.clone(), || Ok(self.jwt.claim_indices))?;

        let payload_offset_b64 =
            UInt16::<C::BaseField>::new_witness(cs.clone(), || Ok(self.jwt.pay_offset_b64 as u16))?;

        let payload_len_b64 =
            UInt16::<C::BaseField>::new_witness(cs.clone(), || Ok(self.jwt.pay_len_b64 as u16))?;

        let sha_pad_jwt_b64 = Vec::<UInt8<C::BaseField>>::new_witness(cs.clone(), || {
            Ok(self.jwt.sha_pad_jwt_b64.clone())
        })?;

        let index_bits =
            IndexBitsVar::<C::BaseField>::new_witness(cs.clone(), || Ok(self.jwt.index_bits))?;

        let pk_op = PublicKeyVar::<C::BaseField, BNP>::new_witness(cs.clone(), || Ok(self.jwt.pk))?;

        // [ZKAPCIR-001] Enforce RSA e=65537
        let expected_e = BigNatVar::<C::BaseField, BNP>::constant(&BigNat::from(gadget::constants::RSA_DEFAULT_EXPONENT))?;
        pk_op.e.enforce_equal_when_carried(&expected_e)?;

        let signature_op =
            SignatureVar::<C::BaseField, BNP>::new_witness(cs.clone(), || Ok(self.jwt.sig))?;

        let total_len =
            UInt16::<C::BaseField>::new_witness(cs.clone(), || Ok(self.jwt.total_len as u16))?;

        let pad_start_byte_idx =
            UInt16::<C::BaseField>::new_witness(
                cs.clone(),
                || Ok(self.jwt.pad_start_byte_idx as u16),
            )?;

        // ============ Audience Witness ============
        let aud_list = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || Ok(self.audience.aud_list))?;

        let zero = FpVar::<C::BaseField>::Constant(C::BaseField::from(0u64));
        let one = FpVar::<C::BaseField>::Constant(C::BaseField::from(1u64));

        gadget::dbg_cs_total!(&cs, "Initial constraints");
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "[Setup] Variable allocation");

        // ============================================================
        // [Phase 1] JWT Authenticity & Claim Extraction
        // ============================================================
        let phase1_start = cs.num_constraints();
        let mut phase1_total_last = phase1_start;

        // [1.1] SHA256 Full Digest (from initial H constants) + RSA-2048 signature verification
        let mut digest = SHA256Gadget::<C::BaseField>::digest_full_with_pad_checked(
            &sha_pad_jwt_b64,
            nblocks,
            &total_len,
            &pad_start_byte_idx,
        )?
        .to_bytes_le()?;

        let result = RSA2048VerifyGadget::verify_opt(&mut digest, &signature_op, &pk_op)?;
        gadget::enforce_true_debug!("RSA Verification", result)?;
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - RSA Verification");

        // [1.2] Base64 decoding and claim extraction
        let sha_pad_jwt_b64_to_fp = sha_pad_jwt_b64
            .iter()
            .map(|u8| u8.to_fp())
            .collect::<ark_relations::r1cs::Result<Vec<_>>>()?;

        // [ZKAPCIR-002] Bind JWT payload boundary to '.' separator
        // If payload_offset_b64/payload_len_b64 are independent of the actual JWT '.' position,
        // an attacker could designate arbitrary regions (e.g. header) as payload to forge claims.
        let dot_char = FpVar::<C::BaseField>::Constant(C::BaseField::from(b'.' as u64));
        let payload_offset_fp = Boolean::le_bits_to_fp(&payload_offset_b64.to_bits_le()?)?;
        let payload_len_fp = Boolean::le_bits_to_fp(&payload_len_b64.to_bits_le()?)?;

        // Defense in depth: payload_offset >= 1 (offset=0 causes field underflow)
        let offset_ge_1 = is_less_than(
            &zero.to_bits_le_with_top_bits_zero(16)?.0,
            &payload_offset_fp.to_bits_le_with_top_bits_zero(16)?.0,
        )?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Payload Offset >= 1");

        gadget::enforce_true_debug!("Payload Offset >= 1", offset_ge_1)?;

        // Defense in depth: payload_offset + payload_len < buffer_len (prevent buffer overrun)
        let buf_len = FpVar::<C::BaseField>::Constant(C::BaseField::from(
            sha_pad_jwt_b64_to_fp.len() as u64,
        ));
        let second_dot_idx = &payload_offset_fp + &payload_len_fp;
        let idx_in_range = is_less_than(
            &second_dot_idx.to_bits_le_with_top_bits_zero(16)?.0,
            &buf_len.to_bits_le_with_top_bits_zero(16)?.0,
        )?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Payload Index Range Check");

        gadget::enforce_true_debug!("Payload Index Range Check", idx_in_range)?;

        // First '.': immediately before payload start (between header and payload)
        let first_dot_idx = &payload_offset_fp - &one;
        // Binary tree selector: O(log n) vs O(n) constraints
        // sha_pad_jwt_b64_to_fp.len() == MAX_JWT_B64_LEN == 1024 == 2^10, so 10 bits suffice
        let first_dot_bits = first_dot_idx.to_bits_le()?;
        let first_dot_char =
            ark_utils::select_array_element(&sha_pad_jwt_b64_to_fp, &first_dot_bits[..10])?;

        gadget::enforce_eq_debug!("Payload Boundary Binding", first_dot_char, dot_char)?;

        // ZKAPCIR-002: structurally bind payload end position == SHA-256 padding start position
        // The SHA-256 gadget already verifies buffer[pad_start_byte_idx] == 0x80,
        // so binding the position alone is sufficient here
        let pad_start_fp = pad_start_byte_idx.to_fp()?;
        second_dot_idx.enforce_equal(&pad_start_fp)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Payload Boundary Check");

        let payload_b64 = slice_v2::slice_efficient(
            &sha_pad_jwt_b64_to_fp,
            &payload_offset_b64,
            &payload_len_b64,
            Config::MAX_PAYLOAD_B64_LEN,
        )?;

        let payload = Base64DecoderGadget::<C::BaseField>::decode(
            &base64_table,
            &payload_b64,
            &index_bits,
        )?;
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Base64 Decoding");

        let aud_bytes = claim_extractor_v2("aud", &payload, &token_claim[0], Config::MAX_AUD_LEN)?;
        let exp_bytes = claim_extractor_v2("exp", &payload, &token_claim[1], Config::MAX_EXP_LEN)?;
        let iss_bytes = claim_extractor_v2("iss", &payload, &token_claim[2], Config::MAX_ISS_LEN)?;
        let nonce_bytes =
            claim_extractor_v2("nonce", &payload, &token_claim[3], Config::MAX_NONCE_LEN)?;
        let sub_bytes = claim_extractor_v2("sub", &payload, &token_claim[4], Config::MAX_SUB_LEN)?;
        // Convert to field elements and pack
        let aud = pack_decompose_bytes_unchecked(&aud_bytes)?;
        let exp = jwt_exp_to_field(&exp_bytes)?;
        let iss = pack_decompose_bytes_unchecked(&iss_bytes)?;

        let last_quote_index = token_claim[3]
            .value_len
            .wrapping_add(&UInt16::constant(u16::MAX));
        let nonce = jwt_nonce_hex_to_field(&nonce_bytes, &last_quote_index)?;
        let sub = pack_decompose_bytes_unchecked(&sub_bytes)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Claims Extraction");
        gadget::dbg_cs_delta!(
            &cs,
            &mut phase1_total_last,
            "[Phase 1] JWT Authenticity & Claim Extraction Total"
        );

        // ============================================================
        // [Phase 2] Issuer Validation and Execution Binding
        // ============================================================
        let phase2_start = cs.num_constraints();
        let mut phase2_total_last = phase2_start;

        // [2.1] Issuer-Public Key verification
        let leaf_inputs = [iss.clone(), pk_op.n.limbs.clone()].concat();
        let leaf = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &leaf_inputs)?;

        path.set_leaf_position(leaf_idx.to_bits_le()?);
        let result = path.verify_membership(&poseidon_param, &poseidon_param, &root, &[leaf])?;
        gadget::enforce_true_debug!("MerkleVerify", result)?;
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Issuer-PublicKey MerkleVerify");

        // [2.2] expiry check: jwt_exp == exp
        let result = exp.is_eq(&jwt_exp)?;
        gadget::enforce_true_debug!("Expiry Check (jwt_exp == exp)", result)?;
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Expiry Check");

        gadget::dbg_cs_delta!(&cs, &mut phase2_total_last, "[Phase 2] Validation Total");

        // ============================================================
        // [Phase 3] Threshold Membership and Anchor Binding (Binding)
        // ============================================================
        let phase3_start = cs.num_constraints();
        let mut phase3_total_last = phase3_start;

        // h_anchor == Poseidon(anchor)
        let target_hanchor = chain_hash_gadget(cs.clone(), &poseidon_param, &anchor.anchor)?;
        gadget::enforce_eq_debug!("Anchor Binding", target_hanchor, hanchor)?;
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Anchor Binding");

        // Nonce binding: nonce == Poseidon(h_sign_userop, random)
        let nonce_inputs = vec![h_sign_user_op, random.clone()];
        let target_nonce =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &nonce_inputs)?;
        gadget::enforce_eq_debug!("Nonce Binding", target_nonce, nonce)?;
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Nonce Binding");

        // aud membership: Poseidon(aud) ∈ aud_list (product trick)
        let target_aud = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &aud)?;
        let mut product = FpVar::<C::BaseField>::Constant(C::BaseField::from(1u64));
        for valid_aud in aud_list.iter() {
            let diff = target_aud.clone() - valid_aud.clone();
            product *= diff;
        }
        gadget::enforce_eq_debug!("Aud Membership", product, zero)?;
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Aud Membership");

        // h_a == Poseidon(a, random)
        let mut a_inputs = a.clone();
        a_inputs.push(random.clone());
        let target_h_a = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &a_inputs)?;
        gadget::enforce_eq_debug!("Context Binding", target_h_a, h_a)?;
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Context Binding");

        // h_aud_list == Poseidon(aud_list)
        let target_h_aud_list =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &aud_list)?;
        gadget::enforce_eq_debug!("Aud List Binding", target_h_aud_list, h_aud_list)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Aud List Binding");
        gadget::dbg_cs_delta!(&cs, &mut phase3_total_last, "[Phase 3] Binding Total");

        // ============================================================
        // [Phase 4] Threshold logic (Vandermonde + indices constraints)
        // ============================================================
        let phase4_start = cs.num_constraints();
        let mut phase4_total_last = phase4_start;

        let result = PoseidonAnchorSchemeGadget::<C::BaseField>::is_a_nonzero(&a)?;
        gadget::enforce_true_debug!("A Vector Nonzero", result)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - A Vector Nonzero");

        let b = vandermonde_matrix.vector_mul_matrix(&a)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Vandermonde Transform");

        // indices constraints:
        //  1) boolean
        //  2) Σ indices = k
        //  3) indices[current_idx] = 1
        //  4) b sparsity helper
        let result = enforce_boolean_selector_debug(&indices)?;
        result.enforce_equal(&Boolean::constant(true))?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Boolean Selectors");

        let result = PoseidonAnchorSchemeGadget::<C::BaseField>::is_b_sparsity(&b, &indices)?;
        gadget::enforce_true_debug!("Sparsity Check", result)?;

        let k_fp = FpVar::<C::BaseField>::Constant(C::BaseField::from(Config::K as u64));
        let result = enforce_selector_cardinality_debug(&indices, &k_fp)?;
        gadget::enforce_true_debug!("Selector Cardinality", result)?;
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Selector Cardinality");

        let is_one = single_multiplexer(&indices, &current_idx)?;
        is_one.enforce_equal(&one)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Current Idx One-hot");

        // random != 0
        random.enforce_not_equal(&zero)?;
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Random Nonzero");

        // current_idx < N
        let n =
            FpVar::<C::BaseField>::new_constant(cs.clone(), C::BaseField::from(Config::N as u8))?;
        let result = is_less_than(
            &current_idx.to_bits_le_with_top_bits_zero(8)?.0,
            &n.to_bits_le_with_top_bits_zero(8)?.0,
        )?;
        gadget::enforce_true_debug!("Index Range Check", result)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Index Range Check");
        gadget::dbg_cs_delta!(&cs, &mut phase4_total_last, "[Phase 4] Logic Total");

        // ============================================================
        // [Phase 5] Output binding (h_id, partial_rhs, lhs)
        // ============================================================
        let phase5_start = cs.num_constraints();
        let mut phase5_total_last = phase5_start;

        // h_id = Poseidon(current_idx, Poseidon(aud, iss, sub))
        let mut h_id_inputs = Vec::<FpVar<C::BaseField>>::new();
        h_id_inputs.extend_from_slice(&aud);
        h_id_inputs.extend_from_slice(&iss);
        h_id_inputs.extend_from_slice(&sub);
        let h_id_ = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &h_id_inputs)?;
        let h_id_inputs_with_index = vec![current_idx.clone(), h_id_.clone()];

        let h_id =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &h_id_inputs_with_index)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Identity Hash");

        // partial_rhs[current_idx] = b[current_idx] * h_id * random
        // lhs = <a, anchor> * random
        let beta = single_multiplexer(&b, &current_idx)?;
        let calc_rhs = beta * h_id.clone() * random.clone();
        gadget::enforce_eq_debug!("RHS Calculation", calc_rhs, partial_rhs)?;

        let lhs_ = PoseidonAnchorSchemeGadget::<C::BaseField>::inner_product(&anchor.anchor, &a)?;
        let calc_lhs = lhs_ * random.clone();
        calc_lhs.enforce_equal(&lhs)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - RHS/LHS Calculation");

        gadget::dbg_cs_delta!(&cs, &mut phase5_total_last, "[Phase 5] Output Total");
        gadget::dbg_cs_total!(&cs, "Total constraints");

        Ok(())
    }
}

impl<C, BNP, Config> BaeraeLightWeightCircuit<C, BNP, Config>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
    Config: ZkPasskeyConfig + Send + Sync,
{
    pub fn generate_mock_circuit() -> Self {
        Self {
            constants: input::CircuitConstants {
                vandermonde_matrix: VandermondeMatrix::new(Config::N, Config::K),
                poseidon_param: get_poseidon_params(),
                base64_table: get_base64_table(),
            },
            public_inputs: input::CircuitPublicInputs {
                hanchor: C::BaseField::default(),
                h_a: C::BaseField::default(),
                root: C::BaseField::default(),
                h_sign_user_op: C::BaseField::default(),
                jwt_exp: C::BaseField::default(),
                partial_rhs: C::BaseField::default(),
                lhs: C::BaseField::default(),
                h_aud_list: C::BaseField::default(),
            },
            jwt: input::JwtWitness {
                nblocks: 0,
                claim_indices: vec![ClaimIndices::default(); Config::CLAIMS.len()],
                pay_offset_b64: 0,
                pay_len_b64: 0,
                sha_pad_jwt_b64: vec![0; Config::MAX_JWT_B64_LEN],
                index_bits: IndexBits::empty(Config::MAX_PAYLOAD_B64_LEN),
                pk: PublicKey::empty(),
                sig: Signature::default(),
                total_len: 0,
                pad_start_byte_idx: 0,
            },
            anchor: input::AnchorWitness {
                anchor: PoseidonAnchor::empty(Config::N - Config::K + 1),
                a: vec![C::BaseField::default(); Config::N - Config::K + 1],
                selector: vec![0; Config::N],
                current_idx: 0,
            },
            merkle: input::MerkleWitness {
                path: Path::empty(Config::TREE_HEIGHT),
                leaf_idx: 0,
            },
            audience: input::AudienceWitness {
                aud_list: vec![C::BaseField::default(); Config::NUM_AUDIENCE_LIMIT],
            },
            misc: input::MiscWitness {
                random: C::BaseField::default(),
            },
            _phantom: PhantomData,
        }
    }

    /// Create circuit from structured input (recommended)
    pub fn from_input(input: input::BaeraeCircuitInput<C::BaseField>) -> Self {
        Self {
            constants: input.constants,
            public_inputs: input.public_inputs,
            jwt: input.jwt,
            anchor: input.anchor,
            merkle: input.merkle,
            audience: input.audience,
            misc: input.misc,
            _phantom: PhantomData,
        }
    }
}

impl<C, BNP, Config> ExposesPublicInputs<C::BaseField> for BaeraeLightWeightCircuit<C, BNP, Config>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
    Config: ZkPasskeyConfig + Send + Sync,
{
    fn public_inputs(&self) -> Vec<C::BaseField> {
        self.public_inputs.to_vec()
    }
}
