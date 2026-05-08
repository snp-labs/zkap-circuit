//! The main ZKAP Groth16 R1CS circuit ([`ZkapCircuit`]).
//!
//! # L1 lock — do not edit constraint logic without a new trusted setup
//!
//! Every change to this file that touches constraint synthesis (variable allocation order,
//! `enforce_*` calls, phase sequencing) will alter the R1CS matrices and invalidate the
//! `ar1cs_blake3` 32-byte gate.  Before merging any such change, verify all six L1 layers:
//!
//! See `.omc/plans/2026-05-08-per-crate-refactor/00-cross-cutting-locks.md § L1` for the
//! full gate checklist (ar1cs_blake3, cs.num_constraints golden, R1CS matrix sha256, …).
//!
//! # Five-phase structure
//!
//! The single `generate_constraints` function encodes five sequential phases:
//! 1. **JWT authenticity & claim extraction** — SHA-256 + RSA-2048 + Base64 + claim indices
//! 2. **Issuer validation & execution binding** — Merkle membership + expiry equality
//! 3. **Threshold membership & anchor binding** — Poseidon hashes + product trick
//! 4. **Vandermonde + indices constraints** — selector boolean/cardinality/sparsity
//! 5. **Output binding** — h_id, partial_rhs, lhs commitments
//!
//! # Mock circuit for trusted setup
//!
//! [`ZkapCircuit::generate_mock_circuit`] produces a circuit with zeroed public inputs and
//! placeholder witnesses suitable for `Groth16::setup`.  The R1CS matrix structure is
//! identical to the real proving circuit — only the concrete field values differ, which is
//! fine because Groth16 setup depends only on the matrix structure, not the values.
//!
//! `assert!(self.anchor.selector.len() == self.params.n as usize)` inside
//! `generate_constraints` is an intentional panic-on-host-bug guard — do **not** replace it
//! with `SynthesisError`; the panic path preserves R1CS variable allocation ordering.

#![allow(unused_variables)]
#![allow(unused_mut)]

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

use crate::types::CircuitConfig;
use crate::token::jwt_field::{jwt_exp_to_field, jwt_nonce_hex_to_field};
use crate::{
    ExposesPublicInputs, witness,
    token::{
        ClaimIndices,
        claimverifier::claim_extractor_v2,
        constraints::{ClaimIndicesVar, RSA2048VerifyGadget},
    },
};
use ark_utils::{
    comparison::enforce_less_than, packing::pack_decompose_bytes_unchecked, single_multiplexer,
    slice_efficient,
};
use gadget::{
    anchor::poseidon::{
        PoseidonAnchor,
        constraints::{
            PoseidonAnchorSchemeGadget, PoseidonAnchorVar, enforce_boolean_selectors,
            enforce_selector_cardinality,
        },
    },
    base64::{
        Base64TableVar, IndexBits,
        constraints::{Base64DecoderGadget, IndexBitsVar},
        get_base64_table,
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
};

/// The main Groth16 R1CS circuit for the ZKAP protocol.
///
/// Implements [`ConstraintSynthesizer`] and encodes the full five-phase proof statement:
/// JWT authenticity and claim extraction (SHA-256 + RSA-2048), issuer/key Merkle membership,
/// threshold anchor binding, audience membership, and output commitment.
///
/// Fields are grouped by logical role:
/// - `constants`: circuit constants fixed at setup time (Vandermonde matrix, Poseidon params, Base64 table)
/// - `public_inputs`: values exposed to the verifier (hanchor, h_a, root, h_sign_user_op, …)
/// - `jwt`: JWT witness (SHA-256 padding, Base64 index bits, RSA key and signature)
/// - `anchor`: threshold anchor witness (anchor polynomial, selector, a-vector)
/// - `merkle`: Merkle path and leaf index
/// - `audience`: padded audience list
/// - `misc`: blinding randomness
///
/// Construct via [`ZkapCircuit::from_input`] for proving, or [`ZkapCircuit::generate_mock_circuit`]
/// for trusted setup.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ZkapCircuit<C, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
{
    /// Circuit configuration (runtime parameters)
    pub params: CircuitConfig,
    /// Circuit constants (determined at setup time)
    pub constants: witness::CircuitConstants<C::BaseField>,
    /// Public inputs (exposed to the verifier)
    pub public_inputs: witness::CircuitPublicInputs<C::BaseField>,
    /// JWT-related witness
    pub jwt: witness::JwtWitness,
    /// Anchor/Threshold witness
    pub anchor: witness::AnchorWitness<C::BaseField>,
    /// Merkle tree witness
    pub merkle: witness::MerkleWitness<C::BaseField>,
    /// Audience witness
    pub audience: witness::AudienceWitness<C::BaseField>,
    /// Miscellaneous witness
    pub misc: witness::MiscWitness<C::BaseField>,
    /// Phantom data for type parameters
    _phantom: PhantomData<BNP>,
}

impl<C, BNP> ConstraintSynthesizer<C::BaseField> for ZkapCircuit<C, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>,
    ) -> ark_relations::r1cs::Result<()> {
        assert!(self.anchor.selector.len() == self.params.n as usize);
        // Implement the constraint generation logic here

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
        let hanchor =
            FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.hanchor))?;

        let h_a = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.h_a))?;

        let root = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.root))?;

        let h_sign_user_op =
            FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.h_sign_user_op))?;

        let jwt_exp =
            FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.jwt_exp))?;

        let partial_rhs =
            FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.partial_rhs))?;

        let lhs = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.lhs))?;

        let h_aud_list =
            FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.public_inputs.h_aud_list))?;

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
                .anchor
                .selector
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

        let token_claim = Vec::<ClaimIndicesVar<C::BaseField>>::new_witness(cs.clone(), || {
            Ok(self.jwt.claim_indices)
        })?;

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

        // Enforce RSA public exponent e == 65537, preventing substitution of weak exponents.
        let expected_e = BigNatVar::<C::BaseField, BNP>::constant(&BigNat::from(
            gadget::constants::RSA_DEFAULT_EXPONENT,
        ))?;
        pk_op.e.enforce_equal_when_carried(&expected_e)?;

        let signature_op =
            SignatureVar::<C::BaseField, BNP>::new_witness(cs.clone(), || Ok(self.jwt.sig))?;

        let total_len =
            UInt16::<C::BaseField>::new_witness(cs.clone(), || Ok(self.jwt.total_len as u16))?;

        let pad_start_byte_idx = UInt16::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(self.jwt.pad_start_byte_idx as u16)
        })?;

        // ============ Audience Witness ============
        let aud_list =
            Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || Ok(self.audience.aud_list))?;

        let zero = FpVar::<C::BaseField>::Constant(C::BaseField::from(0u64));
        let one = FpVar::<C::BaseField>::Constant(C::BaseField::from(1u64));

        // ============================================================
        // [Phase 1] JWT Authenticity & Claim Extraction
        // ============================================================

        // [1.1] SHA256 Full Digest (from initial H constants) + RSA-2048 signature verification
        let mut digest = SHA256Gadget::<C::BaseField>::digest_full_with_pad_checked(
            &sha_pad_jwt_b64,
            nblocks,
            &total_len,
            &pad_start_byte_idx,
        )?
        .to_bytes_le()?;

        let result = RSA2048VerifyGadget::verify_opt(&mut digest, &signature_op, &pk_op)?;
        result.enforce_equal(&Boolean::TRUE)?;

        // [1.2] Base64 decoding and claim extraction
        let sha_pad_jwt_b64_to_fp = sha_pad_jwt_b64
            .iter()
            .map(|u8| u8.to_fp())
            .collect::<ark_relations::r1cs::Result<Vec<_>>>()?;

        // Bind JWT payload boundary to the '.' separator positions.
        // If payload_offset_b64/payload_len_b64 are independent of the actual JWT '.' position,
        // an attacker could designate arbitrary regions (e.g. header) as payload to forge claims.
        let dot_char = FpVar::<C::BaseField>::Constant(C::BaseField::from(b'.' as u64));
        let payload_offset_fp = Boolean::le_bits_to_fp(&payload_offset_b64.to_bits_le()?)?;
        let payload_len_fp = Boolean::le_bits_to_fp(&payload_len_b64.to_bits_le()?)?;

        // Defense in depth: payload_offset >= 1 (offset=0 causes field underflow)
        enforce_less_than(
            &zero.to_bits_le_with_top_bits_zero(16)?.0,
            &payload_offset_fp.to_bits_le_with_top_bits_zero(16)?.0,
        )?;

        // Defense in depth: payload_offset + payload_len < buffer_len (prevent buffer overrun)
        let buf_len =
            FpVar::<C::BaseField>::Constant(C::BaseField::from(sha_pad_jwt_b64_to_fp.len() as u64));
        let second_dot_idx = &payload_offset_fp + &payload_len_fp;
        enforce_less_than(
            &second_dot_idx.to_bits_le_with_top_bits_zero(16)?.0,
            &buf_len.to_bits_le_with_top_bits_zero(16)?.0,
        )?;

        // First '.': immediately before payload start (between header and payload)
        let first_dot_idx = &payload_offset_fp - &one;
        // Binary tree selector: O(log n) vs O(n) constraints
        // sha_pad_jwt_b64_to_fp.len() == MAX_JWT_B64_LEN == 1024 == 2^10, so 10 bits suffice
        let first_dot_bits = first_dot_idx.to_bits_le()?;
        let first_dot_char =
            ark_utils::select_array_element(&sha_pad_jwt_b64_to_fp, &first_dot_bits[..10])?;

        first_dot_char.enforce_equal(&dot_char)?;

        // Structurally bind payload end position to the SHA-256 padding start position.
        // The SHA-256 gadget already verifies buffer[pad_start_byte_idx] == 0x80,
        // so binding the position alone is sufficient here
        let pad_start_fp = pad_start_byte_idx.to_fp()?;
        second_dot_idx.enforce_equal(&pad_start_fp)?;

        let payload_b64 = slice_efficient(
            &sha_pad_jwt_b64_to_fp,
            &payload_offset_b64,
            &payload_len_b64,
            self.params.max_payload_b64_len as usize,
        )?;

        let payload =
            Base64DecoderGadget::<C::BaseField>::decode(&base64_table, &payload_b64, &index_bits)?;

        let aud_bytes = claim_extractor_v2(
            "aud",
            &payload,
            &token_claim[0],
            self.params.max_aud_len as usize,
        )?;
        let exp_bytes = claim_extractor_v2(
            "exp",
            &payload,
            &token_claim[1],
            self.params.max_exp_len as usize,
        )?;
        let iss_bytes = claim_extractor_v2(
            "iss",
            &payload,
            &token_claim[2],
            self.params.max_iss_len as usize,
        )?;
        let nonce_bytes = claim_extractor_v2(
            "nonce",
            &payload,
            &token_claim[3],
            self.params.max_nonce_len as usize,
        )?;
        let sub_bytes = claim_extractor_v2(
            "sub",
            &payload,
            &token_claim[4],
            self.params.max_sub_len as usize,
        )?;
        // Convert to field elements and pack
        let aud = pack_decompose_bytes_unchecked(&aud_bytes)?;
        let exp = jwt_exp_to_field(&exp_bytes)?;
        let iss = pack_decompose_bytes_unchecked(&iss_bytes)?;

        let last_quote_index = token_claim[3]
            .value_len
            .wrapping_add(&UInt16::constant(u16::MAX));
        let nonce = jwt_nonce_hex_to_field(&nonce_bytes, &last_quote_index)?;
        let sub = pack_decompose_bytes_unchecked(&sub_bytes)?;

        // ============================================================
        // [Phase 2] Issuer Validation and Execution Binding
        // ============================================================

        // [2.1] Issuer-Public Key verification
        let leaf_inputs = [iss.clone(), pk_op.n.limbs.clone()].concat();
        let leaf = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &leaf_inputs)?;

        path.set_leaf_position(leaf_idx.to_bits_le()?);
        let result = path.verify_membership(&poseidon_param, &poseidon_param, &root, &[leaf])?;
        result.enforce_equal(&Boolean::TRUE)?;

        // [2.2] expiry check: jwt_exp == exp
        exp.enforce_equal(&jwt_exp)?;

        // ============================================================
        // [Phase 3] Threshold Membership and Anchor Binding (Binding)
        // ============================================================

        // h_anchor == Poseidon(anchor)
        let target_hanchor = chain_hash_gadget(cs.clone(), &poseidon_param, &anchor.anchor)?;
        target_hanchor.enforce_equal(&hanchor)?;

        // Nonce binding: nonce == Poseidon(h_sign_userop, random)
        let nonce_inputs = vec![h_sign_user_op, random.clone()];
        let target_nonce =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &nonce_inputs)?;
        target_nonce.enforce_equal(&nonce)?;

        // aud membership: Poseidon(aud) ∈ aud_list (product trick)
        let target_aud = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &aud)?;
        let mut product = FpVar::<C::BaseField>::Constant(C::BaseField::from(1u64));
        for valid_aud in aud_list.iter() {
            let diff = target_aud.clone() - valid_aud.clone();
            product *= diff;
        }
        product.enforce_equal(&zero)?;

        // h_a == Poseidon(a, random)
        let mut a_inputs = a.clone();
        a_inputs.push(random.clone());
        let target_h_a = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &a_inputs)?;
        target_h_a.enforce_equal(&h_a)?;

        // h_aud_list == Poseidon(aud_list)
        let target_h_aud_list =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &aud_list)?;
        target_h_aud_list.enforce_equal(&h_aud_list)?;

        // ============================================================
        // [Phase 4] Threshold logic (Vandermonde + indices constraints)
        // ============================================================

        PoseidonAnchorSchemeGadget::<C::BaseField>::enforce_a_nonzero(&a)?;

        let b = vandermonde_matrix.vector_mul_matrix(&a)?;

        // indices constraints:
        //  1) boolean
        //  2) Σ indices = k
        //  3) indices[current_idx] = 1
        //  4) b sparsity helper
        enforce_boolean_selectors(&indices)?;

        PoseidonAnchorSchemeGadget::<C::BaseField>::enforce_b_sparsity(&b, &indices)?;

        let k_fp = FpVar::<C::BaseField>::Constant(C::BaseField::from(self.params.k));
        enforce_selector_cardinality(&indices, &k_fp)?;

        let is_one = single_multiplexer(&indices, &current_idx)?;
        is_one.enforce_equal(&one)?;

        // random != 0
        random.enforce_not_equal(&zero)?;

        // current_idx < N
        let n = FpVar::<C::BaseField>::new_constant(cs.clone(), C::BaseField::from(self.params.n))?;
        enforce_less_than(
            &current_idx.to_bits_le_with_top_bits_zero(8)?.0,
            &n.to_bits_le_with_top_bits_zero(8)?.0,
        )?;

        // ============================================================
        // [Phase 5] Output binding (h_id, partial_rhs, lhs)
        // ============================================================

        // h_id = Poseidon(current_idx, Poseidon(aud, iss, sub))
        let mut h_id_inputs = Vec::<FpVar<C::BaseField>>::new();
        h_id_inputs.extend_from_slice(&aud);
        h_id_inputs.extend_from_slice(&iss);
        h_id_inputs.extend_from_slice(&sub);
        let h_id_ = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &h_id_inputs)?;
        let h_id_inputs_with_index = vec![current_idx.clone(), h_id_.clone()];

        let h_id =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &h_id_inputs_with_index)?;

        // partial_rhs[current_idx] = b[current_idx] * h_id * random
        // lhs = <a, anchor> * random
        let beta = single_multiplexer(&b, &current_idx)?;
        let calc_rhs = beta * h_id.clone() * random.clone();
        calc_rhs.enforce_equal(&partial_rhs)?;

        let lhs_ = PoseidonAnchorSchemeGadget::<C::BaseField>::inner_product(&anchor.anchor, &a)?;
        let calc_lhs = lhs_ * random.clone();
        calc_lhs.enforce_equal(&lhs)?;

        Ok(())
    }
}

impl<C, BNP> ZkapCircuit<C, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
{
    pub fn generate_mock_circuit(params: &CircuitConfig) -> Self {
        let n = params.n as usize;
        let k = params.k as usize;
        Self {
            params: params.clone(),
            constants: witness::CircuitConstants {
                vandermonde_matrix: VandermondeMatrix::new(n, k),
                poseidon_param: get_poseidon_params(),
                base64_table: get_base64_table(),
            },
            public_inputs: witness::CircuitPublicInputs {
                hanchor: C::BaseField::default(),
                h_a: C::BaseField::default(),
                root: C::BaseField::default(),
                h_sign_user_op: C::BaseField::default(),
                jwt_exp: C::BaseField::default(),
                partial_rhs: C::BaseField::default(),
                lhs: C::BaseField::default(),
                h_aud_list: C::BaseField::default(),
            },
            jwt: witness::JwtWitness {
                nblocks: 0,
                claim_indices: vec![ClaimIndices::default(); params.claims.len()],
                pay_offset_b64: 0,
                pay_len_b64: 0,
                sha_pad_jwt_b64: vec![0; params.max_jwt_b64_len as usize],
                index_bits: IndexBits::empty(params.max_payload_b64_len as usize),
                pk: PublicKey::empty(),
                sig: Signature::default(),
                total_len: 0,
                pad_start_byte_idx: 0,
            },
            anchor: witness::AnchorWitness {
                anchor: PoseidonAnchor::empty(n - k + 1),
                a: vec![C::BaseField::default(); n - k + 1],
                selector: vec![0; n],
                current_idx: 0,
            },
            merkle: witness::MerkleWitness {
                path: Path::empty(params.tree_height as usize),
                leaf_idx: 0,
            },
            audience: witness::AudienceWitness {
                aud_list: vec![C::BaseField::default(); params.num_audience_limit as usize],
            },
            misc: witness::MiscWitness {
                random: C::BaseField::default(),
            },
            _phantom: PhantomData,
        }
    }

    /// Create circuit from structured input (recommended)
    pub fn from_input(input: witness::ZkapCircuitInput<C::BaseField>) -> Self {
        Self {
            params: input.params,
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

impl<C, BNP> ExposesPublicInputs<C::BaseField> for ZkapCircuit<C, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
{
    fn public_inputs(&self) -> Vec<C::BaseField> {
        self.public_inputs.to_vec()
    }
}
