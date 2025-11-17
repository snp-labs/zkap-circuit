use std::{marker::PhantomData, u16};

use ark_crypto_primitives::{
    crh::{
        CRHScheme, CRHSchemeGadget,
        poseidon::constraints::{CRHGadget, CRHParametersVar as PoseidonParameterVar},
    },
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::{CurveVar, GroupOpsBounds},
    uint8::UInt8,
    uint16::UInt16,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use gadget::{
    anchor::{
        constraints::AnchorSchemeGadget,
        poseidon::{
            PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorWitness,
            constraints::{
                PoseidonAnchorPublicKeyVar, PoseidonAnchorSchemeGadget, PoseidonAnchorVar,
                PoseidonAnchorWitnessVar,
            },
        },
    },
    base64::Base64TableVar,
    bigint::constraints::BigNatCircuitParams,
    hashes::poseidon::constraints::chain_hash_gadget,
    mekletree::{MerkleCircuitInput, constraints::MerkleCircuitInputVar},
    signature::schnorr::{
        DigestToScalarField, Signature,
        constraints::{ParametersVar, PublicKeyVar, SignatureVar, verify_pk_root_signature},
    },
    token::{
        claim::{ClaimIndices, constraints::ClaimIndicesVar},
        decode::{TokenPayloadB64, constraints::TokenPayloadB64Var},
        signature::{TokenSig, constraints::TokenSigVar},
    },
    utils::{hex_bytes_to_fp, pack_decompose_bytes, single_multiplexer},
};

use crate::zkpasskey::base::{
    BaseWitness, Circuit, CircuitArgs, CircuitConstant, CircuitConstantArgs, CircuitInstance,
    CircuitOps, Empty,
};

#[cfg(feature = "r1cs-debug")]
use common_gadget::debug::log_r1cs_eq;

pub type OptHashArgs<C, H> =
    CircuitArgs<C, H, PoseidonAnchorPublicKey<<C as CurveGroup>::BaseField>>;

pub type OptHashCircuit<C, H, CV, HG, BNP> = Circuit<
    CircuitConstant<C, H, PoseidonAnchorPublicKey<<C as CurveGroup>::BaseField>>,
    CircuitInstance<<C as CurveGroup>::BaseField>,
    OptHashWitness<C, CV, H, HG, BNP>,
>;

impl<C, H, CV, HG, BNP> ConstraintSynthesizer<C::BaseField> for OptHashCircuit<C, H, CV, HG, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme<Input = [u8]> + Clone + Send + Sync,
    H::Parameters: Send + Sync + Clone,
    H::Output: DigestToScalarField<C>,
    CV: CurveVar<C, C::BaseField>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
    HG: CRHSchemeGadget<H, C::BaseField, InputVar = [UInt8<C::BaseField>]> + Clone,
    BNP: BigNatCircuitParams + Send + Sync,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> ark_relations::r1cs::Result<()> {
        let anchor_key = PoseidonAnchorPublicKeyVar::<C::BaseField>::new_constant(
            cs.clone(),
            self.constant
                .anchor_key
                .ok_or(SynthesisError::AssignmentMissing)?,
        )?;

        let schnorr_param = ParametersVar::<C, CV, H, HG>::new_constant(
            cs.clone(),
            self.constant
                .base
                .schnorr_param
                .ok_or(SynthesisError::AssignmentMissing)?,
        )?;

        let schnorr_vk = PublicKeyVar::<C, CV>::new_constant(
            cs.clone(),
            self.constant
                .base
                .schnorr_vk
                .ok_or(SynthesisError::AssignmentMissing)?,
        )?;

        let poseidon_param = PoseidonParameterVar::<C::BaseField>::new_constant(
            cs.clone(),
            self.constant
                .base
                .poseidon_param
                .ok_or(SynthesisError::AssignmentMissing)?,
        )?;

        let base64_table = Base64TableVar::<C::BaseField>::new_constant(
            cs.clone(),
            self.constant
                .base
                .base64_table
                .ok_or(SynthesisError::AssignmentMissing)?,
        )?;

        let hanchor = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance
                .hanchor
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let root = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance.root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nonce = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance.nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let counter = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance
                .counter
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let h_x = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance.h_x.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let slot = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance.slot.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let h_slot = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            self.instance
                .h_slot
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let anchor = PoseidonAnchorVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness.anchor.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let signature = SignatureVar::<C, CV>::new_witness(cs.clone(), || {
            println!("Creating signature witness: {:?}", self.witness.base.signature);
            self.witness
                .base
                .signature
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let random = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness
                .base
                .random
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let mut mp = MerkleCircuitInputVar::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness
                .base
                .path
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let anchor_witness =
            PoseidonAnchorWitnessVar::<C::BaseField>::new_witness(cs.clone(), || {
                self.witness
                    .anchor_witness
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let token_claim = Vec::<ClaimIndicesVar<C::BaseField>>::new_witness(cs.clone(), || {
            self.witness
                .token_claim
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let token_payload = TokenPayloadB64Var::<C::BaseField>::new_witness(cs.clone(), || {
            self.witness
                .token_payload
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let mut token_sig = TokenSigVar::<C::BaseField, BNP>::new_witness(cs.clone(), || {
            self.witness
                .token_sig
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let z = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || {
            self.witness
                .z
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let slot_indices = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || {
            self.witness
                .slot_indices
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let k = self
            .constant
            .base
            .k
            .ok_or(SynthesisError::AssignmentMissing)?;
        let max_payload_len = self
            .constant
            .base
            .max_payload_len
            .ok_or(SynthesisError::AssignmentMissing)?;
        let max_iss_len = self
            .constant
            .base
            .max_iss_len
            .ok_or(SynthesisError::AssignmentMissing)?;
        let max_nonce_len = self
            .constant
            .base
            .max_nonce_len
            .ok_or(SynthesisError::AssignmentMissing)?;
        let max_sub_len = self
            .constant
            .base
            .max_sub_len
            .ok_or(SynthesisError::AssignmentMissing)?;

        // check 1: hanchor == H(anchor)
        let reconstructed_hanchor = chain_hash_gadget(cs.clone(), &poseidon_param, &anchor.anchor)?;

        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq(
            "hanchor check",
            &[reconstructed_hanchor.clone()],
            &[hanchor.clone()],
        );

        reconstructed_hanchor.enforce_equal(&hanchor)?;

        // check 2: verify root signature
        verify_pk_root_signature::<C, CV, H, HG>(
            cs.clone(),
            &schnorr_param,
            &root,
            &schnorr_vk,
            &signature,
        )?;

        // check 3: anchor verification
        PoseidonAnchorSchemeGadget::<C::BaseField>::verify(&anchor_key, &anchor, &anchor_witness)?;

        // check 4: token verification
        // check 4-1: verify token signature
        token_sig.verify_signature::<C>(token_payload.as_b64_bytes())?;

        // check 4-2: decode payload
        let payload = token_payload.decode_to_bytes(&base64_table, max_payload_len)?;

        // check 4-3: extract claims
        let ext_iss = token_claim[0].claim_extractor("\"iss\"", &payload, max_iss_len)?;
        let ext_nonce = token_claim[1].claim_extractor("\"nonce\"", &payload, max_nonce_len)?;
        let ext_sub = token_claim[2].claim_extractor("\"sub\"", &payload, max_sub_len)?;
        match ext_sub.value() {
            Ok(v) => println!("JWT Sub: {:?}", v),
            Err(_) => println!("JWT Sub: <missing>"),
        }

        // check 4-4: check nonce
        let quote_idx = token_claim[1]
            .value_len
            .wrapping_add(&UInt16::constant(u16::MAX));

        let jwt_nonce = hex_bytes_to_fp(cs.clone(), &ext_nonce, &quote_idx)?;

        match jwt_nonce.value() {
            Ok(v) => println!("JWT Nonce: {}", v.to_string()),
            Err(_) => println!("JWT Nonce: <missing>"),
        }

        let reconstructed_nonce = CRHGadget::<C::BaseField>::evaluate(
            &poseidon_param,
            &[nonce.clone(), counter.clone(), random.clone()],
        )?;

        match reconstructed_nonce.value() {
            Ok(v) => println!("reconstructed Nonce: {}", v.to_string()),
            Err(_) => println!("reconstructed Nonce: <missing>"),
        }

        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq(
            "Nonce Validity",
            &[reconstructed_nonce.clone()],
            &[jwt_nonce.clone()],
        );

        reconstructed_nonce.enforce_equal(&jwt_nonce)?;

        // check 5: verify OIDP public key
        let num_bytes_expected = (C::ScalarField::MODULUS_BIT_SIZE - 1) as usize / 8;
        let pad_char = FpVar::<C::BaseField>::Constant(C::BaseField::from(b'0'));
        let packed_iss = pack_decompose_bytes(&ext_iss, num_bytes_expected, &pad_char)?;

        let leaf_input: Vec<_> = vec![packed_iss, token_sig.pk.n.limbs.clone()].concat();
        let leaf = CRHGadget::<C::BaseField>::evaluate(&poseidon_param, &leaf_input)?;
        mp.enforce_equal_leaf(&leaf)?;
        mp.enforce_membership(&poseidon_param, &root)?;

        let unpacked_h_i =
            pack_decompose_bytes(&[ext_iss, ext_sub].concat(), num_bytes_expected, &pad_char)?;
        match unpacked_h_i.value() {
            Ok(v) => println!("unpacked_h_i: {:?}", v),
            Err(_) => println!("unpacked_h_i: <missing>"),
        }

        let idx = single_multiplexer(&slot_indices, &slot)?;

        let reconstructed_h =
            CRHGadget::<C::BaseField>::evaluate(&poseidon_param, &unpacked_h_i)?;
        
        let reconstructed_h_i =             CRHGadget::<C::BaseField>::evaluate(&poseidon_param, &[idx, reconstructed_h])?;

        let mut slot_input = slot_indices.clone();
        slot_input.push(random.clone());
        let reconstructed_h_slot =
            CRHGadget::<C::BaseField>::evaluate(&poseidon_param, &slot_input)?;
        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq(
            "h_slot check",
            &[reconstructed_h_slot.clone()],
            &[h_slot.clone()],
        );

        reconstructed_h_slot.enforce_equal(&h_slot)?;

        anchor_witness.enforce_slot_activation(&slot_indices, &slot)?;
        anchor_witness.enforce_k_non_zero(k)?;
        anchor_witness.enforce_h_i(&z, &reconstructed_h_i)?;

        // check 6: h_x == H(h)
        let mut h_x_input = anchor_witness.placed_secrets.clone();
        h_x_input.push(random.clone());
        let reconstructed_h_x = CRHGadget::<C::BaseField>::evaluate(&poseidon_param, &h_x_input)?;
        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq("h_x check", &[reconstructed_h_x.clone()], &[h_x.clone()]);

        reconstructed_h_x.enforce_equal(&h_x)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct OptHashWitness<C, CV, H, HG, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CV: CurveVar<C, C::BaseField>,
    H: CRHScheme,
    HG: CRHSchemeGadget<H, C::BaseField, InputVar = [UInt8<C::BaseField>]>,
    BNP: BigNatCircuitParams + Send + Sync,
{
    pub base: BaseWitness<C>,
    pub anchor: Option<PoseidonAnchor<C::BaseField>>,
    pub anchor_witness: Option<PoseidonAnchorWitness<C::BaseField>>,
    pub token_claim: Option<Vec<ClaimIndices>>,
    pub token_payload: Option<TokenPayloadB64>,
    pub token_sig: Option<TokenSig>,
    pub z: Option<Vec<C::BaseField>>, // h_i의 위치에 대한 one-hot 벡터. ex) [0, 1, 0, 0, 0, 0]
    pub slot_indices: Option<Vec<C::BaseField>>, // slot의 각 위치에 대한 인덱스 벡터 indices = [1, 3, 5] => 1,3,5 번째 h_i 사용.
    pub _phantom: PhantomData<(CV, H, HG, BNP)>,
}

#[derive(Clone)]
pub struct OptHashWitnessArgs {
    pub n: usize,
    pub k: usize,
    pub max_jwt_len: usize,
    pub max_payload_len: usize,
    pub keys_len: usize,
    pub tree_height: usize,
}

impl<C, CV, H, HG, BNP> Empty for OptHashWitness<C, CV, H, HG, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CV: CurveVar<C, C::BaseField>,
    H: CRHScheme,
    HG: CRHSchemeGadget<H, C::BaseField, InputVar = [UInt8<C::BaseField>]>,
    BNP: BigNatCircuitParams + Send + Sync,
{
    type Args = OptHashWitnessArgs;

    fn empty(args: Self::Args) -> Self {
        Self {
            base: BaseWitness::empty(args.tree_height),
            anchor: Some(PoseidonAnchor::empty(args.n)),
            anchor_witness: Some(PoseidonAnchorWitness::empty(args.n, args.k)),
            token_claim: Some(vec![ClaimIndices::default(); args.keys_len]),
            token_payload: Some(TokenPayloadB64::empty(
                args.max_jwt_len,
                args.max_payload_len,
            )),
            token_sig: Some(TokenSig::empty()),
            z: Some(vec![C::BaseField::default(); args.n]),
            slot_indices: Some(vec![C::BaseField::default(); args.k]),
            _phantom: PhantomData,
        }
    }
}

impl<C, H, CV, HG, BNP> CircuitOps<C::BaseField> for OptHashCircuit<C, H, CV, HG, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme<Input = [u8]> + Clone + Send + Sync,
    H::Parameters: Send + Sync + Clone,
    H::Output: DigestToScalarField<C>,
    HG: CRHSchemeGadget<H, C::BaseField, InputVar = [UInt8<C::BaseField>]> + Clone,
    CV: CurveVar<C, C::BaseField>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
    BNP: BigNatCircuitParams + Send + Sync,
{
    type Config = OptHashArgs<C, H>;

    fn empty(config: Self::Config) -> Self {
        let constant_args = CircuitConstantArgs {
            n: config.base.n,
            k: config.base.k,
            num_per_block: config.base.num_per_block,
            poseidon_param: config.base.poseidon_param,
            base64_table: config.base.base64_table,
            max_jwt_len: config.base.max_jwt_len,
            max_payload_len: config.base.max_payload_len,
            max_aud_len: config.base.max_aud_len,
            max_iss_len: config.base.max_iss_len,
            max_nonce_len: config.base.max_nonce_len,
            max_sub_len: config.base.max_sub_len,
            tree_height: config.base.tree_height,
            anchor_key: config.anchor_key,
            schnorr_param: config.base.schnorr_param,
            schnorr_vk: config.base.schnorr_vk,
        };

        let instance_args = ();

        let witness_args = OptHashWitnessArgs {
            n: config.base.n,
            k: config.base.k,
            max_jwt_len: config.base.max_jwt_len,
            max_payload_len: config.base.max_payload_len,
            tree_height: config.base.tree_height,
            keys_len: config.base.keys_len,
        };

        Self {
            constant: CircuitConstant::empty(constant_args),
            instance: CircuitInstance::empty(instance_args),
            witness: OptHashWitness::empty(witness_args),
        }
    }

    fn get_constraints(&self) -> usize {
        let cs = ark_relations::r1cs::ConstraintSystem::<C::BaseField>::new_ref();
        self.clone().generate_constraints(cs.clone()).unwrap();
        cs.num_constraints()
    }

    fn get_public_inputs(&self) -> Vec<C::BaseField> {
        let mut inputs = Vec::new();
        inputs.push(self.instance.hanchor.unwrap());
        inputs.push(self.instance.root.unwrap());
        inputs.push(self.instance.nonce.unwrap());
        inputs.push(self.instance.counter.unwrap());
        inputs.push(self.instance.h_x.unwrap());
        inputs.push(self.instance.slot.unwrap());
        inputs.push(self.instance.h_slot.unwrap());
        inputs
    }
}

impl<C, H, CV, HG, BNP> OptHashCircuit<C, H, CV, HG, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme<Input = [u8]> + Clone + Send + Sync,
    H::Parameters: Send + Sync + Clone,
    H::Output: DigestToScalarField<C>,
    HG: CRHSchemeGadget<H, C::BaseField, InputVar = [UInt8<C::BaseField>]> + Clone,
    CV: CurveVar<C, C::BaseField>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
    BNP: BigNatCircuitParams + Send + Sync,
{
    pub fn new(
        constant: CircuitConstant<C, H, PoseidonAnchorPublicKey<C::BaseField>>,
        instance: CircuitInstance<C::BaseField>,
        witness: OptHashWitness<C, CV, H, HG, BNP>,
    ) -> Self {
        Self {
            constant,
            instance,
            witness,
        }
    }

    /// Create an OptHashCircuit from a configuration
    pub fn from_config(config: OptHashArgs<C, H>) -> Self {
        <Self as CircuitOps<C::BaseField>>::empty(config)
    }

    /// Set the constant values for the circuit
    pub fn with_constant(
        mut self,
        constant: CircuitConstant<C, H, PoseidonAnchorPublicKey<C::BaseField>>,
    ) -> Self {
        self.constant = constant;
        self
    }

    /// Set the public instance values for the circuit
    pub fn with_instance(mut self, instance: CircuitInstance<C::BaseField>) -> Self {
        self.instance = instance;
        self
    }

    /// Set the witness values for the circuit
    pub fn with_witness(mut self, witness: OptHashWitness<C, CV, H, HG, BNP>) -> Self {
        self.witness = witness;
        self
    }

    /// Set the hanchor value
    pub fn with_hanchor(mut self, hanchor: C::BaseField) -> Self {
        self.instance.hanchor = Some(hanchor);
        self
    }

    /// Set the root value
    pub fn with_root(mut self, root: C::BaseField) -> Self {
        self.instance.root = Some(root);
        self
    }

    /// Set the nonce value
    pub fn with_nonce(mut self, nonce: C::BaseField) -> Self {
        self.instance.nonce = Some(nonce);
        self
    }

    /// Set the counter value
    pub fn with_counter(mut self, counter: C::BaseField) -> Self {
        self.instance.counter = Some(counter);
        self
    }

    /// Set the h_x value
    pub fn with_h_x(mut self, h_x: C::BaseField) -> Self {
        self.instance.h_x = Some(h_x);
        self
    }

    /// Set the slot value
    pub fn with_slot(mut self, slot: C::BaseField) -> Self {
        self.instance.slot = Some(slot);
        self
    }

    /// Set the h_slot value
    pub fn with_h_slot(mut self, h_slot: C::BaseField) -> Self {
        self.instance.h_slot = Some(h_slot);
        self
    }

    /// Set the signature
    pub fn with_signature(mut self, signature: Signature<C>) -> Self {
        self.witness.base.signature = Some(signature);
        self
    }

    /// Set the random value
    pub fn with_random(mut self, random: C::BaseField) -> Self {
        self.witness.base.random = Some(random);
        self
    }

    /// Set the merkle path
    pub fn with_merkle_path(mut self, path: MerkleCircuitInput<C::BaseField>) -> Self {
        self.witness.base.path = Some(path);
        self
    }

    /// Set the anchor
    pub fn with_anchor(mut self, anchor: PoseidonAnchor<C::BaseField>) -> Self {
        self.witness.anchor = Some(anchor);
        self
    }

    /// Set the anchor witness
    pub fn with_anchor_witness(
        mut self,
        anchor_witness: PoseidonAnchorWitness<C::BaseField>,
    ) -> Self {
        self.witness.anchor_witness = Some(anchor_witness);
        self
    }

    /// Set the token
    pub fn with_token_claim(mut self, token_claim: Vec<ClaimIndices>) -> Self {
        self.witness.token_claim = Some(token_claim);
        self
    }

    pub fn with_token_payload(mut self, token_payload: TokenPayloadB64) -> Self {
        self.witness.token_payload = Some(token_payload);
        self
    }

    pub fn with_token_sig(mut self, token_sig: TokenSig) -> Self {
        self.witness.token_sig = Some(token_sig);
        self
    }

    /// Set the z vector (one-hot vector indicating h_i position)
    pub fn with_z(mut self, z: Vec<C::BaseField>) -> Self {
        self.witness.z = Some(z);
        self
    }

    pub fn with_slot_indices(mut self, slot_indices: Vec<C::BaseField>) -> Self {
        self.witness.slot_indices = Some(slot_indices);
        self
    }

    /// Validate that all required fields are set
    pub fn validate(&self) -> Result<(), String> {
        // Check constant
        if self.constant.anchor_key.is_none() {
            return Err("anchor_key is missing".to_string());
        }
        if self.constant.base.schnorr_param.is_none() {
            return Err("schnorr_param is missing".to_string());
        }
        if self.constant.base.schnorr_vk.is_none() {
            return Err("schnorr_vk is missing".to_string());
        }
        if self.constant.base.poseidon_param.is_none() {
            return Err("poseidon_param is missing".to_string());
        }
        if self.constant.base.base64_table.is_none() {
            return Err("base64_table is missing".to_string());
        }

        // Check instance
        if self.instance.hanchor.is_none() {
            return Err("hanchor is missing".to_string());
        }
        if self.instance.root.is_none() {
            return Err("root is missing".to_string());
        }
        if self.instance.nonce.is_none() {
            return Err("nonce is missing".to_string());
        }
        if self.instance.counter.is_none() {
            return Err("counter is missing".to_string());
        }
        if self.instance.h_x.is_none() {
            return Err("h_x is missing".to_string());
        }

        // Check witness
        if self.witness.anchor.is_none() {
            return Err("anchor is missing".to_string());
        }
        if self.witness.anchor_witness.is_none() {
            return Err("anchor_witness is missing".to_string());
        }
        if self.witness.base.signature.is_none() {
            return Err("signature is missing".to_string());
        }
        if self.witness.base.random.is_none() {
            return Err("random is missing".to_string());
        }
        if self.witness.token_claim.is_none() {
            return Err("token_claim is missing".to_string());
        }
        if self.witness.token_payload.is_none() {
            return Err("token_payload is missing".to_string());
        }
        if self.witness.token_sig.is_none() {
            return Err("token_sig is missing".to_string());
        }
        if self.witness.z.is_none() {
            return Err("z vector is missing".to_string());
        }
        if self.witness.base.path.is_none() {
            return Err("merkle path is missing".to_string());
        }

        Ok(())
    }
}
