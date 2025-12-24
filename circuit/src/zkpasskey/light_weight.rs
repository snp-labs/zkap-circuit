use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        CRHScheme, CRHSchemeGadget,
        poseidon::constraints::{CRHGadget, CRHParametersVar},
    },
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::{CurveVar, GroupOpsBounds},
    prelude::{Boolean, ToBytesGadget},
    uint8::UInt8,
    uint16::UInt16,
};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
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
    base64::{Base64Table, Base64TableVar},
    bigint::constraints::BigNatCircuitParams,
    hashes::{poseidon::constraints::chain_hash_gadget, sha256::constraints::SHA256Gadget},
    mekletree::{MerkleCircuitInput, constraints::MerkleCircuitInputVar},
    signature::{
        rsa::{
            gadget::{PublicKeyVar as RsaPublicKeyVar, SignatureVar as RsaSignatureVar},
            native::{PublicKey as RsaPublicKey, Signature as RsaSignature},
        },
        schnorr::{
            DigestToScalarField, Parameters, PublicKey, Signature,
            constraints::{ParametersVar, PublicKeyVar, SignatureVar, verify_pk_root_signature},
        },
    },
    token::{
        claim::{ClaimIndices, constraints::ClaimIndicesVar},
        decode::{TokenPayloadB64, constraints::TokenPayloadB64Var},
        signature::constraints::RSA2048VerifyGadget,
    },
    utils::{hex_bytes_to_fp, pack_decompose_bytes, single_multiplexer},
};

use crate::zkpasskey::ExposesPublicInputs;

#[cfg(feature = "constraints-logging")]
use gadget::debug::log_r1cs_eq;

#[derive(Clone)]
pub struct LightWeightConstants<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme,
    H::Parameters: Send + Sync,
{
    pub n: Option<usize>,
    pub k: Option<usize>,
    pub anchor_key: Option<PoseidonAnchorPublicKey<C::BaseField>>,
    pub num_per_block: Option<usize>,
    pub max_jwt_len: Option<usize>,
    pub max_payload_len: Option<usize>,
    pub max_aud_len: Option<usize>,
    pub max_iss_len: Option<usize>,
    pub max_nonce_len: Option<usize>,
    pub max_sub_len: Option<usize>,
    pub tree_height: Option<usize>,
    pub schnorr_param: Option<Parameters<C, H>>,
    pub schnorr_vk: Option<PublicKey<C>>,
    pub poseidon_param: Option<PoseidonConfig<C::BaseField>>,
    pub base64_table: Option<Base64Table>,
    pub _phantom: PhantomData<C>,
}

#[derive(Clone)]
pub struct LightWeightInstance<F>
where
    F: PrimeField,
{
    pub hanchor: Option<F>,
    pub root: Option<F>,
    pub counter: Option<F>,
    pub nonce: Option<F>,
    pub h_x: Option<F>,
    pub slot: Option<F>,
    pub h_slot: Option<F>,
}

#[derive(Clone)]
pub struct LightWeightWitness<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    pub signature: Option<Signature<C>>,
    pub random: Option<C::BaseField>,
    pub path: Option<MerkleCircuitInput<C::BaseField>>,
    pub anchor: Option<PoseidonAnchor<C::BaseField>>,
    pub anchor_witness: Option<PoseidonAnchorWitness<C::BaseField>>,
    pub sha256: Option<Vec<u32>>,
    pub nblocks: Option<usize>,
    pub token_claim: Option<Vec<ClaimIndices>>,
    pub token_payload: Option<TokenPayloadB64>,
    pub pk_rsa: Option<RsaPublicKey>,
    pub signature_rsa: Option<RsaSignature>,
    pub z: Option<Vec<C::BaseField>>,
    pub slot_indices: Option<Vec<C::BaseField>>,
}

#[derive(Clone)]
pub struct LightWeightCircuit<C, H, HG, CV, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme,
    H::Parameters: Send + Sync,
    HG: CRHSchemeGadget<H, C::BaseField> + Clone,
    CV: CurveVar<C, C::BaseField>,
    BNP: BigNatCircuitParams,
{
    pub constant: LightWeightConstants<C, H>,
    pub instance: LightWeightInstance<C::BaseField>,
    pub witness: LightWeightWitness<C>,
    _phantom: PhantomData<(CV, BNP, HG)>,
}

impl<C, H, HG, CV, BNP> LightWeightCircuit<C, H, HG, CV, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme,
    H::Parameters: Send + Sync,
    HG: CRHSchemeGadget<H, C::BaseField> + Clone,
    CV: CurveVar<C, C::BaseField>,
    BNP: BigNatCircuitParams,
{
    pub fn new(
        constant: LightWeightConstants<C, H>,
        instance: LightWeightInstance<C::BaseField>,
        witness: LightWeightWitness<C>,
    ) -> Self {
        Self {
            constant,
            instance,
            witness,
            _phantom: PhantomData,
        }
    }

    pub fn empty(
        n: usize,
        k: usize,
        anchor_key: PoseidonAnchorPublicKey<C::BaseField>,
        num_per_block: usize,
        max_jwt_len: usize,
        max_payload_len: usize,
        max_aud_len: usize,
        max_iss_len: usize,
        max_nonce_len: usize,
        max_sub_len: usize,
        tree_height: usize,
        schnorr_param: Parameters<C, H>,
        schnorr_vk: PublicKey<C>,
        poseidon_param: PoseidonConfig<C::BaseField>,
        base64_table: Base64Table,
        keys_len: usize,
    ) -> Self {
        let constant = LightWeightConstants::<C, H> {
            n: Some(n),
            k: Some(k),
            anchor_key: Some(anchor_key),
            num_per_block: Some(num_per_block),
            max_jwt_len: Some(max_jwt_len),
            max_payload_len: Some(max_payload_len),
            max_aud_len: Some(max_aud_len),
            max_iss_len: Some(max_iss_len),
            max_nonce_len: Some(max_nonce_len),
            max_sub_len: Some(max_sub_len),
            tree_height: Some(tree_height),
            schnorr_param: Some(schnorr_param),
            schnorr_vk: Some(schnorr_vk),
            poseidon_param: Some(poseidon_param),
            base64_table: Some(base64_table),
            _phantom: PhantomData,
        };

        let instance = LightWeightInstance {
            hanchor: Some(C::BaseField::default()),
            root: Some(C::BaseField::default()),
            counter: Some(C::BaseField::default()),
            nonce: Some(C::BaseField::default()),
            h_x: Some(C::BaseField::default()),
            slot: Some(C::BaseField::default()),
            h_slot: Some(C::BaseField::default()),
        };

        let witness = LightWeightWitness {
            anchor: Some(PoseidonAnchor::empty(n - k + 1)),
            anchor_witness: Some(PoseidonAnchorWitness::empty(n, k)),
            sha256: Some(vec![0u32; 8]),
            nblocks: Some(0),
            token_claim: Some(vec![ClaimIndices::default(); keys_len]),
            token_payload: Some(TokenPayloadB64::empty(max_jwt_len, max_payload_len)),
            pk_rsa: Some(RsaPublicKey::empty()),
            signature_rsa: Some(RsaSignature::default()),

            signature: Some(Signature::<C>::default()),
            path: Some(MerkleCircuitInput::<C::BaseField>::empty(tree_height)),
            random: Some(C::BaseField::default()),
            z: Some(vec![C::BaseField::default(); n]),
            slot_indices: Some(vec![C::BaseField::default(); k]),
        };

        Self {
            constant,
            instance,
            witness,
            _phantom: PhantomData,
        }
    }

    pub fn number_of_constraints(&self) -> usize
    where
        H: CRHScheme<Input = [u8]> + Clone + Send + Sync,
        HG: CRHSchemeGadget<H, C::BaseField, InputVar = [UInt8<C::BaseField>]> + Clone + Send + Sync,
        H::Parameters: Send + Sync,
        H::Output: DigestToScalarField<C>,
        CV: CurveVar<C, C::BaseField>,
        BNP: BigNatCircuitParams + Send + Sync,
        for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
    {
        let cs = ark_relations::r1cs::ConstraintSystem::<C::BaseField>::new_ref();
        <Self as ConstraintSynthesizer<C::BaseField>>::generate_constraints(self.clone(), cs.clone())
            .expect("constraint generation failed");
        cs.num_constraints()
    }
}

impl<C, CV, H, HG, BNP> ConstraintSynthesizer<C::BaseField>
    for LightWeightCircuit<C, H, HG, CV, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme<Input = [u8]> + Clone + Send + Sync,
    HG: CRHSchemeGadget<H, C::BaseField, InputVar = [UInt8<C::BaseField>]> + Clone + Send + Sync,
    H::Parameters: Send + Sync,
    H::Output: DigestToScalarField<C>,
    CV: CurveVar<C, C::BaseField>,
    BNP: BigNatCircuitParams + Send + Sync,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>,
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
                .schnorr_param
                .ok_or(SynthesisError::AssignmentMissing)?,
        )?;
        let schnorr_vk = PublicKeyVar::<C, CV>::new_constant(
            cs.clone(),
            self.constant
                .schnorr_vk
                .ok_or(SynthesisError::AssignmentMissing)?,
        )?;
        let poseidon_param = CRHParametersVar::<C::BaseField>::new_constant(
            cs.clone(),
            self.constant
                .poseidon_param
                .ok_or(SynthesisError::AssignmentMissing)?,
        )?;
        let base64_table = Base64TableVar::<C::BaseField>::new_constant(
            cs.clone(),
            self.constant
                .base64_table
                .ok_or(SynthesisError::AssignmentMissing)?,
        )?;

        let hanchor = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            Ok(self
                .instance
                .hanchor
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let root = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            Ok(self
                .instance
                .root
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let counter = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            Ok(self
                .instance
                .counter
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let nonce = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            Ok(self
                .instance
                .nonce
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let h_x = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            Ok(self.instance.h_x.ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let slot = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            Ok(self
                .instance
                .slot
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let h_slot = FpVar::<C::BaseField>::new_input(cs.clone(), || {
            Ok(self
                .instance
                .h_slot
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let signature = SignatureVar::<C, CV>::new_witness(cs.clone(), || {
            Ok(self
                .witness
                .signature
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let random = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(self
                .witness
                .random
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let mut path = MerkleCircuitInputVar::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(self.witness.path.ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let anchor = PoseidonAnchorVar::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(self
                .witness
                .anchor
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let anchor_witness =
            PoseidonAnchorWitnessVar::<C::BaseField>::new_witness(cs.clone(), || {
                Ok(self
                    .witness
                    .anchor_witness
                    .ok_or(SynthesisError::AssignmentMissing)?)
            })?;

        let mut sha256 = SHA256Gadget::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(self
                .witness
                .sha256
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let nblocks = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(C::BaseField::from(
                self.witness
                    .nblocks
                    .ok_or(SynthesisError::AssignmentMissing)? as u64,
            ))
        })?;

        let token_claim = Vec::<ClaimIndicesVar<C::BaseField>>::new_witness(cs.clone(), || {
            Ok(self
                .witness
                .token_claim
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let token_payload = TokenPayloadB64Var::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(self
                .witness
                .token_payload
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let pk_rsa = RsaPublicKeyVar::<C::BaseField, BNP>::new_witness(cs.clone(), || {
            Ok(self
                .witness
                .pk_rsa
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let signature_rsa = RsaSignatureVar::<C::BaseField, BNP>::new_witness(cs.clone(), || {
            Ok(self
                .witness
                .signature_rsa
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let z = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || {
            Ok(self.witness.z.ok_or(SynthesisError::AssignmentMissing)?)
        })?;
        let slot_indices = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || {
            Ok(self
                .witness
                .slot_indices
                .ok_or(SynthesisError::AssignmentMissing)?)
        })?;

        let k = self.constant.k.ok_or(SynthesisError::AssignmentMissing)?;
        let max_payload_len = self
            .constant
            .max_payload_len
            .ok_or(SynthesisError::AssignmentMissing)?;
        let max_iss_len = self
            .constant
            .max_iss_len
            .ok_or(SynthesisError::AssignmentMissing)?;
        let max_nonce_len = self
            .constant
            .max_nonce_len
            .ok_or(SynthesisError::AssignmentMissing)?;
        let max_sub_len = self
            .constant
            .max_sub_len
            .ok_or(SynthesisError::AssignmentMissing)?;

        let reconstructed_hanchor = chain_hash_gadget(cs.clone(), &poseidon_param, &anchor.anchor)?;

        #[cfg(feature = "constraints-logging")]
        log_r1cs_eq("hanchor check", &[reconstructed_hanchor.clone()], &[hanchor.clone()]);

        reconstructed_hanchor.enforce_equal(&hanchor)?;

        verify_pk_root_signature::<C, CV, H, HG>(
            cs.clone(),
            &schnorr_param,
            &root,
            &schnorr_vk,
            &signature,
        )?;

        PoseidonAnchorSchemeGadget::<C::BaseField>::verify(&anchor_key, &anchor, &anchor_witness)?;

        let message = token_payload.as_b64_bytes();
        let mut digest = sha256.digest_with_pad(message, nblocks)?.to_bytes_le()?;

        let result = RSA2048VerifyGadget::verify(&mut digest, &signature_rsa, &pk_rsa)?;
        
        #[cfg(feature = "constraints-logging")]
        log_r1cs_eq("RSA signature check", &[result.clone()], &[Boolean::constant(true)]);
        
        result.enforce_equal(&Boolean::constant(true))?;

        let payload = token_payload.decode_to_bytes(&base64_table, max_payload_len)?;

        // check 4-3: extract claims
        let ext_iss = token_claim[0].claim_extractor("\"iss\"", &payload, max_iss_len)?;
        let ext_nonce = token_claim[1].claim_extractor("\"nonce\"", &payload, max_nonce_len)?;
        let ext_sub = token_claim[2].claim_extractor("\"sub\"", &payload, max_sub_len)?;

        // check 4-4: check nonce
        let quote_idx = token_claim[1]
            .value_len
            .wrapping_add(&UInt16::constant(u16::MAX));

        let jwt_nonce = hex_bytes_to_fp(cs.clone(), &ext_nonce, &quote_idx)?;

        let reconstructed_nonce = CRHGadget::<C::BaseField>::evaluate(
            &poseidon_param,
            &[nonce.clone(), counter.clone(), random.clone()],
        )?;
        
        #[cfg(feature = "constraints-logging")]
        log_r1cs_eq("nonce check", &[reconstructed_nonce.clone()], &[jwt_nonce.clone()]);
        
        reconstructed_nonce.enforce_equal(&jwt_nonce)?;

        // check 5: verify OIDP public key
        let num_bytes_expected = (C::ScalarField::MODULUS_BIT_SIZE - 1) as usize / 8;
        let pad_char = FpVar::<C::BaseField>::Constant(C::BaseField::from(b'0'));
        let packed_iss = pack_decompose_bytes(&ext_iss, num_bytes_expected, &pad_char)?;

        let leaf_input: Vec<_> = vec![packed_iss, pk_rsa.n.limbs.clone()].concat();
        let leaf = CRHGadget::<C::BaseField>::evaluate(&poseidon_param, &leaf_input)?;
        path.enforce_equal_leaf(&leaf)?;
        path.enforce_membership(&poseidon_param, &root)?;

        let unpacked_h_i =
            pack_decompose_bytes(&[ext_iss, ext_sub].concat(), num_bytes_expected, &pad_char)?;

        let idx = single_multiplexer(&slot_indices, &slot)?;

        let reconstructed_h = CRHGadget::<C::BaseField>::evaluate(&poseidon_param, &unpacked_h_i)?;

        let reconstructed_h_i =
            CRHGadget::<C::BaseField>::evaluate(&poseidon_param, &[idx, reconstructed_h])?;

        let mut slot_input = slot_indices.clone();
        slot_input.push(random.clone());
        let reconstructed_h_slot =
            CRHGadget::<C::BaseField>::evaluate(&poseidon_param, &slot_input)?;

        #[cfg(feature = "constraints-logging")]
        log_r1cs_eq("h_slot check", &[reconstructed_h_slot.clone()], &[h_slot.clone()]);

        reconstructed_h_slot.enforce_equal(&h_slot)?;

        anchor_witness.enforce_slot_activation(&slot_indices, &slot)?;
        anchor_witness.enforce_k_non_zero(k)?;
        anchor_witness.enforce_h_i(&z, &reconstructed_h_i)?;

        // check 6: h_x == H(h)
        let mut h_x_input = anchor_witness.placed_secrets.clone();
        h_x_input.push(random.clone());
        let reconstructed_h_x = CRHGadget::<C::BaseField>::evaluate(&poseidon_param, &h_x_input)?;

        #[cfg(feature = "constraints-logging")]
        log_r1cs_eq("h_x check", &[reconstructed_h_x.clone()], &[h_x.clone()]);
        
        reconstructed_h_x.enforce_equal(&h_x)?;
        Ok(())
    }
}

impl<C, H, HG, CV, BNP> ExposesPublicInputs<C::BaseField> for LightWeightCircuit<C, H, HG, CV, BNP>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme<Input = [u8]> + Clone + Send + Sync,
    HG: CRHSchemeGadget<H, C::BaseField, InputVar = [UInt8<C::BaseField>]> + Clone + Send + Sync,
    H::Parameters: Send + Sync,
    H::Output: DigestToScalarField<C>,
    CV: CurveVar<C, C::BaseField>,
    BNP: BigNatCircuitParams + Send + Sync,
{
    fn public_inputs(&self) -> Vec<C::BaseField> {
        vec![
            self.instance.hanchor.unwrap(),
            self.instance.root.unwrap(),
            self.instance.counter.unwrap(),
            self.instance.nonce.unwrap(),
            self.instance.h_x.unwrap(),
            self.instance.slot.unwrap(),
            self.instance.h_slot.unwrap(),
        ]
    }
}
