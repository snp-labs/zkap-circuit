use ark_crypto_primitives::{merkle_tree::Path, sponge::Absorb, sponge::poseidon::PoseidonConfig};
use ark_ff::PrimeField;
use ark_serialize::*;

use gadget::{
    anchor::poseidon::PoseidonAnchor,
    base64::{Base64Table, IndexBits},
    matrix::VandermondeMatrix,
    merkletree::tree_config::MerkleTreeParams,
    signature::rsa::{PublicKey, Signature},
};

use crate::constants::CircuitConfig;
use crate::token::ClaimIndices;

/// Circuit constants (determined at setup time)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CircuitConstants<F: PrimeField> {
    pub vandermonde_matrix: VandermondeMatrix<F>,
    pub poseidon_param: PoseidonConfig<F>,
    pub base64_table: Base64Table,
}

/// Public inputs (exposed to the verifier)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CircuitPublicInputs<F: PrimeField> {
    /// H(anchor)
    pub hanchor: F,
    /// H(a, random)
    pub h_a: F,
    /// Merkle root
    pub root: F,
    /// H(sign_user_op)
    pub h_sign_user_op: F,
    /// JWT expiration time
    pub jwt_exp: F,
    /// partial_rhs at current_idx
    pub partial_rhs: F,
    /// <a, anchor> * random
    pub lhs: F,
    /// H(aud_list)
    pub h_aud_list: F,
}

impl<F: PrimeField> CircuitPublicInputs<F> {
    /// Convert public inputs to a vector
    pub fn to_vec(&self) -> Vec<F> {
        vec![
            self.hanchor,
            self.h_a,
            self.root,
            self.h_sign_user_op,
            self.jwt_exp,
            self.partial_rhs,
            self.lhs,
            self.h_aud_list,
        ]
    }
}

/// JWT-related witness (SHA256 + Base64 + RSA)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct JwtWitness {
    /// Number of SHA256 blocks (final block index, 0-indexed)
    pub nblocks: usize,
    /// Claim indices
    pub claim_indices: Vec<ClaimIndices>,
    /// Payload Base64 offset
    pub pay_offset_b64: usize,
    /// Payload Base64 length
    pub pay_len_b64: usize,
    /// SHA-padded full JWT (header.payload with SHA256 padding)
    pub sha_pad_jwt_b64: Vec<u8>,
    /// Base64 index bits
    pub index_bits: IndexBits,
    /// RSA public key
    pub pk: PublicKey,
    /// RSA signature
    pub sig: Signature,
    /// Total JWT length (before padding)
    pub total_len: usize,
    /// Padding start byte index (absolute position)
    pub pad_start_byte_idx: usize,
}

/// Anchor/Threshold witness
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AnchorWitness<F: PrimeField> {
    /// Anchor value
    pub anchor: PoseidonAnchor<F>,
    /// A vector
    pub a: Vec<F>,
    /// Selector vector
    pub selector: Vec<u8>,
    /// Current index
    pub current_idx: usize,
}

/// Merkle tree witness
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerkleWitness<F: PrimeField + Absorb> {
    /// Merkle path
    pub path: Path<MerkleTreeParams<F>>,
    /// Leaf index
    pub leaf_idx: usize,
}

/// Audience witness
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AudienceWitness<F: PrimeField> {
    /// Padded audience list
    pub aud_list: Vec<F>,
}

/// Miscellaneous witness
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MiscWitness<F: PrimeField> {
    /// Random value
    pub random: F,
}

/// Struct bundling all circuit inputs
#[derive(Clone)]
pub struct ZkapCircuitInput<F: PrimeField + Absorb> {
    /// Circuit configuration (runtime parameters)
    pub params: CircuitConfig,
    /// Circuit constants
    pub constants: CircuitConstants<F>,
    /// Public inputs
    pub public_inputs: CircuitPublicInputs<F>,
    /// JWT witness
    pub jwt: JwtWitness,
    /// Anchor witness
    pub anchor: AnchorWitness<F>,
    /// Merkle witness
    pub merkle: MerkleWitness<F>,
    /// Audience witness
    pub audience: AudienceWitness<F>,
    /// Miscellaneous witness
    pub misc: MiscWitness<F>,
}

impl<F: PrimeField + Absorb> ZkapCircuitInput<F> {
    /// Extract only the public inputs
    pub fn extract_public_inputs(&self) -> Vec<F> {
        self.public_inputs.to_vec()
    }
}
