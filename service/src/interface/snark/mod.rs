use ark_ec::pairing::Pairing;
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ZkpasskeySetupRequestDto {
    pub max_jwt_len: usize,
    pub max_payload_len: usize,
    pub max_aud_len: usize,
    pub max_iss_len: usize,
    pub max_sub_len: usize,
    pub tree_height: usize,
    pub anchor_key_path: String,
    pub schnorr_key_path: String,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKeyExtension<E: Pairing> {
    pub pk: ProvingKey<E>,
    /// JWT의 최대 길이
    pub max_jwt_len: usize,
    /// payload의 최대 길이
    pub max_payload_len: usize,
    /// audience의 최대 길이 
    pub max_aud_len: usize,
    /// issuer의 최대 길이
    pub max_iss_len: usize,
    /// nonce의 최대 길이
    pub max_nonce_len: usize,
    /// subject의 최대 길이
    pub max_sub_len: usize,
    /// pk tree height
    pub tree_height: usize,
}

