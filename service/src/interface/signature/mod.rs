use ark_crypto_primitives::crh::CRHScheme;
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use gadget::signature::schnorr::{Parameters, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrPublicKeyExtension<C: CurveGroup, H: CRHScheme>
where
    H::Parameters: Send + Sync,
{
    pub params: Parameters<C, H>,
    pub vk: PublicKey<C>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrSecretKeyExtension<C: CurveGroup, H: CRHScheme>
where 
    H::Parameters: Send + Sync,
{
    pub params: Parameters<C, H>,
    pub sk: SecretKey<C>,
}

#[derive(Serialize, Deserialize)]
pub struct SchnorrSignRequestDto {
    pub message: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct SchnorrSignResponseDto {
    pub signature: Vec<u8>,
}