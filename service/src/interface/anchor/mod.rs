use std::str::FromStr;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use gadget::anchor::poseidon::PoseidonAnchorPublicKey;
use serde::{Deserialize, Serialize};

use crate::error::error::ApplicationError;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorKeyExtension<F: PrimeField> {
    pub anchor_key: PoseidonAnchorPublicKey<F>,
    pub n: usize,
    pub k: usize,
    pub max_aud_len: Option<usize>,
    pub max_iss_len: Option<usize>,
    pub max_sub_len: usize,
}

// #[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
// pub struct DLAnchorKeyExtension<C: CurveGroup> {
//     pub anchor_key: DLAnchorPublicKey<C>,
//     pub n: usize,
//     pub k: usize,
//     pub max_aud_len: Option<usize>,
//     pub max_iss_len: Option<usize>,
//     pub max_sub_len: usize,
// }

pub enum AnchorType {
    DL,
    Poseidon,
}

#[derive(Serialize, Deserialize)]
pub struct AnchorKeyGenRequestDto {
    pub n: usize,
    pub k: usize,
    pub max_aud_len: Option<usize>,
    pub max_iss_len: Option<usize>,
    pub max_sub_len: usize,
}

#[derive(Serialize, Deserialize)]
pub struct AnchorRequestDto {
    pub variant: String,
    pub anchor_key_path: String,
    pub secrets: Vec<SecretDto>,
}

#[derive(Serialize, Deserialize)]
pub struct AnchorResponseDto {
    pub anchor: Vec<String>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct SecretDto {
    pub sub: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Secret {
    pub sub: String,
    pub iss: String,
    pub aud: String,
}

#[derive(Serialize, Deserialize)]
pub struct DeriveSecretIndicesRequestDto {
    pub variant: String,
    pub anchor_key_path: String,
    pub anchor: Vec<String>,
    pub known_secrets: Vec<SecretDto>,
}

#[derive(Serialize, Deserialize)]
pub struct DeriveSecretIndicesResponseDto {
    pub indices: Vec<u8>,
}

impl FromStr for AnchorType {
    type Err = ApplicationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "DL" => Ok(AnchorType::DL),
            "POSEIDON" => Ok(AnchorType::Poseidon),
            _ => Err(ApplicationError::InvalidVariant),
        }
    }
}
