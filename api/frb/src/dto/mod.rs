use serde::{Deserialize, Serialize};

pub mod anchor;
pub mod proof;
pub mod schnorr;
pub mod hash;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiSecretDto {
    pub sub: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<String>,
}

impl From<FfiSecretDto> for zkpasskey_service::interface::anchor::SecretDto {
    fn from(dto: FfiSecretDto) -> Self {
        Self {
            sub: dto.sub,
            iss: dto.iss,
            aud: dto.aud,
        }
    }
}