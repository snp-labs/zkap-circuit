use serde::{Deserialize, Serialize};

use super::FfiSecretDto;

#[derive(Debug, Clone, Deserialize)]
pub struct CreatePoseidonAnchorReq {
    pub key_path: String,
    pub secrets: Vec<FfiSecretDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreatePoseidonAnchorRes {
    pub anchor: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateDlAnchorReq {
    pub handle: u64,
    pub secrets: Vec<FfiSecretDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateDlAnchorRes {
    pub anchor: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PoseidonDeriveIndicesReq {
    pub key_path: String,
    pub anchor: Vec<String>,
    pub known_secrets: Vec<FfiSecretDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PoseidonDeriveIndicesRes {
    pub indices: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DlDeriveIndicesReq {
    pub handle: u64,
    pub anchor: Vec<String>,
    pub known_secrets: Vec<FfiSecretDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DlDeriveIndicesRes {
    pub indices: Vec<u8>,
}
