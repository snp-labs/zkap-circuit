use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct GenerateSchnorrSignatureReq {
    pub schnorr_key_path: String,
    pub root: String, // hex string, 서명은 merkle root에 대해서만 수행합니다.
}

#[derive(Debug, Clone, Serialize)]
pub struct GenerateSchnorrSignatureRes {
    pub signature: Vec<u8>,
}