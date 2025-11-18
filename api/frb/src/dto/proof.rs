use serde::{Deserialize, Serialize};

use super::FfiSecretDto;

#[derive(Debug, Clone, Deserialize)]
pub struct GenerateProofReq {
    pub pk_path: String,
    pub anchor_key_path: String,
    pub schnorr_key_path: String,
    pub anchor_parts: Vec<String>,
    pub selected_secrets: Vec<FfiSecretDto>,
    pub jwts: Vec<String>,
    pub pks: Vec<String>,
    pub mps: Vec<Vec<String>>,
    pub root: String,
    pub signature: Vec<u8>,
    pub leaf_index: Vec<u32>,
    pub selector: Vec<bool>,
    pub counter: String,
    pub random: String,
    pub h_userop: String,
    pub slot: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GenerateProofRes {
    pub proof: Vec<String>,
    pub public_inputs: Vec<String>,
}