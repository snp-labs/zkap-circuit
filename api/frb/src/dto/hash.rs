use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct GeneratePoseidonHashReq {
    pub inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratePoseidonHashRes {
    pub hash: String,
}