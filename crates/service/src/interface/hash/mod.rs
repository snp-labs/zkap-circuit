use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct HashRequestDto {
    pub inputs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct HashResponseDto {
    pub hash: String,
}