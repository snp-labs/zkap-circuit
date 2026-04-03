//! Hash generation DTOs

/// Poseidon hash request (platform-agnostic core type)
#[derive(Debug, Clone)]
pub struct GeneratePoseidonHashReqCore {
    pub inputs: Vec<String>,
}

/// Poseidon hash response (platform-agnostic core type)
#[derive(Debug, Clone)]
pub struct GeneratePoseidonHashResCore {
    pub hash: String,
}
