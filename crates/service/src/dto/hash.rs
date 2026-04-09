//! Hash generation DTOs

/// Result of [`crate::generate_aud_hash`]: per-audience hashes and their combined hash.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AudHashResult {
    /// Per-audience Poseidon hash values (decimal field-element strings, one per audience)
    pub individual: Vec<String>,
    /// Combined Poseidon hash of all individual audience hashes
    pub combined: String,
}
