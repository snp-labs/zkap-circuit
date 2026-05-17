//! Hash generation DTOs

/// Request for [`crate::generate_poseidon_hash`].
///
/// Each entry in `field_elements` is parsed as either a `0x`-prefixed hex
/// string or a decimal string representing a BN254 Fr element.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HashRequest {
    /// Field-element inputs to the Poseidon CRH. Each entry must be parseable
    /// as `0x`-hex or decimal.
    pub field_elements: Vec<String>,
}

/// Response from [`crate::generate_poseidon_hash`].
///
/// `hash` is the resulting BN254 Fr element rendered as a `0x`-prefixed
/// lowercase big-endian hex string.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HashResponse {
    /// `0x`-prefixed lowercase big-endian hex of the Poseidon output.
    pub hash: String,
}

/// Request for [`crate::generate_audience_hashes`].
///
/// `audiences` is order-sensitive: callers must supply the audiences in the
/// order they expect them hashed (the function does not sort). Duplicate
/// entries are permitted and each occupies its own slot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AudienceHashRequest {
    /// JWT `aud` claim values, ordered. Length must be ≤
    /// `CircuitConfig::num_audience_limit`; shorter inputs are padded with
    /// `CircuitConfig::forbidden_string` to reach the limit.
    pub audiences: Vec<String>,
}

/// Response from [`crate::generate_audience_hashes`].
///
/// `audience_hashes` mirrors the post-padding slot order; entry `i` is the
/// Poseidon hash of the audience occupying slot `i` (or of the
/// `forbidden_string` if that slot was padded). `audience_list_hash` is the
/// Poseidon over the per-audience hashes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AudienceHashResponse {
    /// Per-audience Poseidon hashes — `0x`-prefixed lowercase big-endian hex
    /// strings. Length equals `CircuitConfig::num_audience_limit`.
    pub audience_hashes: Vec<String>,
    /// Combined Poseidon hash of the per-audience hashes —
    /// `0x`-prefixed lowercase big-endian hex.
    pub audience_list_hash: String,
}

/// Request for [`crate::generate_issuer_key_hash`].
///
/// `rsa_modulus_b64` must be the base64 encoding of exactly 256 bytes (the
/// RSA-2048 modulus); shorter or longer modulus bytes are rejected. The
/// RSA public exponent is fixed at 65537 in-circuit and is not accepted
/// through this API.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IssuerKeyHashRequest {
    /// JWT issuer string (the `iss` claim). Internally padded with the
    /// circuit's pad character up to `CircuitConfig::max_iss_len`.
    pub issuer: String,
    /// Base64 of the 256-byte RSA-2048 modulus `n`.
    pub rsa_modulus_b64: String,
}

/// Response from [`crate::generate_issuer_key_hash`].
///
/// `hash` is the Merkle-leaf Poseidon hash over `[iss_limbs ‖ n_limbs]`,
/// rendered as a `0x`-prefixed lowercase big-endian hex string.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IssuerKeyHashResponse {
    /// `0x`-prefixed lowercase big-endian hex of the issuer-key Merkle leaf.
    pub hash: String,
}
