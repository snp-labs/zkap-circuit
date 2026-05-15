//! Anchor generation DTOs

/// JWT claim triple consumed by [`crate::generate_anchor`].
///
/// Field values are passed **raw** (no surrounding JSON quotes); the service
/// wraps them in `"…"` internally before deriving the per-credential scalar,
/// matching the on-circuit absorption of the original JWT payload bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnchorSecret {
    /// JWT `sub` — the identity the credential is issued to. Pass the raw
    /// value (e.g. `"user_0"`); the service quotes it internally before
    /// padding to `CircuitConfig::max_sub_len`.
    pub subject: String,
    /// JWT `iss` — the identity provider that signed the credential. Pass the
    /// raw value (e.g. `"https://accounts.google.com"`); the service quotes
    /// it internally before padding to `CircuitConfig::max_iss_len`.
    pub issuer: String,
    /// JWT `aud` — the intended relying party. Pass the raw value (e.g.
    /// `"my-app"`); the service quotes it internally before padding to
    /// `CircuitConfig::max_aud_len`.
    pub audience: String,
}

/// Request for [`crate::generate_anchor`].
///
/// `secrets.len()` must equal `config.n` (one entry per Vandermonde matrix
/// row); otherwise the call fails with
/// [`crate::error::ApplicationError::AnchorDimensionMismatch`].
///
/// `secrets` is order-sensitive — the order callers supply is the order the
/// scheme assigns to matrix rows, so the resulting anchor evaluations depend
/// on it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenerateAnchorRequest {
    /// JWT claim triples (one per matrix row). Length must equal `config.n`.
    pub secrets: Vec<AnchorSecret>,
}

/// Response from [`crate::generate_anchor`].
///
/// - `anchor_evaluations.len() == config.n - config.k + 1` (Vandermonde
///   polynomial evaluation count for the threshold scheme).
/// - `hanchor` is the sequential Poseidon chain hash of the evaluations in
///   the order they appear in `anchor_evaluations`. The chain order is part
///   of the contract — the in-circuit `hanchor` public input is computed
///   identically.
/// - All hex strings are `0x`-prefixed lowercase big-endian BN254 Fr (matches
///   the encoding used by the hash API).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenerateAnchorResponse {
    /// Anchor polynomial evaluations as `0x`-prefixed lowercase big-endian
    /// hex BN254 Fr strings. Length is `config.n - config.k + 1`.
    pub anchor_evaluations: Vec<String>,
    /// Sequential Poseidon chain hash of `anchor_evaluations`, encoded as a
    /// `0x`-prefixed lowercase big-endian hex BN254 Fr string. Equals the
    /// in-circuit `hanchor` public input.
    pub hanchor: String,
}
