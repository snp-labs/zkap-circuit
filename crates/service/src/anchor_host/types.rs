use serde::{Deserialize, Serialize};

/// A JWT claim triple representing a single user identity credential.
///
/// Holds the `sub` (subject), `iss` (issuer), and `aud` (audience) claims extracted from a JWT.
/// Used as input to [`generate_anchor`](crate::anchor_host::poseidon::generate_anchor) to derive the
/// per-credential Poseidon scalar `x` that feeds into the threshold anchor.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Secret {
    /// JWT `sub` (subject) — the identity the credential is issued to.
    /// Combined with [`Self::iss`] and [`Self::aud`] when deriving the
    /// per-credential anchor scalar.
    pub sub: String,
    /// JWT `iss` (issuer) — the identity provider that signed the credential.
    /// Distinct issuers produce distinct anchor scalars even for the same
    /// subject, so credentials from different IdPs are not aliased.
    pub iss: String,
    /// JWT `aud` (audience) — the intended relying party. Anchored alongside
    /// `sub`/`iss` so a credential issued for one audience cannot be replayed
    /// against a different one.
    pub aud: String,
}
