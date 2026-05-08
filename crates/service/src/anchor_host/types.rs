use serde::{Deserialize, Serialize};

/// A JWT claim triple representing a single user identity credential.
///
/// Holds the `sub` (subject), `iss` (issuer), and `aud` (audience) claims extracted from a JWT.
/// Used as input to [`generate_anchor`](crate::anchor_host::poseidon::generate_anchor) to derive the
/// per-credential Poseidon scalar `x` that feeds into the threshold anchor.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Secret {
    pub sub: String,
    pub iss: String,
    pub aud: String,
}
