//! Proof generation DTOs — host-facing request/response surface for
//! [`crate::Prover::prove`].
//!
//! Mirrors the `anchor` / `hash` module conventions: every BN254 Fr value
//! crosses the boundary as a `String` (accepted as either `0x`-prefixed
//! lowercase big-endian hex or a plain decimal — parsed via
//! [`ark_utils::hex_decimal_to_field`]); RSA-2048 bulk bytes cross as
//! base64 (`*_b64` suffix); JWT credentials cross as their compact
//! serialization. Response field-element strings are always emitted as
//! `0x`-prefixed lowercase big-endian hex.

/// Request for [`crate::Prover::prove`].
///
/// **Top-level flattening**: no nested "shared" struct — batch-shared
/// inputs sit at the top level alongside `credentials`. Per-credential
/// inputs are grouped in [`ProveCredential`] (matches the `anchor` /
/// `hash` `Vec<Struct>` convention).
///
/// **Field-element string encoding**: every BN254 Fr value (`random`,
/// `h_sign_user_op`, every entry of `anchor`, `merkle_root`, every entry
/// of each credential's `merkle_path`) is parsed via
/// [`ark_utils::hex_decimal_to_field`], which accepts either form:
///
/// - `0x`-prefixed lowercase big-endian hex (e.g. `"0x1a2b..."`), or
/// - a plain decimal string (e.g. `"1234567890..."`).
///
/// Both forms are interchangeable per-field.
///
/// **`hanchor` is not a request input.** It is the sequential Poseidon
/// chain hash of `anchor` and is computed internally by the adapter; the
/// caller cannot pick a `hanchor` inconsistent with `anchor`. The
/// response's `SharedPublicInputs::hanchor` field exposes the computed
/// value for verifier use.
///
/// **Shape invariants** (validated at the boundary; failures surface as
/// [`crate::error::ApplicationError::InvalidProveRequest`]):
///
/// - `credentials.len() == config.k`
/// - `anchor.len() == config.n - config.k + 1`
/// - `credentials[i].merkle_path.len() == config.tree_height`
/// - `credentials[i].merkle_leaf_idx < 2^config.tree_height`
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProveRequest {
    /// Randomness salt — BN254 Fr (hex or decimal).
    pub random: String,
    /// Hash of the signed user-op payload — BN254 Fr (hex or decimal).
    pub h_sign_user_op: String,
    /// Anchor polynomial evaluations from
    /// [`crate::generate_anchor`]'s
    /// [`crate::dto::GenerateAnchorResponse::anchor_evaluations`].
    /// Length = `config.n - config.k + 1`; each entry is BN254 Fr
    /// (hex or decimal).
    pub anchor: Vec<String>,
    /// Issuer-key Merkle tree root — BN254 Fr (hex or decimal).
    pub merkle_root: String,
    /// One entry per JWT credential. `credentials.len()` must equal
    /// `config.k` (the threshold scheme requires exactly `k` shares).
    pub credentials: Vec<ProveCredential>,
}

/// Per-credential inputs to [`ProveRequest`].
///
/// One entry per JWT participating in the batch; ordering is significant
/// (the per-credential inputs in the response — `jwt_exp[i]`,
/// `verification_rhs[i]` — pair index-wise with this list).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProveCredential {
    /// JWT compact serialization — `header.payload.signature`. The
    /// signature segment is part of the JWT; do **not** pass it
    /// separately. The adapter extracts the `sub` / `iss` / `aud`
    /// claims from the payload for anchor `x` derivation and re-uses
    /// the signature segment as the RSA signature bytes.
    pub jwt: String,
    /// Base64 of the 256-byte RSA-2048 modulus for the issuer that
    /// signed this JWT. Accepts both standard and URL-safe base64
    /// alphabets, with or without padding (decoded via
    /// `gadget::base64::decode_any_base64`).
    pub rsa_modulus_b64: String,
    /// Merkle authentication path siblings — BN254 Fr strings (hex or
    /// decimal). Length = `config.tree_height`:
    ///
    /// - `merkle_path[0]` is the leaf-level sibling hash.
    /// - `merkle_path[1..tree_height]` are the inner-node sibling
    ///   hashes, root-ward.
    pub merkle_path: Vec<String>,
    /// Leaf index in the issuer-key Merkle tree. Bounded:
    /// `merkle_leaf_idx < 2^config.tree_height`.
    pub merkle_leaf_idx: u64,
}
