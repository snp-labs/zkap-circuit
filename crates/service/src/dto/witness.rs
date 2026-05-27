//! Witness wire DTO shared by native and wasm witness generators.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use circuit::types::F;

/// Circuit-agnostic witness bundle emitted by witness synthesis.
///
/// The public-input layout is:
/// `[hanchor, h_a, root, h_sign_user_op, jwt_exp, partial_rhs, lhs,
///   h_aud_list]`
///
/// Both vectors are just `Vec<F>`, so a WASM module can serialize them via
/// [`CanonicalSerialize`] and a native host can [`CanonicalDeserialize`] and prove
/// without linking constraint code.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct WitnessBundle {
    /// Flat wire-value vector from `synthesize_full_assignment`.
    pub full_assignment: Vec<F>,
    /// 8-element canonical public-input layout (see struct docs).
    pub public_inputs: Vec<F>,
}
