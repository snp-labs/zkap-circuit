//! Canonical public-input layout for the ZKAP Groth16 circuit.
//!
//! The order of variants in [`PUBLIC_INPUTS`] is the **single source of truth**
//! for the 8-element wire layout — it is the same order:
//!
//! 1. emitted into the witness vector by `prove()`,
//! 2. written into the manifest's `public_input_names` by `generate_setup`, and
//! 3. decoded from `ProofComponents::public_inputs` in `dto::proof`.
//!
//! Changing this order is a **wire-protocol-breaking change** and invalidates
//! the on-chain Solidity Groth16Verifier.

/// Identifier of each Groth16 public-input slot.
///
/// The canonical wire position of each variant is given by
/// [`PublicInputSlot::index`], which equals its position in [`PUBLIC_INPUTS`].
///
/// Adding a new variant requires updating the exhaustive `match` in
/// `crate::groth16::prover::prove` — the compiler will refuse to build
/// until every slot is handled.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PublicInputSlot {
    /// `H(anchor)` — Poseidon chain hash of the threshold anchor. Index 0.
    Hanchor,
    /// `H(a)` — Poseidon hash of the per-batch `a` value. Index 1.
    Ha,
    /// Merkle root of the per-batch identity tree. Index 2.
    Root,
    /// `H(sign_user_op)` — Poseidon hash of the user-operation signature digest. Index 3.
    HSignUserOp,
    /// JWT `exp` claim packed into a BN254 Fr. Index 4.
    JwtExp,
    /// Partial RHS of the threshold-scheme pairing equation. Index 5.
    PartialRhs,
    /// Pairing-equation LHS commitment. Index 6.
    Lhs,
    /// `H(aud_list)` — Poseidon hash of the audience allow-list. Index 7.
    HAudList,
}

/// Canonical ordered array of all 8 public-input slots.
///
/// **Do not reorder entries.** The position of each entry is its wire index.
pub const PUBLIC_INPUTS: [PublicInputSlot; 8] = [
    PublicInputSlot::Hanchor,
    PublicInputSlot::Ha,
    PublicInputSlot::Root,
    PublicInputSlot::HSignUserOp,
    PublicInputSlot::JwtExp,
    PublicInputSlot::PartialRhs,
    PublicInputSlot::Lhs,
    PublicInputSlot::HAudList,
];

impl PublicInputSlot {
    /// Canonical wire-format name (matches `manifest.public_input_names` entries).
    pub const fn name(self) -> &'static str {
        match self {
            PublicInputSlot::Hanchor => "hanchor",
            PublicInputSlot::Ha => "h_a",
            PublicInputSlot::Root => "root",
            PublicInputSlot::HSignUserOp => "h_sign_user_op",
            PublicInputSlot::JwtExp => "jwt_exp",
            PublicInputSlot::PartialRhs => "partial_rhs",
            PublicInputSlot::Lhs => "lhs",
            PublicInputSlot::HAudList => "h_aud_list",
        }
    }

    /// Position in the public-input vector (0-based).
    ///
    /// Equals the index of this slot in [`PUBLIC_INPUTS`].
    pub const fn index(self) -> usize {
        match self {
            PublicInputSlot::Hanchor => 0,
            PublicInputSlot::Ha => 1,
            PublicInputSlot::Root => 2,
            PublicInputSlot::HSignUserOp => 3,
            PublicInputSlot::JwtExp => 4,
            PublicInputSlot::PartialRhs => 5,
            PublicInputSlot::Lhs => 6,
            PublicInputSlot::HAudList => 7,
        }
    }
}

/// Canonical ordered array of wire-format names, one per slot.
///
/// Each entry is `PUBLIC_INPUTS[i].name()` — the position in this array
/// is the wire index of the corresponding slot.
pub const PUBLIC_INPUT_NAMES: [&str; 8] = [
    PUBLIC_INPUTS[0].name(),
    PUBLIC_INPUTS[1].name(),
    PUBLIC_INPUTS[2].name(),
    PUBLIC_INPUTS[3].name(),
    PUBLIC_INPUTS[4].name(),
    PUBLIC_INPUTS[5].name(),
    PUBLIC_INPUTS[6].name(),
    PUBLIC_INPUTS[7].name(),
];

/// Compile-time assertion: exactly 8 public inputs.
const _: () = assert!(PUBLIC_INPUTS.len() == 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_inputs_array_in_canonical_order() {
        for (i, slot) in PUBLIC_INPUTS.iter().enumerate() {
            assert_eq!(slot.index(), i, "PUBLIC_INPUTS[{i}].index() != {i}");
        }
    }

    #[test]
    fn public_input_names_match_legacy() {
        assert_eq!(
            PUBLIC_INPUT_NAMES,
            [
                "hanchor",
                "h_a",
                "root",
                "h_sign_user_op",
                "jwt_exp",
                "partial_rhs",
                "lhs",
                "h_aud_list",
            ]
        );
    }

    #[test]
    fn slot_index_round_trips() {
        let slots = [
            PublicInputSlot::Hanchor,
            PublicInputSlot::Ha,
            PublicInputSlot::Root,
            PublicInputSlot::HSignUserOp,
            PublicInputSlot::JwtExp,
            PublicInputSlot::PartialRhs,
            PublicInputSlot::Lhs,
            PublicInputSlot::HAudList,
        ];
        for slot in slots {
            assert_eq!(
                PUBLIC_INPUTS[slot.index()],
                slot,
                "round-trip failed for {slot:?}"
            );
        }
    }
}
