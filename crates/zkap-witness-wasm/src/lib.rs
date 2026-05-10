//! Wasm witness-generator artifact for the ZKAP main circuit.
//!
//! Thin wrapper that plugs `circuit::ZkapCircuit<CG, BNP>` into the generic
//! [`ark_ar1cs_wasm_witness`] runtime. The interesting code lives in
//! [`input`] (V1 semantic schema) and the build-time blake3 emit
//! (`build.rs`); everything else is one trait impl plus the macro
//! invocation.

// Phase 8 H5-finalize: `[workspace.lints.rust] missing_docs = "warn"` is
// active workspace-wide, but on `target_arch = "wasm32"` the
// `ark_ar1cs_wasm_witness::export_witness_generator!` macro at the
// bottom of this file emits two undocumented `extern "C" fn` items
// (`witness_generate` / `witness_pair_check`) that the macro definition
// (in an external crate) does not let us doc-annotate. Allow
// `missing_docs` crate-wide on wasm32 only so the wasm artifact stays
// emit-able without forking the macro. Host builds keep the warn — the
// hand-written items in this crate (`ZkapWitnessGenerator`, helper
// functions in `input.rs`, errors) are all documented.
#![cfg_attr(target_arch = "wasm32", allow(missing_docs))]
//!
//! ## Curve and field
//!
//! `WitnessGenerator::Field = circuit::types::F` (BN254 Fr — `ark_bn254::Fr`).
//! `WitnessGenerator::CurveId = Bn254`. The wasm artifact is locked to BN254;
//! re-targeting to a different curve requires a new crate (or a feature gate).
//!
//! ## Native vs wasm32 builds
//!
//! On `target_arch = "wasm32"`, `EMBEDDED_AR1CS_BLAKE3` is bound at build time
//! from the `.arzkey` pointed to by `$AR1CS_WITNESS_ARZKEY_PATH` and is the
//! load-bearing pair contract. On native (e.g. `cargo test`), `build.rs`
//! falls back to a zero placeholder when the env var is unset — host-side
//! code MUST cross-check the `.arzkey` itself, not this constant.
//!
//! ## crate-type: cdylib + rlib
//!
//! Built as both `cdylib` (wasm32 ABI exports via `export_witness_generator!`)
//! and `rlib` (native unit tests + `tests/wasm_to_prove.rs` integration test
//! that rebuilds this crate for `wasm32-unknown-unknown` and re-instantiates
//! it via `wasmtime`).
//!
//! ## gadget feature pin
//!
//! This crate depends on `gadget` with `features = ["crypto", "base64", "rsa"]`
//! rather than `features = ["full"]`. Although those three currently equal `full`,
//! pinning them explicitly ensures a future `gadget` release that adds a new
//! sub-feature to `full` does not silently pull extra bytes into the wasm artifact.
//!
//! ## getrandom (wasm32)
//!
//! `getrandom` is listed as a `[target.'cfg(target_arch = "wasm32")'.dependencies]`
//! with `features = ["js"]` to satisfy `rand_core`'s wasm32-unknown-unknown
//! import requirement. This crate does not call RNG directly.

pub mod error;
pub mod input;

pub use error::ZkapWitnessError;
pub use input::{ZkapMainCircuit, build_main_circuit, into_circuit_input};

// Re-export V1 wire types and the field codec helpers from `ark-utils`
// so existing call sites (`zkap_witness_wasm::ZkapInputV1`, etc.) keep
// working. Wire schema and codec live in two distinct ark-utils
// modules after PR1 of L4 absorption.
pub use ark_utils::codec::field::{NonCanonicalFieldError, fe_from_be32_canonical, fe_to_be32};
pub use ark_utils::wire::{CircuitConfig, RSA_2048_BYTES, ZkapInputV1};

include!(concat!(env!("OUT_DIR"), "/embedded.rs"));

use ark_ar1cs_format::CurveId;
use ark_ar1cs_wasm_witness::WitnessGenerator;
use circuit::types::F;

// Cross-ref: this order MUST match `CircuitPublicInputs` field declaration order
// in `circuit::witness` and the `instance` vector produced by
// `ZkapCircuit::generate_constraints` / `ConstraintSynthesizer`. Any reorder
// of `CircuitPublicInputs` fields or the synthesizer's `enforce_*` call sequence
// is a silent host-side instance-vector bug — bump `CIRCUIT_ID` and update
// this slice in the same commit. See W5 (issue W10) for the gate rationale.
const ZKAP_PUBLIC_INPUT_NAMES: &[&str] = &[
    "hanchor",        // CircuitPublicInputs::hanchor       (field 0)
    "h_a",            // CircuitPublicInputs::h_a            (field 1)
    "root",           // CircuitPublicInputs::root           (field 2)
    "h_sign_user_op", // CircuitPublicInputs::h_sign_user_op (field 3)
    "jwt_exp",        // CircuitPublicInputs::jwt_exp        (field 4)
    "partial_rhs",    // CircuitPublicInputs::partial_rhs    (field 5)
    "lhs",            // CircuitPublicInputs::lhs            (field 6)
    "h_aud_list",     // CircuitPublicInputs::h_aud_list     (field 7)
];

/// Wasm witness generator for the ZKAP main circuit.
///
/// Accepts the semantic [`ZkapInputV1`] payload and reconstructs the full
/// circuit on the wasm side via [`ZkapInputV1::build_main_circuit`]. This
/// is the only `WitnessGenerator` impl exported by this crate; bumping
/// the wire format requires bumping [`Self::CIRCUIT_ID`] in lockstep.
pub struct ZkapWitnessGenerator;

impl WitnessGenerator for ZkapWitnessGenerator {
    type Field = F;
    type Input = ZkapInputV1;
    type Circuit = ZkapMainCircuit;
    type Error = ZkapWitnessError;

    /// Stable circuit identifier. Bump when [`ZkapInputV1`]'s wire format
    /// changes — the host cross-checks this against the same string in
    /// the deployment manifest.
    const CIRCUIT_ID: &'static str = "zkap-main-v1";
    const CURVE_ID: CurveId = CurveId::Bn254;

    fn public_input_names() -> &'static [&'static str] {
        ZKAP_PUBLIC_INPUT_NAMES
    }

    fn build_circuit(input: ZkapInputV1) -> Result<Self::Circuit, ZkapWitnessError> {
        build_main_circuit(input)
    }
}

ark_ar1cs_wasm_witness::export_witness_generator!(
    generator = ZkapWitnessGenerator,
    embedded_blake3 = EMBEDDED_AR1CS_BLAKE3,
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Acceptance: the wasm export's stable identifier is `zkap-main-v1`.
    /// Failing this test means the schema changed without a CIRCUIT_ID
    /// bump (host pair-check tooling will then silently accept mismatched
    /// payloads).
    #[test]
    fn circuit_id_is_locked_to_v1() {
        assert_eq!(ZkapWitnessGenerator::CIRCUIT_ID, "zkap-main-v1");
    }

    /// Acceptance: `EMBEDDED_AR1CS_BLAKE3` is exactly 32 bytes and exposed
    /// as a public const. The wasm export pairs (ptr, len) where len = 32.
    #[test]
    fn embedded_blake3_constant_shape() {
        let bytes: &[u8; 32] = &EMBEDDED_AR1CS_BLAKE3;
        assert_eq!(bytes.len(), 32);
    }

    /// Acceptance: `public_input_names()` returns the eight ZKAP public
    /// inputs in the order the circuit allocates them. Drift here is a
    /// host-side instance-vector bug waiting to happen.
    #[test]
    fn public_input_names_are_locked() {
        assert_eq!(
            ZkapWitnessGenerator::public_input_names(),
            &[
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

    /// Guard: `ZKAP_PUBLIC_INPUT_NAMES` has exactly 8 entries — one per
    /// `CircuitPublicInputs` field. If `CircuitPublicInputs` gains or loses a
    /// field without a corresponding update here AND a `CIRCUIT_ID` bump, the
    /// host's instance-vector indexing silently breaks. Pair this test with
    /// `public_input_names_are_locked` so both the count and content are pinned.
    #[test]
    fn public_input_names_count_matches_circuit_public_inputs() {
        // CircuitPublicInputs has 8 fields: hanchor, h_a, root, h_sign_user_op,
        // jwt_exp, partial_rhs, lhs, h_aud_list.
        // If this count ever changes, bump CIRCUIT_ID and update ZKAP_PUBLIC_INPUT_NAMES.
        const EXPECTED_PUBLIC_INPUT_COUNT: usize = 8;
        assert_eq!(
            ZKAP_PUBLIC_INPUT_NAMES.len(),
            EXPECTED_PUBLIC_INPUT_COUNT,
            "ZKAP_PUBLIC_INPUT_NAMES length mismatch: expected {} entries (one per \
             CircuitPublicInputs field). Update ZKAP_PUBLIC_INPUT_NAMES and bump CIRCUIT_ID.",
            EXPECTED_PUBLIC_INPUT_COUNT,
        );
    }
}
