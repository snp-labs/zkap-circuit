//! Wasm witness-generator artifact for the ZKAP main circuit.
//!
//! Thin wrapper that plugs `circuit::ZkapCircuit<CG, BNP>` into the generic
//! [`ark_ar1cs_wasm_witness`] runtime. The interesting code lives in
//! [`input`] (V1 semantic schema) and the build-time blake3 emit
//! (`build.rs`); everything else is one trait impl plus the macro
//! invocation.

pub mod error;
pub mod input;

pub use error::ZkapWitnessError;
pub use input::{
    build_main_circuit, circuit_config_from_v1, config_v1_from_circuit, into_circuit_input,
    ZkapMainCircuit,
};

// Re-export V1 wire types from the dedicated crate so existing call sites
// (`zkap_witness_wasm::ZkapInputV1`, etc.) keep working.
pub use zkap_input_types::{
    fe_from_be32_canonical, fe_to_be32, NonCanonicalFieldError, ZkapCircuitConfigV1, ZkapInputV1,
    RSA_2048_BYTES,
};

include!(concat!(env!("OUT_DIR"), "/embedded.rs"));

use ark_ar1cs_format::CurveId;
use ark_ar1cs_wasm_witness::WitnessGenerator;
use circuit::constants::F;

const ZKAP_PUBLIC_INPUT_NAMES: &[&str] = &[
    "hanchor",
    "h_a",
    "root",
    "h_sign_user_op",
    "jwt_exp",
    "partial_rhs",
    "lhs",
    "h_aud_list",
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
    generator       = ZkapWitnessGenerator,
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
}
