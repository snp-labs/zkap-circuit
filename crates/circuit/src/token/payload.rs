//! JWT payload slicing helpers used by the main circuit.

use ark_ff::PrimeField;
use ark_r1cs_helpers::slice_efficient;
use ark_r1cs_std::{fields::fp::FpVar, uint16::UInt16};
use ark_relations::gr1cs::SynthesisError;

pub(crate) fn slice_jwt_payload_b64_region<F: PrimeField>(
    jwt_b64_bytes: &[FpVar<F>],
    payload_offset: &UInt16<F>,
    payload_len: &UInt16<F>,
    max_payload_len: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    slice_efficient(jwt_b64_bytes, payload_offset, payload_len, max_payload_len)
}
