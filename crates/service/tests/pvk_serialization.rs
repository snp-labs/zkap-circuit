//! PVK-SER-DISCOVERY — preflight invariant for the 2026-05 ark-ar1cs
//! boundary migration.
//!
//! The post-migration CRS bundle ships `pvk.bin` (arkworks
//! `CanonicalSerialize` of `PreparedVerifyingKey<Bn254>`) as a
//! manifest-validated artifact. This test locks in the round-trip
//! invariant the migration depends on:
//!
//!   prepare_verifying_key(&vk)
//!       .serialize_uncompressed(buf)
//!       === PreparedVerifyingKey::deserialize_uncompressed(buf)
//!       === re-serialize === same bytes
//!
//! If this test ever fails (e.g. arkworks bump changes the PVK type so
//! `deserialize_uncompressed` is no longer derived), the migration's
//! Option A — keeping `pvk.bin` as a manifest entry — is no longer
//! viable. Halt the bundle layout work and fall back to Option B
//! (derive pvk at load time from vk.bin) per
//! `docs/phase-1-desired-architecture.md` D1.
//!
//! The test runs a tiny `x * y = z` ConstraintSynthesizer (not
//! `ZkapCircuit`) so the preflight finishes in well under a second.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_groth16::{Groth16, PreparedVerifyingKey, prepare_verifying_key};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{SeedableRng, rngs::StdRng};

/// Minimal `x * y = z` R1CS — same pattern as `ToyCircuit` in
/// `crates/zkap-witness-wasm/tests/wasm_to_prove.rs` but standalone.
#[derive(Clone)]
struct ToyCircuit;

impl ConstraintSynthesizer<Fr> for ToyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let z = cs.new_input_variable(|| Ok(Fr::from(15u64)))?;
        let x = cs.new_witness_variable(|| Ok(Fr::from(3u64)))?;
        let y = cs.new_witness_variable(|| Ok(Fr::from(5u64)))?;
        cs.enforce_r1cs_constraint(
            || LinearCombination::from(x),
            || LinearCombination::from(y),
            || LinearCombination::from(z),
        )?;
        Ok(())
    }
}

/// PVK round-trip invariant — see module docs for the migration rationale.
#[test]
fn prepared_verifying_key_round_trips_uncompressed() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
    let (_pk, vk) = Groth16::<Bn254>::setup(ToyCircuit, &mut rng).expect("Groth16::setup");

    let pvk = prepare_verifying_key(&vk);

    let mut buf = Vec::new();
    pvk.serialize_uncompressed(&mut buf)
        .expect("pvk serialize_uncompressed");

    let recovered = PreparedVerifyingKey::<Bn254>::deserialize_uncompressed(&buf[..])
        .expect("pvk deserialize_uncompressed");

    let mut buf2 = Vec::new();
    recovered
        .serialize_uncompressed(&mut buf2)
        .expect("recovered pvk re-serialize_uncompressed");

    assert_eq!(
        buf, buf2,
        "PreparedVerifyingKey<Bn254> uncompressed round-trip bytes diverged"
    );
}
