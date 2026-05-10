//! Protocol type aliases for the ZKAP circuit.
//!
//! This module collects the concrete curve/field/hash choices used throughout
//! the crate as a single set of type aliases:
//!
//! | Alias          | Concrete type                              |
//! |----------------|--------------------------------------------|
//! | `F`            | BN254 base field (`ark_ed_on_bn254`)       |
//! | `CG`           | `ark_ed_on_bn254::EdwardsProjective`       |
//! | `BNP`          | `BigNat2048Params` (2048-bit, 64-bit limbs)|
//! | `PoseidonHash` | `CRH<F>`                                   |
//! | `BN254`        | `ark_bn254::Bn254` (pairing engine)        |
//! | `PAD_CHAR`     | `'\0'` — SHA-256 padding sentinel          |
//!
//! `CircuitConfig` is re-exported from `ark_utils::wire` — it is the single
//! canonical runtime-parameter type shared across all crates.

use std::fmt::Debug;

use ark_crypto_primitives::crh::poseidon::CRH;
use gadget::bigint::constraints::BigNatCircuitParams;

/// SHA-256 padding sentinel character used by host-side string→field
/// conversions to fill the unused tail of fixed-length claim buffers.
pub const PAD_CHAR: char = '\0';

/// Re-export of the unified [`CircuitConfig`] from `ark_utils::wire`.
///
/// PR3 consolidation (S6.A2) replaced the legacy circuit-side
/// `CircuitConfig` (`Vec<u8>`/`Vec<Vec<u8>>` fields) and
/// `RawCircuitConfig` (JSON-friendly `String` fields) with a single
/// type. PR1 of L4 absorption then moved that type from
/// `zkap-input-types` into `ark-utils::wire` so it co-locates with its
/// `field_codec`. `String` and `Vec<u8>` share the same
/// `CanonicalSerialize` byte output, so `.arzkey` byte compatibility
/// is preserved.
pub use ark_utils::wire::CircuitConfig;

const LAMBDA: usize = 2048; // 2048 bits

/// 2048-bit `BigNatCircuitParams` instantiation used by the RSA-2048
/// signature gadget — 32 limbs of 64 bits each.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigNat2048Params;
impl BigNatCircuitParams for BigNat2048Params {
    const LIMB_WIDTH: usize = 64;
    const N_LIMBS: usize = LAMBDA / 64;
}

/// `ark_ed_on_bn254::EdwardsProjective` — the inner curve whose base
/// field [`F`] hosts every R1CS variable in the circuit.
pub type CG = ark_ed_on_bn254::EdwardsProjective;
/// Base field of [`CG`]; the protocol field used by every R1CS gadget.
pub type F = <CG as ark_ec::CurveGroup>::BaseField;
/// Poseidon CRH instantiated over [`F`].
pub type PoseidonHash = CRH<F>;
/// `ark_bn254::Bn254` — the pairing engine used by Groth16.
pub type BN254 = ark_bn254::Bn254;
/// 2048-bit BigNat parameters used by RSA-2048 verification inside the ZKAP
/// circuit. The `2048` matches the JWT signing key size — RSA limbs are
/// packed into BN254 field elements via `BigNat2048Params`'s 64-bit limb
/// schedule. Used as the `BNP` type parameter on [`crate::zkap::ZkapCircuit`].
pub type BNP = BigNat2048Params;
