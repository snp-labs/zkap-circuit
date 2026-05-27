//! Big-integer (multi-limb) arithmetic for RSA helpers and R1CS.
//!
//! [`BigNatCircuitParams`] fixes the native limb layout used by RSA-2048 helpers.
//! With the `constraints` feature, [`constraints`] additionally provides
//! [`BigNatVar`](constraints::BigNatVar) — an R1CS variable representing a large
//! natural number as a vector of field-element limbs.
//! [`utils`] contains native conversion helpers (`fe_to_nat`, `nat_to_fe`,
//! `nat_to_limbs`, `limbs_to_nat`, `fit_nat_to_limbs`, `field_characteristic_to_nat`)
//! that are also useful outside of R1CS contexts.

use std::fmt::Debug;

#[cfg(feature = "constraints")]
pub mod constraints;
pub mod utils;

/// Compile-time constants fixing the limb representation for a multi-limb big integer.
///
/// For RSA-2048 over BN254, the canonical choice is `LIMB_WIDTH = 64` and
/// `N_LIMBS = 32` (giving 2048 bits total). Different instantiations can use wider
/// limbs to reduce constraint count at the cost of larger field elements.
pub trait BigNatCircuitParams: Clone + Debug + Eq + PartialEq + Send + Sync {
    /// Width of each limb in bits; must satisfy `LIMB_WIDTH < |F|` so each limb
    /// fits in a single field element without overflow.
    const LIMB_WIDTH: usize;
    /// Number of limbs; total bit width = `LIMB_WIDTH * N_LIMBS`.
    const N_LIMBS: usize;
}
