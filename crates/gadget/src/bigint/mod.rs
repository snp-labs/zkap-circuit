//! Big-integer (multi-limb) arithmetic for RSA in R1CS.
//!
//! [`constraints`] provides [`BigNatVar`](constraints::BigNatVar) — an R1CS variable
//! representing a large natural number as a vector of field-element limbs — plus
//! [`BigNatCircuitParams`](constraints::BigNatCircuitParams) for RSA-2048 limb sizing.
//! [`utils`] contains native conversion helpers (`fe_to_nat`, `nat_to_fe`,
//! `nat_to_limbs`, `limbs_to_nat`, `fit_nat_to_limbs`, `field_characteristic_to_nat`)
//! that are also useful outside of R1CS contexts.

pub mod constraints;
pub mod utils;
