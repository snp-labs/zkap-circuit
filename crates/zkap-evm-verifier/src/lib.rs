//! Solidity on-chain Groth16 verifier codegen.
//!
//! Extracted from `zkap-service::evm` (Phase 4 / S11) so the heavy
//! `ark-ec` + `ark-groth16` codegen surface lives in its own crate and
//! can be depended on independently of the prove/verify orchestration
//! in [`zkap-service`](https://crates.io/crates/zkap-service).
//!
//! # Public surface
//!
//! - [`groth16_verifier_solidity::SolidityContractGenerator`] — trait
//!   implemented for `ark_groth16::VerifyingKey<E>`; writes a
//!   self-contained `Groth16Verifier.sol` to disk.
//! - [`solidity_types::Solidity`] — converts arkworks field/curve
//!   elements (`Fp`, `Fp2`, `Affine<P>`, `Projective<P>`, `Vec<T>`) into
//!   the `["0x...", ...]` hex-string vectors expected by the on-chain
//!   verifier ABI.
//!
//! For convenience, both traits are re-exported at the crate root.

pub mod groth16_verifier_solidity;
pub mod solidity_types;

pub use groth16_verifier_solidity::SolidityContractGenerator;
pub use solidity_types::Solidity;
