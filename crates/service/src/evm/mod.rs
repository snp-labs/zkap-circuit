//! Solidity on-chain verifier codegen (requires `proof` feature).
//!
//! [`groth16_verifier_solidity::SolidityContractGenerator`] generates a
//! `Groth16Verifier.sol` contract from a Groth16 [`ark_groth16::VerifyingKey`].
//! [`solidity_types::Solidity`] converts arkworks field/curve elements to the
//! hex-string format expected by the Solidity verifier ABI.

pub mod groth16_verifier_solidity;
pub mod solidity_types;
