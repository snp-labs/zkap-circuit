//! JWT payload parsing utilities.
//!
//! [`parser::parse_claim_from_str`] locates a named claim in a JSON payload string
//! and returns a [`Claim`] with byte-level indices compatible with
//! the circuit's [`circuit::token::ClaimIndices`].

pub mod parser;

pub use parser::Claim;
