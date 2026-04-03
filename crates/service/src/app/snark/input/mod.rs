//! Input data layer
//!
//! Module that converts raw string input into type-safe domain objects.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────┐
//! │   RawProofRequest   │  ← raw string data coming from outside
//! └──────────┬──────────┘
//!            │ validate & parse
//!            ▼
//! ┌─────────────────────┐
//! │   ProofRequest      │  ← validated domain object (F field elements)
//! └──────────┬──────────┘
//!            │ build context
//!            ▼
//! ┌─────────────────────┐
//! │   ProofContext      │  ← all context needed for proof generation
//! └─────────────────────┘
//! ```

mod raw;
mod request;

pub use raw::RawProofRequest;
pub use request::ProofRequest;
