extern crate alloc;

// R1CS modules (feature = "r1cs")
#[cfg(feature = "r1cs")]
pub mod bit_bytes;
#[cfg(feature = "r1cs")]
pub mod comparison;
#[cfg(feature = "r1cs")]
pub mod select;
#[cfg(feature = "r1cs")]
pub mod slice;
#[cfg(feature = "r1cs")]
pub mod jwt_field;
#[cfg(feature = "r1cs")]
pub mod uint32;
#[cfg(feature = "r1cs")]
pub mod debug;

// EVM codegen (feature = "evm-codegen")
#[cfg(feature = "evm-codegen")]
pub mod evm;

// Field serde (feature = "field-serde")
#[cfg(feature = "field-serde")]
pub mod field_serde;

// IO (feature = "io")
#[cfg(feature = "io")]
pub mod io;

// Always available
pub mod convert;
pub mod error;
pub mod text;

// Always-available re-exports
pub use convert::*;
pub use text::*;

// R1CS re-exports
#[cfg(feature = "r1cs")]
pub use bit_bytes::*;
#[cfg(feature = "r1cs")]
pub use comparison::*;
#[cfg(feature = "r1cs")]
pub use select::*;
#[cfg(feature = "r1cs")]
pub use slice::*;
#[cfg(feature = "r1cs")]
pub use uint32::*;

// Field serde re-exports
#[cfg(feature = "field-serde")]
pub use field_serde::*;

// IO re-exports
#[cfg(feature = "io")]
pub use io::*;
