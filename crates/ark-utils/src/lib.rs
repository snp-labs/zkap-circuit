extern crate alloc;

pub mod debug;

pub mod bit_bytes;
pub mod comparison;
pub mod convert;
pub mod error;
pub mod select;
pub mod slice;
pub mod slice_v2;
pub mod string_v2;
pub mod uint32;

pub mod evm;
pub mod text;
pub mod io;
pub mod field_serde;

pub use bit_bytes::*;
pub use comparison::*;
pub use convert::*;
pub use error::*;
pub use select::*;
pub use slice::*;
pub use uint32::*;

// Explicit re-exports from submodules for flat-path access
pub use slice_v2::{slice_efficient, slice_grouped, log_base_2, segments_to_num_be};
