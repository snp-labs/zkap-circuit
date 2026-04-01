extern crate alloc;

pub mod debug;

pub mod arithmetic;
pub mod bit_byte;
pub mod bit_bytes_v2;
pub mod comparison;
pub mod convert;
pub mod error;
pub mod select;
pub mod slice;
pub mod slice_v2;
pub mod string_v2;
pub mod uint32;

// Alias for consumer code that imports via `bit_bytes::` path
pub use bit_bytes_v2 as bit_bytes;

pub use arithmetic::*;
pub use bit_byte::*;
pub use comparison::*;
pub use convert::*;
pub use error::*;
pub use select::*;
pub use slice::*;
pub use uint32::*;

// Explicit re-exports from v2 modules for flat-path access
pub use bit_bytes_v2::pack_decompose_bytes_unchecked;
pub use slice_v2::{slice_efficient, slice_grouped, log_base_2, segments_to_num_be};
