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

pub use arithmetic::*;
pub use bit_byte::*;
pub use comparison::*;
pub use convert::*;
pub use error::*;
pub use select::*;
pub use slice::*;
pub use uint32::*;

// v2 모듈의 주요 함수들도 re-export (기존 경로 호환성 유지하면서 직접 접근 가능)
pub use bit_bytes_v2::pack_decompose_bytes_unchecked;
pub use slice_v2::{slice_efficient, slice_grouped, log_base_2, segments_to_num_be};
pub use string_v2::{jwt_exp_to_field, jwt_nonce_hex_to_field};