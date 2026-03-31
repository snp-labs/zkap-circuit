//! Cryptographic constants used across the gadget crate.
//!
//! This module centralizes commonly used cryptographic constants to ensure
//! consistency and reduce the risk of errors from hardcoded values.

/// RSA default public exponent (65537 = 0x10001)
///
/// This is the most commonly used RSA public exponent, chosen for its
/// balance between security and efficiency. It has only two bits set,
/// making modular exponentiation fast.
pub const RSA_DEFAULT_EXPONENT: u64 = 65537;

/// RSA default exponent in Base64 URL-safe encoding
///
/// "AQAB" decodes to [1, 0, 1] which represents 65537 in big-endian.
pub const RSA_DEFAULT_EXPONENT_B64: &str = "AQAB";

/// SHA-256 padding marker byte
///
/// Per FIPS 180-4, SHA-256 padding starts with a '1' bit followed by zeros.
/// Since we work with bytes, this is represented as 0x80 (binary: 10000000).
pub const SHA256_PAD_MARKER: u8 = 0x80;
