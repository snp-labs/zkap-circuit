//! Affine-point serialisation to/from coordinate strings.
//!
//! Exports: [`affine_to_hex_str`], [`affine_to_decimal_str`],
//! [`coords_to_affine`], [`FromCoords`], [`FieldParseError`].  Supports
//! short-Weierstrass (`G1Affine`, `G2Affine`) and twisted-Edwards curves.
//! Requires the `field-serde` feature.

use std::fmt::UpperHex;

use ark_ec::{
    AffineRepr,
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
};
use ark_ff::PrimeField;

/// Failure modes for affine-point and field-coordinate parsing.
///
/// Returned by [`coords_to_affine`] and the underlying field-string conversions
/// in [`crate::string`]. The `NotOnCurve` / `NotInCorrectSubgroup`
/// variants are produced by [`FromCoords::validate`] after a candidate point is
/// constructed; `InvalidDecimal` / `InvalidHex` / `InvalidLength` come from the
/// string-to-field decoder before construction.
#[derive(Debug, thiserror::Error)]
pub enum FieldParseError {
    /// Decimal string did not parse as a base-field element.
    #[error("Invalid decimal string for field element")]
    InvalidDecimal,
    /// Hex string did not parse as a base-field element.
    #[error("Invalid hex string for field element")]
    InvalidHex,
    /// ASCII byte count is not a multiple of the field's expected chunk size
    /// (first parameter is the required multiple, second is the actual length).
    #[error("Invalid length for ASCII to field conversion: expected multiple of {0}, got {1}")]
    InvalidLength(usize, usize),
    /// Coordinates parsed but the resulting point fails the curve equation.
    #[error("point is not on curve")]
    NotOnCurve,
    /// Point is on the curve but outside the correct prime-order subgroup —
    /// rejecting it is required for soundness in pairing-based protocols.
    #[error("point is not in correct subgroup")]
    NotInCorrectSubgroup,
}

/// Converts (x, y) coordinates of an Affine point to hex strings (`["0x..", "0x.."]`).
/// - Returns `"0x0"` for the point at infinity.
///
/// # Format vs `field_to_hex`
///
/// This function intentionally diverges from [`crate::field::field_to_hex`]:
///
/// | Property       | `affine_to_hex_str`                              | `field_to_hex`                     |
/// |----------------|--------------------------------------------------|------------------------------------|
/// | Case           | UPPERCASE (`{:X}` on `BigInt`)                   | lowercase (`{:02x}` per-byte loop) |
/// | Width          | BigInt limb-width padded (variable across field sizes) | fixed 64 hex chars (full 32-byte field encoding) |
///
/// The width difference is structural: `{:X}` on a `BigInt` pads to the
/// minimum number of significant u64 limbs, whereas `field_to_hex` always
/// serialises the full 32-byte big-endian field encoding.
///
/// The divergence is intentional — audit §2.6 Option 2 (drift retention).
/// If you need EVM-compatible 32-byte lowercase hex, call
/// [`crate::field::field_to_hex`] directly. The divergence is pinned by
/// tests in the `divergence_tests` module at the bottom of this file.
pub fn affine_to_hex_str<A: AffineRepr>(p: &A) -> Vec<String>
where
    A::BaseField: PrimeField,
    <A::BaseField as PrimeField>::BigInt: UpperHex,
{
    [p.x(), p.y()]
        .into_iter()
        .map(|coord_opt| match coord_opt {
            Some(field_elem) => format!("0x{:X}", field_elem.into_bigint()),
            None => "0x0".to_string(),
        })
        .collect()
}

/// Converts (x, y) coordinates of an Affine point to decimal strings (["..", ".."]).
/// - Returns "0" for the point at infinity.
pub fn affine_to_decimal_str<A: AffineRepr>(p: &A) -> Vec<String>
where
    A::BaseField: PrimeField,
{
    [p.x(), p.y()]
        .into_iter()
        .map(|coord_opt| {
            coord_opt
                .map(|field_elem| field_elem.to_string())
                .unwrap_or_else(|| "0".to_string())
        })
        .collect()
}

impl From<super::string::ConvertError> for FieldParseError {
    fn from(e: super::string::ConvertError) -> Self {
        match e {
            super::string::ConvertError::InvalidHex(_) => FieldParseError::InvalidHex,
            super::string::ConvertError::InvalidDecimal(_) => FieldParseError::InvalidDecimal,
            _ => FieldParseError::InvalidDecimal,
        }
    }
}

/// Converts (x, y) coordinate strings to an Affine point.
/// - Each coordinate follows the `hex_decimal_to_field` rule (hex if 0x prefix, otherwise decimal).
pub fn coords_to_affine<A>(x_str: &str, y_str: &str) -> Result<A, FieldParseError>
where
    A: FromCoords,
    A::BaseField: PrimeField,
{
    let x = super::string::hex_decimal_to_field::<A::BaseField>(x_str)?;
    let y = super::string::hex_decimal_to_field::<A::BaseField>(y_str)?;

    let p = A::from_coords(x, y);

    A::validate(&p)?;

    Ok(p)
}
/// Builder for [`AffineRepr`] points that takes raw `(x, y)` coordinates and
/// returns a validated point.
///
/// Split into `from_coords` (cheap construction without curve checks) and
/// `validate` (which enforces both the curve equation and prime-order
/// subgroup membership) so callers can amortise validation across batches —
/// [`coords_to_affine`] always validates per call.
pub trait FromCoords: AffineRepr {
    /// Construct an affine point from coordinates without validating that it
    /// lies on the curve or in the correct subgroup. Pair with [`Self::validate`]
    /// before use in any soundness-critical path.
    fn from_coords(x: Self::BaseField, y: Self::BaseField) -> Self;
    /// Returns `Ok(())` iff the point lies on the curve **and** in the
    /// prime-order subgroup. Both checks are required for pairing soundness;
    /// the curve check alone admits points of unwanted order.
    fn validate(p: &Self) -> Result<(), FieldParseError>;
}

// SW: G1Affine, G2Affine, etc.
impl<P> FromCoords for SWAffine<P>
where
    P: SWCurveConfig,
    P::BaseField: PrimeField,
{
    fn from_coords(x: Self::BaseField, y: Self::BaseField) -> Self {
        Self::new_unchecked(x, y)
    }

    fn validate(p: &Self) -> Result<(), FieldParseError> {
        if !p.is_on_curve() {
            return Err(FieldParseError::NotOnCurve);
        }
        if !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err(FieldParseError::NotInCorrectSubgroup);
        }
        Ok(())
    }
}

// Twisted Edwards: EdOnBN, etc.
impl<P> FromCoords for TEAffine<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    fn from_coords(x: Self::BaseField, y: Self::BaseField) -> Self {
        Self::new_unchecked(x, y)
    }

    fn validate(p: &Self) -> Result<(), FieldParseError> {
        if !p.is_on_curve() {
            return Err(FieldParseError::NotOnCurve);
        }
        if !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err(FieldParseError::NotInCorrectSubgroup);
        }
        Ok(())
    }
}

// ── Divergence-intent tests (audit §2.6 Option 2) ────────────────────────────
//
// `affine_to_hex_str` intentionally differs from `field_to_hex`:
//   - `field_to_hex`:       lowercase, fixed-width 64 hex chars (zero-padded BE)
//   - `affine_to_hex_str`:  UPPERCASE, leading-zeros trimmed (BigInt UpperHex)
//
// Option 2 was chosen: keep the divergence, pin it with tests so any
// accidental convergence or further drift breaks CI.
// Cross-reference: `zkap-evm-verifier/tests/hex_parity.rs` pins the
// *other* pair (`field_to_hex` ≡ `Solidity::to_solidity` for Fp).
#[cfg(test)]
mod divergence_tests {
    use super::affine_to_hex_str;
    use crate::field::field_to_hex;
    use ark_bn254::{Fr, G1Affine};
    use ark_ec::{AffineRepr, CurveGroup};

    /// Pins `affine_to_hex_str` output for the BN254 G1 generator (x=1, y=2)
    /// and contrasts it with `field_to_hex` on the same values.
    ///
    /// The divergence being pinned: `affine_to_hex_str` pads to BigInt limb
    /// width (16 hex chars), while `field_to_hex` pads to the full 32-byte
    /// field width (64 hex chars). The `assert_eq!` messages carry the detail.
    #[test]
    fn affine_to_hex_str_generator_is_limb_width_not_field_width() {
        let g = G1Affine::generator();
        let affine_out = affine_to_hex_str(&g);
        assert_eq!(affine_out.len(), 2, "generator is not at infinity");

        // Pinned exact output for G1 generator (x=1, y=2).
        // `{:X}` on BigInt pads to the BigInt's u64-limb count (BN254 uses 4
        // limbs = 32 bytes = 64 hex chars for the full representation, but the
        // ark-ff UpperHex impl pads to the minimum significant limbs: 1 limb =
        // 8 bytes = 16 hex chars for values that fit in a single u64).
        assert_eq!(
            affine_out[0], "0x0000000000000001",
            "G1 generator x=1: affine_to_hex_str pads to BigInt limb width (16 hex chars)"
        );
        assert_eq!(
            affine_out[1], "0x0000000000000002",
            "G1 generator y=2: affine_to_hex_str pads to BigInt limb width (16 hex chars)"
        );

        // Contrast: field_to_hex on the same integer values pads to the full
        // 32-byte field width (64 hex chars). These are the divergence pins —
        // if either impl changes format, at least one assertion will break.
        let field_x = field_to_hex(g.x().unwrap());
        let field_y = field_to_hex(g.y().unwrap());
        assert_eq!(
            field_x, "0x0000000000000000000000000000000000000000000000000000000000000001",
            "field_to_hex(x=1) must be fixed-width 64 hex chars, lowercase"
        );
        assert_eq!(
            field_y, "0x0000000000000000000000000000000000000000000000000000000000000002",
            "field_to_hex(y=2) must be fixed-width 64 hex chars, lowercase"
        );

        // Width divergence is explicit: affine = 18 chars, field = 66 chars.
        assert_eq!(
            affine_out[0].len(),
            18,
            "affine x: 0x + 16 hex chars (1 BigInt limb)"
        );
        assert_eq!(
            affine_out[1].len(),
            18,
            "affine y: 0x + 16 hex chars (1 BigInt limb)"
        );
        assert_eq!(
            field_x.len(),
            66,
            "field x: 0x + 64 hex chars (32-byte field)"
        );
        assert_eq!(
            field_y.len(),
            66,
            "field y: 0x + 64 hex chars (32-byte field)"
        );
        assert_ne!(
            affine_out[0], field_x,
            "width divergence: limb-padded ≠ field-padded for x=1"
        );
        assert_ne!(
            affine_out[1], field_y,
            "width divergence: limb-padded ≠ field-padded for y=2"
        );
    }

    /// Pins the UPPERCASE property of `affine_to_hex_str` using a non-trivial
    /// point (G1 * 7) whose coordinates contain A-F hex digits.
    ///
    /// The BN254 G1 generator (x=1, y=2) has no alphabetic hex digits, so
    /// uppercase cannot be demonstrated there. `G1 * 7` has coordinates with
    /// non-trivial byte patterns that include A-F hex chars, making the case
    /// divergence visible. `field_to_hex` always uses lowercase `{:02x}`.
    #[test]
    fn affine_to_hex_str_non_trivial_point_is_uppercase() {
        let p = (G1Affine::generator() * Fr::from(7u64)).into_affine();
        let affine_out = affine_to_hex_str(&p);
        assert_eq!(affine_out.len(), 2, "scaled point is not at infinity");

        let affine_x = &affine_out[0];
        let affine_y = &affine_out[1];

        // Both output strings must be 0x-prefixed.
        assert!(affine_x.starts_with("0x"), "0x prefix required on x");
        assert!(affine_y.starts_with("0x"), "0x prefix required on y");

        // For G1 * 7, coordinates have at least one A-F hex digit —
        // confirm UPPERCASE is used (not lowercase a-f).
        let x_body = affine_x.strip_prefix("0x").unwrap();
        let y_body = affine_y.strip_prefix("0x").unwrap();
        assert!(
            !x_body.is_empty() && x_body.chars().all(|c| c.is_ascii_hexdigit()),
            "affine_to_hex_str x must be valid hex digits"
        );
        assert!(
            !y_body.is_empty() && y_body.chars().all(|c| c.is_ascii_hexdigit()),
            "affine_to_hex_str y must be valid hex digits"
        );
        // If lowercase a-f are present the format has drifted away from UpperHex.
        assert!(
            !x_body.chars().any(|c| matches!(c, 'a'..='f')),
            "affine_to_hex_str x must not contain lowercase hex letters (got: {affine_x})"
        );
        assert!(
            !y_body.chars().any(|c| matches!(c, 'a'..='f')),
            "affine_to_hex_str y must not contain lowercase hex letters (got: {affine_y})"
        );

        // field_to_hex on the same coordinate must be all-lowercase.
        let field_x = field_to_hex(p.x().unwrap());
        let field_y = field_to_hex(p.y().unwrap());
        assert_eq!(field_x.len(), 66, "field_to_hex fixed-width 66 chars");
        assert_eq!(field_y.len(), 66, "field_to_hex fixed-width 66 chars");
        let fx_body = field_x.strip_prefix("0x").unwrap();
        let fy_body = field_y.strip_prefix("0x").unwrap();
        assert!(
            !fx_body.chars().any(|c| c.is_ascii_uppercase()),
            "field_to_hex x must be all-lowercase"
        );
        assert!(
            !fy_body.chars().any(|c| c.is_ascii_uppercase()),
            "field_to_hex y must be all-lowercase"
        );

        // The two forms differ (case divergence — lowercasing affine output
        // would match field_to_hex only if width also matched, which it won't
        // for trimmed values; for full-width coords the case diff is the signal).
        // Either width or case must differ — confirm they're not the same string.
        assert_ne!(affine_x, &field_x, "affine_to_hex_str ≠ field_to_hex for x");
        assert_ne!(affine_y, &field_y, "affine_to_hex_str ≠ field_to_hex for y");
    }
}
