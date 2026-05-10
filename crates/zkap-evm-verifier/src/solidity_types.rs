//! Solidity ABI encoding for arkworks field and curve elements.
//!
//! [`Solidity`] converts `Fp`, `Fp2`, `G1Affine`, and `G2Affine` elements to the
//! `["0x...", ...]` hex-string vectors expected by the on-chain Groth16 verifier.
//! Used by host-facing proof DTOs (e.g. `ProofComponents` in `zkap-service`) and
//! by the Solidity codegen in [`crate::groth16_verifier_solidity`].

use ark_ec::{
    AffineRepr,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use ark_ff::{BigInteger, Fp, Fp2, Fp2Config, FpConfig, PrimeField};

/// Converts an arkworks field or curve element to the
/// `["0x...", ...]` hex-string vector form expected by the on-chain
/// Groth16 verifier ABI. Implementors flatten in the byte order the
/// Solidity verifier reads (e.g., `Fp2` emits `c1` before `c0` to
/// match the Solidity convention; `G2Affine` concatenates `x` then
/// `y`, each in `c1, c0` order).
pub trait Solidity {
    /// Returns the ABI-encoded field/curve element as a vector of
    /// `0x`-prefixed hex strings. Length is type-specific: `Fp` → 1,
    /// `Fp2` → 2, `G1Affine` → 2, `G2Affine` → 4. `Vec<T>` flattens
    /// per-element.
    fn to_solidity(&self) -> Vec<String>;
}

impl<P: FpConfig<N>, const N: usize> Solidity for Fp<P, N> {
    fn to_solidity(&self) -> Vec<String> {
        vec![format!(
            "0x{}",
            hex::encode((*self).into_bigint().to_bytes_be())
        )]
    }
}

impl<P: Fp2Config> Solidity for Fp2<P>
where
    P::Fp: Solidity,
{
    fn to_solidity(&self) -> Vec<String> {
        [self.c1.to_solidity(), self.c0.to_solidity()].concat()
    }
}

impl<T: Solidity> Solidity for Vec<T> {
    fn to_solidity(&self) -> Vec<String> {
        self.iter().flat_map(|x| x.to_solidity()).collect()
    }
}

impl<P: SWCurveConfig> Solidity for Affine<P>
where
    P::BaseField: Solidity,
{
    fn to_solidity(&self) -> Vec<String> {
        [
            self.x().unwrap().to_solidity(),
            self.y().unwrap().to_solidity(),
        ]
        .concat()
    }
}

impl<P: SWCurveConfig> Solidity for Projective<P>
where
    P::BaseField: Solidity,
{
    fn to_solidity(&self) -> Vec<String> {
        [
            self.x.to_solidity(),
            self.y.to_solidity(),
            self.z.to_solidity(),
        ]
        .concat()
    }
}
