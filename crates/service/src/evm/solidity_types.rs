use ark_ec::{
    AffineRepr,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use ark_ff::{BigInteger, Fp, Fp2, Fp2Config, FpConfig, PrimeField};

pub trait Solidity {
    fn to_solidity(&self) -> Vec<String>;
}

impl<P: FpConfig<N>, const N: usize> Solidity for Fp<P, N> {
    fn to_solidity(&self) -> Vec<String> {
        vec![format!("0x{}", hex::encode((*self).into_bigint().to_bytes_be()))]
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
