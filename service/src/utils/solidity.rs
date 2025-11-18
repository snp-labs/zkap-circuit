use ark_ec::{
    AffineRepr,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use ark_ff::{Fp, Fp2, Fp2Config, FpConfig};
use ark_std::Zero;
use std::fmt::Display;

pub trait Solidity {
    fn to_solidity(&self) -> Vec<String>;
}

fn to_solidity<T: Display + Zero>(x: T) -> String {
    if x.is_zero() {
        "0".to_string()
    } else {
        x.to_string()
    }
}

impl<P: FpConfig<N>, const N: usize> Solidity for Fp<P, N> {
    fn to_solidity(&self) -> Vec<String> {
        vec![to_solidity(*self)]
    }
}

impl<P: Fp2Config> Solidity for Fp2<P> {
    fn to_solidity(&self) -> Vec<String> {
        vec![to_solidity(self.c1), to_solidity(self.c0)]
    }
}

impl<T: Solidity> Solidity for Vec<T> {
    fn to_solidity(&self) -> Vec<String> {
        self.iter().map(|x| x.to_solidity()).flatten().collect()
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
