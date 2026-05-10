//! Native big-integer conversion helpers for RSA limb arithmetic.
//!
//! Provides `fe_to_nat` / `nat_to_fe` (field element ↔ `BigUint` round-trips),
//! `nat_to_limbs` / `limbs_to_nat` (split/join a `BigUint` into fixed-width limbs),
//! `fit_nat_to_limbs` (zero-extend or truncate), and `field_characteristic_to_nat`
//! (extract the prime modulus as a `BigUint`). Used by both witness generation and
//! the R1CS gadget in [`crate::bigint::constraints`].

use ark_ff::BigInteger;
use ark_ff::fields::PrimeField;
use num_bigint::BigUint;
use num_traits::One;
use std::borrow::Borrow;

pub type BigNat = BigUint;

// Convert field element to BigNat
pub fn fe_to_nat<F: PrimeField>(fe: &F) -> BigNat {
    BigUint::from_bytes_le(&fe.into_bigint().to_bytes_le())
}

// Convert BigNat to field element
pub fn nat_to_fe<F: PrimeField>(nat: &BigNat) -> F {
    F::from_le_bytes_mod_order(&nat.to_bytes_le())
}

pub fn nat_to_limbs<F: PrimeField>(nat: &BigNat, limb_width: usize, limbs_num: usize) -> Vec<F> {
    let mask = (BigNat::one() << limb_width) - BigNat::one();
    let mut nat = nat.clone();
    let limbs: Vec<F> = (0..limbs_num)
        .map(|_| {
            let limb = &nat & &mask;
            nat >>= limb_width as u32;
            nat_to_fe(&limb)
        })
        .collect();
    limbs
}

pub fn limbs_to_nat<F: PrimeField>(limbs: &[F], limb_width: usize) -> BigNat {
    limbs.iter().rev().fold(BigNat::ZERO, |mut acc, limb| {
        acc <<= limb_width as u32;
        acc += fe_to_nat(limb.borrow());
        acc
    })
}

pub fn fit_nat_to_limbs<F: PrimeField>(n: &BigNat, limb_width: usize) -> Vec<F> {
    nat_to_limbs(n, limb_width, n.bits() as usize / limb_width + 1)
}

#[inline]
pub fn field_characteristic_to_nat<F: PrimeField>() -> BigNat {
    // F::characteristic() is a little-endian array of u64 limbs.
    // Convert it to little-endian bytes, then to BigNat.
    let mut bytes = Vec::with_capacity(F::characteristic().len() * 8);
    for &w in F::characteristic().iter() {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    BigNat::from_bytes_le(&bytes)
}

#[test]
fn test_convert_nat_fe() {
    let nat = BigNat::from(42u64);
    let fe = nat_to_fe::<ark_bn254::Fr>(&nat);
    assert_eq!(fe, ark_bn254::Fr::from(42u64));

    let nat = fe_to_nat(&fe);
    assert_eq!(nat, BigNat::from(42u64));
}

#[test]
fn test_nat_to_limbs() {
    use ark_ff::UniformRand;
    use ark_std::rand::{SeedableRng, rngs::StdRng};
    use std::str::FromStr;

    const RSA_MODULO: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070\
    7595556264018525880784406918290641249515082189298559149176184502808489120072\
    8449926873928072877767359714183472702618963750149718246911650776133798590957\
    0009733045974880842840179742910064245869181719511874612151517265463228221686\
    9987549182422433637259085141865462043576798423387184774447920739934236584823\
    8242811981638150106748104516603773060562016196762561338441436038339044149526\
    3443219011465754445417842402092461651572335077870774981712577246796292638635\
    6373289912154831438167899885040445364023527381951378636564391212010397122822\
    120720357";

    let mut rng = StdRng::seed_from_u64(0u64);
    let f = <ark_bn254::Fr>::rand(&mut rng);
    let f2 = nat_to_fe::<ark_bn254::Fr>(&fe_to_nat(&f));
    assert_eq!(f, f2);

    let m = BigNat::from_str(RSA_MODULO).unwrap();
    let bit_capacity = <ark_bn254::Fr>::MODULUS_BIT_SIZE as usize - 1;
    let m2 = limbs_to_nat::<ark_bn254::Fr>(
        &nat_to_limbs::<ark_bn254::Fr>(&m, bit_capacity, m.bits() as usize / bit_capacity + 1),
        bit_capacity,
    );
    assert_eq!(m, m2);
}
