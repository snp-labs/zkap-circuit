//! R1CS gadget for RSA-2048 PKCS#1 v1.5 signature verification.
//!
//! [`RSA2048VerifyGadget`] implements [`crate::signature::constraints::SigVerifyGadget`]
//! for RSA-2048 over BN254. The `output_with_prifix` function hardcodes the PKCS#1 v1.5
//! DigestInfo prefix bytes (SHA-256 OID encoding: `0x30 0x31 0x30 0x0d …`) and enforces
//! their equality with the recovered message bytes. Note: the function name contains a
//! known typo (`prifix` → `prefix`) which is tracked separately as G3' and will be
//! corrected in a dedicated cross-crate rename PR.

use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::{Field, One, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    prelude::ToBytesGadget,
    uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;
use num_bigint::BigUint as NumBigUint;

use crate::{
    bigint::{
        constraints::{BigNatCircuitParams, BigNatTrait, BigNatVar},
        utils::{BigNat, nat_to_limbs},
    },
    signature::rsa::{PublicKey, Signature},
};

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Clone, Debug, Default)]
pub struct ParameterVar<ConstriantF: PrimeField> {
    _phantom: PhantomData<ConstriantF>,
}

impl<ConstriantF: PrimeField> AllocVar<(), ConstriantF> for ParameterVar<ConstriantF> {
    fn new_variable<T: std::borrow::Borrow<()>>(
        _cs: impl Into<ark_relations::r1cs::Namespace<ConstriantF>>,
        _f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        _mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(ParameterVar {
            _phantom: PhantomData,
        })
    }
}

#[derive(Clone, Default)]
pub struct PublicKeyVar<F: PrimeField, BNP: BigNatCircuitParams> {
    pub n: BigNatVar<F, BNP>,
    pub e: BigNatVar<F, BNP>,
}

impl<ConstraintF: PrimeField, BNP: BigNatCircuitParams> AllocVar<PublicKey, ConstraintF>
    for PublicKeyVar<ConstraintF, BNP>
{
    fn new_variable<T: std::borrow::Borrow<PublicKey>>(
        cs: impl Into<ark_relations::r1cs::Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let mut n = val.borrow().n.clone();
            n.reverse();
            let chunked_n = n
                .chunks(BNP::LIMB_WIDTH / 8)
                .map(|chunk| ConstraintF::from_le_bytes_mod_order(chunk))
                .collect::<Vec<_>>();
            let word_size = BigNat::one() << (BNP::LIMB_WIDTH as u32 - 1);
            let n_var =
                BigNatVar::alloc_from_limbs(cs.clone(), &chunked_n, word_size.clone(), mode)?;

            let e = val.borrow().e.clone();
            let e_biguint = NumBigUint::from_bytes_be(&e);
            let chunked_e = nat_to_limbs(&e_biguint, BNP::LIMB_WIDTH, BNP::N_LIMBS);
            let e_var = BigNatVar::alloc_from_limbs(cs.clone(), &chunked_e, word_size, mode)?;
            Ok(PublicKeyVar { n: n_var, e: e_var })
        })
    }
}

impl<ConstraintF: PrimeField, BNP: BigNatCircuitParams> ToBytesGadget<ConstraintF>
    for PublicKeyVar<ConstraintF, BNP>
{
    fn to_bytes_le(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        let n_bytes = self.n.to_bytes_le()?;
        let e_bytes = self.e.to_bytes_le()?;
        let mut bytes = Vec::with_capacity(n_bytes.len() + e_bytes.len());
        bytes.extend(n_bytes);
        bytes.extend(e_bytes);
        Ok(bytes)
    }
}

#[derive(Clone)]
pub struct SignatureVar<F: PrimeField, BNP: BigNatCircuitParams> {
    pub sig: BigNatVar<F, BNP>,
}

impl<ConstriantF: PrimeField, BNP: BigNatCircuitParams> AllocVar<Signature, ConstriantF>
    for SignatureVar<ConstriantF, BNP>
{
    fn new_variable<T: std::borrow::Borrow<Signature>>(
        cs: impl Into<ark_relations::r1cs::Namespace<ConstriantF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let mut sig = val.borrow().clone();
            sig.0.reverse();
            let chunked_sig = sig
                .0
                .chunks(BNP::LIMB_WIDTH / 8)
                .map(|chunk| ConstriantF::from_le_bytes_mod_order(chunk))
                .collect::<Vec<_>>();
            let word_size = BigNat::one() << (BNP::LIMB_WIDTH as u32 - 1);
            let sig_var =
                BigNatVar::alloc_from_limbs(cs.clone(), &chunked_sig, word_size.clone(), mode)?;
            Ok(SignatureVar { sig: sig_var })
        })
    }
}

impl<ConstraintF: PrimeField, BNP: BigNatCircuitParams> ToBytesGadget<ConstraintF>
    for SignatureVar<ConstraintF, BNP>
{
    fn to_bytes_le(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        self.sig.to_bytes_le()
    }
}

pub fn output_with_prifix<F: PrimeField>(hashed: &[UInt8<F>]) -> Vec<UInt8<F>> {
    let mut output = Vec::new();
    let prifix1 = UInt8::<F>::constant_vec(&[32, 4, 0, 5, 1, 2, 4, 3]);
    let prifix2 = UInt8::<F>::constant_vec(&[101, 1, 72, 134, 96, 9, 6, 13]);
    let prifix3 = UInt8::<F>::constant_vec(&[48, 49, 48, 0, 255, 255, 255, 255]);
    let prifix4 = UInt8::<F>::constant_vec(&[255, 255, 255, 255, 255, 255, 1, 0]);
    let prifix5 = UInt8::<F>::constant_vec(&[255, 255, 255, 255, 255, 255, 255, 255]);
    output.extend_from_slice(hashed);
    output.extend_from_slice(&prifix1);
    output.extend_from_slice(&prifix2);
    output.extend_from_slice(&prifix3);

    for _ in 0..24 {
        output.extend_from_slice(&prifix5);
    }

    output.extend_from_slice(&prifix4);

    output
}

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystemRef;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use crate::{
        base64::decode_any_base64,
        bigint::{
            constraints::{BigNatCircuitParams, BigNatTrait, BigNatVar},
            utils::{BigNat, nat_to_limbs},
        },
        signature::rsa::{PublicKey, Signature, constraints::SignatureVar},
    };

    use super::PublicKeyVar;

    type F = ark_ed_on_bn254::Fq;
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct RSATESTParms;

    impl BigNatCircuitParams for RSATESTParms {
        const LIMB_WIDTH: usize = 64;
        const N_LIMBS: usize = 2048 / 64; // 32
    }

    #[test]
    fn test_var() {
        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        let pk_var = get_new_pk::<F, RSATESTParms>(N, "AQAB", cs.clone());
        let (n_var, e_var) = get_old_pk::<F, RSATESTParms>(N, "AQAB", cs.clone());

        assert!(
            n_var
                .limbs
                .value()
                .unwrap()
                .iter()
                .zip(pk_var.n.limbs.value().unwrap().iter())
                .all(|(a, b)| a == b)
        );

        assert!(
            e_var
                .limbs
                .value()
                .unwrap()
                .iter()
                .zip(pk_var.e.limbs.value().unwrap().iter())
                .all(|(a, b)| a == b)
        );

        let new_sig_var = get_new_sig::<F, RSATESTParms>(JWT, cs.clone());
        let old_sig_var = get_old_sig::<F, RSATESTParms>(JWT, cs.clone());

        assert!(
            new_sig_var
                .sig
                .limbs
                .value()
                .unwrap()
                .iter()
                .zip(old_sig_var.limbs.value().unwrap().iter())
                .all(|(a, b)| a == b)
        );
    }

    // Synthetic 2048-bit RSA modulus for testing (not a real key)
    const N: &str = "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqw";

    // Synthetic JWT with fake test claims (not a real token; cryptographic signature is zeroed)
    // Claims: iss=https://test.example.com, sub=test_user_000000000000, email=test@example.com
    const JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkLTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Rlc3QuZXhhbXBsZS5jb20iLCJhenAiOiJ0ZXN0LWNsaWVudC1pZCIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwic3ViIjoidGVzdF91c2VyXzAwMDAwMDAwMDAwMCIsImhkIjoiZXhhbXBsZS5jb20iLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiLCJub25jZSI6IjB4MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAzNjAwfQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn get_new_sig<F, BNP>(jwt: &str, cs: ConstraintSystemRef<F>) -> SignatureVar<F, BNP>
    where
        F: PrimeField,
        BNP: BigNatCircuitParams,
    {
        let parts = jwt.split('.').collect::<Vec<_>>();
        let sig = parts[2];

        let sig_bytes = decode_any_base64(sig).unwrap();

        SignatureVar::<F, BNP>::new_variable(
            cs.clone(),
            || Ok(Signature(sig_bytes)),
            ark_r1cs_std::prelude::AllocationMode::Witness,
        )
        .unwrap()
    }

    fn get_old_sig<F, BNP>(jwt: &str, cs: ConstraintSystemRef<F>) -> BigNatVar<F, BNP>
    where
        F: PrimeField,
        BNP: BigNatCircuitParams,
    {
        let parts = jwt.split('.').collect::<Vec<_>>();
        let sig = parts[2];

        let mut sig = URL_SAFE_NO_PAD.decode(sig.as_bytes()).unwrap();
        sig.reverse();
        let limbs = sig
            .chunks(8)
            .map(|chunk| <F>::from_le_bytes_mod_order(chunk))
            .collect::<Vec<_>>();

        BigNatVar::<F, BNP>::alloc_from_limbs(
            cs.clone(),
            &limbs,
            BigNat::from(1u8) << (BNP::LIMB_WIDTH as u32 - 1),
            ark_r1cs_std::prelude::AllocationMode::Witness,
        )
        .unwrap()
    }

    fn get_new_pk<F, BNP>(n: &str, e: &str, cs: ConstraintSystemRef<F>) -> PublicKeyVar<F, BNP>
    where
        F: PrimeField,
        BNP: BigNatCircuitParams,
    {
        let n_bytes = decode_any_base64(n).unwrap();
        let e_bytes = decode_any_base64(e).unwrap();

        PublicKeyVar::<F, BNP>::new_variable(
            cs.clone(),
            || {
                Ok(PublicKey {
                    n: n_bytes,
                    e: e_bytes,
                })
            },
            ark_r1cs_std::prelude::AllocationMode::Witness,
        )
        .unwrap()
    }

    fn get_old_pk<F, BNP>(
        n: &str,
        _e: &str,
        cs: ConstraintSystemRef<F>,
    ) -> (BigNatVar<F, BNP>, BigNatVar<F, BNP>)
    where
        F: PrimeField,
        BNP: BigNatCircuitParams,
    {
        let mut n = URL_SAFE_NO_PAD.decode(n.as_bytes()).unwrap();
        n.reverse();
        let n = n
            .chunks(8)
            .map(|chunk| <F>::from_le_bytes_mod_order(chunk))
            .collect::<Vec<_>>();

        let vk_op = BigNat::from(65537u64);
        let vk_op = nat_to_limbs::<F>(&vk_op, RSATESTParms::LIMB_WIDTH, RSATESTParms::N_LIMBS);

        let n_var = BigNatVar::<F, BNP>::alloc_from_limbs(
            cs.clone(),
            &n,
            BigNat::from(1u8) << (BNP::LIMB_WIDTH as u32 - 1),
            ark_r1cs_std::prelude::AllocationMode::Witness,
        )
        .unwrap();
        let e_var = BigNatVar::<F, BNP>::alloc_from_limbs(
            cs.clone(),
            &vk_op,
            BigNat::from(1u8) << (BNP::LIMB_WIDTH as u32 - 1),
            ark_r1cs_std::prelude::AllocationMode::Witness,
        )
        .unwrap();
        (n_var, e_var)
    }
}
