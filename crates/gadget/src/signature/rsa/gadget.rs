use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::{Field, One, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    convert::ToConstraintFieldGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::ToBytesGadget,
    uint8::UInt8,
    uint32::UInt32,
};
use ark_relations::r1cs::SynthesisError;
use num_bigint::BigUint as NumBigUint;

use crate::{
    bigint::{
        constraints::{BigNatCircuitParams, BigNatTrait, BigNatVar},
        utils::{nat_to_limbs, BigNat},
    },
    hashes::{
        Parameter,
        sha256::{SHA256Gadget, constraints::SHA256Gadget as NewSHA256Gadget},
    },
};

#[cfg(feature = "constraints-logging")]
use crate::debug::log_r1cs_eq;

use super::native::{PublicKey, Signature};

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

pub fn rsa_verify_with_state<C, BNP, HP>(
    pk: PublicKeyVar<ConstraintF<C>, BNP>,
    sig: SignatureVar<ConstraintF<C>, BNP>,
    message: &[UInt8<ConstraintF<C>>],
    num_sha2_blocks: FpVar<ConstraintF<C>>,
    state: &[UInt32<ConstraintF<C>>],
) -> Result<(), SynthesisError>
where
    C: CurveGroup,
    BNP: BigNatCircuitParams,
    HP: Parameter<ConstraintF<C>>,
{
    let num_exp_bits: usize = 17; // RSA 2048 uses 17 bits for the exponent
    let mut sha256_gadget = SHA256Gadget::<ConstraintF<C>, HP>::default();

    sha256_gadget = sha256_gadget.set_state(state);
    let mut hashed_msg = sha256_gadget
        .digest_with_pad(message, num_sha2_blocks)
        .unwrap()
        .to_bytes_le()
        .unwrap();
    hashed_msg.reverse();

    let output = output_with_prifix(&hashed_msg);
    let output_fp = output.to_constraint_field().unwrap();

    let result = sig
        .sig
        .pow_mod(&pk.e, &pk.n, num_exp_bits)?
        .to_bytes_le()
        .unwrap();
    let result_fp = result.to_constraint_field().unwrap();
    result_fp.enforce_equal(&output_fp)?;
    Ok(())
}

pub fn new_rsa_verify_with_state<C, BNP>(
    pk: &PublicKeyVar<ConstraintF<C>, BNP>,
    sig: &SignatureVar<ConstraintF<C>, BNP>,
    message: &[UInt8<ConstraintF<C>>],
    num_sha2_blocks: &FpVar<ConstraintF<C>>,
    sha256_gadget: &mut NewSHA256Gadget<ConstraintF<C>>,
) -> Result<(), SynthesisError>
where
    C: CurveGroup,
    BNP: BigNatCircuitParams,
{
    let num_exp_bits: usize = 17; // RSA 2048 uses 17 bits for the exponent

    let mut hashed_msg = sha256_gadget
        .digest_with_pad(message, num_sha2_blocks.clone())
        .unwrap()
        .to_bytes_le()
        .unwrap();
    hashed_msg.reverse();

    let output = output_with_prifix(&hashed_msg);
    let output_fp = output.to_constraint_field().unwrap();

    let result = sig
        .sig
        .pow_mod(&pk.e, &pk.n, num_exp_bits)?
        .to_bytes_le()
        .unwrap();

    let result_fp = result.to_constraint_field().unwrap();

    #[cfg(feature = "constraints-logging")]
    log_r1cs_eq("rsa verify", &result_fp, &output_fp);
    result_fp.enforce_equal(&output_fp)?;
    Ok(())
}

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
            // let n: Vec<u8> = val.borrow().n.0.to_bytes_le();
            let mut n = val.borrow().n.clone();
            n.reverse();
            let chunked_n = n
                .chunks(BNP::LIMB_WIDTH / 8)
                .map(|chunk| ConstraintF::from_le_bytes_mod_order(chunk))
                .collect::<Vec<_>>();
            let word_size = BigNat::one() << BNP::LIMB_WIDTH as u32 - 1;
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
            let word_size = BigNat::one() << BNP::LIMB_WIDTH as u32 - 1;
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

pub fn output_with_prifix<F: PrimeField>(hashed: &Vec<UInt8<F>>) -> Vec<UInt8<F>> {
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
            utils::{nat_to_limbs, BigNat},
        }, signature::rsa::{gadget::SignatureVar, native::{PublicKey, Signature}},
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

    const N: &str = "tsQsUV8QpqrygsY-2-JCQ6Fw8_omM71IM2N_R8pPbzbgOl0p78MZGsgPOQ2HSznjD0FPzsH8oO2B5Uftws04LHb2HJAYlz25-lN5cqfHAfa3fgmC38FfwBkn7l582UtPWZ_wcBOnyCgb3yLcvJrXyrt8QxHJgvWO23ITrUVYszImbXQ67YGS0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0NfFdfsZhTT8YbxBvA8FdODgEwx7u_vf3J9qbi4-Kv8cvqyJuleIRSjVXPsIMnoejIn04APPKIjpMyQdnWlby7rNyQtE4-CV-jcFjqJbE_Xilcvqxt6DirjFCvYeKYl1uHLw";

    const JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImUyNmQ5MTdiMWZlOGRlMTMzODJhYTdjYzlhMWQ2ZTkzMjYyZjMzZTIiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI0MDgwNjA2OTkwMzQtMGVjMGV1ajE3MnZzc2VtaDRpZW1ycWZnNXNkanVqbDQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0MDgwNjA2OTkwMzQtMGVjMGV1ajE3MnZzc2VtaDRpZW1ycWZnNXNkanVqbDQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTEyNjg2ODYxOTQyOTAyNDI1NDQiLCJoZCI6ImtsYXl0bi5mb3VuZGF0aW9uIiwiZW1haWwiOiJjb2xpbi5rbGF5dG5Aa2xheXRuLmZvdW5kYXRpb24iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IkI0NmhtZklMVU9TS1RHSlRDQ3RteHciLCJub25jZSI6IjB4MDU0NjE2NWRmYTUwNGM4MmRhMWU0YWQ5ZmNiZWRkNGY4NTA4NGFkNjVmNjE1M2NjZWE1NTFlNGQxYmVmMTQ3MiIsImlhdCI6MTcyMjQ0MTkzMCwiZXhwIjoxNzIyNDQ1NTMwfQ.QE6VPZFXRPWlKjxgdM5vuPuCeE0RmsL-Yk6gZP6-VFctDPb8juzKYm9JXWOVdIWoWb4m1xtnwE8k1YRap4T6HtfTJq30Vm4NqR7GomKt4j5T1wuZYoitW-wATeuJF1h5mer6ch2JyGP87EoOSuInpG1ISOhG5kVgQr9wCfl18Wr_9kiOcxCsFVckYyE8vJda-mHcmd3BH7Pun8N3SXqshlIkhtBfrRC4gfNIXFwtO8wpw3LvJtvqN5DCzJgN0pdpm0GTzfcDcWGsRUnV2TGVCrjJEg4U8QMSx91VfmtViCC4vOsnbOkLt8GsFCbqb6z6ehSAz288H7CfkKNGFvkJLQ";

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
            BigNat::from(1u8) << BNP::LIMB_WIDTH as u32 - 1,
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
            BigNat::from(1u8) << BNP::LIMB_WIDTH as u32 - 1,
            ark_r1cs_std::prelude::AllocationMode::Witness,
        )
        .unwrap();
        let e_var = BigNatVar::<F, BNP>::alloc_from_limbs(
            cs.clone(),
            &vk_op,
            BigNat::from(1u8) << BNP::LIMB_WIDTH as u32 - 1,
            ark_r1cs_std::prelude::AllocationMode::Witness,
        )
        .unwrap();
        (n_var, e_var)
    }
}
