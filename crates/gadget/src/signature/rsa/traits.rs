// use ark_ec::CurveGroup;
// use ark_ff::Field;
// use ark_r1cs_std::{
//     convert::ToConstraintFieldGadget, eq::EqGadget, prelude::ToBytesGadget, uint8::UInt8,
// };
// use ark_relations::r1cs::SynthesisError;
// use rsa::pkcs8::AssociatedOid;
// use sha2::Digest;

// use crate::{
//     gadget::{
//         bigint::constraint::BigNatCircuitParams,
//         hashes::{
//             CRHScheme, Parameter,
//             constraints::CRHSchemeGadget,
//             sha256::{DigestVar, SHA256Gadget},
//         },
//         signature::constraints::SigVerifyGadget,
//     },
//     primitives::ConstraintF,
// };

// use super::{ParameterVar, PublicKeyVar, SignatureVar, gadget::output_with_prifix, native::Rsa};

//TODO: 현재 사용하지 않는 코드. rsa_verify_with_state만 사용 중이다.
// impl<C, HP, H, CRHG, BNP, D> SigVerifyGadget<Rsa<BNP, D>, ConstraintF<C>>
//     for RsaVerifyGadget<C, HP, H, CRHG, BNP>
// where
//     C: CurveGroup,
//     HP: Parameter<ConstraintF<C>>,
//     H: CRHScheme<Input = [UInt8<ConstraintF<C>>], Output = DigestVar<ConstraintF<C>>>,
//     CRHG: CRHSchemeGadget<H, ConstraintF<C>>,
//     BNP: BigNatCircuitParams,
//     D: Digest + AssociatedOid,
// {
//     type ParametersVar = ParameterVar<ConstraintF<C>>;
//     type PublicKeyVar = PublicKeyVar<ConstraintF<C>, BNP>;
//     type SignatureVar = SignatureVar<ConstraintF<C>, BNP>;

//     fn verify(
//         _parameters: &Self::ParametersVar,
//         public_key: &Self::PublicKeyVar,
//         message: &[UInt8<ConstraintF<C>>],
//         signature: &Self::SignatureVar,
//     ) -> Result<(), SynthesisError> {
//         let num_exp_bits: usize = 17; // RSA 2048 uses 17 bits for the exponent
//         let hashed_msg = SHA256Gadget::<ConstraintF<C>, HP>::digest(message)?;
//         let mut hashed_msg = hashed_msg.to_bytes_le()?;

//         hashed_msg.reverse();

//         let output = output_with_prifix(&hashed_msg);
//         let output_fp = output.to_constraint_field().unwrap();

//         let result = signature
//             .sig
//             .pow_mod(&public_key.e, &public_key.n, num_exp_bits)?
//             .to_bytes_le()
//             .unwrap();
//         let result_fp = result.to_constraint_field().unwrap();
//         result_fp.enforce_equal(&output_fp)?;

//         Ok(())
//     }
// }
