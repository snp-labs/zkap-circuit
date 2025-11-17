use crate::signature::{
    SigVerifyGadget,
    schnorr::{self, DigestToScalarField, PublicKey, Schnorr, Signature},
};
use ark_crypto_primitives::{
    crh::{CRHScheme, CRHSchemeGadget},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_serialize::CanonicalSerialize;
use core::{borrow::Borrow, marker::PhantomData};
use derivative::Derivative;

#[cfg(feature = "r1cs-debug")]
use crate::debug::log_r1cs_eq;

// convenient alias to denote scalars (in the constraint field)
type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// Parameters variable for Schnorr Signature scheme:
/// - Parameters for the message hash function
/// - Group generator
/// - Salt
#[derive(Clone)]
pub struct ParametersVar<
    C: CurveGroup,
    CG: CurveVar<C, ConstraintF<C>>,
    H: CRHScheme + Clone,
    HG: CRHSchemeGadget<H, ConstraintF<C>> + Clone,
> where
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    hash_params: HG::ParametersVar,
    generator: CG,
    salt: Vec<UInt8<ConstraintF<C>>>,
}

/// Public key variable for Schnorr Signature scheme
#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup, CG: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: CurveGroup, CG: CurveVar<C, ConstraintF<C>>")
)]
pub struct PublicKeyVar<C: CurveGroup, CG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    _group: PhantomData<*const C>,

    pub_key: CG,
}

/// Signature variable for Schnorr Signature scheme
#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup, CG: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: CurveGroup, CG: CurveVar<C, ConstraintF<C>>")
)]
pub struct SignatureVar<C: CurveGroup, CG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    _group: PhantomData<CG>,

    prover_response: Vec<UInt8<ConstraintF<C>>>,
    verifier_challenge: Vec<UInt8<ConstraintF<C>>>,
}

/// Gadget for generating R1CS constraints for Schnorr Signature verification
pub struct SchnorrSignatureVerifyGadget<
    C: CurveGroup,
    CG: CurveVar<C, ConstraintF<C>>,
    H: CRHScheme<Input = [u8]> + Send + Sync,
    HG: CRHSchemeGadget<H, ConstraintF<C>>,
> where
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    // required for binding all generics to this struct
    _group: PhantomData<C>,
    _group_gadget: PhantomData<CG>,
    _hash: PhantomData<H>,
    _hash_gadget: PhantomData<HG>,
}

impl<C, CG, H, HG> SigVerifyGadget<Schnorr<C, H>, ConstraintF<C>>
    for SchnorrSignatureVerifyGadget<C, CG, H, HG>
where
    C: CurveGroup,
    CG: CurveVar<C, ConstraintF<C>>,
    H: CRHScheme<Input = [u8]> + Send + Sync + Clone,
    HG: CRHSchemeGadget<H, ConstraintF<C>, InputVar = [UInt8<ConstraintF<C>>]> + Clone,
    <H as CRHScheme>::Parameters: Send + Sync,
    <H as CRHScheme>::Output: DigestToScalarField<C>,
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    type ParametersVar = ParametersVar<C, CG, H, HG>;
    type PublicKeyVar = PublicKeyVar<C, CG>;
    type SignatureVar = SignatureVar<C, CG>;

    /// Set all R1CS constraints for Schnorr signature verification for the given `message`.
    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF<C>>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.clone();
        let mut claimed_prover_commitment = parameters
            .generator
            .scalar_mul_le(prover_response.to_bits_le()?.iter())?;
        let public_key_times_verifier_challenge = public_key
            .pub_key
            .scalar_mul_le(verifier_challenge.to_bits_le()?.iter())?;
        claimed_prover_commitment += &public_key_times_verifier_challenge;

        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(parameters.salt.as_ref());
        hash_input.extend_from_slice(&claimed_prover_commitment.to_bytes_le()?);
        hash_input.extend_from_slice(message);

        let obtained_verifier_challenge =
            HG::evaluate(&parameters.hash_params, &hash_input)?.to_bytes_le()?;

        obtained_verifier_challenge.is_eq(&verifier_challenge.to_vec())
    }
}

pub fn verify_pk_root_signature<C, CV, H, HG>(
    _cs: ConstraintSystemRef<C::BaseField>,
    parameters: &ParametersVar<C, CV, H, HG>,
    root: &FpVar<C::BaseField>,
    public_key: &PublicKeyVar<C, CV>,
    signature: &SignatureVar<C, CV>,
) -> Result<(), SynthesisError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CV: CurveVar<C, C::BaseField>,
    H: CRHScheme<Input = [u8]> + Send + Sync + Clone,
    HG: CRHSchemeGadget<H, C::BaseField, InputVar = [UInt8<C::BaseField>]> + Clone,
    H::Parameters: Send + Sync,
    H::Output: DigestToScalarField<C>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    let message = root.to_bytes_le()?;
    let valid_sig_var = SchnorrSignatureVerifyGadget::<C, CV, H, HG>::verify(
        parameters, public_key, &message, signature,
    )?;

    #[cfg(feature = "r1cs-debug")]
    log_r1cs_eq("Schnorr PK Root Signature Validity", &[valid_sig_var.clone()], &[Boolean::TRUE]);

    valid_sig_var.enforce_equal(&Boolean::TRUE)?;
    Ok(())
}

// R1CS variable allocation for Schnorr parameters
impl<C, CG, H, HG> AllocVar<schnorr::Parameters<C, H>, ConstraintF<C>>
    for ParametersVar<C, CG, H, HG>
where
    C: CurveGroup,
    CG: CurveVar<C, ConstraintF<C>>,
    H: CRHScheme + Clone,
    HG: CRHSchemeGadget<H, ConstraintF<C>> + Clone,
    <H as CRHScheme>::Parameters: Send + Sync,
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    fn new_variable<T: Borrow<schnorr::Parameters<C, H>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let hash_params = HG::ParametersVar::new_variable(
                cs.clone(),
                || Ok(&val.borrow().hash_params),
                mode,
            )?;
            let generator = CG::new_variable(cs.clone(), || Ok(val.borrow().generator), mode)?;
            let salt = match mode {
                AllocationMode::Constant => UInt8::constant_vec(&val.borrow().salt),
                AllocationMode::Input => UInt8::new_input_vec(cs.clone(), &val.borrow().salt)?,
                AllocationMode::Witness => {
                    UInt8::new_witness_vec(cs.clone(), &val.borrow().salt.map(|x| Some(x)))?
                }
            };
            return Ok(Self {
                hash_params,
                generator,
                salt,
            });
        })
    }
}

// R1CS variable allocation for Schnorr public key
impl<C, CG> AllocVar<PublicKey<C>, ConstraintF<C>> for PublicKeyVar<C, CG>
where
    C: CurveGroup,
    CG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pub_key = CG::new_variable(cs, f, mode)?;
        Ok(Self {
            pub_key,
            _group: PhantomData,
        })
    }
}

// R1CS variable allocation for Schnorr signature
impl<C, CG> AllocVar<Signature<C>, ConstraintF<C>> for SignatureVar<C, CG>
where
    C: CurveGroup,
    CG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let mut response_bytes = Vec::new();
            val.borrow()
                .prover_response
                .serialize_uncompressed(&mut response_bytes)
                .unwrap();
            let mut challenge_bytes = Vec::new();
            val.borrow()
                .verifier_challenge
                .serialize_uncompressed(&mut challenge_bytes)
                .unwrap();

            let (prover_response, verifier_challenge) = match mode {
                AllocationMode::Constant => (
                    UInt8::constant_vec(&response_bytes),
                    UInt8::constant_vec(&challenge_bytes),
                ),
                AllocationMode::Input => (
                    UInt8::new_input_vec(cs.clone(), &response_bytes)?,
                    UInt8::new_input_vec(cs.clone(), &challenge_bytes)?,
                ),
                AllocationMode::Witness => (
                    UInt8::new_witness_vec(cs.clone(), &response_bytes)?,
                    UInt8::new_witness_vec(cs.clone(), &challenge_bytes)?,
                ),
            };
            Ok(SignatureVar {
                prover_response,
                verifier_challenge,
                _group: PhantomData,
            })
        })
    }
}

// implementing equality checking for Schnorr public key struct within R1CS
impl<C, CG> EqGadget<ConstraintF<C>> for PublicKeyVar<C, CG>
where
    C: CurveGroup,
    CG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

// implement signature to bytes conversion for Schnorr signature (needed for proof serialization)
impl<C, CG> ToBytesGadget<ConstraintF<C>> for SignatureVar<C, CG>
where
    C: CurveGroup,
    CG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    fn to_bytes_le(&self) -> Result<Vec<UInt8<ConstraintF<C>>>, SynthesisError> {
        let mut bytes = self.prover_response.to_bytes_le()?;
        bytes.extend_from_slice(self.verifier_challenge.to_bytes_le()?.as_slice());
        Ok(bytes)
    }
}

// implement signature to bytes conversion for Schnorr public key (needed for proof serialization)
impl<C, CG> ToBytesGadget<ConstraintF<C>> for PublicKeyVar<C, CG>
where
    C: CurveGroup,
    CG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CG: GroupOpsBounds<'a, C, CG>,
{
    fn to_bytes_le(&self) -> Result<Vec<UInt8<ConstraintF<C>>>, SynthesisError> {
        self.pub_key.to_bytes_le()
    }
}
