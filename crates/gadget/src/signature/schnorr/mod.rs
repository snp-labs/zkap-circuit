use ark_crypto_primitives::crh::CRHScheme;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, ToConstraintField, fields::PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::{hash::Hash, marker::PhantomData, vec::Vec};
use rand::Rng;
use std::fmt::Debug;
use std::ops::Mul;

use derivative::Derivative;
pub mod constraints;

use crate::signature::{SignatureScheme, errors::SignatureError};

/// Schnorr Signature Scheme
pub struct Schnorr<C: CurveGroup, H: CRHScheme> {
    _group: PhantomData<C>,
    _hash: PhantomData<H>,
}

/// Parameters for Schnorr Signature scheme:
/// - Parameters for the message hash function
/// - Group generator
/// - Salt
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone(
    bound = "C: CurveGroup, H: CRHScheme, <H as CRHScheme>::Parameters: Send + Sync"
))]
pub struct Parameters<C: CurveGroup, H: CRHScheme>
where
    <H as CRHScheme>::Parameters: Send + Sync + Clone,
{
    pub hash_params: H::Parameters,
    pub generator: C::Affine,
    pub salt: [u8; 32],
}

// Public key is simply an alias to an affine group element (struct is overkill)
pub type PublicKey<C> = <C as CurveGroup>::Affine;

/// Secret Key for Schnorr Signature (contains only a scalar)
#[derive(Clone, Default, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey<C: CurveGroup>(pub C::ScalarField);

/// Convenient trait for conversing a message hash digest to a scalar. This is mostly defined for
/// making the type system work.
pub trait DigestToScalarField<C: CurveGroup> {
    /// Transform this value into a scalar. Allowed to fail if conversion not possible.
    fn digest_to_scalar_field(&self) -> Result<C::ScalarField, SignatureError>;
}

impl<C: CurveGroup> DigestToScalarField<C> for Vec<u8> {
    /// Transform this value into a scalar using an attempt to deserialize the hash as a scalar.
    /// Returns an error of deserialization is not possible.
    fn digest_to_scalar_field(&self) -> Result<C::ScalarField, SignatureError> {
        Ok(C::ScalarField::deserialize_uncompressed(self.as_slice())?)
    }
}

/// Schnorr signature
#[derive(Clone, Default, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<C: CurveGroup> {
    pub prover_response: C::ScalarField,
    pub verifier_challenge: C::ScalarField,
}

impl<C: CurveGroup + Hash, H: CRHScheme<Input = [u8]> + Send + Sync> SignatureScheme
    for Schnorr<C, H>
where
    C::ScalarField: PrimeField,
    <H as CRHScheme>::Parameters: Send + Sync,
    <H as CRHScheme>::Output: DigestToScalarField<C>,
{
    type Parameters = Parameters<C, H>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, SignatureError> {
        let hash_params = H::setup(rng)?;
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let generator = C::rand(rng).into();

        Ok(Parameters {
            hash_params,
            generator,
            salt,
        })
    }

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), SignatureError> {
        // Secret key is a random scalar x
        // the public key is y = xG
        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();

        Ok((public_key, SecretKey(secret_key)))
    }

    fn sign<R: Rng>(
        parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, SignatureError> {
        // (k, e);
        let (random_scalar, verifier_challenge) = loop {
            // Sample a random scalar `k` from the prime scalar field.
            let random_scalar: C::ScalarField = C::ScalarField::rand(rng);
            // Commit to the random scalar via r := k · G.
            // This is the prover's first msg in the Sigma protocol.
            let prover_commitment = parameters.generator.mul(random_scalar).into_affine();

            // Hash everything to get verifier challenge.
            // e := H(salt || r || msg);
            let mut hash_input = Vec::new();
            hash_input.extend_from_slice(&parameters.salt);
            prover_commitment.serialize_uncompressed(&mut hash_input)?;
            hash_input.extend_from_slice(&message);

            let hash_digest = H::evaluate(&parameters.hash_params, hash_input.as_slice())?;

            if let Ok(verifier_challenge) = hash_digest.digest_to_scalar_field() {
                break (random_scalar, verifier_challenge);
            }
        };
        // k - xe;
        let prover_response = random_scalar - (verifier_challenge * sk.0);
        let signature = Signature {
            prover_response,
            verifier_challenge,
        };

        Ok(signature)
    }

    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, SignatureError> {
        let Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        // sG = kG - eY
        // kG = sG + eY
        // so we first solve for kG.
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = pk.mul(verifier_challenge);
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        // e = H(salt, kG, msg)
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&parameters.salt);
        claimed_prover_commitment.serialize_uncompressed(&mut hash_input)?;
        hash_input.extend_from_slice(&message);

        // cast the hash output to get e
        let hash_digest = H::evaluate(&parameters.hash_params, hash_input.as_slice())?;

        let obtained_verifier_challenge = hash_digest.digest_to_scalar_field();
        // The signature is valid iff the computed verifier challenge is the same as the one
        // provided in the signature
        match obtained_verifier_challenge {
            Ok(obtained_verifier_challenge) => {
                Ok(*verifier_challenge == obtained_verifier_challenge)
            }
            Err(_) => Ok(false),
        }
    }
}

impl<ConstraintF: Field, C: CurveGroup + ToConstraintField<ConstraintF>, H: CRHScheme>
    ToConstraintField<ConstraintF> for Parameters<C, H>
where
    <H as CRHScheme>::Parameters: Send + Sync,
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        self.generator.into_group().to_field_elements()
    }
}
