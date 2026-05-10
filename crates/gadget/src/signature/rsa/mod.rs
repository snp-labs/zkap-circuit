//! Native RSA-2048 / PKCS#1 v1.5 key generation, signing, and verification.
//!
//! Provides [`PublicKey`], [`SecretKey`], [`Signature`], and [`Parameter`] types, plus
//! the [`Rsa`] struct implementing [`crate::signature::SignatureScheme`]. Keys are
//! represented as big-integer limbs (see [`crate::bigint`]). The `setup`, `keygen`,
//! `sign`, and `verify` methods use the `rsa` crate internally. The corresponding
//! R1CS gadget that enforces PKCS#1 v1.5 verification in-circuit is in [`constraints`].

pub mod constraints;

use std::marker::PhantomData;

use crate::bigint::{constraints::BigNatCircuitParams, utils::nat_to_limbs};
use crate::signature::{SignatureScheme, errors::SignatureError};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigUint as NumBigUint;
use rand::Rng;
use rsa::BigUint;
use rsa::pkcs1v15::Signature as CrateSignature;
use rsa::pkcs8::AssociatedOid;
use rsa::rand_core::OsRng;
use rsa::signature::{RandomizedSigner, Verifier};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{SigningKey, VerifyingKey},
    traits::{PrivateKeyParts, PublicKeyParts},
};
use sha2::Digest;

/// RSA-2048 public key in raw big-endian byte form.
///
/// `n` holds the 256-byte modulus and `e` the (typically 3-byte) public exponent,
/// both big-endian. [`to_limbs`](PublicKey::to_limbs) converts them to the limb
/// representation consumed by [`PublicKeyVar`](constraints::PublicKeyVar).
#[derive(Debug, Clone, Default, CanonicalSerialize, PartialEq, Eq, Hash, CanonicalDeserialize)]
pub struct PublicKey {
    /// RSA modulus `n` as a big-endian byte vector (256 bytes for RSA-2048).
    pub n: Vec<u8>,
    /// RSA public exponent `e` as a big-endian byte vector (typically `[0x01, 0x00, 0x01]`).
    pub e: Vec<u8>,
}

impl PublicKey {
    /// Returns a placeholder `PublicKey` with all-ones bytes, safe to use as a
    /// dummy witness when the actual key is not yet known (e.g., in `empty` circuit inputs).
    pub fn empty() -> Self {
        PublicKey {
            n: vec![1; 256],
            e: vec![1; 3],
        }
    }

    /// Decomposes `n` and `e` into `BNP::N_LIMBS` little-endian limbs of `BNP::LIMB_WIDTH` bits
    /// each, expressed as `C::BaseField` elements for use in the R1CS gadget.
    pub fn to_limbs<BNP, C>(&self) -> (Vec<C::BaseField>, Vec<C::BaseField>)
    where
        BNP: BigNatCircuitParams,
        C: CurveGroup,
        C::BaseField: PrimeField,
    {
        let n_biguint = NumBigUint::from_bytes_be(&self.n);
        let e_biguint = NumBigUint::from_bytes_be(&self.e);

        let n_limbs = nat_to_limbs(&n_biguint, BNP::LIMB_WIDTH, BNP::N_LIMBS);
        let e_limbs = nat_to_limbs(&e_biguint, BNP::LIMB_WIDTH, BNP::N_LIMBS);

        (n_limbs, e_limbs)
    }
}

/// RSA-2048 private key bundle.
///
/// Holds all components needed by the `rsa` crate for PKCS#1 v1.5 signing.
/// Never serialized to disk or committed to a circuit; only used by the native prover.
#[derive(Debug, Clone, Default)]
pub struct SecretKey {
    /// Corresponding public key, cached to avoid recomputation.
    pub pk: PublicKey,
    /// RSA modulus `n = p * q`.
    pub n: BigUint,
    /// RSA private exponent `d ≡ e⁻¹ (mod λ(n))`.
    pub d: BigUint,
    /// Prime factors `[p, q]` used for CRT-accelerated signing.
    pub primes: Vec<BigUint>,
}

/// Public parameters for the RSA scheme.
///
/// RSA-2048 / PKCS#1 v1.5 has no per-instance public parameters beyond the key itself,
/// so this struct is empty.  It exists to satisfy the [`SignatureScheme`] interface
/// which requires a `Parameters` associated type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {}

/// A raw PKCS#1 v1.5 RSA-2048 signature (256 big-endian bytes).
///
/// Wraps the signature byte vector produced by the `rsa` crate.  The default value
/// is 256 zero bytes, used as a dummy witness in empty circuit inputs.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature(pub Vec<u8>);

impl Default for Signature {
    fn default() -> Self {
        Signature(vec![0u8; 256])
    }
}

/// RSA-2048 / PKCS#1 v1.5 signature scheme parameterised by limb layout and digest.
///
/// `BNP` controls how the 2048-bit modulus is split into field-element limbs (e.g. 32 limbs of
/// 64 bits each).  `D` is the digest algorithm (typically `sha2::Sha256`).  Instantiate as
/// `Rsa::<MyBNP, Sha256>` and call the trait methods via [`SignatureScheme`].
pub struct Rsa<BNP: BigNatCircuitParams, D> {
    _params: PhantomData<(BNP, D)>,
}

impl<BNP, D> Rsa<BNP, D>
where
    BNP: BigNatCircuitParams,
    D: Digest + AssociatedOid,
{
    fn setup<R: Rng>(_rng: &mut R) -> Result<Parameter, SignatureError> {
        // RSA does not require any specific parameters for setup
        Ok(Parameter {})
    }

    fn keygen<R: Rng>(
        _pp: &Parameter,
        _rng: &mut R,
    ) -> Result<(PublicKey, SecretKey), SignatureError> {
        let bits = BNP::LIMB_WIDTH * BNP::N_LIMBS; // 2048 bits for RSA-2048
        let mut rng = OsRng; // Use OsRng for cryptographic randomness

        let priv_key =
            RsaPrivateKey::new(&mut rng, bits).map_err(|_| SignatureError::GenerateLibKeyError)?;

        let pub_key = RsaPublicKey::from(&priv_key);
        let pub_key = PublicKey {
            n: pub_key.n().to_bytes_be(),
            e: pub_key.e().to_bytes_be(),
        };

        Ok((
            pub_key.clone(),
            SecretKey {
                pk: pub_key,
                n: priv_key.n().clone(),
                d: priv_key.d().clone(),
                primes: priv_key.primes().to_vec(),
            },
        ))
    }

    fn sign<R: Rng>(
        _pp: &Parameter,
        sk: &SecretKey,
        message: &[u8],
        _rng: &mut R,
    ) -> Result<Signature, SignatureError> {
        let priv_key = RsaPrivateKey::from_components(
            sk.n.clone(),
            BigUint::from_bytes_be(&sk.pk.e),
            sk.d.clone(),
            sk.primes.clone(),
        )
        .map_err(|_| SignatureError::GenerateLibKeyError)?;

        let mut rng = OsRng; // Use OsRng for cryptographic randomness
        let signing_key = SigningKey::<D>::new(priv_key);
        let signature = signing_key.sign_with_rng(&mut rng, message);
        let sig_bytes: Box<[u8]> = signature.into();
        Ok(Signature(sig_bytes.to_vec()))
    }

    fn verify(
        _pp: &Parameter,
        pk: &PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool, SignatureError> {
        let pub_key =
            RsaPublicKey::new(BigUint::from_bytes_be(&pk.n), BigUint::from_bytes_be(&pk.e))
                .map_err(|_| SignatureError::GenerateLibKeyError)?;

        let verifying_key = VerifyingKey::<D>::new(pub_key);
        let signature = CrateSignature::try_from(signature.0.as_slice())
            .map_err(|_| SignatureError::GenerateLibSignatureError)?;
        verifying_key
            .verify(message, &signature)
            .map_err(|e| SignatureError::LibSignatureVerifyError(e.to_string()))?;

        Ok(true)
    }
}

impl<BNP, D> SignatureScheme for Rsa<BNP, D>
where
    BNP: BigNatCircuitParams,
    D: Digest + AssociatedOid,
{
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Parameters = Parameter;
    type Signature = Signature;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, SignatureError> {
        Self::setup(rng)
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), SignatureError> {
        Self::keygen(pp, rng)
    }

    fn sign<R: Rng>(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, SignatureError> {
        Self::sign(pp, sk, message, rng)
    }

    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, SignatureError> {
        Self::verify(pp, pk, message, signature)
    }
}

#[cfg(test)]
#[allow(clippy::upper_case_acronyms)]
mod tests {
    use rand::rngs::OsRng;
    use sha2::Sha256;

    use crate::{bigint::constraints::BigNatCircuitParams, signature::rsa::Rsa};

    const LAMBDA: usize = 2048; // 2048 bits

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNat512TestParams;
    impl BigNatCircuitParams for BigNat512TestParams {
        const LIMB_WIDTH: usize = 64;
        const N_LIMBS: usize = LAMBDA / 64;
    }

    pub type BNP = BigNat512TestParams;

    #[test]
    fn test_rsa_signature() {
        let mut rsg_rng = OsRng;
        let params = Rsa::<BNP, Sha256>::setup(&mut rsg_rng).unwrap();
        let (public_key, secret_key) = Rsa::<BNP, Sha256>::keygen(&params, &mut rsg_rng).unwrap();

        let message = b"Hello, RSA!";
        let signature =
            Rsa::<BNP, Sha256>::sign(&params, &secret_key, message, &mut rsg_rng).unwrap();

        assert!(Rsa::<BNP, Sha256>::verify(&params, &public_key, message, &signature).unwrap());
    }
}
