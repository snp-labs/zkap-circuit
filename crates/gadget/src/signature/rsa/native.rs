use std::marker::PhantomData;
use std::panic::{self, AssertUnwindSafe};

use crate::bigint::{constraints::BigNatCircuitParams, utils::nat_to_limbs};
use crate::signature::{SignatureScheme, errors::SignatureError};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
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

#[derive(Debug, Clone, Default, CanonicalSerialize, PartialEq, Eq, Hash, CanonicalDeserialize)]
pub struct PublicKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

impl PublicKey {
    pub fn empty() -> Self {
        PublicKey {
            n: vec![1; 256],
            e: vec![1; 3],
        }
    }

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

#[derive(Debug, Clone, Default)]
pub struct SecretKey {
    pub pk: PublicKey,        // Public key part
    pub n: BigUint,           // RSA modulus
    pub d: BigUint,           // RSA private exponent
    pub primes: Vec<BigUint>, // RSA primes
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature(pub Vec<u8>);

impl Default for Signature {
    fn default() -> Self {
        Signature(vec![0u8; 256])
    }
}

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

        // TODO: 반복되는 에러처리 코드 개선
        let result = panic::catch_unwind(AssertUnwindSafe(|| RsaPrivateKey::new(&mut rng, bits)));

        let priv_key = match result {
            Ok(Ok(key)) => key,
            Ok(Err(_e)) => return Err(SignatureError::GenerateLibKeyError),
            Err(_) => {
                return Err(SignatureError::Panic(
                    "lib priv_key generation panicked".to_string(),
                ));
            }
        };

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
        // TODO: 반복되는 에러처리 코드 개선
        let result = panic::catch_unwind(move || {
            RsaPrivateKey::from_components(
                sk.n.clone(),
                BigUint::from_bytes_be(&sk.pk.e),
                sk.d.clone(),
                sk.primes.clone(),
            )
        });

        let priv_key = match result {
            Ok(Ok(key)) => key,
            Ok(Err(_e)) => return Err(SignatureError::GenerateLibKeyError),
            Err(_) => {
                return Err(SignatureError::Panic(
                    "lib priv_key generation panicked".to_string(),
                ));
            }
        };

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
        // TODO: 반복되는 에러처리 코드 개선
        let result = panic::catch_unwind(move || {
            RsaPublicKey::new(BigUint::from_bytes_be(&pk.n), BigUint::from_bytes_be(&pk.e))
        });

        let pub_key = match result {
            Ok(Ok(key)) => key,
            Ok(Err(_e)) => return Err(SignatureError::GenerateLibKeyError),
            Err(_) => {
                return Err(SignatureError::Panic(
                    "lib pub_key generation panicked".to_string(),
                ));
            }
        };

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
mod tests {
    use rand::rngs::OsRng;
    use sha2::Sha256;

    use crate::{bigint::constraints::BigNatCircuitParams, signature::rsa::native::Rsa};

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
