//! Signature scheme traits and re-exports for RSA-based JWT verification.
//!
//! [`SignatureScheme`] is the abstract interface for key generation, signing, and
//! verification. The RSA-2048 / PKCS#1 v1.5 instantiation lives in [`rsa`]. The
//! R1CS gadget trait [`constraints::SigVerifyGadget`] is re-exported at this level
//! so that circuit code can import it as `gadget::signature::SigVerifyGadget`.

use ark_serialize::CanonicalSerialize;
use ark_std::hash::Hash;
use errors::SignatureError;
use rand::prelude::Rng;

pub mod constraints;
pub mod errors;
pub mod rsa;

pub use constraints::SigVerifyGadget;
pub trait SignatureScheme {
    type Parameters: Clone + Send + Sync;
    type PublicKey: CanonicalSerialize + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: Clone + Default;
    type Signature: Clone + Default + Send + Sync;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, SignatureError>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), SignatureError>;

    fn sign<R: Rng>(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, SignatureError>;

    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, SignatureError>;
}
