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

/// Abstract interface for a public-key signature scheme.
///
/// Implementors supply concrete key, parameter, and signature types together with
/// the four lifecycle methods (`setup`, `keygen`, `sign`, `verify`). The RSA-2048
/// instantiation is [`rsa::Rsa`]; new schemes can be added without touching circuit code.
pub trait SignatureScheme {
    /// Scheme-specific public parameters (e.g., hash OID for RSA PKCS#1).
    type Parameters: Clone + Send + Sync;
    /// Public key type; must be serialisable and hashable for use as circuit input.
    type PublicKey: CanonicalSerialize + Hash + Eq + Clone + Default + Send + Sync;
    /// Secret key type; never leaves the prover and is not committed to the circuit.
    type SecretKey: Clone + Default;
    /// Opaque signature bytes; passed to both the native verifier and the R1CS gadget.
    type Signature: Clone + Default + Send + Sync;

    /// Generates public parameters for the scheme (may be a no-op, e.g. for RSA).
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, SignatureError>;

    /// Derives a fresh `(PublicKey, SecretKey)` pair from the public parameters.
    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), SignatureError>;

    /// Signs `message` under `sk` and the public parameters.
    fn sign<R: Rng>(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, SignatureError>;

    /// Returns `true` when `signature` over `message` is valid under `pk`.
    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, SignatureError>;
}
