use std::path::PathBuf;

use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use once_cell::sync::OnceCell;
use rand::{SeedableRng, rngs::StdRng, thread_rng};

use crate::{
    core::signature::{SignatureService, schnorr::SchnorrSignatureService},
    error::error::ApplicationError,
    interface::signature::{
        SchnorrPublicKeyExtension, SchnorrSecretKeyExtension, SchnorrSignRequestDto,
        SchnorrSignResponseDto,
    },
    service::{
        constants::{AppCurve, AppField, Blake2},
        key::io::load_key_uncompressed,
    },
    utils::point::str_to_field,
};

// pub fn init_signing_key(secret: &str) -> Result<(), ApplicationError> {
//     let secret_bytes = hex::decode(secret)
//         .map_err(|e| ApplicationError::Other(format!("Invalid hex in SCHNORR_SECRET: {}", e)))?;

//     if secret_bytes.len() > 32 {
//         return Err(ApplicationError::Other(
//             "SCHNORR_SECRET is too long; must be at most 32 bytes".to_string(),
//         ));
//     }

//     let mut seed = [0u8; 32];
//     seed[..secret_bytes.len()].copy_from_slice(&secret_bytes[..secret_bytes.len()]);
//     let mut rng = StdRng::from_seed(seed);

//     let (_, sk) = SchnorrSignatureService::keygen(&mut rng)?;

//     SIGNING_KEY
//         .set(sk)
//         .map_err(|_| ApplicationError::Other("Failed to set Schnorr secret key".to_string()))
// }

pub fn load_schnorr_sk() -> Result<SchnorrSecretKeyExtension<AppCurve, Blake2>, ApplicationError> {
    dotenv::dotenv().ok();

    let secret_hex = std::env::var("SCHNORR_SECRET")
        .map_err(|_| ApplicationError::EnvVarNotFound("SCHNORR_SECRET".to_string()))?;

    let secret_bytes = hex::decode(&secret_hex)
        .map_err(|e| ApplicationError::Other(format!("Invalid hex in SCHNORR_SECRET: {}", e)))?;

    if secret_bytes.len() > 32 {
        return Err(ApplicationError::Other(
            "SCHNORR_SECRET is too long; must be at most 32 bytes".to_string(),
        ));
    }

    let mut seed = [0u8; 32];
    seed[..secret_bytes.len()].copy_from_slice(&secret_bytes[..secret_bytes.len()]);
    let mut rng = StdRng::from_seed(seed);

    let (_, sk) = SchnorrSignatureService::keygen(&mut rng)?;

    Ok(sk)
}

pub fn schnorr_sign(
    key_path: String,
    root: String,
) -> Result<SchnorrSignResponseDto, ApplicationError> {
    let sk = load_key_uncompressed(&PathBuf::from(key_path))?;

    let mut rng = thread_rng();

    let root = str_to_field::<AppField>(&root).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to convert root to field element: {}", e))
    })?;

    let root_bytes_le = root.into_bigint().to_bytes_le();

    let signature = SchnorrSignatureService::sign(&sk, &root_bytes_le, &mut rng)?;

    let mut bytes = vec![];
    signature
        .serialize_uncompressed(&mut bytes)
        .map_err(|e| ApplicationError::Other(format!("Failed to serialize signature: {}", e)))?;

    Ok(SchnorrSignResponseDto { signature: bytes })
}

// pub fn get_schnorr_pk() -> Result<SchnorrPublicKeyExtension<AppCurve, Blake2>, ApplicationError> {
//     let sk = SIGNING_KEY.get().ok_or(ApplicationError::Other(
//         "Schnorr signing key not initialized".to_string(),
//     ))?;
//     Ok(SchnorrSignatureService::get_public_key(&sk)?)
// }
