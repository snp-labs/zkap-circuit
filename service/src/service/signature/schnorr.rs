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
    service::constants::{AppCurve, Blake2},
};

static SIGNING_KEY: OnceCell<SchnorrSecretKeyExtension<AppCurve, Blake2>> = OnceCell::new();

pub fn init_signing_key(secret: &str) -> Result<(), ApplicationError> {
    let secret_bytes = hex::decode(secret)
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

    SIGNING_KEY
        .set(sk)
        .map_err(|_| ApplicationError::Other("Failed to set Schnorr secret key".to_string()))
}

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
    dto: SchnorrSignRequestDto,
) -> Result<SchnorrSignResponseDto, ApplicationError> {
    let sk = SIGNING_KEY.get().ok_or(ApplicationError::Other(
        "Schnorr signing key not initialized".to_string(),
    ))?;
    let mut rng = thread_rng();

    let signature = SchnorrSignatureService::sign(&sk, &dto.message, &mut rng)?;

    let mut bytes = vec![];
    signature
        .serialize_uncompressed(&mut bytes)
        .map_err(|e| ApplicationError::Other(format!("Failed to serialize signature: {}", e)))?;

    Ok(SchnorrSignResponseDto { signature: bytes })
}

pub fn get_schnorr_pk() -> Result<SchnorrPublicKeyExtension<AppCurve, Blake2>, ApplicationError> {
    let sk = SIGNING_KEY.get().ok_or(ApplicationError::Other(
        "Schnorr signing key not initialized".to_string(),
    ))?;
    Ok(SchnorrSignatureService::get_public_key(&sk)?)
}
