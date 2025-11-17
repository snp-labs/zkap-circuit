use ark_std::rand::Rng;
use ark_ec::CurveGroup;
use gadget::signature::{SignatureScheme, schnorr::Schnorr};

use crate::core::signature::{SignatureParams, SignatureService};
use crate::error::error::SchnorrServiceError;
use crate::interface::signature::{SchnorrPublicKeyExtension, SchnorrSecretKeyExtension};
use crate::service::constants::{AppCurve, Blake2};


pub struct SchnorrSignatureParams;

impl SignatureParams for SchnorrSignatureParams {
    type PublicKey = SchnorrPublicKeyExtension<AppCurve, Blake2>;
    type SecretKey = SchnorrSecretKeyExtension<AppCurve, Blake2>;
    type Signature = <Schnorr<AppCurve, Blake2> as SignatureScheme>::Signature;
}

type SchnorrScheme = Schnorr<AppCurve, Blake2>;

pub struct SchnorrSignatureService;

impl SignatureService<SchnorrSignatureParams> for SchnorrSignatureService {
    fn keygen<R: Rng>(
        rng: &mut R,
    ) -> Result<
        (
            <SchnorrSignatureParams as SignatureParams>::PublicKey,
            <SchnorrSignatureParams as SignatureParams>::SecretKey,
        ),
        SchnorrServiceError,
    > {
        let params = SchnorrScheme::setup(rng).map_err(|e| {
            SchnorrServiceError::KeyGenerationFailed(format!("Failed to setup parameters: {}", e))
        })?;

        let (vk, sk) = SchnorrScheme::keygen(&params, rng).map_err(|e| {
            SchnorrServiceError::KeyGenerationFailed(format!("Failed to generate keys: {}", e))
        })?;
        Ok((
            SchnorrPublicKeyExtension {
                params: params.clone(),
                vk,
            },
            SchnorrSecretKeyExtension { params, sk },
        ))
    }

    fn sign<R: Rng>(
        secret_key: &<SchnorrSignatureParams as SignatureParams>::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<<SchnorrSignatureParams as SignatureParams>::Signature, SchnorrServiceError> {
        SchnorrScheme::sign(&secret_key.params, &secret_key.sk, message, rng)
            .map_err(|e| SchnorrServiceError::SigningFailed(format!("Signing failed: {}", e)))
    }

    fn verify(
        public_key: &<SchnorrSignatureParams as SignatureParams>::PublicKey,
        message: &[u8],
        signature: &<SchnorrSignatureParams as SignatureParams>::Signature,
    ) -> Result<bool, SchnorrServiceError> {
        SchnorrScheme::verify(&public_key.params, &public_key.vk, message, signature)
            .map_err(|e| SchnorrServiceError::SigningFailed(format!("Verification failed: {}", e)))
    }

    fn get_public_key(
            sk: &<SchnorrSignatureParams as SignatureParams>::SecretKey,
        ) -> Result<<SchnorrSignatureParams as SignatureParams>::PublicKey, SchnorrServiceError> {
        let vk = (sk.params.generator * sk.sk.0).into_affine();
        Ok(SchnorrPublicKeyExtension {
            params: sk.params.clone(),
            vk,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_schnorr_core_keygen() {
        let mut rng = test_rng();
        let (_public_key, secret_key) = SchnorrSignatureService::keygen(&mut rng).unwrap();

        // 키가 올바르게 생성되었는지 간단한 검증
        assert!(secret_key.sk.0 != ark_ed_on_bn254::Fr::from(0u64));
    }

    #[test]
    fn test_schnorr_core_sign_and_verify() {
        let mut rng = test_rng();
        let (public_key, secret_key) = SchnorrSignatureService::keygen(&mut rng).unwrap();

        let message = b"Hello, Schnorr Core!";
        let signature = SchnorrSignatureService::sign(&secret_key, message, &mut rng).unwrap();

        let is_valid = SchnorrSignatureService::verify(&public_key, message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_schnorr_core_invalid_signature() {
        let mut rng = test_rng();
        let (_public_key1, secret_key1) = SchnorrSignatureService::keygen(&mut rng).unwrap();
        let (public_key2, _) = SchnorrSignatureService::keygen(&mut rng).unwrap();

        let message = b"Hello, Schnorr Core!";
        let signature = SchnorrSignatureService::sign(&secret_key1, message, &mut rng).unwrap();

        // 다른 공개키로 검증 시도 (실패해야 함)
        let is_valid = SchnorrSignatureService::verify(&public_key2, message, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_schnorr_core_wrong_message() {
        let mut rng = test_rng();
        let (public_key, secret_key) = SchnorrSignatureService::keygen(&mut rng).unwrap();

        let message = b"Hello, Schnorr Core!";
        let wrong_message = b"Wrong message";
        let signature = SchnorrSignatureService::sign(&secret_key, message, &mut rng).unwrap();

        // 다른 메시지로 검증 시도 (실패해야 함)
        let is_valid =
            SchnorrSignatureService::verify(&public_key, wrong_message, &signature).unwrap();
        assert!(!is_valid);
    }
}
