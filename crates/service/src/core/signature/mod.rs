pub mod schnorr;

use ark_std::rand::Rng;
use crate::error::error::SchnorrServiceError;

// 각 서명 스킴의 구현에 필요한 타입들을 모아놓은 "설정" 트레잇
pub trait SignatureParams {
    type PublicKey;
    type SecretKey;
    type Signature;
}

pub trait SignatureService<P: SignatureParams> {
    /// 키 쌍을 생성합니다
    fn keygen<R: Rng>(
        rng: &mut R,
    ) -> Result<(P::PublicKey, P::SecretKey), SchnorrServiceError>;

    /// 메시지에 대한 서명을 생성합니다
    fn sign<R: Rng>(
        secret_key: &P::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<P::Signature, SchnorrServiceError>;

    /// 서명을 검증합니다
    fn verify(
        public_key: &P::PublicKey,
        message: &[u8],
        signature: &P::Signature,
    ) -> Result<bool, SchnorrServiceError>;

    fn get_public_key(
        sk: &P::SecretKey,
    ) -> Result<P::PublicKey, SchnorrServiceError>;
}