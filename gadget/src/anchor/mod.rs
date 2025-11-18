use ark_std::rand::Rng;

use crate::anchor::error::AnchorError;

pub mod constraints;
// pub mod dl;
pub mod error;
pub mod poseidon;
pub mod utils;

/// Anchor Scheme의 핵심 트레잇 V3
///
/// 주요 개선사항:
/// - 불필요한 메서드 제거 (get_indices는 별도 유틸리티로 분리)
/// - 더 명확한 책임 분리
/// - 타입 파라미터 간소화
pub trait AnchorScheme {
    type Matrix;
    type PublicKey;
    type Secret;
    type Anchor;
    type Witness;

    /// 공개 키 생성
    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::PublicKey, AnchorError>;

    /// Anchor 생성 (시크릿 전체에서)
    fn generate_anchor(
        pk: &Self::PublicKey,
        secrets: &Self::Secret,
        matrix: &Self::Matrix,
    ) -> Result<Self::Anchor, AnchorError>;

    /// Witness 생성 (부분 시크릿에서)
    fn generate_witness(
        pk: &Self::PublicKey,
        secrets: &Self::Secret,
        selector: &[usize],
        matrix: &Self::Matrix,
    ) -> Result<Self::Witness, AnchorError>;

    /// Anchor와 Witness 검증
    fn verify(anchor: &Self::Anchor, witness: &Self::Witness) -> Result<(), AnchorError>;
}

/// Anchor 관련 헬퍼 함수들을 위한 트레잇
pub trait AnchorUtils {
    type Field;

    /// 두 벡터의 내적 계산
    fn inner_product(v1: &[Self::Field], v2: &[Self::Field]) -> Result<Self::Field, AnchorError>;
}
