use std::path::PathBuf;

/// 증명 생성을 위한 원시 입력 데이터
#[derive(Debug, Clone)]
pub struct RawProofRequest {
    /// Proving key 파일 경로
    pub pk_path: PathBuf,

    /// JWT 토큰들
    pub jwts: Vec<String>,

    /// RSA 공개키 modulus (Base64 인코딩)
    pub pk_ops: Vec<String>,

    /// 머클 경로들 (각 JWT에 대해)
    pub merkle_paths: Vec<Vec<String>>,

    /// 머클 트리 리프 인덱스들
    pub leaf_indices: Vec<usize>,

    /// 머클 루트 (hex/decimal 문자열)
    pub root: String,

    /// 앵커 값들 (마지막 요소는 hanchor)
    pub anchor: Vec<String>,

    /// 서명된 UserOperation 해시
    pub h_sign_user_op: String,

    /// 블라인딩을 위한 랜덤 값
    pub random: String,

    /// 허용된 Audience 목록
    pub aud_list: Vec<String>,
}

impl RawProofRequest {
    /// 새로운 RawProofRequest 생성
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pk_path: PathBuf,
        jwts: Vec<String>,
        pk_ops: Vec<String>,
        merkle_paths: Vec<Vec<String>>,
        leaf_indices: Vec<usize>,
        root: String,
        anchor: Vec<String>,
        h_sign_user_op: String,
        random: String,
        aud_list: Vec<String>,
    ) -> Self {
        Self {
            pk_path,
            jwts,
            pk_ops,
            merkle_paths,
            leaf_indices,
            root,
            anchor,
            h_sign_user_op,
            random,
            aud_list,
        }
    }

    /// JWT 토큰 개수 반환
    pub fn token_count(&self) -> usize {
        self.jwts.len()
    }
}
