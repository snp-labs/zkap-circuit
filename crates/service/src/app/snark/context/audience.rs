use circuit::constants::F;

/// Audience 검증을 위한 계산된 컨텍스트
#[derive(Clone)]
pub struct AudienceContext {
    /// 패딩된 Audience 목록 (Config::NUM_AUDIENCE_LIMIT 길이)
    pub padded_list: Vec<F>,

    /// H(padded_aud_list)
    pub h_aud_list: F,
}

impl AudienceContext {
    /// 새로운 AudienceContext 생성
    pub fn new(padded_list: Vec<F>, h_aud_list: F) -> Self {
        Self {
            padded_list,
            h_aud_list,
        }
    }
}
