use circuit::constants::F;

/// 앵커 검증을 위한 계산된 컨텍스트
#[derive(Clone)]
pub struct AnchorContext {
    /// 선택자 벡터 (현재 선택된 JWT 토큰 위치 표시)
    pub selector: Vec<u8>,

    /// <a, anchor> * random = <b, h_known> * random 을 위한 a 벡터
    pub a: Vec<F>,

    /// H(a, random) 값
    pub h_a: F,

    /// <a, anchor> * random - LHS 값
    pub lhs: F,

    /// 각 증명에 대한 partial RHS 값들
    pub partial_rhs_list: Vec<F>,

    /// 선택된 인덱스들 (selector[i] == 1인 i들)
    pub current_idx_list: Vec<usize>,
}

impl AnchorContext {
    /// 새로운 AnchorContext 생성
    pub fn new(
        selector: Vec<u8>,
        a: Vec<F>,
        h_a: F,
        lhs: F,
        partial_rhs_list: Vec<F>,
        current_idx_list: Vec<usize>,
    ) -> Self {
        Self {
            selector,
            a,
            h_a,
            lhs,
            partial_rhs_list,
            current_idx_list,
        }
    }

    /// i번째 증명에 대한 partial RHS 값
    pub fn partial_rhs_for(&self, proof_index: usize) -> F {
        self.partial_rhs_list[proof_index]
    }

    /// i번째 증명에 대한 current index
    pub fn current_idx_for(&self, proof_index: usize) -> usize {
        self.current_idx_list[proof_index]
    }
}
