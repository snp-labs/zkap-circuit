pub mod constraints;

#[derive(Clone, Debug, Default)]
pub struct ClaimIndices {
    pub offset: usize,
    pub claim_len: usize,
    pub colon_idx: usize,
    pub value_idx: usize,
    pub value_len: usize,
}