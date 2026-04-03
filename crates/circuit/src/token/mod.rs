use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

pub mod claimverifier;
pub mod constraints;

#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct ClaimIndices {
    pub offset: usize,
    pub claim_len: usize,
    pub colon_idx: usize,
    pub value_idx: usize,
    pub value_len: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Claim {
    pub key: String,
    pub value: String,
    pub indices: ClaimIndices,
}

impl Claim {
    pub fn empty() -> Self {
        Claim {
            key: String::new(),
            value: String::new(),
            indices: ClaimIndices::default(),
        }
    }
}
