use crate::signature::rsa::native::{PublicKey, Signature};

pub mod constraints;

#[derive(Clone)]
pub struct TokenSig {
    pub sig: Signature,
    pub pk: PublicKey,
    pub state: Vec<u32>,
    pub nblocks: usize,
}

impl TokenSig {
    pub fn empty() -> Self {
        Self {
            sig: Signature::default(),
            pk: PublicKey::empty(),
            state: vec![0u32; 8],
            nblocks: 1,
        }
    }
}
