use gadget::anchor::error::AnchorError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("{0}")]
    InvalidFormat(String),

    #[error("Invalid variant")]
    InvalidVariant,

    #[error("{0}")]
    Other(String),

    #[error("Anchor error: {0}")]
    AnchorError(#[from] AnchorError),

    #[error("Poseidon hash error")]
    PoseidonHashError,
}
