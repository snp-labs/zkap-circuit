use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("{0}")]
    InvalidFormat(String),

    #[error("Invalid variant")]
    InvalidVariant,

    #[error("{0}")]
    Other(String),
}

// -----------------------------------------------------------------------------
// crate 내부 전용 에러들 (외부로 노출하지 않음)
// -----------------------------------------------------------------------------

#[derive(Debug, Error)]
pub(crate) enum KeyError {
    #[error("Failed to load key from path {path}: {source}")]
    LoadFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Deserialization failed for {path}: {source}")]
    DeserializeFailed {
        path: String,
        #[source]
        source: ark_serialize::SerializationError,
    },
}

impl From<KeyError> for ApplicationError {
    fn from(e: KeyError) -> Self {
        ApplicationError::InvalidFormat(e.to_string())
    }
}
