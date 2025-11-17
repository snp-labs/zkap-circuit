use thiserror::Error;
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LinearSystemError {
    #[error("Invalid Matrix Dimensions")]
    InvalidMatrixDimensions,

    #[error("Invalid Length: {0}")]
    InvalidLength(String),

    #[error("Matrix is singular (no pivot found in column {0})")]
    SingularMatrix(usize),

    #[error("solution verify failed")]
    SolutionVerifyFailed,
}
