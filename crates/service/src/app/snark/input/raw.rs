use std::path::PathBuf;

/// Raw input data for proof generation
#[derive(Debug, Clone)]
pub struct RawProofRequest {
    /// Proving key file path
    pub pk_path: PathBuf,

    /// JWT tokens
    pub jwts: Vec<String>,

    /// RSA public key modulus (Base64 encoded)
    pub pk_ops: Vec<String>,

    /// Merkle paths (one per JWT)
    pub merkle_paths: Vec<Vec<String>>,

    /// Merkle tree leaf indices
    pub leaf_indices: Vec<usize>,

    /// Merkle root (hex/decimal string)
    pub root: String,

    /// Anchor values (last element is hanchor)
    pub anchor: Vec<String>,

    /// Signed UserOperation hash
    pub h_sign_user_op: String,

    /// Random value for blinding
    pub random: String,

    /// Allowed audience list
    pub aud_list: Vec<String>,
}

impl RawProofRequest {
    /// Create a new RawProofRequest
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

    /// Returns the number of JWT tokens
    pub fn token_count(&self) -> usize {
        self.jwts.len()
    }
}
