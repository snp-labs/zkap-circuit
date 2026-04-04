use std::fmt::Debug;

use ark_crypto_primitives::crh::poseidon::CRH;
use ark_serialize::*;
use gadget::bigint::constraints::BigNatCircuitParams;

pub const PAD_CHAR: char = '\0';

/// JSON-friendly circuit configuration intended for human-readable config files.
///
/// All string-typed fields (e.g. `claims`, `forbidden_string`) are kept as `String`/`Vec<String>`
/// for ergonomic serialisation.  Convert to [`CircuitConfig`] via `Into`/`From` before use in
/// proof generation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RawCircuitConfig {
    pub max_jwt_b64_len: u64,
    pub max_payload_b64_len: u64,
    pub max_aud_len: u64,
    pub max_exp_len: u64,
    pub max_iss_len: u64,
    pub max_nonce_len: u64,
    pub max_sub_len: u64,
    pub n: u64,
    pub k: u64,
    pub tree_height: u64,
    pub num_audience_limit: u64,
    pub claims: Vec<String>,
    pub forbidden_string: String,
}

/// Runtime circuit parameters used throughout proof generation and verification.
///
/// Unlike [`RawCircuitConfig`], all byte-string fields are stored as `Vec<u8>` for compatibility
/// with `CanonicalSerialize`.  Obtain an instance from [`RawCircuitConfig`] via `Into`, or load
/// one from a JSON file with [`CircuitConfig::from_json_file`].  Call [`CircuitConfig::validate`]
/// to enforce parameter constraints before use.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CircuitConfig {
    pub max_jwt_b64_len: u64,
    pub max_payload_b64_len: u64,
    pub max_aud_len: u64,
    pub max_exp_len: u64,
    pub max_iss_len: u64,
    pub max_nonce_len: u64,
    pub max_sub_len: u64,
    pub n: u64,
    pub k: u64,
    pub tree_height: u64,
    pub num_audience_limit: u64,
    pub claims: Vec<Vec<u8>>,
    pub forbidden_string: Vec<u8>,
}

impl From<RawCircuitConfig> for CircuitConfig {
    fn from(raw: RawCircuitConfig) -> Self {
        Self {
            max_jwt_b64_len: raw.max_jwt_b64_len,
            max_payload_b64_len: raw.max_payload_b64_len,
            max_aud_len: raw.max_aud_len,
            max_exp_len: raw.max_exp_len,
            max_iss_len: raw.max_iss_len,
            max_nonce_len: raw.max_nonce_len,
            max_sub_len: raw.max_sub_len,
            n: raw.n,
            k: raw.k,
            tree_height: raw.tree_height,
            num_audience_limit: raw.num_audience_limit,
            claims: raw.claims.into_iter().map(|s| s.into_bytes()).collect(),
            forbidden_string: raw.forbidden_string.into_bytes(),
        }
    }
}

impl CircuitConfig {
    /// Validate the parameter constraints required by the ZKAP circuit.
    ///
    /// Checks that `k >= 1`, `k <= n`, `tree_height >= 1`, `max_payload_b64_len <= max_jwt_b64_len`,
    /// `num_audience_limit >= 1`, and that `claims` is non-empty.  Returns an error string
    /// describing the first violation found.
    pub fn validate(&self) -> Result<(), String> {
        if self.k < 1 {
            return Err(format!("k must be >= 1, got: {}", self.k));
        }
        if self.k > self.n {
            return Err(format!("k ({}) must be <= n ({})", self.k, self.n));
        }
        if self.n < 1 {
            return Err(format!("n must be >= 1, got: {}", self.n));
        }
        if self.tree_height < 1 {
            return Err(format!(
                "tree_height must be >= 1, got: {}",
                self.tree_height
            ));
        }
        if self.max_payload_b64_len > self.max_jwt_b64_len {
            return Err(format!(
                "max_payload_b64_len ({}) must be <= max_jwt_b64_len ({})",
                self.max_payload_b64_len, self.max_jwt_b64_len
            ));
        }
        if self.num_audience_limit < 1 {
            return Err(format!(
                "num_audience_limit must be >= 1, got: {}",
                self.num_audience_limit
            ));
        }
        if self.claims.is_empty() {
            return Err("claims must not be empty".into());
        }
        Ok(())
    }

    /// JSON config file에서 로드 (RawCircuitConfig → CircuitConfig 변환)
    pub fn from_json_file(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        let raw: RawCircuitConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse config: {}", e))?;
        let config: Self = raw.into();
        config.validate()?;
        Ok(config)
    }
}

const LAMBDA: usize = 2048; // 2048 bits
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigNat2048Params;
impl BigNatCircuitParams for BigNat2048Params {
    const LIMB_WIDTH: usize = 64;
    const N_LIMBS: usize = LAMBDA / 64;
}

pub type CG = ark_ed_on_bn254::EdwardsProjective;
pub type F = <CG as ark_ec::CurveGroup>::BaseField;
pub type PoseidonHash = CRH<F>;
pub type BigNatTestParams = BigNat2048Params;
pub type BN254 = ark_bn254::Bn254;
pub type CV = ark_ed_on_bn254::constraints::EdwardsVar;
pub type BNP = BigNat2048Params;
