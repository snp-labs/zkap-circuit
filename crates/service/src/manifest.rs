use std::path::Path;

use circuit::constants::ZkPasskeyConfig;
use serde::Deserialize;

use crate::error::ApplicationError;

#[derive(Deserialize)]
pub struct CrsManifest {
    pub profile: String,
    pub params: CrsParams,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct CrsParams {
    pub MAX_JWT_B64_LEN: usize,
    pub MAX_PAYLOAD_B64_LEN: usize,
    pub MAX_AUD_LEN: usize,
    pub MAX_EXP_LEN: usize,
    pub MAX_ISS_LEN: usize,
    pub MAX_NONCE_LEN: usize,
    pub MAX_SUB_LEN: usize,
    pub N: usize,
    pub K: usize,
    pub TREE_HEIGHT: usize,
    pub NUM_AUDIENCE_LIMIT: usize,
}

/// Load and validate manifest.json from the same directory as the proving key.
/// Returns Ok(()) if manifest matches or doesn't exist (backwards compatible).
/// Returns Err if manifest exists but parameters don't match.
pub fn validate_crs_manifest<Config: ZkPasskeyConfig>(
    pk_path: &Path,
) -> Result<(), ApplicationError> {
    let keys_dir = match pk_path.parent() {
        Some(dir) => dir,
        None => return Ok(()), // no parent dir, skip
    };

    let manifest_path = keys_dir.join("manifest.json");
    if !manifest_path.exists() {
        log::warn!(
            "No manifest.json found in {}. Cannot verify CRS parameter match.",
            keys_dir.display()
        );
        return Ok(());
    }

    let content = std::fs::read_to_string(&manifest_path).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to read manifest.json: {}", e))
    })?;

    let manifest: CrsManifest = serde_json::from_str(&content).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to parse manifest.json: {}", e))
    })?;

    let p = &manifest.params;
    let mut mismatches = Vec::new();

    macro_rules! check {
        ($name:ident) => {
            if p.$name != Config::$name {
                mismatches.push(format!(
                    "  {} : CRS={}, binary={}",
                    stringify!($name),
                    p.$name,
                    Config::$name
                ));
            }
        };
    }

    check!(MAX_JWT_B64_LEN);
    check!(MAX_PAYLOAD_B64_LEN);
    check!(MAX_AUD_LEN);
    check!(MAX_EXP_LEN);
    check!(MAX_ISS_LEN);
    check!(MAX_NONCE_LEN);
    check!(MAX_SUB_LEN);
    check!(N);
    check!(K);
    check!(TREE_HEIGHT);
    check!(NUM_AUDIENCE_LIMIT);

    if mismatches.is_empty() {
        log::info!(
            "CRS manifest validated OK (profile: {})",
            manifest.profile
        );
        Ok(())
    } else {
        Err(ApplicationError::InvalidFormat(format!(
            "CRS parameter mismatch! The proving key was generated with different parameters.\n\
             Manifest profile: {}\n\
             Mismatches:\n{}\n\
             Regenerate CRS with matching ZK_PROFILE or rebuild the binary.",
            manifest.profile,
            mismatches.join("\n")
        )))
    }
}
