use std::path::Path;

use circuit::constants::CircuitConfig;
use serde::Deserialize;

use crate::error::ApplicationError;

#[derive(Deserialize)]
pub struct CrsManifest {
    pub profile: String,
    pub params: CrsParams,
    pub claims: Option<Vec<String>>,
    pub forbidden_string: Option<String>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct CrsParams {
    pub MAX_JWT_B64_LEN: u64,
    pub MAX_PAYLOAD_B64_LEN: u64,
    pub MAX_AUD_LEN: u64,
    pub MAX_EXP_LEN: u64,
    pub MAX_ISS_LEN: u64,
    pub MAX_NONCE_LEN: u64,
    pub MAX_SUB_LEN: u64,
    pub N: u64,
    pub K: u64,
    pub TREE_HEIGHT: u64,
    pub NUM_AUDIENCE_LIMIT: u64,
}

/// Validate that a `manifest.json` beside the proving key matches the active [`CircuitConfig`].
///
/// Looks for `manifest.json` in the same directory as `pk_path`.  If the file is absent the
/// function succeeds (backwards-compatible).  If present, every circuit parameter in the manifest
/// is compared against `params`; any mismatch causes an error listing all differing fields.
pub fn validate_crs_manifest(
    params: &CircuitConfig,
    pk_path: &Path,
) -> Result<(), ApplicationError> {
    let keys_dir = match pk_path.parent() {
        Some(dir) => dir,
        None => return Ok(()), // no parent dir, skip
    };

    let manifest_path = keys_dir.join("manifest.json");
    if !manifest_path.exists() {
        return Err(ApplicationError::InvalidFormat(format!(
            "No manifest.json found in {}. Cannot verify CRS parameter integrity. \
             Regenerate CRS keys with generate_crs to create a manifest, \
             or set ZKAP_SKIP_MANIFEST_CHECK=1 for development only.",
            keys_dir.display()
        )));
    }

    // Allow skipping manifest check for development workflows only
    if std::env::var("ZKAP_SKIP_MANIFEST_CHECK").is_ok() {
        log::warn!(
            "ZKAP_SKIP_MANIFEST_CHECK is set — skipping CRS manifest validation. \
             Do NOT use this in production."
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
        ($manifest_name:ident, $config_field:ident) => {
            if p.$manifest_name != params.$config_field {
                mismatches.push(format!(
                    "  {} : CRS={}, config={}",
                    stringify!($manifest_name),
                    p.$manifest_name,
                    params.$config_field
                ));
            }
        };
    }

    check!(MAX_JWT_B64_LEN, max_jwt_b64_len);
    check!(MAX_PAYLOAD_B64_LEN, max_payload_b64_len);
    check!(MAX_AUD_LEN, max_aud_len);
    check!(MAX_EXP_LEN, max_exp_len);
    check!(MAX_ISS_LEN, max_iss_len);
    check!(MAX_NONCE_LEN, max_nonce_len);
    check!(MAX_SUB_LEN, max_sub_len);
    check!(N, n);
    check!(K, k);
    check!(TREE_HEIGHT, tree_height);
    check!(NUM_AUDIENCE_LIMIT, num_audience_limit);

    if mismatches.is_empty() {
        log::info!("CRS manifest validated OK (profile: {})", manifest.profile);
        Ok(())
    } else {
        Err(ApplicationError::InvalidFormat(format!(
            "CRS parameter mismatch! The proving key was generated with different parameters.\n\
             Manifest profile: {}\n\
             Mismatches:\n{}\n\
             Regenerate CRS with matching config or use the correct config file.",
            manifest.profile,
            mismatches.join("\n")
        )))
    }
}

/// Load a [`CircuitConfig`] from a `manifest.json` file.
///
/// Reads and deserialises the JSON at `manifest_path`, maps the CRS parameter fields to a
/// [`CircuitConfig`], then calls [`CircuitConfig::validate`] before returning.  Use this when
/// you want to derive circuit parameters from an existing CRS manifest rather than a separate
/// config file.
pub fn load_params_from_manifest(manifest_path: &Path) -> Result<CircuitConfig, ApplicationError> {
    let content = std::fs::read_to_string(manifest_path).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to read manifest.json: {}", e))
    })?;

    let manifest: CrsManifest = serde_json::from_str(&content).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to parse manifest.json: {}", e))
    })?;

    let p = &manifest.params;

    let claims: Vec<Vec<u8>> = manifest
        .claims
        .unwrap_or_else(|| {
            vec![
                "aud".to_string(),
                "exp".to_string(),
                "iss".to_string(),
                "nonce".to_string(),
                "sub".to_string(),
            ]
        })
        .into_iter()
        .map(|s| s.into_bytes())
        .collect();

    let forbidden_string: Vec<u8> = manifest
        .forbidden_string
        .unwrap_or_else(|| "forbidden".to_string())
        .into_bytes();

    let config = CircuitConfig {
        max_jwt_b64_len: p.MAX_JWT_B64_LEN,
        max_payload_b64_len: p.MAX_PAYLOAD_B64_LEN,
        max_aud_len: p.MAX_AUD_LEN,
        max_exp_len: p.MAX_EXP_LEN,
        max_iss_len: p.MAX_ISS_LEN,
        max_nonce_len: p.MAX_NONCE_LEN,
        max_sub_len: p.MAX_SUB_LEN,
        n: p.N,
        k: p.K,
        tree_height: p.TREE_HEIGHT,
        num_audience_limit: p.NUM_AUDIENCE_LIMIT,
        claims,
        forbidden_string,
    };

    config
        .validate()
        .map_err(|e| ApplicationError::InvalidFormat(format!("Invalid manifest params: {}", e)))?;

    Ok(config)
}
