//! Boundary adapter: [`ProveRequest`] → `(SharedDecoded, Vec<CredentialDecoded>)`.
//!
//! Wire-decoding only. Validates the request's shape against
//! `CircuitConfig`, decodes every string-encoded field element via
//! [`ark_utils::codec::string::hex_decimal_to_field`], and decodes the
//! base64-encoded RSA modulus and JWT signature segment. Returns lean
//! F-based DTOs ready for the prover's per-credential streaming loop.
//!
//! All cryptographic derivation (`derive_x_from_secret`,
//! `derive_selector_from_x_list_and_anchor`, JWT claim parsing for the
//! anchor secret) is handled by
//! [`crate::groth16::prover::prove`] using these decoded values.
//!
//! All decoding / shape failures surface as
//! [`crate::error::ApplicationError::InvalidProveRequest`] with a precise
//! dotted field path.
//!
//! Notable per-finding decisions:
//!
//! - **C8**: Production decoding uses [`gadget::base64::decode_any_base64`]
//!   exclusively; the `base64` crate stays a dev-dependency for fixture
//!   construction in the unit tests below.
//! - **C11**: The tree-height bounds check uses [`u64::checked_shl`] to avoid
//!   overflow when `tree_height >= 64`.

use ark_utils::codec::string::hex_decimal_to_field;
use circuit::types::{CircuitConfig, F};
use gadget::base64::decode_any_base64;

use crate::dto::ProveRequest;
use crate::error::ApplicationError;
use super::RSA_2048_BYTES;

/// Wire-decoded fields shared across every JWT in a K-credential batch.
///
/// `pub(crate)` boundary DTO returned by [`prove_request_to_decoded`].
/// Carries only values that came directly off the wire — derived
/// cryptographic state (`anchor_known_x`, `anchor_selector`,
/// `anchor_current_idx`) is computed by
/// [`crate::groth16::prover::prove`] from this DTO plus the JWTs.
pub(crate) struct SharedDecoded {
    pub random: F,
    pub h_sign_user_op: F,
    /// Anchor scalar evaluations — length = `n - k + 1`.
    pub anchor_values: Vec<F>,
    pub merkle_root: F,
}

/// Wire-decoded per-credential fields. Genuine byte sequences
/// (`jwt_bytes`, `rsa_modulus_bytes`, `rsa_signature_bytes`) stay as
/// `Vec<u8>`; field-element fields are stored as `F`.
pub(crate) struct CredentialDecoded {
    pub jwt_bytes: Vec<u8>,
    /// RSA-2048 modulus N — exactly 256 bytes.
    pub rsa_modulus_bytes: Vec<u8>,
    /// PKCS#1 v1.5 SHA-256 RSA-2048 signature — exactly 256 bytes.
    pub rsa_signature_bytes: Vec<u8>,
    pub merkle_leaf_sibling_hash: F,
    /// Merkle inner-node sibling hashes — length = `tree_height - 1`.
    pub merkle_auth_path: Vec<F>,
    pub merkle_leaf_idx: u64,
}

/// Convert an external [`ProveRequest`] into the wire-decoded DTOs
/// consumed by [`crate::groth16::prover::prove`].
///
/// Performs only:
/// 1. [`CircuitConfig::validate`]
/// 2. Shape validation against `n`, `k`, `tree_height`
/// 3. Hex/decimal → F decoding for field-element strings
/// 4. Base64 decoding for RSA modulus and JWT signature segment
///
/// All cryptographic derivation (`derive_x_from_secret`,
/// `derive_selector_from_x_list_and_anchor`, JWT claim parsing) is the
/// prover's responsibility. Failures surface as
/// [`ApplicationError::InvalidProveRequest`] with a dotted field path
/// identifying the offending input.
pub(crate) fn prove_request_to_decoded(
    request: &ProveRequest,
    cfg: &CircuitConfig,
) -> Result<(SharedDecoded, Vec<CredentialDecoded>), ApplicationError> {
    // 0. Config validation (Codex #4 — fail fast before any n - k + 1 arithmetic).
    cfg.validate()
        .map_err(|e| ApplicationError::InvalidProveRequest {
            field: "config".into(),
            message: e.to_string(),
        })?;

    let k = cfg.k as usize;
    let n = cfg.n as usize;
    let th = cfg.tree_height as usize;

    // 1. Shape validation
    if request.credentials.len() != k {
        return Err(ApplicationError::InvalidProveRequest {
            field: "credentials".into(),
            message: format!(
                "credentials.len()={} but config.k={}",
                request.credentials.len(),
                k
            ),
        });
    }
    let expected_anchor_len = n - k + 1;
    if request.anchor.len() != expected_anchor_len {
        return Err(ApplicationError::InvalidProveRequest {
            field: "anchor".into(),
            message: format!(
                "anchor.len()={} but config.n - config.k + 1 = {}",
                request.anchor.len(),
                expected_anchor_len
            ),
        });
    }
    // checked_shl avoids overflow at tree_height >= 64 (codex C11).
    let max_leaf_idx_exclusive = 1u64.checked_shl(cfg.tree_height as u32).ok_or_else(|| {
        ApplicationError::InvalidProveRequest {
            field: "tree_height".into(),
            message: format!(
                "tree_height={} is too large for u64 leaf-index range",
                cfg.tree_height
            ),
        }
    })?;
    for (i, cred) in request.credentials.iter().enumerate() {
        if cred.merkle_path.len() != th {
            return Err(ApplicationError::InvalidProveRequest {
                field: format!("credentials[{}].merkle_path", i),
                message: format!(
                    "merkle_path.len()={} but config.tree_height={}",
                    cred.merkle_path.len(),
                    th
                ),
            });
        }
        if cred.merkle_leaf_idx >= max_leaf_idx_exclusive {
            return Err(ApplicationError::InvalidProveRequest {
                field: format!("credentials[{}].merkle_leaf_idx", i),
                message: format!(
                    "merkle_leaf_idx={} must be < 2^tree_height ({})",
                    cred.merkle_leaf_idx, max_leaf_idx_exclusive
                ),
            });
        }
    }

    // 2. Decode shared field-element strings
    let random = decode_field_string(&request.random, "random")?;
    let h_sign_user_op = decode_field_string(&request.h_sign_user_op, "h_sign_user_op")?;
    let merkle_root = decode_field_string(&request.merkle_root, "merkle_root")?;
    let anchor_values: Vec<F> = request
        .anchor
        .iter()
        .enumerate()
        .map(|(i, s)| decode_field_string(s, &format!("anchor[{}]", i)))
        .collect::<Result<_, _>>()?;

    // 3. Per-credential decoding
    let mut credentials: Vec<CredentialDecoded> = Vec::with_capacity(k);
    for (i, cred) in request.credentials.iter().enumerate() {
        // 3a. Decode JWT signature segment
        let rsa_signature_bytes = decode_jwt_signature_segment(&cred.jwt, i)?;

        // 3b. Decode RSA modulus
        let rsa_modulus_bytes = decode_any_base64(&cred.rsa_modulus_b64).map_err(|e| {
            ApplicationError::InvalidProveRequest {
                field: format!("credentials[{}].rsa_modulus_b64", i),
                message: format!("base64 decode failed: {}", e),
            }
        })?;
        if rsa_modulus_bytes.len() != RSA_2048_BYTES {
            return Err(ApplicationError::InvalidProveRequest {
                field: format!("credentials[{}].rsa_modulus_b64", i),
                message: format!(
                    "expected {} bytes after base64 decode, got {}",
                    RSA_2048_BYTES,
                    rsa_modulus_bytes.len()
                ),
            });
        }

        // 3c. Split merkle path: [0] = leaf sibling, [1..] = inner siblings
        let merkle_leaf_sibling_hash = decode_field_string(
            &cred.merkle_path[0],
            &format!("credentials[{}].merkle_path[0]", i),
        )?;
        let merkle_auth_path: Vec<F> = cred.merkle_path[1..]
            .iter()
            .enumerate()
            .map(|(j, s)| {
                decode_field_string(s, &format!("credentials[{}].merkle_path[{}]", i, j + 1))
            })
            .collect::<Result<_, _>>()?;

        credentials.push(CredentialDecoded {
            jwt_bytes: cred.jwt.as_bytes().to_vec(),
            rsa_modulus_bytes,
            rsa_signature_bytes,
            merkle_leaf_sibling_hash,
            merkle_auth_path,
            merkle_leaf_idx: cred.merkle_leaf_idx,
        });
    }

    Ok((
        SharedDecoded {
            random,
            h_sign_user_op,
            anchor_values,
            merkle_root,
        },
        credentials,
    ))
}

/// Decode a hex-or-decimal field-element string and tag the failure with
/// `field_path` for `InvalidProveRequest`.
fn decode_field_string(s: &str, field_path: &str) -> Result<F, ApplicationError> {
    hex_decimal_to_field::<F>(s).map_err(|e| ApplicationError::InvalidProveRequest {
        field: field_path.into(),
        message: format!("invalid field-element string: {}", e),
    })
}

/// Decode the last segment of a `header.payload.signature` JWT compact
/// serialization. Validates segment count and produces a 256-byte RSA-2048
/// signature.
fn decode_jwt_signature_segment(jwt: &str, cred_idx: usize) -> Result<Vec<u8>, ApplicationError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt", cred_idx),
            message: format!("expected 3 dot-separated JWT segments, got {}", parts.len()),
        });
    }
    let sig_bytes =
        decode_any_base64(parts[2]).map_err(|e| ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt.signature", cred_idx),
            message: format!("base64 decode failed: {}", e),
        })?;
    if sig_bytes.len() != RSA_2048_BYTES {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt.signature", cred_idx),
            message: format!("expected {} bytes, got {}", RSA_2048_BYTES, sig_bytes.len()),
        });
    }
    Ok(sig_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_utils::codec::field::fe_to_be32;
    use base64::Engine as _;
    use base64::engine::general_purpose;
    use circuit::types::CircuitConfig;

    use crate::dto::{AnchorSecret, ProveCredential};

    fn anchor_test_config() -> CircuitConfig {
        CircuitConfig {
            max_jwt_b64_len: 1024,
            max_payload_b64_len: 640,
            max_aud_len: 155,
            max_exp_len: 20,
            max_iss_len: 93,
            max_nonce_len: 93,
            max_sub_len: 93,
            n: 6,
            k: 3,
            tree_height: 4,
            num_audience_limit: 5,
            claims: vec![
                "aud".into(),
                "exp".into(),
                "iss".into(),
                "nonce".into(),
                "sub".into(),
            ],
            forbidden_string: "forbidden".into(),
        }
    }

    fn url_b64(bytes: &[u8]) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Build a fixture JWT with the given (sub, iss, aud) string claims.
    /// The signature segment is 256 bytes of `[0xAB; 256]` (junk — the
    /// adapter only decodes, no verification).
    fn make_jwt(sub: &str, iss: &str, aud: &str) -> String {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let payload = format!(
            r#"{{"aud":"{aud}","exp":1700000000,"iss":"{iss}","nonce":"abc123","sub":"{sub}"}}"#
        );
        let sig = vec![0xABu8; RSA_2048_BYTES];
        format!(
            "{}.{}.{}",
            url_b64(header.as_bytes()),
            url_b64(payload.as_bytes()),
            url_b64(&sig)
        )
    }

    fn rsa_modulus_b64() -> String {
        url_b64(&vec![0xCDu8; RSA_2048_BYTES])
    }

    fn hex_fe(b: u8) -> String {
        let mut s = String::from("0x");
        for _ in 0..31 {
            s.push_str("00");
        }
        s.push_str(&format!("{:02x}", b));
        s
    }

    fn merkle_path(th: usize, base: u8) -> Vec<String> {
        (0..th)
            .map(|i| hex_fe(base.wrapping_add(i as u8)))
            .collect()
    }

    /// Build a happy-path ProveRequest with k credentials and an anchor
    /// produced by `generate_anchor` over n secrets where the first k
    /// match the JWT-derived secrets.
    fn happy_path_request(cfg: &CircuitConfig) -> (ProveRequest, Vec<AnchorSecret>) {
        let n = cfg.n as usize;
        let k = cfg.k as usize;
        let th = cfg.tree_height as usize;

        // n total secrets — the first k will be presented as JWTs.
        let all_secrets: Vec<AnchorSecret> = (0..n)
            .map(|i| AnchorSecret {
                subject: format!("user_{i}"),
                issuer: "https://accounts.google.com".into(),
                audience: "test-audience".into(),
            })
            .collect();

        let anchor_resp = crate::generate_anchor(
            cfg,
            crate::dto::GenerateAnchorRequest {
                secrets: all_secrets.clone(),
            },
        )
        .unwrap();

        let credentials: Vec<ProveCredential> = all_secrets
            .iter()
            .take(k)
            .enumerate()
            .map(|(i, secret)| ProveCredential {
                jwt: make_jwt(&secret.subject, &secret.issuer, &secret.audience),
                rsa_modulus_b64: rsa_modulus_b64(),
                merkle_path: merkle_path(th, 0x10 + i as u8),
                merkle_leaf_idx: i as u64,
            })
            .collect();

        let request = ProveRequest {
            random: hex_fe(0x01),
            h_sign_user_op: hex_fe(0x02),
            anchor: anchor_resp.anchor_evaluations.clone(),
            merkle_root: hex_fe(0x03),
            credentials,
        };
        (request, all_secrets)
    }

    #[test]
    fn prove_request_to_decoded_round_trip() {
        let cfg = anchor_test_config();
        let (req, _) = happy_path_request(&cfg);
        let (shared, credentials) =
            prove_request_to_decoded(&req, &cfg).expect("adapter must succeed");

        // Shared anchor + merkle_root field round-trip to F.
        for (i, s) in req.anchor.iter().enumerate() {
            let fe = hex_decimal_to_field::<F>(s).unwrap();
            assert_eq!(shared.anchor_values[i], fe, "anchor[{}] should round-trip", i);
        }
        let root_fe = hex_decimal_to_field::<F>(&req.merkle_root).unwrap();
        assert_eq!(shared.merkle_root, root_fe);

        // shapes
        let k = cfg.k as usize;
        let n = cfg.n as usize;
        assert_eq!(credentials.len(), k);
        assert_eq!(shared.anchor_values.len(), n - k + 1);
    }

    #[test]
    fn prove_request_to_decoded_splits_merkle_path() {
        let cfg = anchor_test_config();
        let (req, _) = happy_path_request(&cfg);
        let (_, credentials) = prove_request_to_decoded(&req, &cfg).unwrap();

        let th = cfg.tree_height as usize;
        for (i, cred) in req.credentials.iter().enumerate() {
            // path[0] → leaf sibling
            let leaf_fe = hex_decimal_to_field::<F>(&cred.merkle_path[0]).unwrap();
            assert_eq!(credentials[i].merkle_leaf_sibling_hash, leaf_fe);
            // path[1..] → auth path of length tree_height - 1
            assert_eq!(credentials[i].merkle_auth_path.len(), th - 1);
            for (j, s) in cred.merkle_path[1..].iter().enumerate() {
                let fe = hex_decimal_to_field::<F>(s).unwrap();
                assert_eq!(credentials[i].merkle_auth_path[j], fe);
            }
        }
    }

    #[test]
    fn prove_request_to_decoded_extracts_signature_from_jwt() {
        let cfg = anchor_test_config();
        let (req, _) = happy_path_request(&cfg);
        let (_, credentials) = prove_request_to_decoded(&req, &cfg).unwrap();

        for (i, cred) in req.credentials.iter().enumerate() {
            let parts: Vec<&str> = cred.jwt.split('.').collect();
            let sig_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
            assert_eq!(sig_bytes.len(), RSA_2048_BYTES);
            assert_eq!(credentials[i].rsa_signature_bytes, sig_bytes);
        }
    }

    #[test]
    fn prove_request_to_decoded_decodes_anchor_values_to_fields() {
        // Smoke check: shared.anchor_values F-encoding stays canonical.
        let cfg = anchor_test_config();
        let (req, _) = happy_path_request(&cfg);
        let (shared, _) = prove_request_to_decoded(&req, &cfg).unwrap();
        for (i, s) in req.anchor.iter().enumerate() {
            let fe = hex_decimal_to_field::<F>(s).unwrap();
            assert_eq!(fe_to_be32(&shared.anchor_values[i]), fe_to_be32(&fe));
        }
    }

    #[test]
    fn invalid_hex_in_anchor_reports_field_path() {
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        req.anchor[2] = "not_hex".into();
        match prove_request_to_decoded(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "anchor[2]");
            }
            other => panic!(
                "expected InvalidProveRequest for anchor[2], got {:?}",
                other.err()
            ),
        }
    }

    #[test]
    fn invalid_decimal_in_anchor_accepted() {
        // Mix hex and decimal entries — both must be parsed.
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        // Replace anchor[0] with decimal form of its current hex value.
        let fe = hex_decimal_to_field::<F>(&req.anchor[0]).unwrap();
        let decimal = fe.to_string();
        req.anchor[0] = decimal;
        // Should still succeed and produce the same anchor_values[0].
        let (shared, _) = prove_request_to_decoded(&req, &cfg).unwrap();
        assert_eq!(shared.anchor_values[0], fe);
    }

    #[test]
    fn wrong_merkle_path_length_reports_field() {
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        req.credentials[1].merkle_path.pop(); // off-by-one
        match prove_request_to_decoded(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "credentials[1].merkle_path");
            }
            other => panic!("expected InvalidProveRequest, got {:?}", other.err()),
        }
    }

    #[test]
    fn wrong_credentials_count() {
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        req.credentials.pop();
        match prove_request_to_decoded(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "credentials");
            }
            other => panic!("expected InvalidProveRequest, got {:?}", other.err()),
        }
    }

    #[test]
    fn wrong_rsa_modulus_length() {
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        req.credentials[0].rsa_modulus_b64 = url_b64(&vec![0xCDu8; 255]); // wrong length
        match prove_request_to_decoded(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "credentials[0].rsa_modulus_b64");
            }
            other => panic!("expected InvalidProveRequest, got {:?}", other.err()),
        }
    }

    #[test]
    fn merkle_leaf_idx_out_of_range() {
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        let th = cfg.tree_height as u32;
        // 2^tree_height is the first out-of-range value.
        req.credentials[2].merkle_leaf_idx = 1u64 << th;
        match prove_request_to_decoded(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "credentials[2].merkle_leaf_idx");
            }
            other => panic!("expected InvalidProveRequest, got {:?}", other.err()),
        }
    }

    #[test]
    fn prove_request_to_decoded_rejects_invalid_cfg() {
        // Construct an intentionally invalid CircuitConfig — k > n.
        // The adapter must reject this at the cfg.validate() gate before
        // any `n - k + 1` arithmetic runs.
        let mut cfg = anchor_test_config();
        cfg.k = cfg.n + 1; // k > n is invalid

        let (req, _) = happy_path_request(&anchor_test_config());
        match prove_request_to_decoded(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "config");
            }
            other => panic!(
                "expected InvalidProveRequest for config, got {:?}",
                other.err()
            ),
        }
    }
}
