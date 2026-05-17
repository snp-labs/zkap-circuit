//! Boundary adapter: [`ProveRequest`] → [`crate::witness::WitnessRequest`].
//!
//! Validates the request's shape against `CircuitConfig`, decodes every
//! string-encoded field element via [`ark_utils::codec::string::hex_decimal_to_field`],
//! parses each JWT to derive the per-credential anchor `x`, derives the
//! anchor selector, and composes the internal witness DTO. All decoding
//! / shape failures surface as
//! [`crate::error::ApplicationError::InvalidProveRequest`] with a precise
//! dotted field path.
//!
//! Notable per-finding decisions:
//!
//! - **C5**: [`crate::jwt::parser::parse_claim_from_str`] returns the
//!   JSON-quoted form for string claims (e.g. `"\"user_0\""`). The adapter
//!   strips the surrounding `"` before constructing [`AnchorSecret`] so
//!   [`crate::anchor_host::poseidon::derive_x_from_secret`] does not see a
//!   double-quoted value.
//! - **C8**: Production decoding uses [`gadget::base64::decode_any_base64`]
//!   exclusively; the `base64` crate stays a dev-dependency for fixture
//!   construction in the unit tests below.
//! - **C11**: The tree-height bounds check uses [`u64::checked_shl`] to avoid
//!   overflow when `tree_height >= 64`.

use ark_utils::codec::field::fe_to_be32;
use ark_utils::codec::string::hex_decimal_to_field;
use circuit::types::{CircuitConfig, F};
use gadget::anchor::poseidon::{PoseidonAnchor, PoseidonAnchorPublicKey};
use gadget::base64::decode_any_base64;
use gadget::matrix::VandermondeMatrix;

use crate::anchor_host::AnchorConfig;
use crate::anchor_host::poseidon::{derive_selector_from_x_list_and_anchor, derive_x_from_secret};
use crate::dto::{AnchorSecret, ProveCredential, ProveRequest};
use crate::error::ApplicationError;
use crate::jwt::parser::parse_claim_from_str;
use crate::witness::{PerJwtFields, WitnessRequest, SharedFields};

/// RSA-2048 modulus / signature byte length.
const RSA_2048_BYTES: usize = 256;

/// Convert an external [`ProveRequest`] into the internal witness
/// [`WitnessRequest`].
///
/// All decoding, shape, and consistency checks happen here so the prover
/// itself receives a fully validated, in-memory witness DTO. Failures
/// surface as [`ApplicationError::InvalidProveRequest`] with a dotted
/// field path identifying the offending input.
pub(crate) fn prove_request_to_internal(
    request: &ProveRequest,
    cfg: &CircuitConfig,
) -> Result<WitnessRequest, ApplicationError> {
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
    let random_fe = decode_field_string(&request.random, "random")?;
    let h_sign_user_op_fe = decode_field_string(&request.h_sign_user_op, "h_sign_user_op")?;
    let merkle_root_fe = decode_field_string(&request.merkle_root, "merkle_root")?;
    let anchor_fields: Vec<F> = request
        .anchor
        .iter()
        .enumerate()
        .map(|(i, s)| decode_field_string(s, &format!("anchor[{}]", i)))
        .collect::<Result<_, _>>()?;

    let random_be = fe_to_be32(&random_fe);
    let h_sign_user_op_be = fe_to_be32(&h_sign_user_op_fe);
    let merkle_root_be = fe_to_be32(&merkle_root_fe);
    let anchor_values_be: Vec<[u8; 32]> = anchor_fields.iter().map(fe_to_be32).collect();

    // 3. Per-credential decoding
    let poseidon_params = crate::poseidon_params();
    let anchor_ctx = AnchorConfig::from_params(cfg);

    let mut x_list: Vec<F> = Vec::with_capacity(k);
    let mut per_jwt_partial: Vec<PerJwtPartial> = Vec::with_capacity(k);

    for (i, cred) in request.credentials.iter().enumerate() {
        // 3a. Parse JWT and derive anchor x
        let secret = parse_jwt_claims_triple(cred, i)?;
        let x = derive_x_from_secret(&secret, poseidon_params, &anchor_ctx).map_err(|e| {
            ApplicationError::InvalidProveRequest {
                field: format!("credentials[{}].jwt", i),
                message: format!("derive_x_from_secret failed: {}", e),
            }
        })?;
        x_list.push(x);

        // 3b. Decode JWT signature segment
        let sig_bytes = decode_jwt_signature_segment(&cred.jwt, i)?;

        // 3c. Decode RSA modulus
        let rsa_mod_bytes = decode_any_base64(&cred.rsa_modulus_b64).map_err(|e| {
            ApplicationError::InvalidProveRequest {
                field: format!("credentials[{}].rsa_modulus_b64", i),
                message: format!("base64 decode failed: {}", e),
            }
        })?;
        if rsa_mod_bytes.len() != RSA_2048_BYTES {
            return Err(ApplicationError::InvalidProveRequest {
                field: format!("credentials[{}].rsa_modulus_b64", i),
                message: format!(
                    "expected {} bytes after base64 decode, got {}",
                    RSA_2048_BYTES,
                    rsa_mod_bytes.len()
                ),
            });
        }

        // 3d. Split merkle path: [0] = leaf sibling, [1..] = inner siblings
        let leaf_sibling_fe = decode_field_string(
            &cred.merkle_path[0],
            &format!("credentials[{}].merkle_path[0]", i),
        )?;
        let merkle_leaf_sibling_hash_be = fe_to_be32(&leaf_sibling_fe);
        let merkle_auth_path_be: Vec<[u8; 32]> = cred.merkle_path[1..]
            .iter()
            .enumerate()
            .map(|(j, s)| {
                decode_field_string(s, &format!("credentials[{}].merkle_path[{}]", i, j + 1))
                    .map(|fe| fe_to_be32(&fe))
            })
            .collect::<Result<_, _>>()?;

        per_jwt_partial.push(PerJwtPartial {
            jwt_bytes: cred.jwt.as_bytes().to_vec(),
            rsa_modulus_be: rsa_mod_bytes,
            rsa_signature_be: sig_bytes,
            merkle_leaf_sibling_hash_be,
            merkle_auth_path_be,
            merkle_leaf_idx: cred.merkle_leaf_idx,
        });
    }

    // 4. Derive selector and map credential i → selector 1-position
    let matrix = VandermondeMatrix::<F>::new(n, k);
    let pk = PoseidonAnchorPublicKey::<F> {
        params: poseidon_params.clone(),
    };
    let anchor_obj = PoseidonAnchor::new(anchor_fields.clone());
    let selector = derive_selector_from_x_list_and_anchor(&pk, &x_list, &anchor_obj, &matrix)
        .map_err(|e| ApplicationError::InvalidProveRequest {
            field: "anchor / jwts".into(),
            message: format!(
                "no valid selector found — anchor and JWT claim shares are inconsistent: {}",
                e
            ),
        })?;
    let one_positions: Vec<usize> = selector
        .iter()
        .enumerate()
        .filter(|&(_, &s)| s == 1)
        .map(|(j, _)| j)
        .collect();
    // Defensive: selector must have cardinality k by construction.
    if one_positions.len() != k {
        return Err(ApplicationError::InvalidProveRequest {
            field: "anchor / jwts".into(),
            message: format!(
                "derived selector cardinality={} but expected k={}",
                one_positions.len(),
                k
            ),
        });
    }

    // 5. Compose internal WitnessRequest
    let anchor_known_x_be: Vec<[u8; 32]> = x_list.iter().map(fe_to_be32).collect();
    let shared = SharedFields {
        random_be,
        h_sign_user_op_be,
        anchor_values_be,
        anchor_known_x_be,
        anchor_selector: selector,
        merkle_root_be,
    };
    let per_jwt: Vec<PerJwtFields> = per_jwt_partial
        .into_iter()
        .enumerate()
        .map(|(i, t)| PerJwtFields {
            jwt_bytes: t.jwt_bytes,
            rsa_modulus_be: t.rsa_modulus_be,
            rsa_signature_be: t.rsa_signature_be,
            anchor_current_idx: one_positions[i] as u64,
            merkle_leaf_sibling_hash_be: t.merkle_leaf_sibling_hash_be,
            merkle_auth_path_be: t.merkle_auth_path_be,
            merkle_leaf_idx: t.merkle_leaf_idx,
        })
        .collect();

    Ok(WitnessRequest { shared, per_jwt })
}

/// Intermediate per-credential bundle, used to defer
/// `anchor_current_idx` assignment until the selector is derived.
struct PerJwtPartial {
    jwt_bytes: Vec<u8>,
    rsa_modulus_be: Vec<u8>,
    rsa_signature_be: Vec<u8>,
    merkle_leaf_sibling_hash_be: [u8; 32],
    merkle_auth_path_be: Vec<[u8; 32]>,
    merkle_leaf_idx: u64,
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

/// Parse the JWT payload's `sub` / `iss` / `aud` claims and strip the JSON
/// quotes so the values can be fed to [`derive_x_from_secret`] unchanged
/// (the derivation wraps each claim in `"…"` internally — see codex C5).
fn parse_jwt_claims_triple(
    cred: &ProveCredential,
    cred_idx: usize,
) -> Result<AnchorSecret, ApplicationError> {
    let parts: Vec<&str> = cred.jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt", cred_idx),
            message: format!("expected 3 dot-separated JWT segments, got {}", parts.len()),
        });
    }
    let payload_bytes =
        decode_any_base64(parts[1]).map_err(|e| ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt.payload", cred_idx),
            message: format!("base64 decode failed: {}", e),
        })?;
    let payload_str = core::str::from_utf8(&payload_bytes).map_err(|e| {
        ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt.payload", cred_idx),
            message: format!("not UTF-8: {}", e),
        }
    })?;

    let subject = extract_string_claim(payload_str, "sub", cred_idx)?;
    let issuer = extract_string_claim(payload_str, "iss", cred_idx)?;
    let audience = extract_string_claim(payload_str, "aud", cred_idx)?;

    Ok(AnchorSecret {
        subject,
        issuer,
        audience,
    })
}

/// Look up a quoted JSON string claim in the JWT payload and return the raw
/// value with the wrapping `"` characters stripped. Codex C5: if the claim
/// value is not surrounded by `"…"`, return [`ApplicationError::InvalidProveRequest`].
fn extract_string_claim(
    payload: &str,
    key: &str,
    cred_idx: usize,
) -> Result<String, ApplicationError> {
    let claim =
        parse_claim_from_str(payload, key).map_err(|e| ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt", cred_idx),
            message: format!("claim `{}`: {}", key, e),
        })?;
    let value = claim.value;
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt", cred_idx),
            message: format!("claim `{}` is not a JSON string", key),
        });
    }
    // Strip surrounding quotes — note value is ASCII-quoted, so byte slicing
    // is safe.
    Ok(value[1..value.len() - 1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose;
    use circuit::types::CircuitConfig;

    use crate::dto::ProveCredential;

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
    fn prove_request_to_internal_round_trip() {
        let cfg = anchor_test_config();
        let (req, _) = happy_path_request(&cfg);
        let internal = prove_request_to_internal(&req, &cfg).expect("adapter must succeed");

        // anchor + merkle_root field re-encoded equal to the request fields.
        for (i, s) in req.anchor.iter().enumerate() {
            let fe = hex_decimal_to_field::<F>(s).unwrap();
            assert_eq!(
                fe_to_be32(&fe),
                internal.shared.anchor_values_be[i],
                "anchor[{}] should round-trip",
                i
            );
        }
        let root_fe = hex_decimal_to_field::<F>(&req.merkle_root).unwrap();
        assert_eq!(fe_to_be32(&root_fe), internal.shared.merkle_root_be);

        // shapes
        let k = cfg.k as usize;
        let n = cfg.n as usize;
        assert_eq!(internal.per_jwt.len(), k);
        assert_eq!(internal.shared.anchor_known_x_be.len(), k);
        assert_eq!(internal.shared.anchor_selector.len(), n);
        assert_eq!(
            internal
                .shared
                .anchor_selector
                .iter()
                .filter(|&&b| b == 1)
                .count(),
            k
        );
    }

    #[test]
    fn prove_request_to_internal_derives_known_x() {
        let cfg = anchor_test_config();
        let (req, all_secrets) = happy_path_request(&cfg);
        let internal = prove_request_to_internal(&req, &cfg).unwrap();

        let params = crate::poseidon_params();
        let ctx = AnchorConfig::from_params(&cfg);
        let k = cfg.k as usize;
        for (i, secret) in all_secrets.iter().enumerate().take(k) {
            let expected_x = derive_x_from_secret(secret, params, &ctx).unwrap();
            assert_eq!(
                fe_to_be32(&expected_x),
                internal.shared.anchor_known_x_be[i],
                "anchor_known_x_be[{}] must match direct derive_x_from_secret",
                i
            );
        }
    }

    #[test]
    fn prove_request_to_internal_derives_selector_and_positions() {
        let cfg = anchor_test_config();
        let (req, _) = happy_path_request(&cfg);
        let internal = prove_request_to_internal(&req, &cfg).unwrap();

        let n = cfg.n as usize;
        let k = cfg.k as usize;
        assert_eq!(internal.shared.anchor_selector.len(), n);
        let cardinality = internal
            .shared
            .anchor_selector
            .iter()
            .filter(|&&b| b == 1)
            .count();
        assert_eq!(cardinality, k, "selector cardinality must equal k");

        // Each per_jwt[i].anchor_current_idx must be the i-th 1-position.
        let one_positions: Vec<usize> = internal
            .shared
            .anchor_selector
            .iter()
            .enumerate()
            .filter(|&(_, &s)| s == 1)
            .map(|(j, _)| j)
            .collect();
        for (i, p) in one_positions.iter().enumerate() {
            assert_eq!(
                internal.per_jwt[i].anchor_current_idx, *p as u64,
                "per_jwt[{}].anchor_current_idx must equal the {}-th 1-position",
                i, i
            );
        }
    }

    #[test]
    fn prove_request_to_internal_splits_merkle_path() {
        let cfg = anchor_test_config();
        let (req, _) = happy_path_request(&cfg);
        let internal = prove_request_to_internal(&req, &cfg).unwrap();

        let th = cfg.tree_height as usize;
        for (i, cred) in req.credentials.iter().enumerate() {
            // path[0] → leaf sibling
            let leaf_fe = hex_decimal_to_field::<F>(&cred.merkle_path[0]).unwrap();
            assert_eq!(
                fe_to_be32(&leaf_fe),
                internal.per_jwt[i].merkle_leaf_sibling_hash_be
            );
            // path[1..] → auth path of length tree_height - 1
            assert_eq!(internal.per_jwt[i].merkle_auth_path_be.len(), th - 1);
            for (j, s) in cred.merkle_path[1..].iter().enumerate() {
                let fe = hex_decimal_to_field::<F>(s).unwrap();
                assert_eq!(fe_to_be32(&fe), internal.per_jwt[i].merkle_auth_path_be[j]);
            }
        }
    }

    #[test]
    fn prove_request_to_internal_extracts_signature_from_jwt() {
        let cfg = anchor_test_config();
        let (req, _) = happy_path_request(&cfg);
        let internal = prove_request_to_internal(&req, &cfg).unwrap();

        for (i, cred) in req.credentials.iter().enumerate() {
            let parts: Vec<&str> = cred.jwt.split('.').collect();
            let sig_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
            assert_eq!(sig_bytes.len(), RSA_2048_BYTES);
            assert_eq!(internal.per_jwt[i].rsa_signature_be, sig_bytes);
        }
    }

    #[test]
    fn invalid_hex_in_anchor_reports_field_path() {
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        req.anchor[2] = "not_hex".into();
        match prove_request_to_internal(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "anchor[2]");
            }
            other => panic!(
                "expected InvalidProveRequest for anchor[2], got {:?}",
                other
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
        // decimal string of fe via ark_ff Display.
        let decimal = fe.to_string();
        req.anchor[0] = decimal;
        // Should still succeed and produce the same anchor_values_be[0].
        let internal = prove_request_to_internal(&req, &cfg).unwrap();
        assert_eq!(fe_to_be32(&fe), internal.shared.anchor_values_be[0]);
    }

    #[test]
    fn wrong_merkle_path_length_reports_field() {
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        req.credentials[1].merkle_path.pop(); // off-by-one
        match prove_request_to_internal(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "credentials[1].merkle_path");
            }
            other => panic!("expected InvalidProveRequest, got {:?}", other),
        }
    }

    #[test]
    fn wrong_credentials_count() {
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        req.credentials.pop();
        match prove_request_to_internal(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "credentials");
            }
            other => panic!("expected InvalidProveRequest, got {:?}", other),
        }
    }

    #[test]
    fn wrong_rsa_modulus_length() {
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        req.credentials[0].rsa_modulus_b64 = url_b64(&vec![0xCDu8; 255]); // wrong length
        match prove_request_to_internal(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "credentials[0].rsa_modulus_b64");
            }
            other => panic!("expected InvalidProveRequest, got {:?}", other),
        }
    }

    #[test]
    fn selector_derivation_failure() {
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        // Replace anchor with completely unrelated values — no selector
        // combination will validate.
        for (i, entry) in req.anchor.iter_mut().enumerate() {
            *entry = hex_fe(0xF0 + i as u8);
        }
        match prove_request_to_internal(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "anchor / jwts");
            }
            other => panic!("expected InvalidProveRequest, got {:?}", other),
        }
    }

    #[test]
    fn merkle_leaf_idx_out_of_range() {
        let cfg = anchor_test_config();
        let (mut req, _) = happy_path_request(&cfg);
        let th = cfg.tree_height as u32;
        // 2^tree_height is the first out-of-range value.
        req.credentials[2].merkle_leaf_idx = 1u64 << th;
        match prove_request_to_internal(&req, &cfg) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "credentials[2].merkle_leaf_idx");
            }
            other => panic!("expected InvalidProveRequest, got {:?}", other),
        }
    }

    #[test]
    fn jwt_claim_quotes_stripped() {
        // Regression for codex C5: if the adapter forwarded the quoted
        // form, derive_x_from_secret would receive `"\"user_0\""` and
        // double-quote it, producing a different x than the canonical
        // `AnchorSecret { sub: "user_0", ... }` form.
        let cfg = anchor_test_config();
        let (req, all_secrets) = happy_path_request(&cfg);
        let internal = prove_request_to_internal(&req, &cfg).unwrap();

        let params = crate::poseidon_params();
        let ctx = AnchorConfig::from_params(&cfg);
        // Canonical (unquoted) derivation must match.
        let canonical_x = derive_x_from_secret(&all_secrets[0], params, &ctx).unwrap();
        // Double-quoted variant must NOT match.
        let double_quoted = AnchorSecret {
            subject: format!("\"{}\"", all_secrets[0].subject),
            issuer: format!("\"{}\"", all_secrets[0].issuer),
            audience: format!("\"{}\"", all_secrets[0].audience),
        };
        let bad_x = derive_x_from_secret(&double_quoted, params, &ctx).unwrap();
        assert_ne!(
            fe_to_be32(&canonical_x),
            fe_to_be32(&bad_x),
            "fixture must distinguish quoted vs unquoted forms"
        );
        assert_eq!(
            fe_to_be32(&canonical_x),
            internal.shared.anchor_known_x_be[0],
            "adapter must strip JSON quotes before deriving x"
        );
    }
}
