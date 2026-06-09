//! Off-circuit pre-flight validation of decoded prove inputs.
//!
//! Mirrors — on the host, before any Groth16 work — a subset of the
//! cryptographic relations that [`circuit::zkap::ZkapCircuit`]'s
//! `generate_constraints` enforces, so an inconsistent [`ProveRequest`]
//! fails fast with a precise [`ApplicationError::InvalidProveRequest`]
//! instead of only being rejected post-hoc by the prover's
//! `PreflightMode::VerifyAfter` (i.e. after the whole proof was computed).
//!
//! ## Checks performed (the gaps the synthesis path does NOT already close)
//! - **Issuer-key Merkle membership** — `leaf = Poseidon(iss ‖ pk.n.limbs)`
//!   must be a member of `merkle_root` at `merkle_leaf_idx`
//!   (`zkap.rs` Phase 2.1). `build_merkle_witness` only checks the path
//!   *length*; it never recomputes the root.
//! - **Nonce execution binding** — the JWT `nonce` claim must equal
//!   `Poseidon(h_sign_user_op, random)` (`zkap.rs` Phase 3). Nothing in the
//!   synthesis path checks this off-circuit today.
//! - **`random != 0`** (`zkap.rs` Phase 4).
//!
//! ## Deliberately NOT re-checked here
//! - **Anchor / threshold membership** — already enforced upstream by
//!   `derive_selector_from_x_list_and_anchor` in [`super::prove`], which
//!   rejects JWT shares inconsistent with the registered anchor before this
//!   runs.
//! - **Shape / length / base64 / field canonicality / selector cardinality**
//!   — covered by the adapter and the `circuit_input` stage builders.
//! - **RSA-2048 signature validity** — intentionally out of scope (no
//!   off-circuit RSA), so this module stays cheap and dependency-light.
//!   The signature is still verified in-circuit and re-checked by
//!   `VerifyAfter`.
//!
//! The recipes here reuse the exact host helpers the witness builders use
//! (`claim_value_bytes_padded`, `try_bytes_to_fields`, the issuer-key leaf
//! recipe from [`crate::generate_issuer_key_hash`], the `MerkleTreeParams`
//! Poseidon config) so a passing validation implies the corresponding
//! in-circuit constraint is satisfiable.

use ark_crypto_primitives::crh::{CRHScheme, poseidon::CRH};
use ark_crypto_primitives::merkle_tree::Path;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::Zero;

use ark_codec::string::try_bytes_to_fields;
use circuit::types::{BNP, CG, CircuitConfig, F};
use gadget::base64::decode_any_base64;
use gadget::merkletree::tree_config::MerkleTreeParams;
use gadget::signature::rsa::PublicKey;

use crate::error::ApplicationError;
use crate::jwt::parser::locate_claim;

use super::adapter::{CredentialDecoded, SharedDecoded};
use super::circuit_input::{AudienceStage, claim_value_bytes_padded};

fn invalid(field_path: &str, suffix: &str, message: impl Into<String>) -> ApplicationError {
    ApplicationError::InvalidProveRequest {
        field: format!("{field_path}.{suffix}"),
        message: message.into(),
    }
}

/// Decode the base64url payload segment of a `header.payload.signature` JWT.
/// Lightweight: touches only the payload segment (no RSA / SHA work).
fn decode_payload(field_path: &str, jwt_bytes: &[u8]) -> Result<Vec<u8>, ApplicationError> {
    let jwt_str = core::str::from_utf8(jwt_bytes)
        .map_err(|e| invalid(field_path, "jwt", format!("not UTF-8: {e}")))?;
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid(
            field_path,
            "jwt",
            format!("expected 3 dot-separated segments, got {}", parts.len()),
        ));
    }
    decode_any_base64(parts[1]).map_err(|e| {
        invalid(
            field_path,
            "jwt",
            format!("payload base64 decode failed: {e}"),
        )
    })
}

/// Parse a JWT `nonce` claim value of the form `"0x[0-9A-Fa-f]{1,64}"` into a
/// field element, accumulating `acc = acc * 16 + hex_digit`. `value` is the
/// raw claim value **including** its surrounding quotes (the byte range
/// [`locate_claim`] returns). This mirrors the in-circuit
/// `jwt_nonce_hex_to_field` recipe (`circuit::token::jwt_field::nonce`).
fn jwt_nonce_to_field(field_path: &str, value: &[u8]) -> Result<F, ApplicationError> {
    // Minimum valid value is `"0x0"` => 5 bytes (two quotes + `0x` + 1 digit).
    if value.len() < 5 {
        return Err(invalid(
            field_path,
            "jwt",
            "nonce too short for \"0x<hex>\"",
        ));
    }
    if value[0] != b'"' || value[1] != b'0' || value[2] != b'x' {
        return Err(invalid(field_path, "jwt", "nonce must start with \"0x"));
    }
    let last = value.len() - 1;
    if value[last] != b'"' {
        return Err(invalid(field_path, "jwt", "nonce missing closing quote"));
    }
    let hex = &value[3..last];
    if hex.is_empty() || hex.len() > 64 {
        return Err(invalid(
            field_path,
            "jwt",
            format!("nonce hex digit count {} not in 1..=64", hex.len()),
        ));
    }
    let sixteen = F::from(16u64);
    let mut acc = F::zero();
    for &b in hex {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'a'..=b'f' => (b - b'a' + 10) as u64,
            b'A'..=b'F' => (b - b'A' + 10) as u64,
            other => {
                return Err(invalid(
                    field_path,
                    "jwt",
                    format!("non-hex byte 0x{other:02x} in nonce"),
                ));
            }
        };
        acc = acc * sixteen + F::from(digit);
    }
    Ok(acc)
}

/// Validate decoded prove inputs against the in-circuit relations the
/// synthesis path does not already enforce. Fails fast on the first
/// inconsistency (per-credential, in `credentials` order).
///
/// Run BEFORE the per-credential witness build loop in
/// [`super::prove::synthesize_witnesses_streaming`], and AFTER the anchor /
/// selector derivation (so the anchor-membership gate keeps firing first for
/// inputs that are inconsistent with the anchor).
pub(super) fn validate_decoded_inputs(
    cfg: &CircuitConfig,
    shared: &SharedDecoded,
    credentials: &[CredentialDecoded],
    poseidon_param: &PoseidonConfig<F>,
) -> Result<(), ApplicationError> {
    // [Phase 4] random must be non-zero (the circuit enforces `random != 0`).
    if shared.random.is_zero() {
        return Err(ApplicationError::InvalidProveRequest {
            field: "random".into(),
            message: "random must be non-zero".into(),
        });
    }

    // [Phase 3] Nonce binding target — identical for every credential:
    // nonce == Poseidon(h_sign_user_op, random).
    let expected_nonce = CRH::<F>::evaluate(poseidon_param, [shared.h_sign_user_op, shared.random])
        .map_err(|e| ApplicationError::PoseidonHashError(format!("nonce binding target: {e}")))?;

    // RSA public exponent for the issuer-key leaf (mirrors
    // `generate_issuer_key_hash`; the circuit fixes e == 65537).
    let e_decoded =
        decode_any_base64(gadget::constants::RSA_DEFAULT_EXPONENT_B64).map_err(|e| {
            ApplicationError::InvalidBase64(format!("internal RSA exponent constant: {e}"))
        })?;

    for (i, cred) in credentials.iter().enumerate() {
        let path = format!("credentials[{i}]");
        let payload = decode_payload(&path, &cred.jwt_bytes)?;
        let payload_str = core::str::from_utf8(&payload)
            .map_err(|e| invalid(&path, "jwt", format!("payload not UTF-8: {e}")))?;

        // ── [Phase 2.1] Issuer-key Merkle membership ────────────────────
        // leaf = Poseidon(iss ‖ pk.n.limbs); recompute the root from the
        // supplied sibling path and assert it equals `merkle_root`.
        let iss_idx = locate_claim(payload_str, "iss")
            .map_err(|e| invalid(&path, "jwt", format!("locate `iss`: {e}")))?;
        let iss_packed = try_bytes_to_fields::<F>(&claim_value_bytes_padded(
            &payload,
            &iss_idx,
            cfg.max_iss_len as usize,
        ))?;
        let pk = PublicKey {
            n: cred.rsa_modulus_bytes.clone(),
            e: e_decoded.clone(),
        };
        let n_limbs = pk.to_limbs::<BNP, CG>().0;
        let mut leaf_inputs = Vec::with_capacity(iss_packed.len() + n_limbs.len());
        leaf_inputs.extend_from_slice(&iss_packed);
        leaf_inputs.extend_from_slice(&n_limbs);
        let leaf = CRH::<F>::evaluate(poseidon_param, leaf_inputs)
            .map_err(|e| ApplicationError::PoseidonHashError(format!("merkle leaf: {e}")))?;

        let merkle_path = Path::<MerkleTreeParams<F>> {
            leaf_sibling_hash: cred.merkle_leaf_sibling_hash,
            auth_path: cred.merkle_auth_path.clone(),
            leaf_index: cred.merkle_leaf_idx as usize,
        };
        let is_member = merkle_path
            .verify(
                poseidon_param,
                poseidon_param,
                &shared.merkle_root,
                [leaf].as_slice(),
            )
            .map_err(|e| ApplicationError::CryptographicError(format!("merkle verify: {e}")))?;
        if !is_member {
            return Err(ApplicationError::InvalidProveRequest {
                field: format!("{path}.merkle_path"),
                message: "issuer-key leaf is not a member of merkle_root at merkle_leaf_idx (\
                          check rsa_modulus_b64, merkle_path, merkle_leaf_idx, merkle_root)"
                    .into(),
            });
        }

        // ── [Phase 3] Nonce execution binding ───────────────────────────
        let nonce_idx = locate_claim(payload_str, "nonce")
            .map_err(|e| invalid(&path, "jwt", format!("locate `nonce`: {e}")))?;
        let value_start = nonce_idx.offset + nonce_idx.value_idx;
        let value_end = value_start + nonce_idx.value_len;
        let actual_nonce = jwt_nonce_to_field(&path, &payload[value_start..value_end])?;
        if actual_nonce != expected_nonce {
            return Err(ApplicationError::InvalidProveRequest {
                field: format!("{path}.jwt"),
                message: "JWT `nonce` claim is not bound to Poseidon(h_sign_user_op, random) \
                          (the JWT was not minted for this h_sign_user_op / random)"
                    .into(),
            });
        }
    }

    Ok(())
}

/// Cross-check the batch-shared `h_aud_list` produced by witness synthesis
/// against the canonical host helper [`crate::generate_audience_hashes`] run
/// over the audiences extracted from the JWTs.
///
/// This is the prove-time *liveness* guard for the
/// "correctness-by-validation, not by byte-pinning" model: it catches
/// witness-generator drift (the original per-credential `aud_list` bug) BEFORE
/// a proof is computed/submitted, independent of any sha256/signature pin on
/// `witness_gen.wasm`. It is NOT a security gate — the on-chain verifier
/// already pins `h_aud_list` against the registered value
/// (`AccountKeyZkOAuthRS256Verifier.validate`, `InvalidAudienceList`); a
/// drifted generator merely produces an on-chain-rejected proof. This guard
/// turns that wasted round-trip into an immediate, precise error.
///
/// Routes through the public `generate_audience_hashes` (raw-string → quoted →
/// `str_to_limbs` → Poseidon → combine) which is a different path from the
/// witness builder's (`aud_packed_from_jwt` → `try_bytes_to_fields` →
/// `build_shared_audience_stage`), so a divergence between the two surfaces
/// here rather than only as an on-chain revert. The two paths still share
/// `locate_claim` (byte-range extraction) and the `poseidon_params()`
/// singleton, so this catches list-assembly / padding / combine drift — the
/// original per-credential `aud_list` bug — but NOT byte-range-extraction
/// drift. `field: "h_aud_list"` is returned only on the *mismatch* branch; a
/// `generate_audience_hashes` failure (e.g. an over-length aud) is remapped to
/// `field: "credentials"`.
pub(super) fn validate_shared_audience(
    cfg: &CircuitConfig,
    credentials: &[CredentialDecoded],
    shared: &AudienceStage,
) -> Result<(), ApplicationError> {
    let mut audiences = Vec::with_capacity(credentials.len());
    for (i, cred) in credentials.iter().enumerate() {
        let path = format!("credentials[{i}]");
        let payload = decode_payload(&path, &cred.jwt_bytes)?;
        let payload_str = core::str::from_utf8(&payload)
            .map_err(|e| invalid(&path, "jwt", format!("payload not UTF-8: {e}")))?;
        let idx = locate_claim(payload_str, "aud")
            .map_err(|e| invalid(&path, "jwt", format!("locate `aud`: {e}")))?;
        let start = idx.offset + idx.value_idx;
        let end = start + idx.value_len;
        let value = &payload[start..end];
        // `locate_claim` returns the value WITH its surrounding quotes; strip
        // them to recover the raw aud `generate_audience_hashes` re-quotes.
        if value.len() < 2 || value[0] != b'"' || value[value.len() - 1] != b'"' {
            return Err(invalid(&path, "jwt", "aud claim is not a quoted string"));
        }
        let raw = core::str::from_utf8(&value[1..value.len() - 1])
            .map_err(|e| invalid(&path, "jwt", format!("aud not UTF-8: {e}")))?;
        audiences.push(raw.to_string());
    }

    // Remap the helper's own error variants (e.g. an over-length aud surfacing
    // as a `str_to_limbs`/`TextEncodingError`, or `AudienceLimitExceeded`) to a
    // request-attributed error rather than leaking the internal variant.
    let canonical = crate::generate_audience_hashes(cfg, crate::AudienceHashRequest { audiences })
        .map_err(|e| ApplicationError::InvalidProveRequest {
            field: "credentials".into(),
            message: format!("audience cross-check (generate_audience_hashes) failed: {e}"),
        })?;
    let synthesized = crate::field_to_hex(shared.h_aud_list);
    if synthesized != canonical.audience_list_hash {
        return Err(ApplicationError::InvalidProveRequest {
            field: "h_aud_list".into(),
            message: format!(
                "synthesized h_aud_list ({}) != canonical generate_audience_hashes ({}) \
                 — witness-generator audience-list drift",
                synthesized, canonical.audience_list_hash
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::circuit_input::{build_shared_audience_stage, per_credential_h_aud};
    use super::*;
    use ark_crypto_primitives::merkle_tree::MerkleTree;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use gadget::hashes::poseidon::get_poseidon_params;

    fn cfg() -> CircuitConfig {
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

    // ── nonce hex parsing ───────────────────────────────────────────────

    #[test]
    fn nonce_parses_canonical_hex_with_accumulation() {
        // "0x1a2b" => 0x1a2b accumulated MSB-first.
        let got = jwt_nonce_to_field("c", b"\"0x1a2b\"").expect("parse");
        assert_eq!(got, F::from(0x1a2bu64));
    }

    #[test]
    fn nonce_parses_mixed_case_and_single_digit() {
        assert_eq!(jwt_nonce_to_field("c", b"\"0xF\"").unwrap(), F::from(15u64));
        assert_eq!(
            jwt_nonce_to_field("c", b"\"0xdeadBEEF\"").unwrap(),
            F::from(0xdeadbeefu64)
        );
    }

    #[test]
    fn nonce_rejects_bad_prefix_missing_quote_and_non_hex() {
        assert!(jwt_nonce_to_field("c", b"\"1a2b\"").is_err()); // no 0x
        assert!(jwt_nonce_to_field("c", b"\"0x1a2b").is_err()); // no closing quote
        assert!(jwt_nonce_to_field("c", b"\"0xZZ\"").is_err()); // non-hex
        assert!(jwt_nonce_to_field("c", b"\"0x\"").is_err()); // zero digits
    }

    // ── merkle membership ───────────────────────────────────────────────

    /// Build a real Poseidon Merkle tree over `MerkleTreeParams`, take a
    /// genuine membership proof for one leaf, and assert `Path::verify`
    /// (the exact call `validate_decoded_inputs` makes) accepts the true
    /// root and rejects a tampered one. Locks the host recipe to the
    /// in-circuit `verify_membership`.
    #[test]
    fn merkle_path_verify_accepts_true_root_rejects_tampered() {
        let params = get_poseidon_params::<F>();
        // 4 leaves (tree of height 3): each leaf is a single-field slice.
        let leaves: Vec<Vec<F>> = (0..4u64).map(|i| vec![F::from(100 + i)]).collect();
        let tree = MerkleTree::<MerkleTreeParams<F>>::new(&params, &params, &leaves)
            .expect("build merkle tree");
        let root = tree.root();

        let idx = 2usize;
        let path = tree.generate_proof(idx).expect("proof");
        let leaf = &leaves[idx];

        assert!(
            path.verify(&params, &params, &root, leaf.as_slice())
                .unwrap(),
            "true root must verify"
        );
        let tampered = root + F::from(1u64);
        assert!(
            !path
                .verify(&params, &params, &tampered, leaf.as_slice())
                .unwrap(),
            "tampered root must NOT verify"
        );
    }

    // ── random guard ────────────────────────────────────────────────────

    #[test]
    fn rejects_zero_random_before_touching_credentials() {
        let params = get_poseidon_params::<F>();
        let shared = SharedDecoded {
            random: F::zero(),
            h_sign_user_op: F::from(7u64),
            anchor_values: vec![F::zero(); (cfg().n - cfg().k + 1) as usize],
            merkle_root: F::zero(),
        };
        // Empty credentials: the random guard must fire first regardless.
        match validate_decoded_inputs(&cfg(), &shared, &[], &params) {
            Err(ApplicationError::InvalidProveRequest { field, message }) => {
                assert_eq!(field, "random");
                assert!(message.contains("non-zero"));
            }
            other => panic!("expected random!=0 rejection, got {other:?}"),
        }
    }

    // ── shared audience cross-check (C1) ────────────────────────────────

    fn jwt_with_aud(aud: &str) -> Vec<u8> {
        let payload = format!(
            r#"{{"aud":"{aud}","iss":"https://issuer","sub":"u","nonce":"0x1","exp":1700000000}}"#
        );
        let p = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("hdr.{p}.sig").into_bytes()
    }

    fn cred_with_aud(aud: &str) -> CredentialDecoded {
        CredentialDecoded {
            jwt_bytes: jwt_with_aud(aud),
            rsa_modulus_bytes: vec![],
            rsa_signature_bytes: vec![],
            merkle_leaf_sibling_hash: F::zero(),
            merkle_auth_path: vec![],
            merkle_leaf_idx: 0,
        }
    }

    fn shared_for(auds: &[&str], cfg: &CircuitConfig, params: &PoseidonConfig<F>) -> AudienceStage {
        let per_cred: Vec<F> = auds
            .iter()
            .enumerate()
            .map(|(i, a)| {
                per_credential_h_aud(&format!("credentials[{i}]"), &jwt_with_aud(a), cfg, params)
                    .unwrap()
            })
            .collect();
        build_shared_audience_stage(&per_cred, cfg, params).unwrap()
    }

    #[test]
    fn shared_audience_matches_canonical_generate_audience_hashes() {
        let cfg = cfg();
        let params = get_poseidon_params::<F>();
        let auds = ["aud-alpha", "aud-bravo", "aud-charlie"];
        let creds: Vec<CredentialDecoded> = auds.iter().map(|a| cred_with_aud(a)).collect();
        let shared = shared_for(&auds, &cfg, &params);
        validate_shared_audience(&cfg, &creds, &shared).expect("synthesized == canonical");
    }

    #[test]
    fn drifted_h_aud_list_is_rejected() {
        let cfg = cfg();
        let params = get_poseidon_params::<F>();
        let auds = ["aud-alpha", "aud-bravo", "aud-charlie"];
        let creds: Vec<CredentialDecoded> = auds.iter().map(|a| cred_with_aud(a)).collect();
        let good = shared_for(&auds, &cfg, &params);
        // Simulate witness-generator drift: same list, tampered chained hash.
        let drifted = AudienceStage {
            aud_list: good.aud_list.clone(),
            h_aud_list: good.h_aud_list + F::from(1u64),
        };
        match validate_shared_audience(&cfg, &creds, &drifted) {
            Err(ApplicationError::InvalidProveRequest { field, message }) => {
                assert_eq!(field, "h_aud_list");
                assert!(message.contains("drift"), "got msg {message}");
            }
            other => panic!("expected drift rejection, got {other:?}"),
        }
    }

    fn jwt_with_aud_array() -> Vec<u8> {
        let payload =
            r#"{"aud":["a","b"],"iss":"https://issuer","sub":"u","nonce":"0x1","exp":1700000000}"#;
        let p = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("hdr.{p}.sig").into_bytes()
    }

    /// Array-valued `aud` is intentionally unsupported by this guard (it
    /// requires a quoted scalar string). This is redundant with the upstream
    /// `extract_string_claim` gate (`prove.rs` x-list derivation) today, but
    /// pinning it here locks the behavior so a future relaxation upstream can't
    /// silently turn array aud into a false-reject via this guard alone.
    #[test]
    fn array_valued_aud_is_rejected() {
        let cfg = cfg();
        let cred = CredentialDecoded {
            jwt_bytes: jwt_with_aud_array(),
            rsa_modulus_bytes: vec![],
            rsa_signature_bytes: vec![],
            merkle_leaf_sibling_hash: F::zero(),
            merkle_auth_path: vec![],
            merkle_leaf_idx: 0,
        };
        let dummy = AudienceStage {
            aud_list: vec![],
            h_aud_list: F::zero(),
        };
        match validate_shared_audience(&cfg, &[cred], &dummy) {
            Err(ApplicationError::InvalidProveRequest { field, .. }) => {
                assert_eq!(field, "credentials[0].jwt");
            }
            other => panic!("expected array-aud rejection, got {other:?}"),
        }
    }

    #[test]
    fn single_credential_matches_canonical() {
        let cfg = cfg();
        let params = get_poseidon_params::<F>();
        let auds = ["solo-aud"];
        let creds: Vec<CredentialDecoded> = auds.iter().map(|a| cred_with_aud(a)).collect();
        let shared = shared_for(&auds, &cfg, &params);
        validate_shared_audience(&cfg, &creds, &shared).expect("k=1 synthesized == canonical");
    }

    #[test]
    fn duplicate_audiences_match_canonical() {
        let cfg = cfg();
        let params = get_poseidon_params::<F>();
        let auds = ["dup", "dup", "other"];
        let creds: Vec<CredentialDecoded> = auds.iter().map(|a| cred_with_aud(a)).collect();
        let shared = shared_for(&auds, &cfg, &params);
        validate_shared_audience(&cfg, &creds, &shared).expect("duplicates handled identically");
    }

    /// `cfg.forbidden_string` ("forbidden") is special only as PADDING; a real
    /// aud that happens to equal it must still match the canonical helper.
    #[test]
    fn aud_equal_to_forbidden_string_is_not_special() {
        let cfg = cfg();
        let params = get_poseidon_params::<F>();
        assert_eq!(cfg.forbidden_string, "forbidden");
        let auds = ["forbidden", "b", "c"];
        let creds: Vec<CredentialDecoded> = auds.iter().map(|a| cred_with_aud(a)).collect();
        let shared = shared_for(&auds, &cfg, &params);
        validate_shared_audience(&cfg, &creds, &shared).expect("aud==forbidden matches canonical");
    }

    /// Quoted aud length exactly `max_aud_len` (the boundary `str_to_limbs`
    /// accepts with `>` not `>=`): raw = `max_aud_len - 2` chars + 2 quotes.
    #[test]
    fn aud_at_max_len_boundary_matches_canonical() {
        let cfg = cfg();
        let params = get_poseidon_params::<F>();
        let raw = "a".repeat(cfg.max_aud_len as usize - 2);
        let auds = [raw.as_str(), "b", "c"];
        let creds: Vec<CredentialDecoded> = auds.iter().map(|a| cred_with_aud(a)).collect();
        let shared = shared_for(&auds, &cfg, &params);
        validate_shared_audience(&cfg, &creds, &shared)
            .expect("aud quoted to max_aud_len matches canonical");
    }
}
