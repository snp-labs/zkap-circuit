use ark_crypto_primitives::{
    crh::CRHScheme,
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;
use ark_utils::pad;
use ark_utils::try_str_to_fields;
use circuit::types::{CircuitConfig, F, PoseidonHash};

use super::AnchorConfig;
use crate::dto::{AnchorSecret, GenerateAnchorRequest, GenerateAnchorResponse};
use crate::error::ApplicationError;

use gadget::{
    anchor::{
        AnchorScheme,
        error::AnchorError,
        poseidon::{
            PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorScheme, PoseidonAnchorSecret,
            build_anchor_witness,
        },
    },
    matrix::VandermondeMatrix,
};

/// Generate the threshold anchor from a list of JWT claim secrets.
///
/// Each [`AnchorSecret`] is hashed via Poseidon into a per-credential scalar
/// `x` (each of `subject` / `issuer` / `audience` is wrapped in `"…"` and
/// padded to its `CircuitConfig::max_*_len` before absorption — callers pass
/// raw strings; the JSON-style quoting is internal). The `x` values are then
/// combined through the Vandermonde-based [`PoseidonAnchorScheme`] to produce
/// `n - k + 1` anchor polynomial evaluations, and `hanchor` is the sequential
/// Poseidon chain hash of those evaluations (which equals the in-circuit
/// `hanchor` public input).
///
/// `request.secrets.len()` must equal `config.n`; otherwise the call fails
/// with [`ApplicationError::AnchorDimensionMismatch`]. Per-claim length
/// violations surface as [`ApplicationError::InvalidClaimValue`] with `which`
/// set to `"subject"`, `"issuer"`, or `"audience"`. Poseidon evaluation
/// failures surface as [`ApplicationError::HashFailed`].
pub fn generate_anchor(
    config: &CircuitConfig,
    request: GenerateAnchorRequest,
) -> Result<GenerateAnchorResponse, ApplicationError> {
    let expected = config.n as usize;
    let got = request.secrets.len();
    if got != expected {
        return Err(ApplicationError::AnchorDimensionMismatch { expected, got });
    }

    let ctx = AnchorConfig::from_params(config);
    let poseidon_params = crate::poseidon_params();

    let anchor_key = PoseidonAnchorPublicKey {
        params: poseidon_params.clone(),
    };

    let x_list: Vec<F> = request
        .secrets
        .iter()
        .map(|s| derive_x_from_secret(s, &anchor_key.params, &ctx))
        .collect::<Result<Vec<F>, ApplicationError>>()?;

    let anchor_secret = PoseidonAnchorSecret(x_list);
    let anchor = PoseidonAnchorScheme::generate_anchor(&anchor_key, &anchor_secret, &ctx.matrix)?;

    let hanchor_field = chain_hash_anchor(&anchor.0, poseidon_params)?;

    Ok(GenerateAnchorResponse {
        anchor_evaluations: anchor.0.iter().map(|f| crate::field_to_hex(*f)).collect(),
        hanchor: crate::field_to_hex(hanchor_field),
    })
}

/// Sequential Poseidon chain hash matching the in-circuit `hanchor` recipe:
/// `H(v[0])`, then `H(prev, v[i])` for `i in 1..len`.
///
/// Inlined here (rather than reusing `witness::input::chain_hash_native`) so
/// that [`generate_anchor`] remains compilable without the `proof` feature
/// (`witness/input.rs` is `proof`-gated).
fn chain_hash_anchor(
    values: &[F],
    params: &PoseidonConfig<F>,
) -> Result<F, ApplicationError> {
    if values.is_empty() {
        return Err(ApplicationError::HashFailed(
            "chain_hash on empty anchor".into(),
        ));
    }
    let mut h = PoseidonHash::evaluate(params, [values[0]])
        .map_err(|e| ApplicationError::HashFailed(format!("Poseidon chain[0]: {}", e)))?;
    for v in &values[1..] {
        h = PoseidonHash::evaluate(params, [h, *v])
            .map_err(|e| ApplicationError::HashFailed(format!("Poseidon chain[i]: {}", e)))?;
    }
    Ok(h)
}

pub(crate) fn derive_x_from_secret(
    secret: &AnchorSecret,
    poseidon_param: &PoseidonConfig<F>,
    ctx: &AnchorConfig,
) -> Result<F, ApplicationError> {
    // Wrap each raw claim in JSON-style quotes so the byte sequence absorbed
    // here matches what the in-circuit JWT extractor produces from the raw
    // payload bytes.
    let aud_quoted = format!("\"{}\"", secret.audience);
    let iss_quoted = format!("\"{}\"", secret.issuer);
    let sub_quoted = format!("\"{}\"", secret.subject);

    let aud_processed = pad(&aud_quoted, ctx.max_aud_len, ctx.pad_char).map_err(|e| {
        ApplicationError::InvalidClaimValue {
            which: "audience".into(),
            message: e.to_string(),
        }
    })?;
    let iss_processed = pad(&iss_quoted, ctx.max_iss_len, ctx.pad_char).map_err(|e| {
        ApplicationError::InvalidClaimValue {
            which: "issuer".into(),
            message: e.to_string(),
        }
    })?;
    let sub_processed = pad(&sub_quoted, ctx.max_sub_len, ctx.pad_char).map_err(|e| {
        ApplicationError::InvalidClaimValue {
            which: "subject".into(),
            message: e.to_string(),
        }
    })?;

    let input = [aud_processed, iss_processed, sub_processed].concat();

    let limbs = try_str_to_fields::<F>(&input)
        .map_err(|e| ApplicationError::HashFailed(format!("byte-to-field conversion: {}", e)))?;

    let hashed = PoseidonHash::evaluate(poseidon_param, limbs)
        .map_err(|e| ApplicationError::HashFailed(format!("Poseidon evaluation: {}", e)))?;

    Ok(hashed)
}

#[allow(dead_code)]
pub(crate) fn derive_selector_from_x_list_and_anchor<F: PrimeField + Absorb>(
    pk: &PoseidonAnchorPublicKey<F>,
    x_list: &[F],
    anchor: &PoseidonAnchor<F>,
    matrix: &VandermondeMatrix<F>,
) -> Result<Vec<u8>, ApplicationError> {
    let (_m, n) = matrix.dimensions();
    let k = matrix.k;

    // Check that the number of known secrets matches k
    if x_list.len() != k {
        Err(AnchorError::DimensionMismatch(
            "Number of known secrets must match k".to_string(),
        ))
        .map_err(|e| ApplicationError::InvalidFormat(format!("{}", e)))?
    }

    // 1. Generate all index combinations that select k positions out of n.
    // e.g.: n=6, k=3 -> [[0,1,2], [0,1,3], ...]
    let index_combinations = combinations(n, k);

    // 2. Attempt verification for each index combination.
    for index_combo in index_combinations {
        // Assume the secret order provided by the caller (known_secrets[i])
        // maps 1:1 to the selected index order (index_combo[i]).

        // 3. Build selector
        let mut selector = vec![0u8; n];
        for &position in &index_combo {
            selector[position] = 1;
        }

        // 4. Build witness and verify
        // Pass known_secrets as-is to check
        // whether Anchor[index_combo[i]] == known_secrets[i].
        let witness = build_anchor_witness(&pk.params, x_list, &selector, matrix).map_err(|e| {
            ApplicationError::InvalidFormat(format!("Failed to build witness: {}", e))
        })?;

        if PoseidonAnchorScheme::verify(anchor, &witness).is_ok() {
            return Ok(selector);
        }
    }
    // All combinations tried but none succeeded
    Err(AnchorError::InvalidParameters(
        "No valid selector found".to_string(),
    ))
    .map_err(|e| ApplicationError::InvalidFormat(format!("{}", e)))
}

// nCk combination generator
#[allow(dead_code)]
fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    if k == 0 || k > n {
        return result;
    }
    let mut indices: Vec<usize> = (0..k).collect();
    loop {
        result.push(indices.clone());
        let mut i = k;
        while i > 0 {
            i -= 1;
            if indices[i] != i + n - k {
                break;
            }
        }
        if indices[0] == n - k {
            break;
        }
        indices[i] += 1;
        for j in i + 1..k {
            indices[j] = indices[j - 1] + 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use gadget::anchor::poseidon::PoseidonAnchorScheme;
    use gadget::hashes::poseidon::get_poseidon_params;

    type F = ark_bn254::Fr;

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

    fn anchor_secret(sub: &str, iss: &str, aud: &str) -> AnchorSecret {
        AnchorSecret {
            subject: sub.into(),
            issuer: iss.into(),
            audience: aud.into(),
        }
    }

    #[test]
    fn generate_anchor_basic() {
        let cfg = anchor_test_config();
        let secrets: Vec<AnchorSecret> = (0..cfg.n)
            .map(|i| {
                anchor_secret(
                    &format!("user_{}", i),
                    "https://accounts.google.com",
                    "test-audience",
                )
            })
            .collect();
        let resp = generate_anchor(&cfg, GenerateAnchorRequest { secrets }).unwrap();
        assert_eq!(
            resp.anchor_evaluations.len(),
            (cfg.n - cfg.k + 1) as usize
        );
        assert!(resp.hanchor.starts_with("0x"));
        for ev in &resp.anchor_evaluations {
            assert!(ev.starts_with("0x"));
        }
    }

    #[test]
    fn generate_anchor_deterministic() {
        let cfg = anchor_test_config();
        let secrets: Vec<AnchorSecret> = (0..cfg.n)
            .map(|i| anchor_secret(&format!("user_{}", i), "issuer", "aud"))
            .collect();
        let r1 = generate_anchor(
            &cfg,
            GenerateAnchorRequest {
                secrets: secrets.clone(),
            },
        )
        .unwrap();
        let r2 = generate_anchor(&cfg, GenerateAnchorRequest { secrets }).unwrap();
        assert_eq!(r1.anchor_evaluations, r2.anchor_evaluations);
        assert_eq!(r1.hanchor, r2.hanchor);
    }

    #[test]
    fn generate_anchor_dimension_mismatch_too_few() {
        let cfg = anchor_test_config();
        let secrets: Vec<AnchorSecret> = (0..cfg.n - 1)
            .map(|i| anchor_secret(&format!("user_{}", i), "iss", "aud"))
            .collect();
        let n = cfg.n as usize;
        match generate_anchor(&cfg, GenerateAnchorRequest { secrets }) {
            Err(ApplicationError::AnchorDimensionMismatch { expected, got }) => {
                assert_eq!(expected, n);
                assert_eq!(got, n - 1);
            }
            other => panic!("expected AnchorDimensionMismatch, got {:?}", other),
        }
    }

    #[test]
    fn generate_anchor_dimension_mismatch_too_many() {
        let cfg = anchor_test_config();
        let secrets: Vec<AnchorSecret> = (0..cfg.n + 1)
            .map(|i| anchor_secret(&format!("user_{}", i), "iss", "aud"))
            .collect();
        let n = cfg.n as usize;
        match generate_anchor(&cfg, GenerateAnchorRequest { secrets }) {
            Err(ApplicationError::AnchorDimensionMismatch { expected, got }) => {
                assert_eq!(expected, n);
                assert_eq!(got, n + 1);
            }
            other => panic!("expected AnchorDimensionMismatch, got {:?}", other),
        }
    }

    #[test]
    fn generate_anchor_subject_too_long_returns_invalid_claim_value() {
        let cfg = anchor_test_config();
        // Even the raw subject alone exceeds max_sub_len (93); after the
        // service wraps it in quotes it is still over the limit.
        let oversized = "x".repeat(cfg.max_sub_len as usize + 4);
        let mut secrets: Vec<AnchorSecret> = (0..cfg.n)
            .map(|i| anchor_secret(&format!("user_{}", i), "iss", "aud"))
            .collect();
        secrets[0].subject = oversized;
        match generate_anchor(&cfg, GenerateAnchorRequest { secrets }) {
            Err(ApplicationError::InvalidClaimValue { which, .. }) => {
                assert_eq!(which, "subject");
            }
            other => panic!("expected InvalidClaimValue, got {:?}", other),
        }
    }

    #[test]
    fn test_derive_selector_from_x_list_and_anchor() {
        let n = 6;
        let k = 2;

        // Setup
        let pk = PoseidonAnchorPublicKey {
            params: get_poseidon_params::<F>(),
        };
        let matrix = VandermondeMatrix::<F>::new(n, k);
        let ctx = AnchorConfig {
            matrix_rows: n,
            matrix_cols: k,
            max_aud_len: 21,
            max_iss_len: 21,
            max_sub_len: 20,
            pad_char: '\0',
            matrix: matrix.clone(),
        };

        let all_secrets_data = [
            anchor_secret("user1", "issuer1", "aud1"),
            anchor_secret("user2", "issuer2", "aud2"),
            anchor_secret("user3", "issuer3", "aud3"),
            anchor_secret("user4", "issuer4", "aud4"),
            anchor_secret("user5", "issuer5", "aud5"),
            anchor_secret("user6", "issuer6", "aud6"),
        ];

        let all_x_values: Vec<F> = all_secrets_data
            .iter()
            .map(|s| derive_x_from_secret(s, &pk.params, &ctx).unwrap())
            .collect();

        let anchor_secret_in = PoseidonAnchorSecret(all_x_values.clone());

        let anchor =
            PoseidonAnchorScheme::<F>::generate_anchor(&pk, &anchor_secret_in, &matrix).unwrap();

        // Test case 1: known secrets at positions [1, 3]
        let known_indices = [1, 3];
        let known_x_list: Vec<F> = known_indices.iter().map(|&i| all_x_values[i]).collect();

        let result = derive_selector_from_x_list_and_anchor(&pk, &known_x_list, &anchor, &matrix);
        assert!(result.is_ok(), "Should find valid selector");

        let selector = result.unwrap();
        let expected_selector = vec![0, 1, 0, 1, 0, 0];
        assert_eq!(
            selector, expected_selector,
            "Selector should match expected positions"
        );

        let witness = build_anchor_witness(&pk.params, &known_x_list, &selector, &matrix).unwrap();
        assert!(
            PoseidonAnchorScheme::verify(&anchor, &witness).is_ok(),
            "Verification should succeed"
        );
    }

    #[test]
    fn test_derive_selector_from_x_list_and_anchor_different_positions() {
        let n = 6;
        let k = 3;

        let pk = PoseidonAnchorPublicKey {
            params: get_poseidon_params::<F>(),
        };
        let matrix = VandermondeMatrix::<F>::new(n, k);
        let ctx = AnchorConfig {
            matrix_rows: n,
            matrix_cols: k,
            max_aud_len: 21,
            max_iss_len: 21,
            max_sub_len: 20,
            pad_char: '\0',
            matrix: matrix.clone(),
        };

        let all_secrets_data = [
            anchor_secret("alice", "auth1", "app1"),
            anchor_secret("bob", "auth2", "app2"),
            anchor_secret("charlie", "auth3", "app3"),
            anchor_secret("david", "auth4", "app4"),
            anchor_secret("eve", "auth5", "app5"),
            anchor_secret("frank", "auth6", "app6"),
        ];

        let all_x_values: Vec<F> = all_secrets_data
            .iter()
            .map(|s| derive_x_from_secret(s, &pk.params, &ctx).unwrap())
            .collect();

        let anchor_secret_in = PoseidonAnchorSecret(all_x_values.clone());

        let anchor =
            PoseidonAnchorScheme::<F>::generate_anchor(&pk, &anchor_secret_in, &matrix).unwrap();

        // Test case 2: known secrets at positions [0, 2, 5]
        let known_indices = [0, 2, 5];
        let known_x_list: Vec<F> = known_indices.iter().map(|&i| all_x_values[i]).collect();

        let result = derive_selector_from_x_list_and_anchor(&pk, &known_x_list, &anchor, &matrix);
        assert!(result.is_ok(), "Should find valid selector");

        let selector = result.unwrap();
        let expected_selector = vec![1, 0, 1, 0, 0, 1];
        assert_eq!(
            selector, expected_selector,
            "Selector should match expected positions"
        );

        let witness = build_anchor_witness(&pk.params, &known_x_list, &selector, &matrix).unwrap();
        assert!(
            PoseidonAnchorScheme::verify(&anchor, &witness).is_ok(),
            "Verification should succeed"
        );
    }

    #[test]
    fn test_derive_selector_from_x_list_and_anchor_wrong_length() {
        let n = 6;
        let k = 3;

        let pk = PoseidonAnchorPublicKey {
            params: get_poseidon_params::<F>(),
        };
        let matrix = VandermondeMatrix::<F>::new(n, k);

        let dummy_anchor = PoseidonAnchor::new(vec![F::from(0u64); n - k + 1]);

        // Test with wrong number of known secrets (should fail)
        let wrong_known_x_list = vec![F::from(100u64), F::from(200u64)]; // Only 2 instead of 3

        let result = derive_selector_from_x_list_and_anchor(
            &pk,
            &wrong_known_x_list,
            &dummy_anchor,
            &matrix,
        );
        assert!(
            result.is_err(),
            "Should fail with wrong number of known secrets"
        );
    }

    #[test]
    fn test_derive_selector_from_x_list_and_anchor_no_match() {
        let n = 6;
        let k = 3;

        let pk = PoseidonAnchorPublicKey {
            params: get_poseidon_params::<F>(),
        };
        let matrix = VandermondeMatrix::<F>::new(n, k);
        let ctx = AnchorConfig {
            matrix_rows: n,
            matrix_cols: k,
            max_aud_len: 21,
            max_iss_len: 21,
            max_sub_len: 20,
            pad_char: '\0',
            matrix: matrix.clone(),
        };

        let all_secrets_data = [
            anchor_secret("user1", "issuer1", "aud1"),
            anchor_secret("user2", "issuer2", "aud2"),
            anchor_secret("user3", "issuer3", "aud3"),
            anchor_secret("user4", "issuer4", "aud4"),
            anchor_secret("user5", "issuer5", "aud5"),
            anchor_secret("user6", "issuer6", "aud6"),
        ];

        let all_x_values: Vec<F> = all_secrets_data
            .iter()
            .map(|s| derive_x_from_secret(s, &pk.params, &ctx).unwrap())
            .collect();

        let anchor_secret_in = PoseidonAnchorSecret(all_x_values.clone());

        let anchor =
            PoseidonAnchorScheme::<F>::generate_anchor(&pk, &anchor_secret_in, &matrix).unwrap();

        // Test with completely wrong known secrets
        let wrong_known_x_list = vec![F::from(999u64), F::from(888u64), F::from(777u64)];

        let result =
            derive_selector_from_x_list_and_anchor(&pk, &wrong_known_x_list, &anchor, &matrix);
        assert!(result.is_err(), "Should fail with no matching secrets");
    }
}
