use ark_crypto_primitives::{
    crh::CRHScheme,
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;
use ark_utils::try_str_to_fields;
use ark_utils::pad;
use circuit::constants::{F, PoseidonHash, ZkPasskeyConfig};

use super::AnchorConfig;
use crate::{Secret, error::ApplicationError};

use gadget::{
    anchor::{
        AnchorScheme,
        error::AnchorError,
        poseidon::{
            PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorScheme, PoseidonAnchorSecret,
            build_anchor_witness,
        },
    },
    hashes::poseidon::get_poseidon_params,
    matrix::VandermondeMatrix,
};

pub fn create_poseidon_anchor<Config: ZkPasskeyConfig>(
    secrets: Vec<Secret>,
) -> Result<PoseidonAnchor<F>, ApplicationError> {
    let ctx = AnchorConfig::from_config::<Config>();

    let anchor_key = PoseidonAnchorPublicKey {
        params: get_poseidon_params::<F>(),
    };

    let x_list: Vec<F> = secrets
        .iter()
        .map(|s| derive_x_from_secret(s, &anchor_key.params, &ctx))
        .collect::<Result<Vec<F>, ApplicationError>>()?;

    let anchor_secret = PoseidonAnchorSecret(x_list);

    let anchor = PoseidonAnchorScheme::generate_anchor(&anchor_key, &anchor_secret, &ctx.matrix)?;

    Ok(anchor)
}

pub(crate) fn derive_x_from_secret(
    secret: &Secret,
    poseidon_param: &PoseidonConfig<F>,
    ctx: &AnchorConfig,
) -> Result<F, ApplicationError> {
    let aud_processed = pad(&secret.aud, ctx.max_aud_len, ctx.pad_char)?;
    let iss_processed = pad(&secret.iss, ctx.max_iss_len, ctx.pad_char)?;
    let sub_processed = pad(&secret.sub, ctx.max_sub_len, ctx.pad_char)?;

    let input = [aud_processed, iss_processed, sub_processed].concat();

    let limbs =
        try_str_to_fields::<F>(&input).map_err(|e| ApplicationError::InvalidFormat(e.to_string()))?;

    let hashed = PoseidonHash::evaluate(poseidon_param, limbs)
        .map_err(|_| ApplicationError::PoseidonHashError)?;

    Ok(hashed)
}

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
    use crate::Secret;

    type F = ark_bn254::Fr;

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

        // Create Secret objects
        let all_secrets_data = vec![
            Secret { sub: "user1".to_string(), iss: "issuer1".to_string(), aud: "aud1".to_string() },
            Secret { sub: "user2".to_string(), iss: "issuer2".to_string(), aud: "aud2".to_string() },
            Secret { sub: "user3".to_string(), iss: "issuer3".to_string(), aud: "aud3".to_string() },
            Secret { sub: "user4".to_string(), iss: "issuer4".to_string(), aud: "aud4".to_string() },
            Secret { sub: "user5".to_string(), iss: "issuer5".to_string(), aud: "aud5".to_string() },
            Secret { sub: "user6".to_string(), iss: "issuer6".to_string(), aud: "aud6".to_string() },
        ];

        // Derive x values from secrets
        let all_x_values: Vec<F> = all_secrets_data
            .iter()
            .map(|s| derive_x_from_secret(s, &pk.params, &ctx).unwrap())
            .collect();

        let anchor_secret = PoseidonAnchorSecret(all_x_values.clone());

        // Generate anchor
        let anchor = PoseidonAnchorScheme::<F>::generate_anchor(&pk, &anchor_secret, &matrix).unwrap();

        // Test case 1: known secrets at positions [1, 3]
        let known_indices = vec![1, 3];
        let known_x_list: Vec<F> = known_indices.iter().map(|&i| all_x_values[i]).collect();

        let result = derive_selector_from_x_list_and_anchor(&pk, &known_x_list, &anchor, &matrix);
        assert!(result.is_ok(), "Should find valid selector");

        let selector = result.unwrap();
        println!("Found selector: {:?}", selector);

        // Verify the selector matches expected indices
        let expected_selector = vec![0, 1, 0, 1, 0, 0];
        assert_eq!(
            selector, expected_selector,
            "Selector should match expected positions"
        );

        // Verify with witness generation
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

        // Create Secret objects
        let all_secrets_data = vec![
            Secret { sub: "alice".to_string(), iss: "auth1".to_string(), aud: "app1".to_string() },
            Secret { sub: "bob".to_string(), iss: "auth2".to_string(), aud: "app2".to_string() },
            Secret { sub: "charlie".to_string(), iss: "auth3".to_string(), aud: "app3".to_string() },
            Secret { sub: "david".to_string(), iss: "auth4".to_string(), aud: "app4".to_string() },
            Secret { sub: "eve".to_string(), iss: "auth5".to_string(), aud: "app5".to_string() },
            Secret { sub: "frank".to_string(), iss: "auth6".to_string(), aud: "app6".to_string() },
        ];

        // Derive x values from secrets
        let all_x_values: Vec<F> = all_secrets_data
            .iter()
            .map(|s| derive_x_from_secret(s, &pk.params, &ctx).unwrap())
            .collect();

        let anchor_secret = PoseidonAnchorSecret(all_x_values.clone());

        // Generate anchor
        let anchor = PoseidonAnchorScheme::<F>::generate_anchor(&pk, &anchor_secret, &matrix).unwrap();

        // Test case 2: known secrets at positions [0, 2, 5]
        let known_indices = vec![0, 2, 5];
        let known_x_list: Vec<F> = known_indices.iter().map(|&i| all_x_values[i]).collect();

        let result = derive_selector_from_x_list_and_anchor(&pk, &known_x_list, &anchor, &matrix);
        assert!(result.is_ok(), "Should find valid selector");

        let selector = result.unwrap();
        println!("Found selector: {:?}", selector);

        // Verify the selector matches expected indices
        let expected_selector = vec![1, 0, 1, 0, 0, 1];
        assert_eq!(
            selector, expected_selector,
            "Selector should match expected positions"
        );

        // Verify with witness generation
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

        // Setup
        let pk = PoseidonAnchorPublicKey {
            params: get_poseidon_params::<F>(),
        };
        let matrix = VandermondeMatrix::<F>::new(n, k);

        // Create dummy anchor
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

        // Create Secret objects
        let all_secrets_data = vec![
            Secret { sub: "user1".to_string(), iss: "issuer1".to_string(), aud: "aud1".to_string() },
            Secret { sub: "user2".to_string(), iss: "issuer2".to_string(), aud: "aud2".to_string() },
            Secret { sub: "user3".to_string(), iss: "issuer3".to_string(), aud: "aud3".to_string() },
            Secret { sub: "user4".to_string(), iss: "issuer4".to_string(), aud: "aud4".to_string() },
            Secret { sub: "user5".to_string(), iss: "issuer5".to_string(), aud: "aud5".to_string() },
            Secret { sub: "user6".to_string(), iss: "issuer6".to_string(), aud: "aud6".to_string() },
        ];

        // Derive x values from secrets
        let all_x_values: Vec<F> = all_secrets_data
            .iter()
            .map(|s| derive_x_from_secret(s, &pk.params, &ctx).unwrap())
            .collect();

        let anchor_secret = PoseidonAnchorSecret(all_x_values.clone());

        // Generate anchor
        let anchor = PoseidonAnchorScheme::<F>::generate_anchor(&pk, &anchor_secret, &matrix).unwrap();

        // Test with completely wrong known secrets
        let wrong_known_x_list = vec![F::from(999u64), F::from(888u64), F::from(777u64)];

        let result =
            derive_selector_from_x_list_and_anchor(&pk, &wrong_known_x_list, &anchor, &matrix);
        assert!(result.is_err(), "Should fail with no matching secrets");
    }
}
