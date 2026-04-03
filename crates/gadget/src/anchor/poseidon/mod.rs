pub mod constraints;

use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;

use crate::{
    anchor::{AnchorScheme, AnchorUtils, error::AnchorError},
    hashes::poseidon::get_poseidon_params,
    matrix::VandermondeMatrix,
};

// ==================== Core Data Structures ====================

/// Poseidon Anchor value (length: m = n - k + 1)
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchor<F: PrimeField>(pub Vec<F>);

impl<F: PrimeField> PoseidonAnchor<F> {
    pub fn new(values: Vec<F>) -> Self {
        Self(values)
    }

    pub fn empty(size: usize) -> Self {
        Self(vec![F::zero(); size])
    }
}

/// Poseidon Anchor public key
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorPublicKey<F: PrimeField> {
    pub params: PoseidonConfig<F>,
}

/// Poseidon Anchor secret (length: n)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorSecret<F: PrimeField>(pub Vec<F>);

impl<F: PrimeField> From<Vec<F>> for PoseidonAnchorSecret<F> {
    fn from(value: Vec<F>) -> Self {
        Self(value)
    }
}

/// Poseidon Anchor Witness
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorWitness<F: PrimeField> {
    /// Auxiliary vector a (size: m = n - k + 1)
    pub a: Vec<F>,
    /// Vector b = a * Matrix (size: n)
    pub b: Vec<F>,
    /// Hashed secret values (size: n)
    /// Hash values only at positions where selector is 1, zero elsewhere
    pub h_known: Vec<F>,
}

impl<F: PrimeField> PoseidonAnchorWitness<F> {
    pub fn empty(n: usize, k: usize) -> Self {
        let m = n - k + 1;
        Self {
            a: vec![F::zero(); m],
            b: vec![F::zero(); n],
            h_known: vec![F::zero(); n],
        }
    }

    /// Compute partial RHS for split proof
    /// partial_rhs[i] = b[i] * h_known[i]
    pub fn compute_partial_rhs(&self) -> Vec<F> {
        self.b
            .iter()
            .zip(self.h_known.iter())
            .map(|(b_i, h_i)| *b_i * *h_i)
            .collect()
    }
}

// ==================== Utility Functions ====================

/// Helper function for building a Witness
///
/// This function computes h_known in the same way as the circuit:
/// h_known[i] = H(i, secret[hash_idx]) where selector[i] == 1
///
/// # Arguments
/// * `params` - Poseidon parameters
/// * `secrets` - Secret vector to hash (already in H(aud, iss, sub) form)
/// * `selector` - Vector indicating which positions contain secrets
/// * `matrix` - Vandermonde matrix
pub fn build_anchor_witness<F: PrimeField + Absorb>(
    params: &PoseidonConfig<F>,
    secrets: &[F],
    selector: &[u8],
    matrix: &VandermondeMatrix<F>,
) -> Result<PoseidonAnchorWitness<F>, AnchorError> {
    let n = matrix.matrix[0].len();

    if selector.len() != n {
        return Err(AnchorError::DimensionMismatch(format!(
            "Selector length ({}) must match matrix n ({})",
            selector.len(),
            n
        )));
    }

    // 1. Compute vector a
    let vector_a = matrix.calculate_vector_a(selector)?;

    // 2. Compute vector b: b = a * Matrix
    let vector_b = matrix.vector_multiply(&vector_a)?;

    // 3. Build h_known vector - computed the same way as the circuit
    // Circuit: h_id = H(current_idx, H(aud, iss, sub))
    // Therefore h_known[i] = H(i, secrets[hash_idx])
    let mut h_known = vec![F::zero(); n];
    let mut hash_idx = 0;
    for (i, &sel) in selector.iter().enumerate() {
        if sel == 1 {
            if hash_idx >= secrets.len() {
                return Err(AnchorError::DimensionMismatch(format!(
                    "Not enough secrets provided. Expected at least {}, got {}",
                    hash_idx + 1,
                    secrets.len()
                )));
            }
            // H(index, secret)
            let index_and_hash = vec![F::from(i as u64), secrets[hash_idx]];
            h_known[i] = CRH::<F>::evaluate(params, index_and_hash)
                .map_err(|_| AnchorError::CryptoError("Hash failed".to_string()))?;
            hash_idx += 1;
        }
    }

    Ok(PoseidonAnchorWitness {
        a: vector_a,
        b: vector_b,
        h_known,
    })
}

// ==================== Hash Cache Structure ====================

/// Structure caching secret hashing results
/// to avoid redundant hashing
#[derive(Clone, Debug)]
pub struct HashedSecretsCache<F: PrimeField> {
    /// Hash values for each index (H(index || secret))
    pub hashes: Vec<F>,
}

impl<F: PrimeField + Absorb> HashedSecretsCache<F> {
    /// Create cache by hashing the secret vector all at once
    pub fn new(params: &PoseidonConfig<F>, secrets: &[F]) -> Result<Self, AnchorError> {
        let hashes = secrets
            .iter()
            .enumerate()
            .map(|(i, &secret)| {
                let input = vec![F::from(i as u64), secret];
                CRH::<F>::evaluate(params, input)
                    .map_err(|_| AnchorError::CryptoError("Hash failed".to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { hashes })
    }

    /// Get the hash value for a specific index
    pub fn get(&self, index: usize) -> Option<F> {
        self.hashes.get(index).copied()
    }

    /// Build the h_known vector according to selector
    /// Fills in hashes of known_secrets in order at positions where selector is 1
    pub fn build_h_known(&self, selector: &[u8]) -> Result<Vec<F>, AnchorError> {
        // Verify that the number of 1s in selector matches the number of known secrets (k)
        let ones_count = selector.iter().filter(|&&s| s == 1).count();
        if ones_count != self.hashes.len() {
            return Err(AnchorError::DimensionMismatch(format!(
                "Number of 1s in selector ({}) must match known secrets length ({})",
                ones_count,
                self.hashes.len()
            )));
        }

        // Fill in hashes of known_secrets in order at positions where selector is 1
        let mut h_known = vec![F::zero(); selector.len()];
        let mut hash_idx = 0;
        for (i, &s) in selector.iter().enumerate() {
            if s == 1 {
                h_known[i] = self.hashes[hash_idx];
                hash_idx += 1;
            }
        }

        Ok(h_known)
    }

    /// Return the full hash vector
    pub fn as_vec(&self) -> &[F] {
        &self.hashes
    }
}

// ==================== Poseidon Anchor Scheme V3 ====================

pub struct PoseidonAnchorScheme<F: PrimeField> {
    _phantom: core::marker::PhantomData<F>,
}

impl<F: PrimeField + Absorb> AnchorUtils for PoseidonAnchorScheme<F> {
    type Field = F;

    fn inner_product(v1: &[Self::Field], v2: &[Self::Field]) -> Result<Self::Field, AnchorError> {
        if v1.len() != v2.len() {
            return Err(AnchorError::DimensionMismatch(
                "Inner product vectors must have the same length".to_string(),
            ));
        }

        let sum = v1
            .iter()
            .zip(v2.iter())
            .fold(F::zero(), |acc, (a, b)| acc + *a * *b);

        Ok(sum)
    }
}

impl<F: PrimeField + Absorb> AnchorScheme for PoseidonAnchorScheme<F> {
    type Anchor = PoseidonAnchor<F>;
    type PublicKey = PoseidonAnchorPublicKey<F>;
    type Matrix = VandermondeMatrix<F>;
    type Secret = PoseidonAnchorSecret<F>;
    type Witness = PoseidonAnchorWitness<F>;
    fn setup<R: Rng>(_rng: &mut R, _n: usize) -> Result<Self::PublicKey, AnchorError> {
        let params = get_poseidon_params();
        Ok(PoseidonAnchorPublicKey { params })
    }

    /// Generate Anchor
    /// Anchor = Matrix(m X n) * h(n X 1) (h: hashed secret vector)
    ///
    /// Note: secrets must already be hashed in H(aud, iss, sub) form.
    /// This function additionally computes H(index, secret).
    fn generate_anchor(
        pk: &Self::PublicKey,
        secrets: &Self::Secret,
        matrix: &Self::Matrix,
    ) -> Result<Self::Anchor, AnchorError> {
        let (_, n) = matrix.dimensions();

        if secrets.0.len() != n {
            return Err(AnchorError::DimensionMismatch(format!(
                "Secrets length ({}) must match matrix n ({})",
                secrets.0.len(),
                n
            )));
        }

        // Hash secrets into H(index, secret) form
        // Since secrets are already in H(aud, iss, sub) form,
        // the final result is H(index, H(aud, iss, sub))
        let mut hashed_secrets = Vec::with_capacity(n);
        for (i, &secret) in secrets.0.iter().enumerate() {
            let input = vec![F::from(i as u64), secret];
            let hash = CRH::<F>::evaluate(&pk.params, input)
                .map_err(|_| AnchorError::CryptoError("Hash failed".to_string()))?;
            hashed_secrets.push(hash);
        }

        // Matrix-vector multiplication: Anchor = Matrix * h
        let anchor_values = matrix.multiply_vector(&hashed_secrets)?;

        Ok(PoseidonAnchor::new(anchor_values))
    }

    fn generate_witness(
        pk: &Self::PublicKey,
        secrets: &Self::Secret,
        selector: &[u8],
        matrix: &Self::Matrix,
    ) -> Result<Self::Witness, AnchorError> {
        // Generate witness using the new helper function
        build_anchor_witness(&pk.params, &secrets.0, selector, matrix)
    }

    fn verify(anchor: &Self::Anchor, witness: &Self::Witness) -> Result<(), AnchorError> {
        // Verify: <a, Anchor> == <b, h_known>
        let lhs = Self::inner_product(&witness.a, &anchor.0)?;
        let rhs = Self::inner_product(&witness.b, &witness.h_known)?;

        if lhs == rhs {
            Ok(())
        } else {
            Err(AnchorError::VerificationFailed2)
        }
    }
}

// ==================== Utility Functions ====================

/// Optimized function for finding valid indices from an Anchor
///
/// Extracted from the original get_indices into a standalone function for clearer responsibility
pub fn find_valid_indices<F>(
    pk: &PoseidonAnchorPublicKey<F>,
    anchor: &PoseidonAnchor<F>,
    known_secrets: &PoseidonAnchorSecret<F>,
    matrix: &VandermondeMatrix<F>,
) -> Result<Vec<usize>, AnchorError>
where
    F: PrimeField + Absorb,
{
    let (n, k) = matrix.dimensions();
    // let m = n - k + 1;

    if known_secrets.0.len() != k {
        return Err(AnchorError::DimensionMismatch(format!(
            "Known secrets length ({}) must match k ({})",
            known_secrets.0.len(),
            k
        )));
    }

    // Optimization: hash secrets upfront for reuse
    let _hashed_cache = HashedSecretsCache::new(&pk.params, &known_secrets.0)?;

    // Generate all combinations of k from n indices
    let index_combinations = generate_combinations(n, k);

    // Try permutations for each combination
    for index_combo in index_combinations {
        let secret_permutations = generate_permutations(&known_secrets.0);

        for secret_perm in &secret_permutations {
            // Build selector
            let mut selector = vec![0; n];
            for &idx in &index_combo {
                selector[idx] = 1;
            }

            // Generate and verify witness (passing only known secrets)
            let permuted_known_secrets = PoseidonAnchorSecret(secret_perm.clone());
            let witness = PoseidonAnchorScheme::<F>::generate_witness(
                pk,
                &permuted_known_secrets,
                &selector,
                matrix,
            )?;

            if PoseidonAnchorScheme::<F>::verify(anchor, &witness).is_ok() {
                return Ok(index_combo);
            }
        }
    }

    Err(AnchorError::InvalidParameters(
        "No valid selector found".to_string(),
    ))
}

/// Generate all combinations of k elements chosen from n
fn generate_combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    if k > n {
        return vec![];
    }
    if k == 0 {
        return vec![vec![]];
    }
    if k == n {
        return vec![(0..n).collect()];
    }

    let mut result = Vec::new();
    let mut combination = vec![0; k];
    generate_combinations_helper(0, 0, n, k, &mut combination, &mut result);
    result
}

fn generate_combinations_helper(
    start: usize,
    depth: usize,
    n: usize,
    k: usize,
    combination: &mut Vec<usize>,
    result: &mut Vec<Vec<usize>>,
) {
    if depth == k {
        result.push(combination.clone());
        return;
    }

    for i in start..=(n - k + depth) {
        combination[depth] = i;
        generate_combinations_helper(i + 1, depth + 1, n, k, combination, result);
    }
}

/// Generate all permutations of a vector
fn generate_permutations<F: Clone>(items: &[F]) -> Vec<Vec<F>> {
    if items.is_empty() {
        return vec![vec![]];
    }
    if items.len() == 1 {
        return vec![items.to_vec()];
    }

    let mut result = Vec::new();
    for i in 0..items.len() {
        let mut remaining = items.to_vec();
        let current = remaining.remove(i);

        for mut perm in generate_permutations(&remaining) {
            perm.insert(0, current.clone());
            result.push(perm);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::matrix::VandermondeMatrix;

    use super::*;
    use ark_std::rand::thread_rng;

    type F = ark_bn254::Fr;
    type PAS = PoseidonAnchorScheme<F>;

    #[test]
    fn test_setup_v3() {
        let mut rng = thread_rng();
        let pk = PAS::setup(&mut rng, 6).unwrap();
        assert!(pk.params.alpha > 0);
    }

    #[test]
    fn test_hashed_secrets_cache() {
        let mut rng = thread_rng();
        let pk = PAS::setup(&mut rng, 6).unwrap();

        let secrets = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
        let cache = HashedSecretsCache::new(&pk.params, &secrets).unwrap();

        assert_eq!(cache.hashes.len(), 3);
        assert_ne!(cache.get(0).unwrap(), F::from(0u64));
    }

    #[test]
    fn test_generate_anchor_v3() {
        let mut rng = thread_rng();
        let n = 6;
        let k = 3;

        let pk = PAS::setup(&mut rng, n).unwrap();
        let matrix = VandermondeMatrix::<F>::new(n, k);

        let secrets = PoseidonAnchorSecret(vec![
            F::from(100u64),
            F::from(200u64),
            F::from(300u64),
            F::from(400u64),
            F::from(500u64),
            F::from(600u64),
        ]);

        let anchor = PAS::generate_anchor(&pk, &secrets, &matrix).unwrap();
        assert_eq!(anchor.0.len(), n - k + 1);
    }

    #[test]
    fn test_generate_witness_and_verify_v3() {
        let mut rng = thread_rng();
        let n = 6;
        let k = 3;

        let pk = PAS::setup(&mut rng, n).unwrap();
        let matrix = VandermondeMatrix::<F>::new(n, k);

        let all_secrets = vec![
            F::from(100u64),
            F::from(200u64),
            F::from(300u64),
            F::from(400u64),
            F::from(500u64),
            F::from(600u64),
        ];

        let secrets = PoseidonAnchorSecret(all_secrets.clone());
        let anchor = PAS::generate_anchor(&pk, &secrets, &matrix).unwrap();

        // selector: indices 1, 3, 4 are known
        let selector = vec![0, 1, 0, 1, 1, 0];

        // Extract known secrets
        let known_secrets: Vec<F> = selector
            .iter()
            .enumerate()
            .filter_map(|(i, &s)| if s == 1 { Some(all_secrets[i]) } else { None })
            .collect();
        let known_secrets = PoseidonAnchorSecret(known_secrets);

        let witness = PAS::generate_witness(&pk, &known_secrets, &selector, &matrix).unwrap();
        // Verify
        assert!(PAS::verify(&anchor, &witness).is_ok());
    }

    #[test]
    fn test_combinations_generation() {
        let combos = generate_combinations(4, 2);
        // C(4,2) = 6
        assert_eq!(combos.len(), 6);

        // Expected combinations
        assert!(combos.contains(&vec![0, 1]));
        assert!(combos.contains(&vec![2, 3]));
    }

    #[test]
    fn test_permutations_generation() {
        let items = vec![1, 2, 3];
        let perms = generate_permutations(&items);
        // 3! = 6
        assert_eq!(perms.len(), 6);
    }
}
