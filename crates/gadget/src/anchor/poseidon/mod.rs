//! Poseidon-based instantiation of the threshold anchor scheme.
//!
//! Provides [`PoseidonAnchorScheme`] and the [`build_anchor_witness`] function which
//! constructs the Vandermonde witness from a set of `k`-of-`n` secrets. Invariants:
//! the selector cardinality must equal `k`, and the secrets slice must have length `n`.
//! [`HashedSecretsCache`] stores pre-hashed secrets to avoid redundant hash evaluations.

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
    /// Wraps `values` as a [`PoseidonAnchor`]; the caller must ensure
    /// `values.len() == m` where `m = n − k + 1`.
    pub fn new(values: Vec<F>) -> Self {
        Self(values)
    }

    /// Returns an all-zero anchor of the given `size`; used to allocate
    /// placeholder witnesses before values are computed.
    pub fn empty(size: usize) -> Self {
        Self(vec![F::zero(); size])
    }
}

/// Poseidon Anchor public key
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonAnchorPublicKey<F: PrimeField> {
    /// Fixed Poseidon configuration (MDS matrix + round constants) shared by both
    /// native and in-circuit evaluation; produced once by
    /// [`crate::hashes::poseidon::get_poseidon_params`].
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
    /// Returns an all-zero witness for an `(n, k)` scheme; used to allocate
    /// placeholder witnesses where `m = n − k + 1` determines vector lengths.
    pub fn empty(n: usize, k: usize) -> Self {
        let m = n - k + 1;
        Self {
            a: vec![F::zero(); m],
            b: vec![F::zero(); n],
            h_known: vec![F::zero(); n],
        }
    }

    /// Compute partial RHS for split proof.
    /// `partial_rhs[i] = b[i] * h_known[i]`
    pub fn compute_partial_rhs(&self) -> Vec<F> {
        self.b
            .iter()
            .zip(self.h_known.iter())
            .map(|(b_i, h_i)| *b_i * *h_i)
            .collect()
    }
}

// ==================== Utility Functions ====================

/// Helper function for building a Witness.
///
/// This function computes `h_known` in the same way as the circuit:
/// `h_known[i] = H(i, secret[hash_idx])` where `selector[i] == 1`.
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
    /// Hash values for each entry (H(full-n-position, secret)), one per selected secret.
    pub hashes: Vec<F>,
}

impl<F: PrimeField + Absorb> HashedSecretsCache<F> {
    /// Create a cache of `H(full_n_position, secret)` for each `(position, secret)` pair.
    ///
    /// **Indices are full-n positions (matching [`build_anchor_witness`]), NOT k-subset
    /// positions.** `positions[i]` must be the position of `secrets[i]` within the
    /// full n-vector, i.e. the index that appears in the circuit's `H(current_idx, secret)`
    /// computation.
    ///
    /// # Safety invariant (§4.2 / M-2)
    /// Before this fix, `new` used the k-subset enumeration index (0, 1, 2, …) as the
    /// hash preimage. `build_anchor_witness` uses the full-n selector position. The two
    /// conventions diverge for any selected index beyond the first (position > 0 in the
    /// full vector). Full-n position is adopted as the single truth source so that caches
    /// and witnesses are always interchangeable.
    pub fn new(
        params: &PoseidonConfig<F>,
        positions: &[usize],
        secrets: &[F],
    ) -> Result<Self, AnchorError> {
        if positions.len() != secrets.len() {
            return Err(AnchorError::DimensionMismatch(format!(
                "positions length ({}) must match secrets length ({})",
                positions.len(),
                secrets.len()
            )));
        }

        let hashes = positions
            .iter()
            .zip(secrets.iter())
            .map(|(&pos, &secret)| {
                // H(full-n-position, secret) — same convention as build_anchor_witness
                let input = vec![F::from(pos as u64), secret];
                CRH::<F>::evaluate(params, input)
                    .map_err(|_| AnchorError::CryptoError("Hash failed".to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { hashes })
    }

    /// Get the hash value for the `index`-th entry in the cache (0-based into the
    /// internal array, not a full-n position).
    pub fn get(&self, index: usize) -> Option<F> {
        self.hashes.get(index).copied()
    }

    /// Build the h_known vector according to selector.
    ///
    /// Places each cached `H(full-n-position, secret)` at the corresponding selector-1
    /// position in the output, producing the same `h_known` layout as
    /// [`build_anchor_witness`].
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

/// Concrete implementation of [`crate::anchor::AnchorScheme`] using Poseidon CRH over BN254-Fr.
///
/// The field type `F` is parameterised so tests can substitute a smaller field;
/// production callers use `ark_bn254::Fr`. All hash evaluations use the fixed
/// parameters from [`crate::hashes::poseidon::get_poseidon_params`].
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
    /// Build the Poseidon public key. The Poseidon CRH parameters used by
    /// this scheme are universal (BN254-Fr, fixed rate/capacity), so the
    /// resulting [`PoseidonAnchorPublicKey`] is intentionally independent
    /// of both `rng` and the anchor width `n`. The `n` argument is
    /// validated to keep callers from masking a logic error.
    fn setup<R: Rng>(_rng: &mut R, n: usize) -> Result<Self::PublicKey, AnchorError> {
        if n == 0 {
            return Err(AnchorError::InvalidParameters(
                "n must be > 0 for a Poseidon anchor scheme".to_string(),
            ));
        }
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
            Err(AnchorError::VerificationFailed)
        }
    }
}

// ==================== Utility Functions ====================

/// Generate all `k`-element index subsets of `0..n` in lexicographic order.
///
/// Single source of truth for host-side `C(n, k)` enumeration across the
/// workspace. Previously this logic was duplicated in
/// `service::anchor::poseidon` (for `derive_selector_from_x_list_and_anchor`)
/// and in `circuit/tests/groth16_integration.rs`; both call sites now route
/// through this `pub` entry point.
///
/// Returns `vec![]` if `k > n`, `vec![vec![]]` if `k == 0`, and the single
/// `(0..n)` tuple if `k == n`.
pub fn generate_combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
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

#[cfg(test)]
#[allow(clippy::upper_case_acronyms)]
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

        // Use full-n positions [2, 4, 5] for a k=3 subset of n=6
        let positions = vec![2usize, 4, 5];
        let secrets = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
        let cache = HashedSecretsCache::new(&pk.params, &positions, &secrets).unwrap();

        assert_eq!(cache.hashes.len(), 3);
        assert_ne!(cache.get(0).unwrap(), F::from(0u64));
    }

    /// Regression guard for §4.2 / M-2: cache and `build_anchor_witness` must produce
    /// identical `H(full-n-position, secret)` values for every selected index.
    #[test]
    fn test_hashed_secrets_cache_matches_build_anchor_witness() {
        let mut rng = thread_rng();
        let n = 6;
        let k = 3;

        let pk = PAS::setup(&mut rng, n).unwrap();
        let matrix = VandermondeMatrix::<F>::new(n, k);

        // Full n-vector of secrets
        let all_secrets: Vec<F> = (1u64..=6).map(F::from).collect();

        // selector: positions 1, 3, 4 are selected (full-n indices)
        let selector: Vec<u8> = vec![0, 1, 0, 1, 1, 0];
        let selected_positions: Vec<usize> = selector
            .iter()
            .enumerate()
            .filter_map(|(i, &s)| if s == 1 { Some(i) } else { None })
            .collect();
        let selected_secrets: Vec<F> = selected_positions.iter().map(|&p| all_secrets[p]).collect();

        // Build cache with full-n positions
        let cache =
            HashedSecretsCache::new(&pk.params, &selected_positions, &selected_secrets).unwrap();

        // Independently compute H(full-n-position, secret) for each selected entry
        for (idx, (&pos, &secret)) in selected_positions
            .iter()
            .zip(selected_secrets.iter())
            .enumerate()
        {
            let expected =
                CRH::<F>::evaluate(&pk.params, vec![F::from(pos as u64), secret]).unwrap();
            assert_eq!(
                cache.get(idx).unwrap(),
                expected,
                "cache hash mismatch at k-index={idx}, full-n-pos={pos}"
            );
        }

        // Build witness via build_anchor_witness (full-n convention)
        let witness =
            build_anchor_witness(&pk.params, &selected_secrets, &selector, &matrix).unwrap();

        // The h_known entries at selector-1 positions must equal the cache entries
        let mut cache_idx = 0;
        for (i, &s) in selector.iter().enumerate() {
            if s == 1 {
                assert_eq!(
                    witness.h_known[i],
                    cache.get(cache_idx).unwrap(),
                    "h_known[{i}] from build_anchor_witness != cache entry {cache_idx}"
                );
                cache_idx += 1;
            }
        }
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
}
