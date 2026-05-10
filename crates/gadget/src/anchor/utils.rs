//! Native helper functions for secret processing and scalar-modulus arithmetic.
//!
//! Available only under the `rsa` feature. Contains helpers for converting string secrets
//! to field elements (`process_secret*`), dividing BaseField values by the ScalarField
//! modulus (`divide_by_scalar_modulus`), and combinatorial utilities (`combinations`,
//! `permute`). These are native (non-circuit) functions and have no R1CS impact.
//!
//! **Deprecation notice**: all public functions in this module have no internal callers
//! and are slated for removal in the next release after external-grep confirmation.
//!
//! TODO: once the workspace-external grep (snp-labs/zkap-circuit's downstreams,
//! baerae-zkap/zkap-zkp) confirms zero callsites for any of these 10 functions,
//! delete this whole module wholesale rather than maintaining its docs (Phase 8
//! critic MINOR #4 follow-up). Until then `#![allow(missing_docs)]` below means
//! we don't gate the workspace-wide `missing_docs = "warn"` flip on writing
//! fresh docs for items that are about to disappear.

// Phase 9 P9-anchor-utils-cleanup option (b) — see TODO in module-level
// `//!` doc above. The H5-staged-4 sweep (Phase 8 `c630dd78`) added fresh
// doc strings to all 10 deprecated public fns to clear the missing_docs
// gate; those docs remain (deletion churn isn't worth it before the
// upstream removal grep), but new items added here do not need to satisfy
// the workspace `missing_docs = "warn"` lint.
#![allow(missing_docs)]

use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use num::BigUint;
use num_integer::Integer;

use ark_utils::try_str_to_fields;

use crate::anchor::error::AnchorError;

/// Hashes and divides each secret in `secrets`, returning `(BaseField, ScalarField)` pairs.
///
/// Each secret string is first decomposed into `BaseField` chunks via [`try_str_to_fields`],
/// then hashed with the provided CRH parameters, and finally divided by the ScalarField modulus
/// to produce a `(quotient, remainder)` pair. The remainder is the value used as the circuit
/// witness scalar.
///
/// Deprecated: no internal callers; see module-level deprecation notice.
#[deprecated(note = "no internal callers — slated for removal next release after external grep")]
#[allow(clippy::type_complexity)]
#[allow(deprecated)]
pub fn process_secrets_vec<C, CRH>(
    secrets: &[String],
    hash_param: &<CRH as CRHScheme>::Parameters,
) -> Result<(Vec<C::BaseField>, Vec<C::ScalarField>), AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CRH: CRHScheme<
            Input = [C::BaseField],
            Output = C::BaseField,
            Parameters = PoseidonConfig<C::BaseField>,
        >,
{
    // 1. Access each element of the vector using `iter()`.
    // 2. Call `process_secret` for each secret using `map()`.
    //    This step produces an iterator of `Result<(Q, R), Error>` values.
    let results_iterator = secrets
        .iter()
        .map(|s| process_secret::<C, CRH>(s, hash_param));

    // 3. Use `collect::<Result<Vec<_>, _>>()` to combine all Result values into one Result.
    //    - If all elements are Ok, returns `Ok(Vec<(Q, R)>)`.
    //    - If any element is Err, returns that `Err` immediately.
    let collected_results: Vec<(C::BaseField, C::ScalarField)> =
        results_iterator.collect::<Result<_, _>>()?;

    // 4. Use `unzip()` to convert a `Vec<(Q, R)>` into a `(Vec<Q>, Vec<R>)` tuple.
    let (q_fields, r_fields): (Vec<_>, Vec<_>) = collected_results.into_iter().unzip();

    Ok((q_fields, r_fields))
}

/// Hashes a single secret string and divides the hash output by the ScalarField modulus.
///
/// Steps: convert `secret` to `BaseField` chunks, CRH-hash them, then perform
/// `(quotient, remainder) = hash_output / ScalarField::MODULUS`. The remainder
/// is the value carried as the circuit secret witness.
///
/// Deprecated: no internal callers; see module-level deprecation notice.
#[deprecated(note = "no internal callers — slated for removal next release after external grep")]
#[allow(deprecated)]
pub fn process_secret<C, CRH>(
    secret: &str,
    hash_param: &<CRH as CRHScheme>::Parameters,
) -> Result<(C::BaseField, C::ScalarField), AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CRH: CRHScheme<
            Input = [C::BaseField],
            Output = C::BaseField,
            Parameters = PoseidonConfig<C::BaseField>,
        >,
{
    let secret = try_str_to_fields::<C::BaseField>(secret)
        .map_err(|e| AnchorError::InvalidParameters(e.to_string()))?;
    let (q, r) = hash_and_divide_by_scalar_modulus::<C, CRH>(&secret, hash_param)?;

    let q_field = <C::BaseField as PrimeField>::from_le_bytes_mod_order(&q);
    let r_field = <C::ScalarField as PrimeField>::from_le_bytes_mod_order(&r);

    Ok((q_field, r_field))
}

/// Convenience wrapper: hash each secret in `secrets` with the Poseidon CRH and return
/// a flat `Vec<BaseField>` (no modular division). Calls `process_no_tk_secrets` internally.
///
/// Deprecated: no internal callers; see module-level deprecation notice.
#[deprecated(note = "no internal callers — slated for removal next release after external grep")]
#[allow(deprecated)]
pub fn process_secrets_poseidon<C>(
    secrets: &[String],
    poseidon_param: &PoseidonConfig<C::BaseField>,
) -> Result<Vec<C::BaseField>, AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    process_no_tk_secrets::<C, CRH<C::BaseField>>(secrets, poseidon_param)
}

/// Maps each secret string in `secrets` through `process_no_tk_secret` and collects the
/// resulting `BaseField` hashes. Fails on the first invalid character or hash error.
///
/// Deprecated: no internal callers; see module-level deprecation notice.
#[deprecated(note = "no internal callers — slated for removal next release after external grep")]
#[allow(deprecated)]
pub fn process_no_tk_secrets<C, CRH>(
    secrets: &[String],
    hash_param: &CRH::Parameters,
) -> Result<Vec<C::BaseField>, AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CRH: CRHScheme<Input = [C::BaseField], Output = C::BaseField>,
{
    secrets
        .iter()
        .map(|s| process_no_tk_secret::<C, CRH>(s, hash_param))
        .collect()
}

/// Converts `secret` to `BaseField` chunks, then hashes them with the given CRH, returning
/// a single `BaseField` element. This is the "no token-key" variant: no modular division.
///
/// Deprecated: no internal callers; see module-level deprecation notice.
#[deprecated(note = "no internal callers — slated for removal next release after external grep")]
pub fn process_no_tk_secret<C, CRH>(
    secret: &str,
    hash_param: &CRH::Parameters,
) -> Result<C::BaseField, AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    CRH: CRHScheme<Input = [C::BaseField], Output = C::BaseField>,
{
    let secret = try_str_to_fields::<C::BaseField>(secret)
        .map_err(|e| AnchorError::InvalidParameters(e.to_string()))?;
    let secret = CRH::evaluate(hash_param, &*secret)
        .map_err(|e| AnchorError::CryptoError(format!("Hash failed: {}", e)))?;

    Ok(secret)
}

/// Divides a `BaseField` element `a` by the `ScalarField` modulus, returning
/// `(quotient_le_bytes, remainder_le_bytes)` as little-endian byte vectors.
///
/// Deprecated: no internal callers; see module-level deprecation notice.
#[deprecated(note = "no internal callers — slated for removal next release after external grep")]
pub fn divide_by_scalar_modulus<C: CurveGroup>(a: C::BaseField) -> (Vec<u8>, Vec<u8>)
where
    C::BaseField: PrimeField,
{
    let modulus = C::ScalarField::MODULUS;
    let modulus = BigUint::from_bytes_le(&modulus.to_bytes_le());

    let a_bigint = BigUint::from_bytes_le(&a.into_bigint().to_bytes_le());

    let (q, r) = a_bigint.div_rem(&modulus);

    (q.to_bytes_le(), r.to_bytes_le())
}

/// Hashes `elements_to_hash` with the CRH, then divides the `BaseField` output by the
/// `ScalarField` modulus, returning `(quotient_le_bytes, remainder_le_bytes)`.
///
/// Deprecated: no internal callers; see module-level deprecation notice.
#[deprecated(note = "no internal callers — slated for removal next release after external grep")]
#[allow(deprecated)]
pub fn hash_and_divide_by_scalar_modulus<C, CRH>(
    elements_to_hash: &[C::BaseField],
    crh_parameters: &CRH::Parameters,
) -> Result<(Vec<u8>, Vec<u8>), AnchorError>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    CRH: CRHScheme<Input = [C::BaseField], Output = C::BaseField>,
{
    // 2. Hash the converted elements.
    let hash_output = CRH::evaluate(crh_parameters, elements_to_hash)
        .map_err(|e| AnchorError::CryptoError(format!("Hash failed: {}", e)))?;

    // 3. Convert the hash result (BaseField) to the target ScalarField type.
    let (q, r) = divide_by_scalar_modulus::<C>(hash_output);

    // 4. Return the result.
    Ok((q, r))
}

/// Multiplies `a * b` in the `ScalarField`, then divides the product by the `ScalarField` modulus,
/// returning `(product_le_bytes, quotient_le_bytes, remainder_le_bytes)`.
///
/// Deprecated: no internal callers; see module-level deprecation notice.
#[deprecated(note = "no internal callers — slated for removal next release after external grep")]
pub fn mul_and_divide_by_scalar_modulus<C: CurveGroup>(
    a: C::ScalarField,
    b: C::ScalarField,
) -> (Vec<u8>, Vec<u8>, Vec<u8>)
where
    C::BaseField: PrimeField,
{
    let modulus = C::ScalarField::MODULUS;
    let modulus = BigUint::from_bytes_le(&modulus.to_bytes_le());

    let a_bigint = BigUint::from_bytes_le(&a.into_bigint().to_bytes_le());
    let b_bigint = BigUint::from_bytes_le(&b.into_bigint().to_bytes_le());

    let product = a_bigint * b_bigint;
    let (q, r) = product.div_rem(&modulus);

    (product.to_bytes_le(), q.to_bytes_le(), r.to_bytes_le())
}

/// Byte-slice variant of [`mul_and_divide_by_scalar_modulus`]: decodes `a` and `b` as
/// little-endian `ScalarField` elements first, then delegates to the field-element version.
///
/// Deprecated: no internal callers; see module-level deprecation notice.
#[deprecated(note = "no internal callers — slated for removal next release after external grep")]
#[allow(deprecated)]
pub fn mul_and_divide_by_scalar_modulus_bytes<C: CurveGroup>(
    a: &[u8],
    b: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>)
where
    C::BaseField: PrimeField,
{
    let a_field = C::ScalarField::from_le_bytes_mod_order(a);
    let b_field = C::ScalarField::from_le_bytes_mod_order(b);
    mul_and_divide_by_scalar_modulus::<C>(a_field, b_field)
}

/// Generates all `C(n, k)` combinations as sorted index vectors.
///
/// Returns an empty `Vec` when `k == 0` or `k > n`. Implemented via the
/// standard revolving-door algorithm. Used by `find_valid_indices` to
/// enumerate candidate selector patterns exhaustively.
///
/// Deprecated: no internal callers; see module-level deprecation notice.
// nCk combination generator
#[deprecated(note = "no internal callers — slated for removal next release after external grep")]
pub fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
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

/// Helper function to generate all permutations of k elements
#[deprecated(note = "no internal callers — slated for removal next release after external grep")]
pub fn permute<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.is_empty() {
        return vec![vec![]];
    }
    let mut result = Vec::new();
    let n = items.len();
    let mut p: Vec<usize> = (0..=n).collect();
    let mut items_clone = items.to_vec();

    result.push(items_clone.clone());

    let mut i = 1;
    while i < n {
        p[i] -= 1;
        let j = if i % 2 == 1 { p[i] } else { 0 };
        items_clone.swap(i, j);
        result.push(items_clone.clone());
        i = 1;
        while i < n && p[i] == 0 {
            p[i] = i;
            i += 1;
        }
    }
    result
}
