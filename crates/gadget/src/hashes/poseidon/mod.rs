//! Poseidon hash scheme — native evaluation and circuit gadgets.
//!
//! Re-exports [`get_poseidon_params`] from [`parameters`] for constructing the
//! `PoseidonConfig` used throughout the codebase (full_rounds=8, partial_rounds=57,
//! width t=3, alpha=5, over BN254-Fr). Circuit-level helpers
//! (`poseidon_chain_hash`, `chain_hash_gadget`) live in [`constraints`].

use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ff::PrimeField;

use crate::hashes::error::HashError;

#[cfg(feature = "constraints")]
pub mod constraints;
pub mod parameters;
pub use parameters::*;

/// Sequential native Poseidon chain hash:
/// `H(values[0])`, then `H(previous, values[i])`.
pub fn chain_hash<F: PrimeField + Absorb>(
    params: &PoseidonConfig<F>,
    values: &[F],
) -> Result<F, HashError> {
    if values.is_empty() {
        return Err(HashError::InvalidInputLength(
            "chain_hash requires at least one value".into(),
        ));
    }

    let mut hash = CRH::<F>::evaluate(params, [values[0]])
        .map_err(|e| HashError::NativeHashError(format!("Poseidon chain[0]: {e}")))?;
    for value in &values[1..] {
        hash = CRH::<F>::evaluate(params, [hash, *value])
            .map_err(|e| HashError::NativeHashError(format!("Poseidon chain[i]: {e}")))?;
    }
    Ok(hash)
}

/// Native output-binding mask for a full-n index:
/// `Poseidon(random, index)`.
pub fn output_mask_for_index<F: PrimeField + Absorb>(
    params: &PoseidonConfig<F>,
    random: F,
    index: usize,
) -> Result<F, HashError> {
    CRH::<F>::evaluate(params, [random, F::from(index as u64)])
        .map_err(|e| HashError::NativeHashError(format!("output_mask[{index}]: {e}")))
}

/// Sum native output-binding masks selected by a `0/1` selector vector.
pub fn selected_output_mask_sum<F: PrimeField + Absorb>(
    params: &PoseidonConfig<F>,
    random: F,
    selector: &[u8],
) -> Result<F, HashError> {
    let mut sum = F::zero();
    for (index, &selected) in selector.iter().enumerate() {
        if selected == 1 {
            sum += output_mask_for_index(params, random, index)?;
        }
    }
    Ok(sum)
}

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
#[allow(missing_docs)] // test-only fixtures; doc strings would just rename the test
pub mod test {
    use ark_bn254::Fr;
    use ark_crypto_primitives::crh::{CRHScheme, poseidon::CRH as PoseidonCRH};
    use std::str::FromStr;

    use crate::hashes::poseidon::get_poseidon_params;

    #[test]
    pub fn test_poseidon() {
        let leaf_hash_params = get_poseidon_params::<Fr>();
        let input = Fr::from(100);
        let digest = PoseidonCRH::<Fr>::evaluate(&leaf_hash_params, [input]).unwrap();
        let digest = digest.to_string();
        assert_eq!(
            digest,
            "8944019647207395670152171990872402962551728342430253464486678728119110275152"
        )
    }

    #[test]
    pub fn test_many_hash() {
        let leaves = [
            "60793721438829799575534163104126076495587489642262739664087223161206222896",
            "60793721438829799575534163104126076495587489642262739664087223161206222896",
            "60793721438829799575534163104126076495587489642262739664087223161206222896",
        ];
        let leaves: Vec<Fr> = leaves.iter().map(|s| Fr::from_str(s).unwrap()).collect();
        let leaf_hash_params = get_poseidon_params::<Fr>();

        let mut h = PoseidonCRH::<Fr>::evaluate(&leaf_hash_params, [leaves[0]]).unwrap();

        for i in 1..leaves.len() {
            h = PoseidonCRH::<Fr>::evaluate(&leaf_hash_params, [h, leaves[i]]).unwrap();
        }
        h = PoseidonCRH::<Fr>::evaluate(&leaf_hash_params, [h]).unwrap();
        println!("Root hash: {}", h);
    }

    #[test]
    pub fn test_hash() {
        let leaves = [
            "60793721438829799575534163104126076495587489642262739664087223161206222896",
            "60793721438829799575534163104126076495587489642262739664087223161206222896",
            "60793721438829799575534163104126076495587489642262739664087223161206222896",
            "12738870951415276049062767805433219702194951383956200739430068538544166999224",
            "12932658665784486555807202865248436514059137724840085341182132917788957941347",
            "20836012989568854622804471791402266091062098710643900233695847467340732046972",
            "14698986519339806236451828659463247489511792067292951493919069774546638612878",
            "1287170156102302074840494793956183776840409400324345031251779766468878108513",
        ];

        let leaves: Vec<Fr> = leaves.iter().map(|s| Fr::from_str(s).unwrap()).collect();

        let leaf_hash_params = get_poseidon_params::<Fr>();

        let h = PoseidonCRH::<Fr>::evaluate(&leaf_hash_params, [leaves[0], leaves[1], leaves[2]])
            .unwrap();
        println!("First leaf hash: {}", h);
    }

    #[test]
    pub fn native_chain_hash_matches_explicit_recipe() {
        let params = get_poseidon_params::<Fr>();
        let values = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let expected_1 = PoseidonCRH::<Fr>::evaluate(&params, [values[0]]).unwrap();
        let expected_2 = PoseidonCRH::<Fr>::evaluate(&params, [expected_1, values[1]]).unwrap();
        let expected_3 = PoseidonCRH::<Fr>::evaluate(&params, [expected_2, values[2]]).unwrap();

        let actual = super::chain_hash(&params, &values).unwrap();
        assert_eq!(actual, expected_3);
    }

    #[test]
    pub fn selected_output_mask_sum_matches_explicit_masks() {
        let params = get_poseidon_params::<Fr>();
        let random = Fr::from(123u64);
        let selector = [1, 0, 1, 1];

        let expected = super::output_mask_for_index(&params, random, 0).unwrap()
            + super::output_mask_for_index(&params, random, 2).unwrap()
            + super::output_mask_for_index(&params, random, 3).unwrap();

        let actual = super::selected_output_mask_sum(&params, random, &selector).unwrap();
        assert_eq!(actual, expected);
    }
}
