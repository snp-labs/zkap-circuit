use ark_ff::PrimeField;
use gadget::anchor::{error::AnchorError, poseidon::PoseidonAnchor};

use crate::utils::point::{FromStrings, str_to_field};

impl<F> FromStrings for PoseidonAnchor<F>
where
    F: PrimeField,
{
    type Err = AnchorError;

    fn from_strings(strings: &[String]) -> Result<Self, Self::Err> {
        let anchor = strings
            .iter()
            .map(|s| {
                str_to_field::<F>(s).map_err(|e| {
                    AnchorError::InvalidParameters(format!(
                        "Failed to parse anchor element from `{}`: {:?}",
                        s, e
                    ))
                })
            })
            .collect::<Result<Vec<F>, AnchorError>>()?;

        Ok(PoseidonAnchor(anchor))
    }
}
