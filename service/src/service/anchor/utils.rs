use std::marker::PhantomData;

use ark_crypto_primitives::{crh::CRHScheme, sponge::Absorb};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use gadget::anchor::dl::DLAnchor;
use gadget::anchor::poseidon::PoseidonAnchor;
use gadget::anchor::{dl::DLAnchorSecret, poseidon::PoseidonAnchorSecret};
use num::BigUint;
use num::Integer;

use crate::utils::point::{FromDecimalCoords, str_to_field};
use crate::{error::error::ApplicationError, interface::anchor::SecretDto};

impl SecretDto {
    pub fn concatenate(
        &self,
        target_len: (usize, usize, usize),  
        pad_char: char,
    ) -> Result<String, ApplicationError> {

        let (aud_len, iss_len, sub_len) = target_len;

        let aud_processed = match &self.aud {
            Some(s) => Self::pad(s, aud_len, pad_char)?,
            None => String::new(),
        };

        let iss_processed = match &self.iss {
            Some(s) => Self::pad(s, iss_len, pad_char)?,
            None => String::new(),
        };

        let sub_processed = match &self.sub {
            Some(s) => Self::pad(s, sub_len, pad_char)?,
            None => String::new(),
        };

        let final_string = [aud_processed, iss_processed, sub_processed].concat();

        Ok(final_string)
    }

    fn pad(s: &str, target_len: usize, pad_char: char) -> Result<String, ApplicationError> {
        if s.len() > target_len {
            return Err(ApplicationError::InvalidFormat(format!(
                "String length exceeds target length: {} > {}",
                s.len(),
                target_len
            )));
        }

        let mut result = String::with_capacity(target_len);
        result.push_str(s);
        let pad_needed = target_len - s.len();
        result.extend(std::iter::repeat(pad_char).take(pad_needed));

        Ok(result)
    }
}

pub trait ConcatenateSecrets {
    type Output;

    fn concatenate(
        &self,
        target_len: (usize, usize, usize), // (aud_len, iss_len, sub_len)
        pad_char: char,
    ) -> Result<Vec<String>, ApplicationError>;
}

impl ConcatenateSecrets for [SecretDto] {
    type Output = Vec<String>;

    fn concatenate(
        &self,
        target_len: (usize, usize, usize), // (aud_len, iss_len, sub_len)
        pad_char: char,
    ) -> Result<Self::Output, ApplicationError> {
        self.iter()
            .map(|s| s.concatenate(target_len, pad_char))
            .collect()
    }
}

pub trait MessageToHashes<F, CRH>
where
    F: PrimeField + Absorb,
    CRH: CRHScheme<Input = [F], Output = F>,
{
    type Output;

    fn to_hashes(&self, hash_params: &CRH::Parameters) -> Result<Self::Output, ApplicationError>;
}

impl<F, CRH, S> MessageToHashes<F, CRH> for [S]
where
    F: PrimeField + Absorb,
    CRH: CRHScheme<Input = [F], Output = F>,
    S: AsRef<str>,
{
    type Output = Vec<F>;

    fn to_hashes(&self, hash_params: &CRH::Parameters) -> Result<Self::Output, ApplicationError> {
        self.iter()
            .map(|s| hash_message_to_field::<F, CRH>(s.as_ref(), hash_params))
            .collect()
    }
}

fn hash_message_to_field<F, CRH>(
    message: &str,
    hash_params: &<CRH as CRHScheme>::Parameters,
) -> Result<F, ApplicationError>
where
    F: PrimeField + Absorb,
    CRH: CRHScheme<Input = [F], Output = F>,
{
    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;

    if message.len() % limb_width != 0 {
        return Err(ApplicationError::InvalidFormat(format!(
            "String length must be a multiple of limb width: {} % {} != 0",
            message.len(),
            limb_width
        )));
    }

    let num_limbs = message.len() / limb_width;
    let mut limbs = Vec::with_capacity(num_limbs);

    for chunk in message.as_bytes().chunks_exact(limb_width) {
        limbs.push(F::from_be_bytes_mod_order(chunk));
    }

    let h =
        CRH::evaluate(&hash_params, limbs).map_err(|e| ApplicationError::Other(e.to_string()))?;
    println!("hashed field: {:?}", h);
    Ok(h)
}

pub trait SecretGenerator {
    type InputField: PrimeField;
    type Output;

    fn generate_secrets(input: Vec<Self::InputField>) -> Result<Self::Output, ApplicationError>;
}

pub struct PoseidonSecretGenerator<F: PrimeField>(PhantomData<F>);

impl<F: PrimeField> SecretGenerator for PoseidonSecretGenerator<F> {
    type InputField = F;
    type Output = PoseidonAnchorSecret<F>;

    fn generate_secrets(input: Vec<Self::InputField>) -> Result<Self::Output, ApplicationError> {
        Ok(input.into())
    }
}

pub struct DLSecretGenerator<C: CurveGroup>(PhantomData<C>);

impl<C: CurveGroup> SecretGenerator for DLSecretGenerator<C>
where
    C::BaseField: PrimeField,
{
    type InputField = C::BaseField;
    type Output = (DLAnchorSecret<C>, Vec<C::BaseField>);

    fn generate_secrets(input: Vec<Self::InputField>) -> Result<Self::Output, ApplicationError> {
        let modulus_bigint = C::ScalarField::MODULUS.into();

        let collected_result = input
            .into_iter()
            .map(|i| {
                let i_bigint: BigUint = i.into_bigint().into();
                let (q_bigint, r_bigint) = i_bigint.div_rem(&modulus_bigint);

                let p = C::BaseField::from(q_bigint);
                let s = C::ScalarField::from(r_bigint);

                Ok::<_, ApplicationError>((p, s))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let (p_vec, s_vec): (Vec<C::BaseField>, Vec<C::ScalarField>) =
            collected_result.into_iter().unzip();

        Ok((s_vec.into(), p_vec))
    }
}

// TODO: 고아(orphan) 규칙 해결해야함. 맘에 들진 않음.
pub struct AppPoseidonAnchor<F: PrimeField>(pub PoseidonAnchor<F>);

impl<F: PrimeField> TryFrom<Vec<String>> for AppPoseidonAnchor<F> {
    type Error = ApplicationError;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let anchor = value
            .iter()
            .map(|a| str_to_field(a))
            .collect::<Result<Vec<F>, _>>()
            .map_err(|e| {
                ApplicationError::InvalidFormat(format!(
                    "Failed to parse anchor from string: {:?}",
                    e
                ))
            })?;
        Ok(AppPoseidonAnchor(PoseidonAnchor(anchor)))
    }
}

pub struct AppDLAnchor<C: CurveGroup>(pub DLAnchor<C>);

impl<C> TryFrom<Vec<String>> for AppDLAnchor<C>
where
    C: CurveGroup,
    C::Affine: FromDecimalCoords,
{
    type Error = ApplicationError;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let points = value
            .chunks(2)
            .map(|pair| {
                C::Affine::from_decimal_coords(&pair[0], &pair[1])
                    .map_err(|e| ApplicationError::InvalidFormat(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(AppDLAnchor(DLAnchor(points)))
    }
}
