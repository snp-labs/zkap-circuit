use ark_ff::PrimeField;

use crate::error::UtilError;

pub trait ToField<F: PrimeField> {
    type Output;

    fn to_fields(&self) -> Result<Self::Output, UtilError>;
}

impl<F: PrimeField> ToField<F> for &str {
    type Output = Vec<F>;

    fn to_fields(&self) -> Result<Self::Output, UtilError> {
        let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;
        let mut bytes = self.as_bytes().to_vec();
        let n_limbs = (bytes.len() + (limb_width - 1)) / limb_width;
        bytes.resize(n_limbs * limb_width, b'0');
        bytes
            .chunks(limb_width)
            .map(|chunk| {
                let field_elem = F::from_be_bytes_mod_order(chunk);
                Ok(field_elem)
            })
            .collect()
    }
}

impl<F: PrimeField> ToField<F> for [&str] {
    type Output = Vec<F>;

    fn to_fields(&self) -> Result<Self::Output, UtilError> {
        self.iter()
            .map(|s| F::from_str(s).map_err(|_| UtilError::ConversionError))
            .collect()
    }
}

impl<F: PrimeField> ToField<F> for [usize] {
    type Output = Vec<F>;

    fn to_fields(&self) -> Result<Self::Output, UtilError> {
        self.iter().map(|&s| Ok(F::from(s as u64))).collect()
    }
}

impl<F: PrimeField> ToField<F> for &String {
    type Output = F;

    fn to_fields(&self) -> Result<Self::Output, UtilError> {
        let bytes = self.as_bytes();
        Ok(F::from_be_bytes_mod_order(bytes))
    }
}

impl<F: PrimeField> ToField<F> for Vec<&String> {
    type Output = Vec<F>;

    fn to_fields(&self) -> Result<Self::Output, UtilError> {
        self.iter()
            .map(|s| {
                let bytes = s.as_bytes();
                Ok(F::from_be_bytes_mod_order(bytes))
            })
            .collect()
    }
}

pub fn str_to_packed_field<F: PrimeField>(
    str: &str,
    pad_char: u8,
    max_claim_len: usize,
) -> Result<Vec<F>, UtilError> {
    let mut bytes = str.as_bytes().to_vec();
    bytes.resize(max_claim_len, pad_char);
    let bytes_string = String::from_utf8(bytes).map_err(|_| UtilError::ConversionError)?;
    let result = bytes_string.as_str().to_fields()?;
    Ok(result)
}

pub fn str_to_fields<F: PrimeField>(s: &str) -> Vec<F> {
    let bytes = s.as_bytes();

    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;
    let n_limbs = (bytes.len() + (limb_width - 1)) / limb_width;
    let expected_length = n_limbs * limb_width;

    assert_eq!(bytes.len(), expected_length);

    bytes
        .chunks(limb_width)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect()
}

pub fn str_to_limbs<F: PrimeField>(s: &str, target_len: usize, pad: u8) -> Vec<F> {
    let mut bytes = s.as_bytes().to_vec();
    bytes.resize(target_len, pad);

    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;
    let n_limbs = (bytes.len() + (limb_width - 1)) / limb_width;
    let expected_length = n_limbs * limb_width;

    assert_eq!(bytes.len(), expected_length);

    bytes
        .chunks(limb_width)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect()
}

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar, fields::fp::FpVar};

    use crate::{ToField, pack_byte_fps_to_fp};

    type Bn254Fr = ark_bn254::Fr;

    #[test]
    fn test_str_to_field() {
        let secret = vec!["hello", "world", "test", "1234", "abcd", "efgh"];
        let fields: Vec<Vec<Bn254Fr>> = secret
            .iter()
            .map(|s| s.to_fields())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(fields.len(), secret.len());

        let padded_secrets: Vec<String> = secret
            .iter()
            .map(|s| {
                let mut bytes = s.as_bytes().to_vec();
                bytes.resize(31, b'0');
                String::from_utf8(bytes).unwrap()
            })
            .collect();

        for (i, field) in fields.iter().enumerate() {
            let expected = Bn254Fr::from_be_bytes_mod_order(padded_secrets[i].as_bytes());
            assert_eq!(
                field[0], expected,
                "Field conversion mismatch at index {}",
                i
            );
        }

        let cs = ark_relations::r1cs::ConstraintSystem::<Bn254Fr>::new_ref();
        let num_bytes_expected = 31;

        let padded_secrets_fields: Vec<Vec<FpVar<Bn254Fr>>> = padded_secrets
            .iter()
            .map(|s| {
                let bytes = s.as_bytes();
                bytes
                    .iter()
                    .map(|chunk| {
                        FpVar::<Bn254Fr>::new_witness(cs.clone(), || Ok(Bn254Fr::from(*chunk)))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<_, _>>()
            .unwrap();

        let fps = padded_secrets_fields
            .iter()
            .map(|secret| pack_byte_fps_to_fp(secret, num_bytes_expected).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(fps.len(), padded_secrets.len());
        for (i, fp) in fps.iter().enumerate() {
            let expected = Bn254Fr::from_be_bytes_mod_order(padded_secrets[i].as_bytes());
            assert_eq!(
                fp.value().unwrap(),
                expected,
                "FP conversion mismatch at index {}",
                i
            );
        }
        println!("number of constraints: {}", cs.num_constraints());
    }
}
