use ark_ff::PrimeField;
use ark_r1cs_std::fields::{FieldVar, fp::FpVar};
use ark_relations::r1cs::SynthesisError;

use crate::utils::one_bit_vector;

pub trait IndexingGadget<F>
where
    F: PrimeField,
{
    /// 자신보다 큰 인덱스에 1이 설정된 벡터를 생성합니다.
    fn to_gt_vector(&self, n: usize) -> Result<Vec<FpVar<F>>, SynthesisError>;

    // /// 자신보다 작은 인덱스에 1이 설정된 벡터를 생성합니다.
    fn to_lt_vector(&self, n: usize) -> Result<Vec<FpVar<F>>, SynthesisError>;
}

impl<F> IndexingGadget<F> for FpVar<F>
where
    F: PrimeField,
{
    fn to_gt_vector(&self, n: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        if n == 0 {
            return Ok(Vec::new());
        }

        let eq: Vec<FpVar<F>> = one_bit_vector(self, n)?;

        let mut out = Vec::with_capacity(n);
        out.push(FpVar::<F>::zero());

        for i in 1..n {
            let next_out = &out[i - 1] + &eq[i - 1];
            out.push(next_out);
        }

        Ok(out)
    }

    fn to_lt_vector(&self, n: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        if n == 0 {
            return Ok(Vec::new());
        }

        let one = FpVar::<F>::one();
        let index_minus_one = self - &one;
        let eq: Vec<FpVar<F>> = one_bit_vector(&index_minus_one, n)?;

        let mut out = eq.clone();
        for i in (0..(n - 1)).rev() {
            out[i] = &out[i] + &out[i + 1];
        }

        Ok(out)
    }
}
