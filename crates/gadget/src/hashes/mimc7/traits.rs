use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

use crate::hashes::{
    Parameter,
    constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
    error::HashError,
};

use super::{
    MiMCGadget, RoundConstantsAccessor, TwoToOneMiMCGadget,
    native::{MiMC, TwoToOneMiMC},
};

impl<F, P> CRHSchemeGadget<MiMC<F, P>, F> for MiMCGadget<F, P>
where
    F: PrimeField,
    P: Parameter<F>,
    P::ParameterStruct: RoundConstantsAccessor<F>,
{
    type InputVar = [FpVar<F>];
    type OutputVar = FpVar<F>;

    fn evaluate(input: &Self::InputVar) -> Result<Self::OutputVar, HashError> {
        let mut res: Self::OutputVar;
        if input.len() == 1 {
            let xl = input[0].clone();
            let xr = input[0].clone();
            res = Self::encrypt(xl, xr);
            res += input[0].clone() + input[0].clone();
        } else {
            res = input[0].clone();
            for i in 1..input.len() {
                let xl = res.clone();
                let xr = input[i].clone();

                res = Self::encrypt(xl.clone(), xr.clone());
                res += xl.clone() + input[i].clone();
            }
        }

        Ok(res)
    }
}

impl<F, P> TwoToOneCRHSchemeGadget<TwoToOneMiMC<F, P>, F> for TwoToOneMiMCGadget<F, P>
where
    F: PrimeField,
    P: Parameter<F>,
    P::ParameterStruct: RoundConstantsAccessor<F>,
{
    type InputVar = FpVar<F>;
    type OutputVar = FpVar<F>;

    fn evaluate(
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<FpVar<F>, HashError> {
        let xl = left_input.clone();
        let xr = right_input.clone();

        let mut res = MiMCGadget::<F, P>::encrypt(xl, xr);
        res = res + left_input + right_input;

        Ok(res)
    }

    fn compress(
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, HashError> {
        Self::evaluate(left_input, right_input)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;

    use ark_r1cs_std::{
        R1CSVar,
        fields::fp::FpVar,
        prelude::{AllocVar, EqGadget},
    };
    use ark_relations::r1cs::ConstraintSystem;

    use crate::hashes::{
        CRHScheme, TwoToOneCRHScheme,
        constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
        mimc7::{
            MiMCGadget, MimcBn254ParamProvider, TwoToOneMiMCGadget,
            native::{MiMC, TwoToOneMiMC},
        },
    };

    #[test]
    fn test_mimc_two_to_one_gadget() {
        let xl = Fr::from(111111);
        let xr = Fr::from(111111);

        let two_to_one_eval =
            TwoToOneMiMC::<Fr, MimcBn254ParamProvider>::evaluate(&xl, &xr).unwrap();

        let cs = ConstraintSystem::<Fr>::new_ref();

        let xl_var = FpVar::new_witness(cs.clone(), || Ok(&xl)).unwrap();
        let xr_var = FpVar::new_witness(cs.clone(), || Ok(&xr)).unwrap();

        let expected_var = FpVar::new_input(cs.clone(), || Ok(two_to_one_eval)).unwrap();
        let result_var =
            TwoToOneMiMCGadget::<Fr, MimcBn254ParamProvider>::evaluate(&xl_var, &xr_var).unwrap();

        expected_var.enforce_equal(&result_var).unwrap();

        assert_eq!(expected_var.value().unwrap(), result_var.value().unwrap());

        assert!(cs.is_satisfied().unwrap());
        println!("number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_mimc_hash_gadget() {
        let xl = Fr::from(111111);
        let xr = Fr::from(111111);

        let input_vec = [xl, xr].to_vec();

        let eval = MiMC::<Fr, MimcBn254ParamProvider>::evaluate(&input_vec[..]).unwrap();

        let cs = ConstraintSystem::<Fr>::new_ref();

        let xl_var = FpVar::new_witness(cs.clone(), || Ok(&xl)).unwrap();
        let xr_var = FpVar::new_witness(cs.clone(), || Ok(&xr)).unwrap();
        let expected_var = FpVar::new_input(cs.clone(), || Ok(&eval)).unwrap();

        let input_var_vec = [xl_var, xr_var].to_vec();

        let result_var =
            MiMCGadget::<Fr, MimcBn254ParamProvider>::evaluate(&input_var_vec).unwrap();

        expected_var.enforce_equal(&result_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_mimc_many_time() {
        let iter = 100;
        let mut input_vec = Vec::with_capacity(iter);
        for i in 0..iter {
            input_vec.push(Fr::from(i as u64));
        }
        let eval = MiMC::<Fr, MimcBn254ParamProvider>::evaluate(&input_vec[..]).unwrap();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let input_var_vec: Vec<FpVar<Fr>> = input_vec
            .iter()
            .map(|&x| FpVar::new_witness(cs.clone(), || Ok(x)).unwrap())
            .collect();
        let expected_var = FpVar::new_input(cs.clone(), || Ok(&eval)).unwrap();
        let result_var =
            MiMCGadget::<Fr, MimcBn254ParamProvider>::evaluate(&input_var_vec).unwrap();
        expected_var.enforce_equal(&result_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("number of constraints: {}", cs.num_constraints());
        assert_eq!(expected_var.value().unwrap(), result_var.value().unwrap());
    }
}
