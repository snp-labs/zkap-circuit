// All the tests below test against the RustCrypto sha2 implementation
#[cfg(test)]
mod test {
    use crate::hashes::{
        CRHScheme, TwoToOneCRHScheme,
        constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
        sha256::{DigestVar, SHA256, SHA256Gadget, Sha256Bn254ParamProvider},
    };

    use ark_bn254::Fr as Bn254Fr;
    use ark_r1cs_std::prelude::*;
    use ark_r1cs_std::uint8::UInt8;
    use ark_relations::{
        ns,
        r1cs::{ConstraintSystem, Namespace},
    };
    use ark_std::rand::RngCore;
    use sha2::{Digest, Sha256}; // Import traits for .value() and other gadget methods

    // const TEST_LENGTHS: &[usize] = &[
    //     0, 1, 2, 8, 20, 40, 55, 56, 57, 63, 64, 65, 90, 100, 127, 128, 129,
    // ];

    const TEST_LENGTHS: &[usize] = &[1024];

    /// Witnesses bytes
    fn to_byte_vars(cs: impl Into<Namespace<Bn254Fr>>, data: &[u8]) -> Vec<UInt8<Bn254Fr>> {
        let cs = cs.into().cs();
        UInt8::new_witness_vec(cs, data).unwrap()
    }

    /// Finalizes a SHA256 gadget and gets the bytes
    fn finalize_var(sha256_var: SHA256Gadget<Bn254Fr, Sha256Bn254ParamProvider>) -> Vec<u8> {
        sha256_var.finalize().unwrap().value().unwrap().to_vec()
    }

    /// Finalizes a native SHA256 struct and gets the bytes
    fn finalize(sha256: Sha256) -> Vec<u8> {
        sha256.finalize().to_vec()
    }

    /// Tests the SHA256 of random strings of varied lengths
    #[test]
    fn varied_lengths() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        for &len in TEST_LENGTHS {
            let mut sha256 = Sha256::default();
            let mut sha256_var = SHA256Gadget::default();

            // Make a random string of the given length
            let mut input_str = vec![0u8; len];
            rng.fill_bytes(&mut input_str);

            // Compute the hashes and assert consistency
            sha256_var
                .update(&to_byte_vars(ns!(cs, "input"), &input_str))
                .unwrap();
            sha256.update(input_str);
            assert_eq!(
                finalize_var(sha256_var),
                finalize(sha256),
                "error at length {}",
                len
            );
            assert!(cs.is_satisfied().unwrap());
            println!("num_constraints {:?}", cs.num_constraints());
        }
    }

    /// Calls `update()` many times
    #[test]
    fn many_updates() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();
        let mut sha256 = Sha256::default();
        let mut sha256_var = SHA256Gadget::default();

        // Append the same 7-byte string 20 times
        for _ in 0..20 {
            let mut input_str = vec![0u8; 7];
            rng.fill_bytes(&mut input_str);

            sha256_var
                .update(&to_byte_vars(ns!(cs, "input"), &input_str))
                .unwrap();
            sha256.update(input_str);
        }

        // Make sure the result is consistent
        assert_eq!(finalize_var(sha256_var), finalize(sha256));
    }

    /// Tests the CRHCheme trait
    #[test]
    fn crh() {
        let hashed_bytes: usize = 100;

        for i in hashed_bytes..hashed_bytes + 1 {
            let more_than_64_bytes = vec![48u8; i];
            let cs = ConstraintSystem::<Bn254Fr>::new_ref();

            let computed_output =
                <SHA256Gadget<Bn254Fr, Sha256Bn254ParamProvider> as CRHSchemeGadget<
                    SHA256<Bn254Fr, Sha256Bn254ParamProvider>,
                    Bn254Fr,
                >>::evaluate(&to_byte_vars(
                    ns!(cs, "input"),
                    &more_than_64_bytes[..i],
                ))
                .unwrap();
            let expected_output =
                <SHA256<Bn254Fr, Sha256Bn254ParamProvider> as CRHScheme>::evaluate(
                    &more_than_64_bytes[..i],
                )
                .unwrap();
            assert_eq!(
                computed_output.value().unwrap().to_vec(),
                expected_output,
                "CRH error"
            );
            assert!(cs.is_satisfied().unwrap());
            println!("{} bytes, num_constraints {:?}", i, cs.num_constraints());
        }
    }

    /// Tests the TwoToOneCRHScheme trait
    #[test]
    fn two_to_one_crh() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        for &len in TEST_LENGTHS {
            // Make random strings of the given length
            let mut left_input = vec![0u8; len];
            let mut right_input = vec![0u8; len];
            rng.fill_bytes(&mut left_input);
            rng.fill_bytes(&mut right_input);

            // Compute the hashes and assert consistency
            let computed_output =
                <SHA256Gadget<Bn254Fr, Sha256Bn254ParamProvider> as TwoToOneCRHSchemeGadget<
                    SHA256<Bn254Fr, Sha256Bn254ParamProvider>,
                    Bn254Fr,
                >>::evaluate(
                    &to_byte_vars(ns!(cs, "left input"), &left_input),
                    &to_byte_vars(ns!(cs, "right input"), &right_input),
                )
                .unwrap();
            let expected_output =
                <SHA256<Bn254Fr, Sha256Bn254ParamProvider> as TwoToOneCRHScheme>::evaluate(
                    left_input,
                    right_input,
                )
                .unwrap();
            assert_eq!(
                computed_output.value().unwrap().to_vec(),
                expected_output,
                "TwoToOneCRH error at length {}",
                len
            );
            println!("num_constraints {:?}", cs.num_constraints());
        }
    }

    /// Tests the EqGadget impl of DigestVar
    #[test]
    fn digest_eq() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Make two distinct digests
        let mut digest1 = [0u8; 32];
        let mut digest2 = [0u8; 32];
        rng.fill_bytes(&mut digest1);
        rng.fill_bytes(&mut digest2);

        // Witness them
        let digest1_var = DigestVar::new_witness(cs.clone(), || Ok(digest1.to_vec())).unwrap();
        let digest2_var = DigestVar::new_witness(cs.clone(), || Ok(digest2.to_vec())).unwrap();

        // Assert that the distinct digests are distinct
        assert!(!digest1_var.is_eq(&digest2_var).unwrap().value().unwrap());

        // Now assert that a digest equals itself
        assert!(digest1_var.is_eq(&digest1_var).unwrap().value().unwrap());
    }
}
