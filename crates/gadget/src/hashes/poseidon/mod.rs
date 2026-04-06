pub mod constraints;
pub mod parameters;
pub use parameters::*;

#[cfg(test)]
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
}
