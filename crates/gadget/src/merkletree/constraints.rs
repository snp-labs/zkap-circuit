use core::borrow::Borrow;

use ark_crypto_primitives::{
    crh::poseidon::constraints::CRHParametersVar, merkle_tree::constraints::PathVar, sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{Boolean, ToBitsGadget},
    uint16::UInt16,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::merkletree::{
    MerkleCircuitInput,
    tree_config::{MerkleTreeParams, MerkleTreeParamsVar},
};

#[cfg(feature = "constraints-logging")]
use crate::debug::log_r1cs_eq;

#[derive(Clone)]
pub struct MerkleCircuitInputVar<F>
where
    F: PrimeField + Absorb,
{
    pub leaf: FpVar<F>,
    pub leaf_idx: UInt16<F>,
    pub path: PathVar<MerkleTreeParams<F>, F, MerkleTreeParamsVar<F>>,
}

impl<F> MerkleCircuitInputVar<F>
where
    F: PrimeField + Absorb,
{
    pub fn enforce_equal_leaf(&self, other: &FpVar<F>) -> Result<(), SynthesisError> {
        #[cfg(feature = "constraints-logging")]
        log_r1cs_eq(
            "Merkle Leaf Equality",
            &[self.leaf.clone()],
            &[other.clone()],
        );

        self.leaf.enforce_equal(other)
    }

    pub fn enforce_membership(
        &mut self,
        hash_param: &CRHParametersVar<F>,
        root: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        self.path.set_leaf_position(self.leaf_idx.to_bits_be()?);

        let membership =
            self.path
                .verify_membership(hash_param, hash_param, root, std::slice::from_ref(&self.leaf))?;

        #[cfg(feature = "constraints-logging")]
        log_r1cs_eq(
            "Merkle Membership Validity",
            &[membership.clone()],
            &[Boolean::TRUE],
        );

        membership.enforce_equal(&Boolean::TRUE)?;
        Ok(())
    }
}

impl<F> AllocVar<MerkleCircuitInput<F>, F> for MerkleCircuitInputVar<F>
where
    F: PrimeField + Absorb,
{
    fn new_variable<T: Borrow<MerkleCircuitInput<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let leaf = FpVar::<F>::new_variable(cs.clone(), || Ok(val.borrow().leaf), mode)?;
            let leaf_idx =
                UInt16::new_variable(cs.clone(), || Ok(val.borrow().leaf_idx as u16), mode)?;
            let path = PathVar::<MerkleTreeParams<F>, F, MerkleTreeParamsVar<F>>::new_variable(
                cs.clone(),
                || Ok(val.borrow().path.clone()),
                mode,
            )?;
            Ok(MerkleCircuitInputVar {
                leaf,
                leaf_idx,
                path,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_crypto_primitives::{
        crh::{
            CRHScheme, CRHSchemeGadget,
            poseidon::{
                CRH,
                constraints::{CRHGadget, CRHParametersVar},
            },
        },
        merkle_tree::{MerkleTree, Path, constraints::PathVar},
        sponge::{Absorb, poseidon::PoseidonConfig},
    };
    use ark_ff::PrimeField;
    use ark_r1cs_std::{
        R1CSVar,
        alloc::AllocVar,
        eq::EqGadget,
        fields::fp::FpVar,
        prelude::{Boolean, ToBitsGadget},
    };
    use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

    use crate::{
        bigint::constraints::BigNatCircuitParams,
        hashes::poseidon::get_poseidon_params,
        merkletree::tree_config::{MerkleTreeParams, MerkleTreeParamsVar},
    };

    const LAMBDA: usize = 2048; // 2048 bits

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct BigNat512TestParams;
    impl BigNatCircuitParams for BigNat512TestParams {
        const LIMB_WIDTH: usize = 64;
        const N_LIMBS: usize = LAMBDA / 64;
    }

    type F = ark_bn254::Fr;
    type BNP = BigNat512TestParams;
    type C = ark_ed_on_bn254::EdwardsProjective;

    fn generate_merkle_tree_input<F: PrimeField + Absorb>(
        tree_height: usize,
        n_leaves: usize,
        idx: usize,
    ) -> (F, Path<MerkleTreeParams<F>>, F) {
        let leaf_hash_param = get_poseidon_params::<F>().clone();
        let two_to_one_hash_param = get_poseidon_params::<F>().clone();
        let mut leaves = Vec::with_capacity(n_leaves);

        for i in 0..n_leaves {
            let leaf = F::from((i) as u64);
            leaves.push(leaf);
        }

        let mut digests = vec![F::zero(); 1 << (tree_height - 1)];
        println!("digests length: {}", digests.len());
        for (i, leaf) in leaves.iter().enumerate() {
            let digest = CRH::evaluate(&leaf_hash_param, [leaf.clone()]).unwrap();
            digests[i] = digest;
        }

        let mt = MerkleTree::<MerkleTreeParams<F>>::new_with_leaf_digest(
            &leaf_hash_param,
            &two_to_one_hash_param,
            digests.clone(),
        )
        .unwrap();

        // path {
        //     leaf_sibling_hash: sibling value => hashed 1 time
        //     auth_path: authentication path => [depth1, depth2, ..., ], closer to root first. With root at depth 0, hash (tree_height - 1) - 1 times. (tree_height - 1) other node hashes, 1 sibling hash
        //     leaf_index: 0 => own index
        // }
        let rt = mt.root();
        let path = mt.generate_proof(idx).unwrap();

        (rt, path, digests[idx])
    }

    fn generate_merkle_tree_verify_gadget<F: PrimeField + Absorb>(
        cs: &ark_relations::r1cs::ConstraintSystemRef<F>,
        poseidon_parameters: PoseidonConfig<F>,
        path: &Path<MerkleTreeParams<F>>,
        root: &F,
        idx: usize,
    ) {
        let hash_params_var =
            CRHParametersVar::<F>::new_constant(cs.clone(), poseidon_parameters.clone()).unwrap();

        let mut path_var = PathVar::<MerkleTreeParams<F>, F, MerkleTreeParamsVar<F>>::new_witness(
            cs.clone(),
            || Ok(path.clone()),
        )
        .unwrap();

        let leaf_pos_var = FpVar::new_witness(cs.clone(), || Ok(F::from(idx as u64))).unwrap();

        let rt_var = FpVar::<F>::new_witness(cs.clone(), || Ok(*root)).unwrap();

        path_var.set_leaf_position(leaf_pos_var.to_bits_le().unwrap());
        let verify_membership = path_var
            .verify_membership(
                &hash_params_var,
                &hash_params_var,
                &rt_var,
                &[leaf_pos_var.clone()],
            )
            .unwrap();
        verify_membership.enforce_equal(&Boolean::TRUE).unwrap();

        println!("test {}", idx);
        println!("number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_merkle_tree_gadget() {
        let tree_height = 5;
        let n_leaves = 5;
        let idx_1 = 0;
        let idx_2 = 1;
        let idx_3 = 2;

        let (root_1, path_1, _) = generate_merkle_tree_input::<F>(tree_height, n_leaves, idx_1);
        let (root_2, path_2, _) = generate_merkle_tree_input::<F>(tree_height, n_leaves, idx_2);
        let (root_3, path_3, _) = generate_merkle_tree_input::<F>(tree_height, n_leaves, idx_3);
        let (root_4, _, _) = generate_merkle_tree_input::<F>(16, 0, 0);
        println!("root_4: {:?}", root_4);

        assert_eq!(root_1, root_2);
        assert_eq!(root_1, root_3);

        println!("path_1: {:?}", path_1);
        println!("path_2: {:?}", path_2);
        println!("path_3: {:?}", path_3);

        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        generate_merkle_tree_verify_gadget(
            &cs,
            get_poseidon_params::<F>(),
            &path_1,
            &root_1,
            idx_1,
        );

        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        generate_merkle_tree_verify_gadget(
            &cs,
            get_poseidon_params::<F>(),
            &path_2,
            &root_2,
            idx_2,
        );
        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        generate_merkle_tree_verify_gadget(
            &cs,
            get_poseidon_params::<F>(),
            &path_3,
            &root_3,
            idx_3,
        );
    }

    #[test]
    fn test_poseidon_hash() {
        let left = F::from(123u64);
        let right = F::from(456u64);
        let poseidon_params = get_poseidon_params::<F>();
        let hash = CRH::evaluate(&poseidon_params, [left, right]).unwrap();
        println!("poseidon hash: {:?}", hash);
    }

    #[test]
    fn test_init_tree() {
        // The Merkle Tree must be synced between rust and solidity.
        // tree_height should be the same for both rust and solidity.
        // With tree_height = 4, hashing is performed 3 times total to reach root.
        // To sync rust and solidity, initialize the Merkle Tree in rust with Hash(0) as the leaf.
        // Then, when updating a leaf, call mt.update with the value directly. Hashing is done internally, so H(value) becomes the leaf.
        let tree_height = 5;

        let leaf_hash_param = get_poseidon_params::<F>().clone();
        let two_to_one_hash_param = get_poseidon_params::<F>().clone();

        let h0 = CRH::evaluate(&leaf_hash_param, [F::from(0u64)]).unwrap();
        let digests = vec![h0; 1 << (tree_height - 1)];

        // Leaves can be created before building the Merkle Tree. In this case, leaves are raw values (not hashes), i.e. 1, 2, 3 become leaves directly.
        // digests[0] = F::from(1u64);

        let mut mt = MerkleTree::<MerkleTreeParams<F>>::new_with_leaf_digest(
            &leaf_hash_param,
            &two_to_one_hash_param,
            digests.clone(),
        )
        .unwrap();

        let _leaves = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
        let h1 = CRH::evaluate(&leaf_hash_param, [F::from(1u64)]).unwrap();
        let h2 = CRH::evaluate(&leaf_hash_param, [h1, F::from(2u64)]).unwrap();
        let h3 = CRH::evaluate(&leaf_hash_param, [h2, F::from(3u64)]).unwrap();
        println!("h3: {:?}", h3);

        // To update an existing Merkle Tree, call update(idx, value). The value is hashed internally, so the leaf node is updated to H(value).
        mt.update(0, &[F::from(1u64)]).unwrap();
        let root = mt.root();
        let path = mt.generate_proof(0).unwrap();
        println!("root: {:?}", root);
        println!("path: {:?}", path);

        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        let value = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
        let values = value
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let _h_var = chain_hash_gadget(cs.clone(), &values).unwrap();
        println!("num constraints: {}", cs.num_constraints());

        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        let parameter =
            CRHParametersVar::<F>::new_constant(cs.clone(), get_poseidon_params::<F>().clone())
                .unwrap();
        let values = value
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let h_var = chain_hash_gadget(cs.clone(), &values).unwrap();
        println!("h_var: {:?}", h_var.value().unwrap());
        let _h_var = CRHGadget::<F>::evaluate(&parameter, &values).unwrap();
        println!("num constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_merkle_wrong_root() {
        let tree_height = 5;
        let n_leaves = 5;
        let idx = 0;

        let (_root, path, _) = generate_merkle_tree_input::<F>(tree_height, n_leaves, idx);
        let wrong_root = F::from(999999u64); // tampered root

        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        let poseidon_params = get_poseidon_params::<F>();
        let hash_params_var =
            CRHParametersVar::<F>::new_constant(cs.clone(), poseidon_params.clone()).unwrap();

        let mut path_var = PathVar::<MerkleTreeParams<F>, F, MerkleTreeParamsVar<F>>::new_witness(
            cs.clone(),
            || Ok(path.clone()),
        )
        .unwrap();

        let leaf_pos_var = FpVar::new_witness(cs.clone(), || Ok(F::from(idx as u64))).unwrap();
        let rt_var = FpVar::<F>::new_witness(cs.clone(), || Ok(wrong_root)).unwrap();

        path_var.set_leaf_position(leaf_pos_var.to_bits_le().unwrap());
        let verify_membership = path_var
            .verify_membership(
                &hash_params_var,
                &hash_params_var,
                &rt_var,
                &[leaf_pos_var],
            )
            .unwrap();
        verify_membership.enforce_equal(&Boolean::TRUE).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Wrong root should not satisfy");
    }

    #[test]
    fn test_merkle_wrong_leaf() {
        let tree_height = 5;
        let n_leaves = 5;
        let idx = 0;

        let (root, path, _) = generate_merkle_tree_input::<F>(tree_height, n_leaves, idx);

        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        let poseidon_params = get_poseidon_params::<F>();
        let hash_params_var =
            CRHParametersVar::<F>::new_constant(cs.clone(), poseidon_params.clone()).unwrap();

        let mut path_var = PathVar::<MerkleTreeParams<F>, F, MerkleTreeParamsVar<F>>::new_witness(
            cs.clone(),
            || Ok(path.clone()),
        )
        .unwrap();

        // Wrong leaf: use 999 instead of idx=0
        let wrong_leaf = FpVar::new_witness(cs.clone(), || Ok(F::from(999u64))).unwrap();
        let rt_var = FpVar::<F>::new_witness(cs.clone(), || Ok(root)).unwrap();

        path_var.set_leaf_position(wrong_leaf.to_bits_le().unwrap());
        let verify_membership = path_var
            .verify_membership(
                &hash_params_var,
                &hash_params_var,
                &rt_var,
                &[wrong_leaf],
            )
            .unwrap();
        verify_membership.enforce_equal(&Boolean::TRUE).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Wrong leaf should not satisfy");
    }

    #[test]
    fn test_merkle_height_2() {
        // Boundary: minimal tree (height=2, 2 leaves)
        let tree_height = 2;
        let n_leaves = 2;
        let idx = 0;

        let (root, path, _) = generate_merkle_tree_input::<F>(tree_height, n_leaves, idx);

        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        generate_merkle_tree_verify_gadget(
            &cs,
            get_poseidon_params::<F>(),
            &path,
            &root,
            idx,
        );

        assert!(cs.is_satisfied().unwrap());
        println!("height-2 tree: {} constraints", cs.num_constraints());
    }

    // H(H(0 || 1) || 2)
    fn chain_hash_gadget<F: PrimeField + Absorb>(
        cs: ConstraintSystemRef<F>,
        values: &[FpVar<F>],
    ) -> Result<FpVar<F>, SynthesisError> {
        let poseidon_params = get_poseidon_params::<F>();
        let parameters = CRHParametersVar::<F>::new_constant(cs.clone(), poseidon_params.clone())?;
        let mut hash = CRHGadget::<F>::evaluate(&parameters, &[values[0].clone()])?;
        for value in values.iter().skip(1) {
            hash = CRHGadget::<F>::evaluate(&parameters, &[hash, value.clone()])?;
        }
        Ok(hash)
    }
}
