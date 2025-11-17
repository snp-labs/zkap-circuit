use ark_crypto_primitives::{crh::CRHScheme, sponge::Absorb};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use common_gadget::{
    anchor::poseidon::{PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorWitness},
    jwt::TokenOpt,
};

use crate::zkpasskey::base::{BaseInstance, BaseWitness, Circuit, CircuitConstArgs, CircuitConstant, CircuitOps, Empty};

pub type HashCircuit<C, H> = Circuit<
    CircuitConstant<C, H, PoseidonAnchorPublicKey<<C as CurveGroup>::BaseField>>,
    HashInstance<<C as CurveGroup>::BaseField>,
    HashWitness<C>,
>;

#[derive(Clone)]
pub struct HashInstance<F>
where
    F: PrimeField,
{
    pub base: BaseInstance<F>,
    pub hash_value: Option<F>,
    pub commitment: Option<F>,
}

#[derive(Clone)]
pub struct HashWitness<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    pub base: BaseWitness<C>,
    pub anchor: Option<PoseidonAnchor<C::BaseField>>,
    pub anchor_witness: Option<PoseidonAnchorWitness<C::BaseField>>,
    pub token: Option<TokenOpt>,
}

impl<F: PrimeField> Empty for HashInstance<F> {
    type Args = ();

    fn empty(_args: Self::Args) -> Self {
        Self {
            base: BaseInstance::empty(()),
            hash_value: Some(F::zero()),
            commitment: Some(F::zero()),
        }
    }
}

#[derive(Clone)]
pub struct HashWitnessArgs {
    pub n: usize,
    pub k: usize,
    pub max_jwt_len: usize,
    pub max_payload_len: usize,
    pub max_overlap_len: usize,
    pub tree_height: usize,
    pub keys: Vec<String>,
}

impl<C> Empty for HashWitness<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    type Args = HashWitnessArgs;

    fn empty(args: Self::Args) -> Self {
        let keys_str: Vec<&str> = args.keys.iter().map(|s| s.as_str()).collect();
        Self {
            base: BaseWitness::empty(args.tree_height),
            anchor: Some(PoseidonAnchor::empty(args.n)),
            anchor_witness: Some(PoseidonAnchorWitness::empty(args.n, args.k)),
            token: Some(TokenOpt::empty(keys_str, args.max_jwt_len, args.max_payload_len, args.max_overlap_len)),
        }
    }
}

#[derive(Clone)]
pub struct HashCircuitConfig<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: ark_crypto_primitives::crh::CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    pub constant_args: CircuitConstArgs<C, H, <PoseidonAnchorPublicKey<C::BaseField> as Empty>::Args>,
    pub n: usize,
    pub k: usize,
    pub max_jwt_len: usize,
    pub max_payload_len: usize,
    pub max_overlap_len: usize,
    pub tree_height: usize,
    pub keys: Vec<String>,
}

impl<C, H> Empty for HashCircuit<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: ark_crypto_primitives::crh::CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    type Args = HashCircuitConfig<C, H>;

    fn empty(args: Self::Args) -> Self {
        Self {
            constant: CircuitConstant::empty(args.constant_args),
            instance: HashInstance::empty(()),
            witness: HashWitness::empty(HashWitnessArgs {
                n: args.n,
                k: args.k,
                max_jwt_len: args.max_jwt_len,
                max_payload_len: args.max_payload_len,
                max_overlap_len: args.max_overlap_len,
                tree_height: args.tree_height,
                keys: args.keys,
            }),
        }
    }
}

impl<C, H> HashCircuit<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: ark_crypto_primitives::crh::CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    pub fn new(
        constant: CircuitConstant<C, H, PoseidonAnchorPublicKey<C::BaseField>>,
        instance: HashInstance<C::BaseField>,
        witness: HashWitness<C>,
    ) -> Self {
        Self {
            constant,
            instance,
            witness,
        }
    }

    pub fn from_config(config: HashCircuitConfig<C, H>) -> Self {
        <Self as Empty>::empty(config)
    }
}

impl<C, H> CircuitOps<C::BaseField> for HashCircuit<C, H>
where 
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme + Clone,
    H::Parameters: Send + Sync + Clone,
{
    type Config = HashCircuitConfig<C, H>;

    fn empty(config: Self::Config) -> Self {
        <Self as Empty>::empty(config)
    }

    fn get_constraints(&self) -> usize {
        let cs = ark_relations::r1cs::ConstraintSystem::<C::BaseField>::new_ref();
        self.clone().generate_constraints(cs.clone()).unwrap();
        cs.num_constraints()
    }

    fn get_public_inputs(&self) -> Vec<C::BaseField> {
        let mut inputs = Vec::new();
        inputs.push(self.instance.base.hanchor.expect("missing hanchor"));
        inputs.push(self.instance.base.root.expect("missing root"));
        inputs.push(self.instance.hash_value.expect("missing hash_value"));
        inputs.push(self.instance.commitment.expect("missing commitment"));
        inputs
    }
}

impl<C, H> ConstraintSynthesizer<C::BaseField> for HashCircuit<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: Clone,
    H: ark_crypto_primitives::crh::CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    fn generate_constraints(
        self,
        _cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>,
    ) -> ark_relations::r1cs::Result<()> {
        // TODO: Implement actual constraint generation
        Ok(())
    }
}
