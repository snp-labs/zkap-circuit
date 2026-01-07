use ark_crypto_primitives::{crh::CRHScheme, sponge::Absorb};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use common_gadget::{
    anchor::poseidon::{PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorWitness},
    jwt::TokenOpt,
};

use crate::zkpasskey::base::{BaseInstance, BaseWitness, Circuit, CircuitConstArgs, CircuitConstant, CircuitOps, Empty};

pub type BaeraeCircuit<C, H> = Circuit<
    CircuitConstant<C, H, PoseidonAnchorPublicKey<<C as CurveGroup>::BaseField>>,
    BaeraeInstance<<C as CurveGroup>::BaseField>,
    BaeraeWitness<C>,
>;

#[derive(Clone)]
pub struct BaeraeInstance<F>
where
    F: PrimeField,
{
    pub base: BaseInstance<F>,
    pub nonce: Option<Vec<F>>,
    pub exp: Option<F>,
}

#[derive(Clone)]
pub struct BaeraeWitness<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    pub base: BaseWitness<C>,
    pub anchor: Option<PoseidonAnchor<C::BaseField>>,
    pub anchor_witness: Option<PoseidonAnchorWitness<C::BaseField>>,
    pub token: Option<TokenOpt>,
}


impl<F: PrimeField> Empty for BaeraeInstance<F> {
    type Args = usize; // nonce length

    fn empty(args: Self::Args) -> Self {
        Self {
            base: BaseInstance::empty(()),
            nonce: Some(vec![F::zero(); args]),
            exp: Some(F::zero()),
        }
    }
}

#[derive(Clone)]
pub struct BaeraeWitnessArgs {
    pub n: usize,
    pub k: usize,
    pub max_jwt_len: usize,
    pub max_payload_len: usize,
    pub max_overlap_len: usize,
    pub tree_height: usize,
    pub keys: Vec<String>,
}

impl<C> Empty for BaeraeWitness<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    type Args = BaeraeWitnessArgs;

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
pub struct BaeraeCircuitConfig<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: ark_crypto_primitives::crh::CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    pub constant_args: CircuitConstArgs<C, H, <PoseidonAnchorPublicKey<C::BaseField> as Empty>::Args>,
    pub nonce_len: usize,
    pub n: usize,
    pub k: usize,
    pub max_jwt_len: usize,
    pub max_payload_len: usize,
    pub max_overlap_len: usize,
    pub tree_height: usize,
    pub keys: Vec<String>,
}

impl<C, H> Empty for BaeraeCircuit<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: ark_crypto_primitives::crh::CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    type Args = BaeraeCircuitConfig<C, H>;

    fn empty(args: Self::Args) -> Self {
        Self {
            constant: CircuitConstant::empty(args.constant_args),
            instance: BaeraeInstance::empty(args.nonce_len),
            witness: BaeraeWitness::empty(BaeraeWitnessArgs {
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

impl<C, H> BaeraeCircuit<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: ark_crypto_primitives::crh::CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    /// Create a new BaeraeCircuit with the given components
    pub fn new(
        constant: CircuitConstant<C, H, PoseidonAnchorPublicKey<C::BaseField>>,
        instance: BaeraeInstance<C::BaseField>,
        witness: BaeraeWitness<C>,
    ) -> Self {
        Self {
            constant,
            instance,
            witness,
        }
    }

    /// Create an empty BaeraeCircuit using the Empty trait implementation
    pub fn from_config(config: BaeraeCircuitConfig<C, H>) -> Self {
        <Self as Empty>::empty(config)
    }
}

impl<C, H> CircuitOps<C::BaseField> for BaeraeCircuit<C, H>
where 
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme + Clone,
    H::Parameters: Send + Sync + Clone,
{
    type Config = BaeraeCircuitConfig<C, H>;

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
        inputs.push(self.instance.base.hanchor.unwrap());
        inputs.push(self.instance.base.root.unwrap());
        inputs.extend_from_slice(self.instance.nonce.as_ref().unwrap());
        inputs.push(self.instance.exp.unwrap());
        inputs
    }
}
impl<C, H> ConstraintSynthesizer<C::BaseField> for BaeraeCircuit<C, H>
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
        Ok(())
    }
}