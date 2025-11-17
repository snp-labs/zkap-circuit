use ark_crypto_primitives::{crh::CRHScheme, sponge::Absorb};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use common_gadget::{
    anchor::dl::{DLAnchor, DLAnchorPublicKey, DLAnchorWitness},
    jwt::TokenOpt,
};

use crate::zkpasskey::base::{BaseInstance, BaseWitness, Circuit, CircuitConstArgs, CircuitConstant, CircuitOps, Empty};

pub type DLCircuit<C, H> = Circuit<
    CircuitConstant<C, H, DLAnchorPublicKey<C>>,
    DLInstance<<C as CurveGroup>::BaseField>,
    DLWitness<C>,
>;

#[derive(Clone)]
pub struct DLInstance<F>
where
    F: PrimeField,
{
    pub base: BaseInstance<F>,
    pub dl_commitment: Option<F>,
    pub dl_proof: Option<Vec<F>>,
}

#[derive(Clone)]
pub struct DLWitness<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    pub base: BaseWitness<C>,
    pub anchor: Option<DLAnchor<C>>,
    pub anchor_witness: Option<DLAnchorWitness<C>>,
    pub token: Option<TokenOpt>,
}

impl<F: PrimeField> Empty for DLInstance<F> {
    type Args = usize; // proof vector length

    fn empty(args: Self::Args) -> Self {
        Self {
            base: BaseInstance::empty(()),
            dl_commitment: Some(F::zero()),
            dl_proof: Some(vec![F::zero(); args]),
        }
    }
}

#[derive(Clone)]
pub struct DLWitnessArgs<C: CurveGroup> {
    pub n: usize,
    pub k: usize,
    pub max_jwt_len: usize,
    pub max_payload_len: usize,
    pub max_overlap_len: usize,
    pub tree_height: usize,
    pub keys: Vec<String>,
    pub generators: Vec<C::Affine>,
}

impl<C> Empty for DLWitness<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    type Args = DLWitnessArgs<C>;

    fn empty(args: Self::Args) -> Self {
        let keys_str: Vec<&str> = args.keys.iter().map(|s| s.as_str()).collect();
        Self {
            base: BaseWitness::empty(args.tree_height),
            anchor: Some(DLAnchor::empty(args.n)),
            anchor_witness: Some(DLAnchorWitness::empty(args.n, args.k)),
            token: Some(TokenOpt::empty(keys_str, args.max_jwt_len, args.max_payload_len, args.max_overlap_len)),
        }
    }
}

#[derive(Clone)]
pub struct DLCircuitConfig<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: ark_crypto_primitives::crh::CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    pub constant_args: CircuitConstArgs<C, H, <DLAnchorPublicKey<C> as Empty>::Args>,
    pub proof_len: usize,
    pub n: usize,
    pub k: usize,
    pub max_jwt_len: usize,
    pub max_payload_len: usize,
    pub max_overlap_len: usize,
    pub tree_height: usize,
    pub keys: Vec<String>,
}

impl<C, H> Empty for DLCircuit<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: ark_crypto_primitives::crh::CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    type Args = DLCircuitConfig<C, H>;

    fn empty(args: Self::Args) -> Self {
        Self {
            constant: CircuitConstant::empty(args.constant_args),
            instance: DLInstance::empty(args.proof_len),
            witness: DLWitness::empty(DLWitnessArgs::<C> {
                n: args.n,
                k: args.k,
                max_jwt_len: args.max_jwt_len,
                max_payload_len: args.max_payload_len,
                max_overlap_len: args.max_overlap_len,
                tree_height: args.tree_height,
                keys: args.keys,
                generators: vec![], // Will be filled from constant_args
            }),
        }
    }
}

impl<C, H> DLCircuit<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: ark_crypto_primitives::crh::CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    pub fn new(
        constant: CircuitConstant<C, H, DLAnchorPublicKey<C>>,
        instance: DLInstance<C::BaseField>,
        witness: DLWitness<C>,
    ) -> Self {
        Self {
            constant,
            instance,
            witness,
        }
    }

    pub fn from_config(config: DLCircuitConfig<C, H>) -> Self {
        <Self as Empty>::empty(config)
    }
}

impl<C, H> CircuitOps<C::BaseField> for DLCircuit<C, H>
where 
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme + Clone,
    H::Parameters: Send + Sync + Clone,
{
    type Config = DLCircuitConfig<C, H>;

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
        inputs.push(self.instance.dl_commitment.expect("missing dl_commitment"));
        inputs.extend_from_slice(self.instance.dl_proof.as_ref().expect("missing dl_proof"));
        inputs
    }
}

impl<C, H> ConstraintSynthesizer<C::BaseField> for DLCircuit<C, H>
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
