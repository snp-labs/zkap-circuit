use ark_crypto_primitives::{
    crh::CRHScheme,
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, Zero};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use gadget::{
    anchor::{dl::DLAnchorPublicKey, poseidon::PoseidonAnchorPublicKey},
    base64::Base64Table,
    mekletree::MerkleCircuitInput,
    signature::schnorr::{Parameters, PublicKey, Signature},
};

#[derive(Clone)]
pub struct CircuitConstant<C, H, AnchorPublicKey>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    pub base: BaseConstant<C, H>,
    pub anchor_key: Option<AnchorPublicKey>,
}

#[derive(Clone)]
pub struct CircuitInstance<F>
where
    F: PrimeField,
{
    pub hanchor: Option<F>,
    pub root: Option<F>,
    pub nonce: Option<F>,
    pub counter: Option<F>,
    pub h_x: Option<F>, // h_i 값들에 대한 해시
    pub slot: Option<F>, // 선택된 secret의 슬롯 번호. 인덱스 아님
    pub h_slot: Option<F>, // slot 값에 대한 해시. H(placed_indices || random)
}

#[derive(Clone)]
pub struct CircuitWitness<C, Anchor, AnchorWitness, TokenType>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    pub base: BaseWitness<C>,
    pub anchor: Option<Anchor>,
    pub anchor_witness: Option<AnchorWitness>,
    pub token: Option<TokenType>,
}

#[derive(Clone)]
pub struct BaseConstant<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    pub n: Option<usize>,
    pub k: Option<usize>,
    pub num_per_block: Option<usize>,
    pub max_jwt_len: Option<usize>,
    pub max_payload_len: Option<usize>,
    pub max_aud_len: Option<usize>,
    pub max_iss_len: Option<usize>,
    pub max_nonce_len: Option<usize>,
    pub max_sub_len: Option<usize>,
    pub tree_height: Option<usize>,
    pub schnorr_param: Option<Parameters<C, H>>,
    pub schnorr_vk: Option<PublicKey<C>>,
    pub poseidon_param: Option<PoseidonConfig<C::BaseField>>,
    pub base64_table: Option<Base64Table>,
}

#[derive(Clone)]
pub struct BaseWitness<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    pub signature: Option<Signature<C>>,
    pub random: Option<C::BaseField>,
    pub path: Option<MerkleCircuitInput<C::BaseField>>,
}

#[derive(Clone)]
pub struct Circuit<Constant, Instance, Witness> {
    pub constant: Constant,
    pub instance: Instance,
    pub witness: Witness,
}

pub trait CircuitOps<F: Field>: ConstraintSynthesizer<F> + Clone + Sized {
    type Config;

    fn empty(config: Self::Config) -> Self;

    fn get_public_inputs(&self) -> Vec<F>;

    fn get_constraints(&self) -> usize {
        let cs = ConstraintSystem::<F>::new_ref();
        self.clone().generate_constraints(cs.clone()).unwrap();
        cs.num_constraints()
    }
}

pub trait Empty {
    type Args;

    fn empty(args: Self::Args) -> Self;
}

#[derive(Clone)]
pub struct CircuitConstantArgs<C, H, AnchorKey>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    pub n: usize,
    pub k: usize,
    pub num_per_block: usize,
    pub max_jwt_len: usize,
    pub max_payload_len: usize,
    pub max_aud_len: usize,
    pub max_iss_len: usize,
    pub max_nonce_len: usize,
    pub max_sub_len: usize,
    pub tree_height: usize,
    pub schnorr_param: Parameters<C, H>,
    pub schnorr_vk: PublicKey<C>,
    pub poseidon_param: PoseidonConfig<C::BaseField>,
    pub anchor_key: AnchorKey,
    pub base64_table: Base64Table,
}

impl<C> Empty for BaseWitness<C>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    type Args = usize; // tree_height

    fn empty(args: Self::Args) -> Self {
        Self {
            signature: Some(Signature::default()),
            random: Some(C::BaseField::zero()),
            path: Some(MerkleCircuitInput::empty(args)),
        }
    }
}

impl<F> Empty for PoseidonAnchorPublicKey<F>
where
    F: PrimeField,
{
    type Args = PoseidonConfig<F>;
    fn empty(args: Self::Args) -> Self {
        let params = args;
        Self { params }
    }
}

impl<C> Empty for DLAnchorPublicKey<C>
where
    C: CurveGroup,
{
    type Args = Vec<C::Affine>;
    fn empty(args: Self::Args) -> Self {
        let generators = args;
        Self { generators }
    }
}

impl<C, H, AnchorKey> Empty for CircuitConstant<C, H, AnchorKey>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    type Args = CircuitConstantArgs<C, H, AnchorKey>;

    fn empty(args: Self::Args) -> Self {
        Self {
            base: BaseConstant {
                n: Some(args.n),
                k: Some(args.k),
                num_per_block: Some(args.num_per_block),
                max_jwt_len: Some(args.max_jwt_len),
                max_payload_len: Some(args.max_payload_len),
                max_aud_len: Some(args.max_aud_len),
                max_iss_len: Some(args.max_iss_len),
                max_nonce_len: Some(args.max_nonce_len),
                max_sub_len: Some(args.max_sub_len),
                tree_height: Some(args.tree_height),
                schnorr_param: Some(args.schnorr_param),
                schnorr_vk: Some(args.schnorr_vk),
                poseidon_param: Some(args.poseidon_param),
                base64_table: Some(args.base64_table),
            },
            anchor_key: Some(args.anchor_key),
        }
    }
}

impl<F> Empty for CircuitInstance<F>
where
    F: PrimeField,
{
    type Args = ();

    fn empty(_args: Self::Args) -> Self {
        Self {
            hanchor: Some(F::zero()),
            root: Some(F::zero()),
            nonce: Some(F::zero()),
            counter: Some(F::zero()),
            h_x: Some(F::zero()),
            slot: Some(F::zero()),
            h_slot: Some(F::zero()),
        }
    }
}

#[derive(Clone)]
pub struct BaseCircuitArgs<C, H>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    pub n: usize,
    pub k: usize,
    pub num_per_block: usize,
    pub max_jwt_len: usize,
    pub max_payload_len: usize,
    pub max_aud_len: usize,
    pub max_iss_len: usize,
    pub max_nonce_len: usize,
    pub max_sub_len: usize,
    pub tree_height: usize,
    pub schnorr_param: Parameters<C, H>,
    pub schnorr_vk: PublicKey<C>,
    pub poseidon_param: PoseidonConfig<C::BaseField>,
    pub base64_table: Base64Table,
    pub keys_len: usize,
}

#[derive(Clone)]
pub struct CircuitArgs<C, H, AK>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    H: CRHScheme,
    H::Parameters: Send + Sync + Clone,
{
    pub base: BaseCircuitArgs<C, H>,
    pub anchor_key: AK,
}