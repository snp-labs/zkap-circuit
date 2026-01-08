use std::path::PathBuf;

use ark_bn254::Bn254;
use ark_groth16::Proof;
use common::constants::{F, ZkPasskeyConfig};

use crate::{
    app,
    error::ApplicationError,
};

pub fn generate_baerae_proof<Config: ZkPasskeyConfig>(
    pk_path: &PathBuf,
    jwts: Vec<String>,
    pk_ops: Vec<String>,
    mp: Vec<Vec<String>>,
    leaf_index: Vec<usize>,
    root: &str,
    anchor_parts: &[String],
    h_sign_userop: &str,
    block_timestamp: &str,
    random: &str,
    aud_list: &[String],
) -> Result<(Vec<Proof<Bn254>>, Vec<Vec<F>>), ApplicationError> {
    app::snark::zkap::generate_baerae_proof::<Config>(
        pk_path,
        jwts,
        pk_ops,
        mp,
        leaf_index,
        root,
        anchor_parts,
        h_sign_userop,
        block_timestamp,
        random,
        aud_list,
    )
}