pub mod snark;
pub mod utils;

pub use snark::{generate_and_write_proving_key, generate_proof, setup_keys, verify_proof};

// TODO: Circuit 구현이 완료되면 아래 코드를 활성화
// use common::circuit::zkpasskey::{base::BaseCircuitArgs, opt_hash::OptHashArgs};
// use crate::{interface::snark::ZkpasskeySetupRequestDto, service::constants::{AppCurve, AppField}};
