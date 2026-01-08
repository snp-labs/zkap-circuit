use common::constants::F;

use crate::{
    app,
    error::ApplicationError,
};

pub fn poseidon_hash(messages: Vec<String>) -> Result<F, ApplicationError> {
    app::hash::poseidon_hash(messages)
}