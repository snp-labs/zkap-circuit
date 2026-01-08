use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Secret {
    pub sub: String,
    pub iss: String,
    pub aud: String,
}
