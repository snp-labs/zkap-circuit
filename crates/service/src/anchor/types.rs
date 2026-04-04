use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Secret {
    pub sub: String,
    pub iss: String,
    pub aud: String,
}
