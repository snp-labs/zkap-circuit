use serde::{Deserialize, Serialize};

pub struct GenerateAnchorReq {
    pub secrets: Vec<Secret>, // JSON strings representing SecretDto
}

pub struct GenerateAnchorRes {
    pub anchor: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Secret {
    pub aud: String,
    pub iss: String,
    pub sub: String,
}

impl From<Secret> for zkpasskey_service::interface::anchor::Secret {
    fn from(secret: Secret) -> Self {
        zkpasskey_service::interface::anchor::Secret {
            aud: secret.aud,
            iss: secret.iss,
            sub: secret.sub,
        }
    }
}

// impl From<GenerateAnchorReq> for Vec<zkpasskey_service::interface::anchor::Secret> {
//     fn from(value: GenerateAnchorReq) -> Self {
//         value
//             .secrets
//             .into_iter()
//             .map(|s| serde_json::from_str(&s).expect("Failed to parse Secret JSON"))
//             .collect()
//     }
// }
impl From<GenerateAnchorReq> for Vec<zkpasskey_service::interface::anchor::Secret> {
    fn from(value: GenerateAnchorReq) -> Self {
        value.secrets.into_iter().map(|s| s.into()).collect()
    }
}
