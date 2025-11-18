use napi_derive::napi;

#[napi(object)]
pub struct GenerateAnchorReq {
  pub secrets: Vec<SecretDto>,
}

#[napi(object)]
pub struct GenerateAnchorRes {
  pub anchor: Vec<String>,
}

#[napi(object)]
pub struct SecretDto {
  pub aud: String,
  pub iss: String,
  pub sub: String,
}

impl From<SecretDto> for zkpasskey_service::interface::anchor::Secret {
  fn from(secret: SecretDto) -> Self {
    zkpasskey_service::interface::anchor::Secret {
      aud: secret.aud,
      iss: secret.iss,
      sub: secret.sub,
    }
  }
}
