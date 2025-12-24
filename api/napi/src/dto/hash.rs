use napi_derive::napi;

#[napi(object)]
pub struct GeneratePoseidonHashReq {
    pub inputs: Vec<String>,
}

#[napi(object)]
pub struct GeneratePoseidonHashRes {
    pub hash: String,
}