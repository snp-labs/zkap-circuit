use std::path::Path;

use anyhow::Context;
use flutter_rust_bridge::frb;

use crate::dto::{
    anchor::{
        CreateDlAnchorReq, CreateDlAnchorRes, CreatePoseidonAnchorReq, CreatePoseidonAnchorRes,
        DlDeriveIndicesReq, DlDeriveIndicesRes, PoseidonDeriveIndicesReq, PoseidonDeriveIndicesRes,
    },
    FfiSecretDto,
};

#[frb]
pub fn frb_create_poseidon_anchor(
    req: CreatePoseidonAnchorReq,
) -> Result<CreatePoseidonAnchorRes, String> {
    fn inner(req: CreatePoseidonAnchorReq) -> anyhow::Result<CreatePoseidonAnchorRes> {
        let secrets = req
            .secrets
            .into_iter()
            .map(|s: FfiSecretDto| s.into())
            .collect();

        let anchor =
            zkpasskey_service::service::anchor::create_poseidon_anchor(req.key_path, secrets)
                .context("service::anchor::create_poseidon_anchor failed")?;

        Ok(CreatePoseidonAnchorRes { anchor })
    }

    inner(req).map_err(|e| e.to_string())
}

#[frb]
pub fn frb_create_dl_anchor(req: CreateDlAnchorReq) -> Result<CreateDlAnchorRes, String> {
    fn inner(req: CreateDlAnchorReq) -> anyhow::Result<CreateDlAnchorRes> {
        let secrets = req
            .secrets
            .into_iter()
            .map(|s: FfiSecretDto| s.into())
            .collect();

        let anchor = zkpasskey_service::service::anchor::create_dl_anchor(req.handle, secrets)
            .context("service::anchor::create_dl_anchor failed")?;

        Ok(CreateDlAnchorRes { anchor })
    }

    inner(req).map_err(|e| e.to_string())
}

#[frb]
pub fn frb_poseidon_derive_indices(
    req: PoseidonDeriveIndicesReq,
) -> Result<PoseidonDeriveIndicesRes, String> {
    fn inner(req: PoseidonDeriveIndicesReq) -> anyhow::Result<PoseidonDeriveIndicesRes> {
        // [디버그 1] 입력 데이터 로그 출력 (기존 유지)
        println!("=== [Rust Debug] Poseidon Indices ===");
        println!("Key Path: {}", req.key_path);
        println!("Anchor len: {}", req.anchor.len());

        if !Path::new(&req.key_path).exists() {
            anyhow::bail!("CRITICAL ERROR: File not found at path: {}", req.key_path);
        }

        let known = req
            .known_secrets
            .into_iter()
            .map(|s: FfiSecretDto| s.into())
            .collect();

        // [수정 포인트 1] .context() 제거
        // 원본 에러(ApplicationError)가 그대로 anyhow로 전달되게 합니다.
        // 만약 context를 꼭 쓰고 싶다면 with_context를 써야 하지만, 지금은 원본 확인이 우선입니다.
        let indices = zkpasskey_service::service::anchor::poseidon_derive_indices(
            req.key_path,
            req.anchor,
            known,
        )?;

        Ok(PoseidonDeriveIndicesRes { indices })
    }

    // [수정 포인트 2] 에러 체인 전체 출력
    inner(req).map_err(|e| {
        // Rust 콘솔에 전체 에러 트리를 출력 (디버깅용)
        println!("=== FULL ERROR DEBUG ===");
        println!("{:?}", e);

        // Flutter로 리턴되는 에러 문자열 구성
        // e.chain()을 통해 "A -> Caused by B -> Caused by C" 형태의 문자열을 만듭니다.
        let mut err_msg = format!("Error: {}\n", e);
        for cause in e.chain().skip(1) {
            err_msg.push_str(&format!("  Caused by: {}\n", cause));
        }
        err_msg
    })
}

#[frb]
pub fn frb_dl_derive_indices(req: DlDeriveIndicesReq) -> Result<DlDeriveIndicesRes, String> {
    fn inner(req: DlDeriveIndicesReq) -> anyhow::Result<DlDeriveIndicesRes> {
        let known = req
            .known_secrets
            .into_iter()
            .map(|s: FfiSecretDto| s.into())
            .collect();

        let indices =
            zkpasskey_service::service::anchor::dl_derive_indices(req.handle, req.anchor, known)
                .context("service::anchor::dl_derive_indices failed")?;

        Ok(DlDeriveIndicesRes { indices })
    }

    inner(req).map_err(|e| e.to_string())
}
