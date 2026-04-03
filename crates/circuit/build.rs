use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // === 0. .env 파일 로딩 (dotenvy) ===
    // 프로젝트 루트의 .env 파일에서 환경 변수를 로딩합니다.
    // 이미 설정된 환경 변수는 덮어쓰지 않습니다 (환경변수 > .env > 기본값).
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = Path::new(&manifest_dir).parent().unwrap().parent().unwrap();
    let env_path = project_root.join(".env");

    if env_path.exists() {
        dotenvy::from_path(&env_path).ok();
        // .env 파일 변경 시 build.rs 재실행
        println!("cargo:rerun-if-changed={}", env_path.display());
    }

    // === 1. 환경 변수 변경 감지 ===
    let watched_vars = [
        "ZK_MAX_JWT_B64_LEN",
        "ZK_MAX_PAYLOAD_B64_LEN",
        "ZK_MAX_AUD_LEN",
        "ZK_MAX_EXP_LEN",
        "ZK_MAX_ISS_LEN",
        "ZK_MAX_NONCE_LEN",
        "ZK_MAX_SUB_LEN",
        "ZK_N",
        "ZK_K",
        "ZK_TREE_HEIGHT",
        "ZK_NUM_AUDIENCE_LIMIT",
    ];
    for var in watched_vars {
        println!("cargo:rerun-if-env-changed={}", var);
    }

    // === 2. 환경 변수 읽기 (기본값 설정) ===
    // 우선순위: 환경변수(또는 .env에서 로딩된 값) > 하드코딩 기본값
    let max_jwt_len: usize = env::var("ZK_MAX_JWT_B64_LEN").unwrap_or_else(|_| "1024".to_string())
        .parse().expect("ZK_MAX_JWT_B64_LEN must be a valid integer");
    let max_payload_len: usize = env::var("ZK_MAX_PAYLOAD_B64_LEN").unwrap_or_else(|_| "640".to_string())
        .parse().expect("ZK_MAX_PAYLOAD_B64_LEN must be a valid integer");
    let max_aud_len: usize = env::var("ZK_MAX_AUD_LEN").unwrap_or_else(|_| "155".to_string())
        .parse().expect("ZK_MAX_AUD_LEN must be a valid integer");
    let max_exp_len: usize = env::var("ZK_MAX_EXP_LEN").unwrap_or_else(|_| "20".to_string())
        .parse().expect("ZK_MAX_EXP_LEN must be a valid integer");
    let max_iss_len: usize = env::var("ZK_MAX_ISS_LEN").unwrap_or_else(|_| "93".to_string())
        .parse().expect("ZK_MAX_ISS_LEN must be a valid integer");
    let max_nonce_len: usize = env::var("ZK_MAX_NONCE_LEN").unwrap_or_else(|_| "93".to_string())
        .parse().expect("ZK_MAX_NONCE_LEN must be a valid integer");
    let max_sub_len: usize = env::var("ZK_MAX_SUB_LEN").unwrap_or_else(|_| "93".to_string())
        .parse().expect("ZK_MAX_SUB_LEN must be a valid integer");
    let n: usize = env::var("ZK_N").unwrap_or_else(|_| "6".to_string())
        .parse().expect("ZK_N must be a valid integer");
    let k: usize = env::var("ZK_K").unwrap_or_else(|_| "3".to_string())
        .parse().expect("ZK_K must be a valid integer");
    let tree_height: usize = env::var("ZK_TREE_HEIGHT").unwrap_or_else(|_| "4".to_string())
        .parse().expect("ZK_TREE_HEIGHT must be a valid integer");
    let aud_limit: usize = env::var("ZK_NUM_AUDIENCE_LIMIT").unwrap_or_else(|_| "5".to_string())
        .parse().expect("ZK_NUM_AUDIENCE_LIMIT must be a valid integer");

    // === 3. 소스 코드 생성 ===
    let content = format!(
        r#"
        impl ZkPasskeyConfig for ZkapConfig {{
            // === JWT Constraints (Dynamic) ===
            const MAX_JWT_B64_LEN: usize = {max_jwt_len};
            const MAX_PAYLOAD_B64_LEN: usize = {max_payload_len};
            const MAX_AUD_LEN: usize = {max_aud_len};
            const MAX_EXP_LEN: usize = {max_exp_len};
            const MAX_ISS_LEN: usize = {max_iss_len};
            const MAX_NONCE_LEN: usize = {max_nonce_len};
            const MAX_SUB_LEN: usize = {max_sub_len};

            // === Logic Constraints (Dynamic) ===
            const N: usize = {n};
            const K: usize = {k};
            const TREE_HEIGHT: usize = {tree_height};
            const NUM_AUDIENCE_LIMIT: usize = {aud_limit};

            // === Fixed Constraints ===
            const PAD_CHAR: char = '\0';
            const CLAIMS: &'static [&'static str] = &["aud", "exp", "iss", "nonce", "sub"];
            const FORBIDDEN_STRING: &'static str = "forbidden";

            type BigNatParams = BigNat2048Params;
        }}
    "#,
        max_jwt_len = max_jwt_len,
        max_payload_len = max_payload_len,
        max_aud_len = max_aud_len,
        max_exp_len = max_exp_len,
        max_iss_len = max_iss_len,
        max_nonce_len = max_nonce_len,
        max_sub_len = max_sub_len,
        n = n,
        k = k,
        tree_height = tree_height,
        aud_limit = aud_limit
    );

    // === 4. 파일 쓰기 ===
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("generated_config.rs");
    fs::write(&dest_path, content).expect("Could not write generated_config.rs");
}
