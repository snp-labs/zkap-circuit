// 파일 경로: zkup/common/build.rs
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // === 1. 환경 변수 읽기 (기본값 설정) ===
    // [확인용] 빌드 로그에 노란색 경고 메시지로 출력됩니다.
    println!(
        "cargo:warning=Build script is RUNNING! ENV_N={:?}",
        std::env::var("ZK_N")
    );

    // [필수] 환경 변수 변경 감지 (이게 있어야 매번 제대로 실행됨)
    println!("cargo:rerun-if-env-changed=ZK_MAX_JWT_B64_LEN");
    println!("cargo:rerun-if-env-changed=ZK_MAX_PAYLOAD_B64_LEN");
    println!("cargo:rerun-if-env-changed=ZK_MAX_AUD_LEN");
    println!("cargo:rerun-if-env-changed=ZK_MAX_EXP_LEN");
    println!("cargo:rerun-if-env-changed=ZK_MAX_ISS_LEN");
    println!("cargo:rerun-if-env-changed=ZK_MAX_NONCE_LEN");
    println!("cargo:rerun-if-env-changed=ZK_MAX_SUB_LEN");
    println!("cargo:rerun-if-env-changed=ZK_N");
    println!("cargo:rerun-if-env-changed=ZK_K");
    println!("cargo:rerun-if-env-changed=ZK_TREE_HEIGHT");
    println!("cargo:rerun-if-env-changed=ZK_AUD_LIMIT");

    // [JWT Constraints]
    let max_jwt_len = env::var("ZK_MAX_JWT_B64_LEN").unwrap_or_else(|_| "1024".to_string());
    let max_payload_len = env::var("ZK_MAX_PAYLOAD_B64_LEN").unwrap_or_else(|_| "640".to_string());
    let max_aud_len = env::var("ZK_MAX_AUD_LEN").unwrap_or_else(|_| "155".to_string());
    let max_exp_len = env::var("ZK_MAX_EXP_LEN").unwrap_or_else(|_| "20".to_string());
    let max_iss_len = env::var("ZK_MAX_ISS_LEN").unwrap_or_else(|_| "93".to_string());
    let max_nonce_len = env::var("ZK_MAX_NONCE_LEN").unwrap_or_else(|_| "93".to_string());
    let max_sub_len = env::var("ZK_MAX_SUB_LEN").unwrap_or_else(|_| "93".to_string());

    // [Logic Constraints]
    let n = env::var("ZK_N").unwrap_or_else(|_| "6".to_string());
    let k = env::var("ZK_K").unwrap_or_else(|_| "3".to_string());
    let tree_height = env::var("ZK_TREE_HEIGHT").unwrap_or_else(|_| "4".to_string());
    let aud_limit = env::var("ZK_AUD_LIMIT").unwrap_or_else(|_| "5".to_string());

    // === 2. 소스 코드 생성 ===
    // PAD_CHAR는 '\0'으로 고정됩니다.
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

    // === 3. 파일 쓰기 ===
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("generated_config.rs");
    fs::write(&dest_path, content).expect("Could not write generated_config.rs");

    // === 4. Re-run Trigger 등록 ===
    // 이 환경 변수들이 바뀔 때만 cargo가 재컴파일을 수행합니다.
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
        "ZK_AUD_LIMIT",
    ];
    for var in watched_vars {
        println!("cargo:rerun-if-env-changed={}", var);
    }
}
