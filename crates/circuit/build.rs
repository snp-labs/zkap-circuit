use std::env;
use std::fs;
use std::path::Path;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../build_common.rs"));

fn main() {
    load_dotenv_from_project_root();
    watch_zk_env_vars();

    let (profile_name, p) = resolve_profile();

    // Log active configuration
    println!(
        "cargo:warning=ZK_PROFILE={} | N={} K={} TREE_HEIGHT={} MAX_PAYLOAD_B64_LEN={}",
        profile_name, p.n, p.k, p.tree_height, p.max_payload_b64_len
    );

    // Generate source code
    let content = format!(
        r#"
        impl ZkPasskeyConfig for ZkapConfig {{
            // === JWT Constraints ===
            const MAX_JWT_B64_LEN: usize = {max_jwt_len};
            const MAX_PAYLOAD_B64_LEN: usize = {max_payload_len};
            const MAX_AUD_LEN: usize = {max_aud_len};
            const MAX_EXP_LEN: usize = {max_exp_len};
            const MAX_ISS_LEN: usize = {max_iss_len};
            const MAX_NONCE_LEN: usize = {max_nonce_len};
            const MAX_SUB_LEN: usize = {max_sub_len};

            // === Logic Constraints ===
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
        max_jwt_len = p.max_jwt_b64_len,
        max_payload_len = p.max_payload_b64_len,
        max_aud_len = p.max_aud_len,
        max_exp_len = p.max_exp_len,
        max_iss_len = p.max_iss_len,
        max_nonce_len = p.max_nonce_len,
        max_sub_len = p.max_sub_len,
        n = p.n,
        k = p.k,
        tree_height = p.tree_height,
        aud_limit = p.num_audience_limit
    );

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("generated_config.rs");
    fs::write(&dest_path, content).expect("Could not write generated_config.rs");
}
