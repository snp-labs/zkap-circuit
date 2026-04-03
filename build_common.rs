// Shared ZK profile configuration for build.rs scripts.
// Used by: crates/circuit/build.rs, bindings/wasm/build.rs
// Include via: include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../build_common.rs"));

#[allow(dead_code)]
struct ZkProfile {
    max_jwt_b64_len: usize,
    max_payload_b64_len: usize,
    max_aud_len: usize,
    max_exp_len: usize,
    max_iss_len: usize,
    max_nonce_len: usize,
    max_sub_len: usize,
    n: usize,
    k: usize,
    tree_height: usize,
    num_audience_limit: usize,
}

#[allow(dead_code)]
fn dev_profile() -> ZkProfile {
    ZkProfile {
        max_jwt_b64_len: 1024,
        max_payload_b64_len: 640,
        max_aud_len: 155,
        max_exp_len: 20,
        max_iss_len: 93,
        max_nonce_len: 93,
        max_sub_len: 93,
        n: 6,
        k: 3,
        tree_height: 4,
        num_audience_limit: 5,
    }
}

#[allow(dead_code)]
fn prod_profile() -> ZkProfile {
    ZkProfile {
        max_jwt_b64_len: 1024,
        max_payload_b64_len: 896,
        max_aud_len: 155,
        max_exp_len: 20,
        max_iss_len: 93,
        max_nonce_len: 93,
        max_sub_len: 93,
        n: 6,
        k: 3,
        tree_height: 16,
        num_audience_limit: 5,
    }
}

#[allow(dead_code)]
fn read_env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(val) => val
            .parse()
            .unwrap_or_else(|_| panic!("{} must be a valid integer, got: {}", name, val)),
        Err(_) => default,
    }
}

/// Resolve the active ZK profile from environment variables.
/// Returns (profile_name, resolved_profile) where individual env vars override profile defaults.
#[allow(dead_code)]
fn resolve_profile() -> (String, ZkProfile) {
    let profile_name = std::env::var("ZK_PROFILE").unwrap_or_else(|_| "dev".to_string());
    let base = match profile_name.as_str() {
        "dev" => dev_profile(),
        "prod" => prod_profile(),
        other => panic!(
            "Unknown ZK_PROFILE: '{}'. Valid values: dev, prod",
            other
        ),
    };

    let resolved = ZkProfile {
        max_jwt_b64_len: read_env_usize("ZK_MAX_JWT_B64_LEN", base.max_jwt_b64_len),
        max_payload_b64_len: read_env_usize("ZK_MAX_PAYLOAD_B64_LEN", base.max_payload_b64_len),
        max_aud_len: read_env_usize("ZK_MAX_AUD_LEN", base.max_aud_len),
        max_exp_len: read_env_usize("ZK_MAX_EXP_LEN", base.max_exp_len),
        max_iss_len: read_env_usize("ZK_MAX_ISS_LEN", base.max_iss_len),
        max_nonce_len: read_env_usize("ZK_MAX_NONCE_LEN", base.max_nonce_len),
        max_sub_len: read_env_usize("ZK_MAX_SUB_LEN", base.max_sub_len),
        n: read_env_usize("ZK_N", base.n),
        k: read_env_usize("ZK_K", base.k),
        tree_height: read_env_usize("ZK_TREE_HEIGHT", base.tree_height),
        num_audience_limit: read_env_usize("ZK_NUM_AUDIENCE_LIMIT", base.num_audience_limit),
    };

    // Validate constraints
    assert!(resolved.k >= 1, "ZK_K must be >= 1, got: {}", resolved.k);
    assert!(resolved.k <= resolved.n, "ZK_K ({}) must be <= ZK_N ({})", resolved.k, resolved.n);
    assert!(resolved.n >= 1, "ZK_N must be >= 1, got: {}", resolved.n);
    assert!(resolved.tree_height >= 1, "ZK_TREE_HEIGHT must be >= 1, got: {}", resolved.tree_height);
    assert!(
        resolved.max_payload_b64_len <= resolved.max_jwt_b64_len,
        "ZK_MAX_PAYLOAD_B64_LEN ({}) must be <= ZK_MAX_JWT_B64_LEN ({})",
        resolved.max_payload_b64_len, resolved.max_jwt_b64_len
    );
    assert!(resolved.num_audience_limit >= 1, "ZK_NUM_AUDIENCE_LIMIT must be >= 1, got: {}", resolved.num_audience_limit);

    (profile_name, resolved)
}

/// Watch all ZK_* environment variables for cargo rebuild.
#[allow(dead_code)]
fn watch_zk_env_vars() {
    let watched_vars = [
        "ZK_PROFILE",
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
}

/// Load .env from project root if it exists.
#[allow(dead_code)]
fn load_dotenv_from_project_root() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // Walk up to find project root (where Cargo.toml has [workspace])
    let mut dir = std::path::Path::new(&manifest_dir);
    loop {
        let env_path = dir.join(".env");
        if env_path.exists() {
            dotenvy::from_path(&env_path).ok();
            println!("cargo:rerun-if-changed={}", env_path.display());
            break;
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }
}
