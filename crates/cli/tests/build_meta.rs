//! Regression gate for `build.rs` provenance env vars.
//!
//! Both `ZKAP_CLI_RUSTC_VERSION` and `ZKAP_CLI_ARK_AR1CS_REV` are baked
//! into every `manifest.json` emitted by `generate_setup`. The build
//! script falls back to the string `"unknown"` on parse failure so the
//! manifest still emits, but a `"unknown"` rev silently drops the
//! ark-ar1cs provenance from the bundle. These tests pin the fallback
//! to genuine failures (network-isolated CI / missing rustc), not to a
//! parser bug in `build.rs`.

#[test]
fn rustc_version_env_is_populated() {
    let v = env!("ZKAP_CLI_RUSTC_VERSION");
    assert_ne!(
        v, "unknown",
        "ZKAP_CLI_RUSTC_VERSION fell back to \"unknown\" — `rustc --version` failed at build time"
    );
    assert!(
        v.contains("rustc"),
        "ZKAP_CLI_RUSTC_VERSION should contain \"rustc\", got {v:?}"
    );
}

#[test]
fn ark_ar1cs_rev_env_is_populated() {
    let v = env!("ZKAP_CLI_ARK_AR1CS_REV");
    assert_ne!(
        v, "unknown",
        "ZKAP_CLI_ARK_AR1CS_REV fell back to \"unknown\" — workspace Cargo.toml parser in \
         build.rs did not match the `ark-ar1cs` dep line"
    );
    // ark-ar1cs rev is a git short or full SHA; require it to be at least
    // 7 hex chars and entirely hex digits.
    assert!(
        v.len() >= 7 && v.chars().all(|c| c.is_ascii_hexdigit()),
        "ZKAP_CLI_ARK_AR1CS_REV is not a hex-only git rev, got {v:?}"
    );
}
