//! Emits build-time env vars consumed by `generate_setup` for
//! `manifest.json#/build`: `ZKAP_CLI_RUSTC_VERSION` (rustc --version)
//! and `ZKAP_CLI_ARK_AR1CS_REV` (the `ark-ar1cs` workspace git rev).
//! On parse failure either value falls back to `"unknown"`; a cargo
//! warning is emitted so the regression is visible at build time,
//! and `tests/build_meta.rs` re-asserts at test time.

use std::path::Path;
use std::process::Command;

fn main() {
    let workspace_cargo_toml = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("Cargo.toml"))
        .expect("workspace root is two parents up from crates/cli");
    println!("cargo:rerun-if-changed={}", workspace_cargo_toml.display());
    println!("cargo:rerun-if-env-changed=RUSTC");

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let rustc_version = Command::new(&rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            println!(
                "cargo:warning=zkap-cli build.rs: `rustc --version` failed; ZKAP_CLI_RUSTC_VERSION=unknown"
            );
            "unknown".into()
        });
    println!("cargo:rustc-env=ZKAP_CLI_RUSTC_VERSION={rustc_version}");

    let ark_rev = std::fs::read_to_string(&workspace_cargo_toml)
        .ok()
        .as_deref()
        .and_then(parse_ark_ar1cs_rev)
        .unwrap_or_else(|| {
            println!(
                "cargo:warning=zkap-cli build.rs: failed to parse `ark-ar1cs` rev from workspace Cargo.toml; ZKAP_CLI_ARK_AR1CS_REV=unknown"
            );
            "unknown".into()
        });
    println!("cargo:rustc-env=ZKAP_CLI_ARK_AR1CS_REV={ark_rev}");
}

/// Pull the first `rev = "…"` off any line whose dep-name starts with
/// `ark-ar1cs`. Originally this filtered on `ark-ar1cs-` (with trailing
/// hyphen) when the upstream was split into `ark-ar1cs-format`/`-prover`/
/// `-zkey` crates; those have since been fused into a single root
/// `ark-ar1cs` crate, so the filter is now a prefix-only check.
fn parse_ark_ar1cs_rev(toml: &str) -> Option<String> {
    for line in toml.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("ark-ar1cs") {
            continue;
        }
        let needle = "rev = \"";
        let idx = trimmed.find(needle)?;
        let after = &trimmed[idx + needle.len()..];
        let end = after.find('"')?;
        return Some(after[..end].to_string());
    }
    None
}
