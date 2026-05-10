//! Embed the `.arzkey` `ar1cs_blake3` constant at build time.
//!
//! `AR1CS_WITNESS_ARZKEY_PATH` is REQUIRED for `target_arch = "wasm32"`
//! builds. The `.wasm` artifact is always shipped paired with its
//! `.arzkey`, and pair verification at runtime is
//! `embedded_ar1cs_blake3 == arzkey.header.ar1cs_blake3`. Embedding a
//! sentinel/placeholder value would silently turn the cross-check into a
//! no-op for circuits that happen to share the placeholder; build.rs
//! therefore aborts on wasm32 when the env var is missing so the failure
//! mode is a hard build error, not a runtime hash mismatch.
//!
//! Native (non-wasm32) builds — produced for `cargo test`, the rlib used
//! by integration tests, etc. — never expose the wasm `extern "C"` exports
//! and therefore never read the embedded constant from anywhere
//! load-bearing. To break the chicken-and-egg between the integration test
//! (which generates its own `.arzkey` at runtime) and this build script
//! (which runs before any test code), the native code path falls back to a
//! zero blake3 with an informational `cargo:warning=` when the env var is
//! unset. The wasm32 path keeps its hard-fail.
//!
//! Reads ONLY the first 48 bytes of the `.arzkey` (header layout is
//! documented in `ark-ar1cs-zkey/src/header.rs`):
//!
//! ```text
//!   offset  0.. 6  "ARZKEY"
//!   offset  6.. 7  version
//!   offset  7.. 8  curve_id
//!   offset  8..16  reserved
//!   offset 16..48  ar1cs_blake3
//! ```
//!
//! Full `.arzkey` deserialization is intentionally avoided — this script
//! must remain compatible with files much larger than the wasm artifact
//! itself (PK + VK sections), and only needs the 32-byte circuit identity.

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

const ENV_VAR: &str = "AR1CS_WITNESS_ARZKEY_PATH";
const HEADER_PROBE_LEN: usize = 48;
const ARZKEY_MAGIC: &[u8; 6] = b"ARZKEY";
const BLAKE3_OFFSET: usize = 16;

fn main() {
    println!("cargo:rerun-if-env-changed={}", ENV_VAR);

    // Only the wasm32 build embeds a load-bearing blake3 constant — native
    // builds never expose the wasm exports that read it. Constraining the
    // hard-fail to wasm32 lets `cargo test` (native rlib build) compile so
    // that `tests/wasm_to_prove.rs` can generate its own `.arzkey` at
    // runtime and respawn cargo against the wasm32 target with the right
    // env var.
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");
    let is_wasm = target_arch == "wasm32";

    let blake3 = match env::var(ENV_VAR) {
        Ok(path) => {
            println!("cargo:rerun-if-changed={}", path);
            read_blake3_from_arzkey(&path)
        }
        Err(_) if is_wasm => {
            // Wasm artifact ships paired with .arzkey; refuse a placeholder.
            panic!(
                "{} is required for target_arch = wasm32 (path to the .arzkey \
                 this wasm is paired with). The build refuses to embed a \
                 placeholder blake3.",
                ENV_VAR
            );
        }
        Err(_) => {
            println!(
                "cargo:warning={} unset; non-wasm build is using a zero blake3 \
                 placeholder. The constant is not read on non-wasm targets, but \
                 production wasm builds MUST set this to the matching .arzkey.",
                ENV_VAR
            );
            [0u8; 32]
        }
    };

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR not set");
    let out_path = PathBuf::from(out_dir).join("embedded.rs");

    let mut hex_literals = String::new();
    for (i, byte) in blake3.iter().enumerate() {
        if i > 0 {
            hex_literals.push_str(", ");
        }
        hex_literals.push_str(&format!("0x{:02x}", byte));
    }
    let content = format!(
        "/// blake3 of the canonical `.ar1cs` body this wasm is paired with.\n\
         /// Bound at build time from $AR1CS_WITNESS_ARZKEY_PATH (REQUIRED).\n\
         pub const EMBEDDED_AR1CS_BLAKE3: [u8; 32] = [{}];\n",
        hex_literals
    );

    let mut f = File::create(&out_path).expect("cannot open OUT_DIR/embedded.rs for write");
    f.write_all(content.as_bytes())
        .expect("write OUT_DIR/embedded.rs failed");
}

fn read_blake3_from_arzkey(path: &str) -> [u8; 32] {
    let mut f = File::open(path).unwrap_or_else(|e| {
        panic!("cannot open `{}` (set via {}): {}", path, ENV_VAR, e);
    });
    let mut buf = [0u8; HEADER_PROBE_LEN];
    f.read_exact(&mut buf)
        .unwrap_or_else(|e| panic!("`{}` shorter than 48-byte header probe: {}", path, e));
    if &buf[0..6] != ARZKEY_MAGIC {
        panic!(
            "`{}` does not start with ARZKEY magic; got {:02x?}",
            path,
            &buf[0..6]
        );
    }
    buf[BLAKE3_OFFSET..BLAKE3_OFFSET + 32]
        .try_into()
        .expect("48-byte buf has 32 bytes at offset 16")
}
