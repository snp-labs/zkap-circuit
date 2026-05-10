//! Shared helpers for the `zkap-cli` binaries.
//!
//! Process-control / config loaders shared by `generate_crs` and `generate_hash`:
//!
//! - [`load_config_or_exit`] — load a [`circuit::types::CircuitConfig`]
//!   from a JSON file, printing a human-readable error and exiting with code 1
//!   on failure.
//! - [`die`] — print an error message to stderr and exit with code 1.
//! - [`write_json_or_exit`] — serialise a value as pretty-printed JSON to a
//!   file path, exiting with code 1 if creation or serialisation fails.
//!
//! Host-side build helpers used by `generate_setup` (port of the host-side
//! checks previously implemented in `crates/zkap-witness-wasm/build-wasm.sh`):
//!
//! - [`read_arzkey_blake3`] — extract bytes 16..48 (`ar1cs_blake3`) from an
//!   `.arzkey` header, validating the `ARZKEY` magic.
//! - [`verify_wasm_exports`] — parse a wasm module and confirm that all
//!   `required` export names are present in its export section.
//! - [`sha256_hex`] — sha256 fingerprint of a file as a 64-char hex string.
//!
//! Keeping these here removes copy-paste patterns from the binary entry points
//! and gives a single place to change exit behaviour.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use circuit::types::CircuitConfig;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Print `msg` to stderr and exit the process with code 1.
///
/// Prefer this over `panic!` in binary entry points so the error appears on
/// stderr without a Rust backtrace.
pub fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("{}", msg);
    std::process::exit(1);
}

/// Load a [`CircuitConfig`] from a JSON file at `path`.
///
/// On any error (missing file, parse failure, validation failure) the function
/// prints a human-readable message to stderr and exits with code 1.
pub fn load_config_or_exit(path: &Path) -> CircuitConfig {
    zkap_service::load_circuit_config(path).unwrap_or_else(|e| {
        die(format!(
            "Failed to load config from {}: {}",
            path.display(),
            e
        ))
    })
}

/// Serialise `data` as pretty-printed JSON and write it to `path`.
///
/// On any error (file creation failure, serialisation failure) the function
/// prints a human-readable message to stderr and exits with code 1.
pub fn write_json_or_exit<T: Serialize>(path: &str, data: &T) {
    let file = std::fs::File::create(path)
        .unwrap_or_else(|e| die(format!("Failed to create output file '{}': {}", path, e)));
    serde_json::to_writer_pretty(file, data)
        .unwrap_or_else(|e| die(format!("Failed to write JSON to '{}': {}", path, e)));
}

/// Read bytes 16..48 (`ar1cs_blake3`) from an `.arzkey` header.
///
/// Validates that the file starts with the 6-byte `ARZKEY` magic and is
/// at least 48 bytes long. Returns the 32-byte `ar1cs_blake3` constant
/// embedded by `ark-ar1cs-zkey` into the file's header — the same value
/// `crates/zkap-witness-wasm/build.rs` reads via the
/// `AR1CS_WITNESS_ARZKEY_PATH` env var to bake the wasm-side
/// `embedded_ar1cs_blake3` constant.
///
/// Mirrors the `dd if=arzkey bs=1 skip=16 count=32` step in
/// `crates/zkap-witness-wasm/build-wasm.sh`'s "Pair / fingerprint identity"
/// block. On any I/O or validation failure the function prints to stderr
/// and exits with code 1 (the binary entry-point convention used by the
/// other helpers in this module).
pub fn read_arzkey_blake3(path: &Path) -> [u8; 32] {
    let mut file = std::fs::File::open(path)
        .unwrap_or_else(|e| die(format!("Failed to open arzkey '{}': {}", path.display(), e)));
    let mut header = [0u8; 48];
    file.read_exact(&mut header).unwrap_or_else(|e| {
        die(format!(
            "Failed to read 48-byte arzkey header from '{}': {}",
            path.display(),
            e
        ))
    });
    if &header[0..6] != b"ARZKEY" {
        die(format!(
            "'{}' does not start with ARZKEY magic",
            path.display()
        ));
    }
    let mut blake3 = [0u8; 32];
    blake3.copy_from_slice(&header[16..48]);
    blake3
}

/// Verify that the wasm module at `path` exports every name in `required`.
///
/// Parses the binary with `wasmparser` and walks its export section,
/// returning `Err(_)` listing any names that were not found. Equivalent to
/// `crates/zkap-witness-wasm/build-wasm.sh`'s
/// `verify_exports_with_wasm_tools` check, but without the external
/// `wasm-tools` dependency.
pub fn verify_wasm_exports(path: &Path, required: &[&str]) -> Result<(), String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("Failed to read wasm '{}': {}", path.display(), e))?;
    let mut found: HashSet<&str> = HashSet::new();
    for payload in wasmparser::Parser::new(0).parse_all(&bytes) {
        let payload = payload
            .map_err(|e| format!("wasmparser parse error in '{}': {}", path.display(), e))?;
        if let wasmparser::Payload::ExportSection(reader) = payload {
            for export in reader {
                let export = export.map_err(|e| {
                    format!("wasmparser export error in '{}': {}", path.display(), e)
                })?;
                if let Some(&want) = required.iter().find(|w| **w == export.name) {
                    found.insert(want);
                }
            }
        }
    }
    let missing: Vec<&str> = required
        .iter()
        .filter(|w| !found.contains(*w))
        .copied()
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("missing exports: {:?}", missing))
    }
}

/// Compute the sha256 of the file at `path` and return it as a lowercase
/// hex string.
///
/// Streams the file in 64 KiB chunks so the wasm artifact (≤ 8 MiB) does
/// not need to be held in memory twice (once for `verify_wasm_exports`,
/// once for the digest).
pub fn sha256_hex(path: &Path) -> Result<String, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}
