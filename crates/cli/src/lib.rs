//! Shared helpers for the `zkap-cli` binaries.
//!
//! Process-control / config loaders shared by `generate_setup` and
//! `generate_hash`:
//!
//! - [`load_config_or_exit`] — load a [`circuit::types::CircuitConfig`]
//!   from a JSON file, printing a human-readable error and exiting with
//!   code 1 on failure.
//! - [`die`] — print an error message to stderr and exit with code 1.
//! - [`write_json_or_exit`] — serialise a value as pretty-printed JSON
//!   to a file path, exiting with code 1 on failure.
//!
//! Host-side helpers used by `generate_setup` to populate
//! `manifest.json`:
//!
//! - [`read_arcs_blake3`] — open `circuit.ar1cs` via
//!   [`ark_ar1cs::format::ArcsFile`], return the 32-byte canonical
//!   `body_blake3()`.
//! - [`read_arcs_blake3_hex`] — `read_arcs_blake3` as a 64-char hex
//!   string (the form `manifest.ar1cs_blake3` uses).
//! - [`sha256_hex`] — sha256 fingerprint of a file as 64-char hex.
//! - [`built_at_now`] — `manifest.build.built_at` RFC3339 timestamp with
//!   `SOURCE_DATE_EPOCH` reproducible-builds support.
//!
//! Manifest schema, builder, and provenance types are re-exported from
//! [`zkap_service::manifest`]; the cli no longer owns its own schema.

use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use circuit::types::{CircuitConfig, F};
use serde::Serialize;
use sha2::{Digest, Sha256};

// Manifest schema lives in `zkap-service` after the 2026-05 boundary
// migration (Commit 2). Re-export the public surface the existing CLI
// binaries and the `manifest_golden` test suite consume.
pub use zkap_service::manifest::{
    ArtifactEntry, ArtifactKey, Artifacts, BuildMetadata, BuilderError, ContributionPublicKeyJson,
    Manifest, ManifestBuilder, ManifestError, Phase2Attestation, PtauRef, SetupProvenance, Shape,
    ToxicWasteDisclosure, canonical_json_bytes, compute_circuit_tag, derive_toxic_waste_disclosure,
    sign_manifest, verify_manifest,
};

/// Print `msg` to stderr and exit the process with code 1.
pub fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("{}", msg);
    std::process::exit(1);
}

/// Load a [`CircuitConfig`] from a JSON file at `path`.
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
pub fn write_json_or_exit<T: Serialize>(path: &str, data: &T) {
    let file = std::fs::File::create(path)
        .unwrap_or_else(|e| die(format!("Failed to create output file '{}': {}", path, e)));
    serde_json::to_writer_pretty(file, data)
        .unwrap_or_else(|e| die(format!("Failed to write JSON to '{}': {}", path, e)));
}

/// Read `circuit.ar1cs` at `path` and return its canonical
/// `body_blake3()` — the 32-byte hash that pins the R1CS body's
/// identity.
///
/// Calls [`ark_ar1cs::format::ArcsFile::read`] internally so the body's
/// self-consistency is validated as a side effect: a malformed
/// `.ar1cs` aborts with a clear error before any hash is returned.
pub fn read_arcs_blake3(path: &Path) -> [u8; 32] {
    let mut file = std::fs::File::open(path).unwrap_or_else(|e| {
        die(format!(
            "Failed to open circuit.ar1cs '{}': {}",
            path.display(),
            e
        ))
    });
    let arcs = ark_ar1cs::format::ArcsFile::<F>::read(&mut file).unwrap_or_else(|e| {
        die(format!(
            "Failed to parse circuit.ar1cs '{}': {}",
            path.display(),
            e
        ))
    });
    arcs.body_blake3()
}

/// [`read_arcs_blake3`] rendered as a 64-char lowercase hex string —
/// the form `manifest.ar1cs_blake3` uses.
pub fn read_arcs_blake3_hex(path: &Path) -> String {
    hex::encode(read_arcs_blake3(path))
}

/// RFC3339 UTC timestamp for `manifest.json#/build/built_at`.
/// Reads `SOURCE_DATE_EPOCH` (Debian reproducible-builds convention)
/// when set; otherwise wallclock. Returns `Err` only when
/// `SOURCE_DATE_EPOCH` is set but not a valid unix-seconds integer.
pub fn built_at_now() -> Result<String, String> {
    let secs = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(raw) => raw.parse::<i64>().map_err(|e| {
            format!("SOURCE_DATE_EPOCH ({raw:?}) is not a valid unix timestamp: {e}")
        })?,
        Err(_) => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("system clock pre-dates UNIX_EPOCH: {e}"))?
            .as_secs() as i64,
    };
    let dt = time::OffsetDateTime::from_unix_timestamp(secs).map_err(|e| {
        format!("SOURCE_DATE_EPOCH ({secs}) is outside the supported time range: {e}")
    })?;
    dt.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| format!("RFC3339 format failure: {e}"))
}

/// Compute the sha256 of the file at `path` and return it as a lowercase
/// hex string.
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
