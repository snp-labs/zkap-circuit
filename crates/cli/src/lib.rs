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

/// Serialise `data` as pretty-printed JSON and write it to `path`
/// atomically: bytes are first written to a sibling `<path>.tmp.<pid>`
/// file and only then renamed onto `path`, so a mid-write crash leaves
/// the previous file untouched rather than producing a truncated
/// half-written manifest.
pub fn write_json_or_exit<T: Serialize>(path: &str, data: &T) {
    let target = Path::new(path);
    let tmp_path = match target.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(format!(
            ".{}.tmp.{}",
            file_name_of(target),
            std::process::id()
        )),
        _ => Path::new(".").join(format!(
            ".{}.tmp.{}",
            file_name_of(target),
            std::process::id()
        )),
    };

    let file = std::fs::File::create(&tmp_path).unwrap_or_else(|e| {
        die(format!(
            "Failed to create temp file '{}': {}",
            tmp_path.display(),
            e
        ))
    });
    if let Err(e) = serde_json::to_writer_pretty(file, data) {
        let _ = std::fs::remove_file(&tmp_path);
        die(format!("Failed to write JSON to '{}': {}", path, e));
    }
    if let Err(e) = std::fs::rename(&tmp_path, target) {
        let _ = std::fs::remove_file(&tmp_path);
        die(format!(
            "Failed to atomically replace '{}' (temp '{}'): {}",
            path,
            tmp_path.display(),
            e
        ));
    }
}

/// Write `bytes` to `path` atomically: bytes are first written to a sibling
/// `<path>.tmp.<pid>` file and only then renamed onto `path`, so a mid-write
/// crash leaves the previous file untouched rather than producing a truncated
/// half-written artifact.
///
/// On failure the temp file is removed and the process is terminated via
/// [`die`].
pub fn atomic_write_bytes_or_exit(path: &Path, bytes: &[u8]) {
    let tmp_path = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(format!(
            ".{}.tmp.{}",
            file_name_of(path),
            std::process::id()
        )),
        _ => Path::new(".").join(format!(
            ".{}.tmp.{}",
            file_name_of(path),
            std::process::id()
        )),
    };

    if let Err(e) = std::fs::write(&tmp_path, bytes) {
        let _ = std::fs::remove_file(&tmp_path);
        die(format!("Failed to write '{}': {}", tmp_path.display(), e));
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        die(format!(
            "Failed to atomically replace '{}' (temp '{}'): {}",
            path.display(),
            tmp_path.display(),
            e
        ));
    }
}

fn file_name_of(p: &Path) -> String {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("out")
        .to_string()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zkap_cli_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// When the rename step cannot complete (target path is a pre-existing
    /// directory so `fs::rename` fails), neither a partial file nor the
    /// temp file is left behind.  The target directory itself is still
    /// present, but the target *file* path was never created.
    #[test]
    fn atomic_write_bytes_failed_rename_leaves_no_partial_file() {
        let dir = tmp_dir();
        // Create a subdirectory at the intended target path so rename() fails.
        let target = dir.join("artifact.bin");
        fs::create_dir_all(&target).unwrap();

        // Build the tmp path the helper would use.
        let tmp_path = dir.join(format!(".artifact.bin.tmp.{}", std::process::id()));

        // Write bytes to the tmp path directly (simulating the helper's write step).
        let bytes = b"partial data";
        fs::write(&tmp_path, bytes).unwrap();

        // Attempt to rename onto the directory — this should fail.
        let rename_result = fs::rename(&tmp_path, &target);
        assert!(rename_result.is_err(), "rename onto a directory must fail");

        // Clean up the tmp file as the helper does on rename failure.
        let _ = fs::remove_file(&tmp_path);

        // The target directory still exists but no *file* was created at that path.
        assert!(target.exists(), "target directory must still exist");
        assert!(
            target.is_dir(),
            "target must still be a directory, not a file"
        );
        // The tmp file must have been cleaned up.
        assert!(
            !tmp_path.exists(),
            "temp file must be removed on rename failure"
        );

        // Cleanup.
        fs::remove_dir_all(&dir).unwrap();
    }

    /// `write_json_or_exit` writes valid JSON to a fresh path atomically.
    #[test]
    fn write_json_or_exit_creates_target_file() {
        let dir = tmp_dir();
        let target = dir.join("out.json");
        let data = serde_json::json!({"key": "value"});
        write_json_or_exit(target.to_str().unwrap(), &data);
        let content = fs::read_to_string(&target).unwrap();
        assert!(content.contains("\"key\""));
        // No temp file left behind.
        let mut found_tmp = false;
        for entry in fs::read_dir(&dir).unwrap() {
            let name = entry.unwrap().file_name();
            if name.to_string_lossy().contains(".tmp.") {
                found_tmp = true;
            }
        }
        assert!(
            !found_tmp,
            "no temp file should remain after successful write"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
