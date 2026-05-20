//! CRS persistence — serialise a [`SetupOutput`] to disk under the
//! post-migration bundle layout.
//!
//! # Bundle layout (Commit 2 of the 2026-05 ark-ar1cs boundary migration)
//!
//! [`persist_setup_output`] writes six files into a target directory:
//!
//! | File                  | Content                                                          |
//! |-----------------------|------------------------------------------------------------------|
//! | `circuit.ar1cs`       | R1CS body in ark-ar1cs canonical envelope (`ArcsFile::write`)    |
//! | `pk.bin`              | Proving key (arkworks `CanonicalSerialize` uncompressed)         |
//! | `vk.bin`              | Verifying key (arkworks `CanonicalSerialize` uncompressed)       |
//! | `pvk.bin`             | Prepared verifying key (arkworks `CanonicalSerialize`)           |
//! | `Groth16Verifier.sol` | Solidity on-chain verifier contract                              |
//! | `config.json`         | Circuit configuration in `CircuitConfig` JSON                    |
//!
//! `manifest.json` is the seventh bundle file but is produced by the CLI
//! (`generate_setup`) — it carries build/commit metadata that the
//! service does not own.
//!
//! Earlier filenames and the wasm witness substrate that pre-dated the
//! 2026-05 ark-ar1cs boundary migration are no longer written; the
//! seven entries above are the entire bundle contract enforced by
//! `scripts/check-bundle-layout.sh`.

use std::io::Cursor;
use std::path::Path;

use ark_ar1cs::format::ArcsFile;
use ark_serialize::CanonicalSerialize;
use circuit::types::{CircuitConfig, F};
use zkap_evm_verifier::SolidityContractGenerator;

use crate::error::ApplicationError;
use crate::groth16::setup::SetupOutput;

// ── Atomic write helper ───────────────────────────────────────────────────────

/// Write `bytes` to `path` atomically via a sibling temp file and rename.
///
/// Creates `<path>.tmp.<pid>` in the same directory, writes `bytes` to it,
/// then renames it onto `path`.  If either step fails the temp file is
/// removed and the original `path` is left untouched.  All failures surface
/// as [`ApplicationError::Io`].
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ApplicationError> {
    let tmp_path = {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("artifact");
        let dir = path.parent().unwrap_or(Path::new("."));
        dir.join(format!(".{}.tmp.{}", file_name, std::process::id()))
    };

    if let Err(e) = std::fs::write(&tmp_path, bytes) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(ApplicationError::Io(e));
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(ApplicationError::Io(e));
    }
    Ok(())
}

// ── Internal API (called by setup()) ─────────────────────────────────────────

/// Persist a [`SetupOutput`] and the originating [`CircuitConfig`] to
/// `output_dir` under the post-migration bundle layout.
///
/// Creates `output_dir` if it does not already exist, then writes six
/// files (see module-level table). Called internally by
/// [`crate::groth16::setup::setup`].
pub(crate) fn persist_setup_output(
    setup: &SetupOutput,
    config: &CircuitConfig,
    output_dir: &Path,
    arcs: &ArcsFile<F>,
) -> Result<(), ApplicationError> {
    std::fs::create_dir_all(output_dir)?;

    write_canonical_uncompressed(&setup.pk, &output_dir.join("pk.bin"), "pk.bin")?;
    write_canonical_uncompressed(&setup.vk, &output_dir.join("vk.bin"), "vk.bin")?;
    write_canonical_uncompressed(&setup.pvk, &output_dir.join("pvk.bin"), "pvk.bin")?;

    write_arcs(arcs, &output_dir.join("circuit.ar1cs"))?;

    // `generate_solidity` returns `std::io::Error`; surface it through the
    // typed `Io` variant rather than collapsing into `Other(String)` so
    // callers can match on `source()` like every other IO failure here.
    // Write via a temp path and rename to preserve atomicity.
    write_solidity_atomic(&setup.vk, &output_dir.join("Groth16Verifier.sol"))?;

    write_config_json(config, &output_dir.join("config.json"))?;

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────
//
// Every IO/serialize failure below funnels through `ApplicationError::Io`
// (via `?`) instead of `Other(format!(...))`, so callers see a uniform
// `std::io::Error` source chain. arkworks' `SerializationError` and
// `serde_json::Error` are wrapped in `io::Error::other` to preserve that
// uniformity without inventing a new variant.

fn write_solidity_atomic(
    vk: &ark_groth16::VerifyingKey<circuit::types::BN254>,
    path: &Path,
) -> Result<(), ApplicationError> {
    let tmp_path = {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Groth16Verifier.sol");
        let dir = path.parent().unwrap_or(Path::new("."));
        dir.join(format!(".{}.tmp.{}", file_name, std::process::id()))
    };
    if let Err(e) = vk.generate_solidity(&tmp_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(ApplicationError::Io(e));
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(ApplicationError::Io(e));
    }
    Ok(())
}

fn write_canonical_uncompressed<T: CanonicalSerialize>(
    value: &T,
    path: &Path,
    label: &str,
) -> Result<(), ApplicationError> {
    let mut cursor = Cursor::new(Vec::new());
    value
        .serialize_uncompressed(&mut cursor)
        .map_err(|e| std::io::Error::other(format!("serialize {label}: {e}")))?;
    atomic_write(path, cursor.get_ref())?;
    Ok(())
}

fn write_arcs(arcs: &ArcsFile<F>, path: &Path) -> Result<(), ApplicationError> {
    let mut cursor = Cursor::new(Vec::new());
    arcs.write(&mut cursor)
        .map_err(|e| std::io::Error::other(format!("ArcsFile::write: {e}")))?;
    atomic_write(path, cursor.get_ref())?;
    Ok(())
}

fn write_config_json(config: &CircuitConfig, path: &Path) -> Result<(), ApplicationError> {
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| std::io::Error::other(format!("serialize config.json: {e}")))?;
    atomic_write(path, json.as_bytes())?;
    Ok(())
}
