//! Shared helpers for the `zkap-cli` binaries.
//!
//! Both `generate_crs` and `generate_hash` need the same three operations:
//!
//! - [`load_config_or_exit`] — load a [`circuit::constants::CircuitConfig`]
//!   from a JSON file, printing a human-readable error and exiting with code 1
//!   on failure.
//! - [`die`] — print an error message to stderr and exit with code 1.
//! - [`write_json_or_exit`] — serialise a value as pretty-printed JSON to a
//!   file path, exiting with code 1 if creation or serialisation fails.
//!
//! Keeping these here removes three identical copy-paste patterns from the
//! binary entry points and gives a single place to change exit behaviour.

use std::path::Path;

use circuit::constants::CircuitConfig;
use serde::Serialize;

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
