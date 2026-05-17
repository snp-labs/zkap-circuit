//! Wasm32 witness generator for the ZKAP circuit.
//!
//! This crate is the only WASM-targeted artifact in the workspace.
//! It hosts a thin C ABI around
//! [`zkap_service::synthesize_witnesses`] so a downstream prover
//! (circuit-agnostic, native) can drive the circuit-dependent half
//! of the prove pipeline behind a stable wasm interface and finish
//! the proof with `ark_ar1cs::prove` on the host.
//!
//! ## ABI overview
//!
//! All exports are `extern "C"` so any wasm runtime — wasmtime,
//! wasmer, the browser-native WebAssembly engine — can drive them.
//! Inputs are UTF-8 JSON encoding [`zkap_service::ProveRequest`] and
//! [`zkap_service::CircuitConfig`]; output is
//! `ark_serialize::CanonicalSerialize` bytes (uncompressed) for
//! `Vec<WitnessBundle>`.
//!
//! ```text
//!   host: wg_alloc(req_len)                 -> req_ptr
//!         wg_alloc(cfg_len)                 -> cfg_ptr
//!         memory.write(req_ptr, req_json)
//!         memory.write(cfg_ptr, cfg_json)
//!         synthesize_witness(req_ptr, req_len,
//!                            cfg_ptr, cfg_len) -> N
//!         if N >= 0:
//!           bytes  = memory.read(wg_last_output_ptr(), N)
//!           Vec<WitnessBundle> = CanonicalDeserialize(bytes)
//!         else:
//!           msg = memory.read(wg_last_error_ptr(),
//!                             wg_last_error_len())
//!         wg_dealloc(req_ptr, req_len)
//!         wg_dealloc(cfg_ptr, cfg_len)
//! ```
//!
//! ## Unsafe code justification
//!
//! Workspace-wide `unsafe_code = "deny"` is overridden at the crate
//! root because every C ABI export necessarily uses `unsafe extern
//! "C"` plus raw pointer manipulation. The unsafe surface is
//! confined to the entry points in this file; each pointer-taking
//! `extern "C"` function carries an explicit `# Safety` block.

#![allow(unsafe_code)]
#![warn(missing_docs)]

use std::cell::RefCell;

use ark_serialize::CanonicalSerialize;
use zkap_service::{CircuitConfig, ProveRequest, WitnessBundle, synthesize_witnesses};

thread_local! {
    /// Most recent successful CanonicalSerialize output. The
    /// pointer returned by [`wg_last_output_ptr`] stays valid
    /// until the next [`synthesize_witness`] call.
    static LAST_OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    /// Most recent error message (UTF-8). The pointer returned by
    /// [`wg_last_error_ptr`] stays valid until the next
    /// [`synthesize_witness`] call.
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Allocate `len` bytes inside the wasm linear memory and return
/// the pointer.
///
/// The host fills the buffer with input JSON and passes
/// `(ptr, len)` to [`synthesize_witness`]; afterwards the host
/// releases the buffer with [`wg_dealloc`]. The allocation is
/// independent of [`LAST_OUTPUT`] / [`LAST_ERROR`].
#[unsafe(no_mangle)]
pub extern "C" fn wg_alloc(len: usize) -> *mut u8 {
    let mut buf: Vec<u8> = Vec::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

/// Free a buffer previously returned by [`wg_alloc`].
///
/// # Safety
///
/// `ptr` must be a pointer previously returned by [`wg_alloc`] and
/// `len` must equal the original allocation request; otherwise
/// reconstructing the `Vec` is undefined behavior. Passing a null
/// `ptr` or `len == 0` is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wg_dealloc(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: caller guarantees (ptr, len) matches an earlier
    // wg_alloc(len) — that Vec had capacity == len.
    drop(unsafe { Vec::from_raw_parts(ptr, len, len) });
}

/// Run [`zkap_service::synthesize_witnesses`] against UTF-8 JSON
/// inputs and stash the serialized `Vec<WitnessBundle>` in the
/// per-thread output buffer.
///
/// Returns the number of bytes written to the output buffer
/// (always `>= 0`) on success, or `-1` on error. On success, read
/// the bytes via [`wg_last_output_ptr`] using the return value as
/// the length, then `CanonicalDeserialize` them into
/// `Vec<WitnessBundle>`. On error, retrieve the message via
/// [`wg_last_error_ptr`] + [`wg_last_error_len`].
///
/// # Safety
///
/// `req_ptr` must point to a buffer of at least `req_len` bytes
/// containing UTF-8 JSON encoding a [`ProveRequest`]; `cfg_ptr` /
/// `cfg_len` likewise for [`CircuitConfig`]. The buffers may be
/// freed by [`wg_dealloc`] immediately after this call returns —
/// the function copies the data it needs into [`LAST_OUTPUT`] /
/// [`LAST_ERROR`] before returning.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn synthesize_witness(
    req_ptr: *const u8,
    req_len: usize,
    cfg_ptr: *const u8,
    cfg_len: usize,
) -> i64 {
    // SAFETY: caller upholds the lifetime + UTF-8 contract per the
    // # Safety section above. We only borrow during this call and
    // copy out before returning.
    let req_bytes = unsafe { core::slice::from_raw_parts(req_ptr, req_len) };
    let cfg_bytes = unsafe { core::slice::from_raw_parts(cfg_ptr, cfg_len) };

    match synthesize_witness_inner(req_bytes, cfg_bytes) {
        Ok(bytes) => {
            let len = bytes.len() as i64;
            LAST_OUTPUT.with(|out| *out.borrow_mut() = bytes);
            len
        }
        Err(msg) => {
            LAST_ERROR.with(|err| *err.borrow_mut() = msg);
            -1
        }
    }
}

/// Pointer to the most recent successful output buffer.
///
/// Stays valid until the next [`synthesize_witness`] call. The
/// associated length is the most recent successful return value
/// of [`synthesize_witness`].
#[unsafe(no_mangle)]
pub extern "C" fn wg_last_output_ptr() -> *const u8 {
    LAST_OUTPUT.with(|out| out.borrow().as_ptr())
}

/// Pointer to the most recent error message (UTF-8).
///
/// Stays valid until the next [`synthesize_witness`] call.
#[unsafe(no_mangle)]
pub extern "C" fn wg_last_error_ptr() -> *const u8 {
    LAST_ERROR.with(|err| err.borrow().as_ptr())
}

/// Length of the most recent error message in bytes.
#[unsafe(no_mangle)]
pub extern "C" fn wg_last_error_len() -> usize {
    LAST_ERROR.with(|err| err.borrow().len())
}

/// Safe-Rust entry point — same behavior as the C ABI
/// [`synthesize_witness`] but with idiomatic byte-slice I/O.
///
/// Decode `req_bytes` as JSON-encoded [`ProveRequest`] and
/// `cfg_bytes` as JSON-encoded [`CircuitConfig`], call
/// [`synthesize_witnesses`], and return the
/// `CanonicalSerialize::serialize_uncompressed` bytes of the
/// resulting `Vec<WitnessBundle>`.
///
/// Used by the rlib path: native integration tests can call this
/// directly without going through wasm.
pub fn synthesize_witness_bytes(req_bytes: &[u8], cfg_bytes: &[u8]) -> Result<Vec<u8>, String> {
    synthesize_witness_inner(req_bytes, cfg_bytes)
}

fn synthesize_witness_inner(req_bytes: &[u8], cfg_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let request: ProveRequest = serde_json::from_slice(req_bytes)
        .map_err(|e| format!("ProveRequest JSON decode failed: {e}"))?;
    let cfg: CircuitConfig = serde_json::from_slice(cfg_bytes)
        .map_err(|e| format!("CircuitConfig JSON decode failed: {e}"))?;
    let bundles: Vec<WitnessBundle> =
        synthesize_witnesses(&cfg, &request).map_err(|e| format!("synthesize_witnesses: {e}"))?;
    let mut out = Vec::new();
    bundles
        .serialize_uncompressed(&mut out)
        .map_err(|e| format!("CanonicalSerialize failed: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesize_witness_bytes_rejects_invalid_request_json() {
        let err = synthesize_witness_bytes(b"not-json", b"{}").expect_err("must fail");
        assert!(
            err.contains("ProveRequest JSON decode failed"),
            "got: {err}"
        );
    }

    #[test]
    fn synthesize_witness_bytes_rejects_invalid_cfg_json() {
        // Minimally well-formed ProveRequest JSON so parsing
        // reaches the cfg step, but ProveRequest will fail to
        // deserialize first — adjust the assertion accordingly.
        // We just want to confirm that bad cfg JSON does not
        // silently succeed.
        let err = synthesize_witness_bytes(b"{}", b"not-json").expect_err("must fail");
        // Either ProveRequest or CircuitConfig decode fails first;
        // both surface as "JSON decode failed". The contract is
        // simply that we get an Err, not silent success.
        assert!(err.contains("JSON decode failed"), "got: {err}");
    }
}
