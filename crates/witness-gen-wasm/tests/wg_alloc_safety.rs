//! Safety tests for the `wg_alloc` / `wg_dealloc` FFI pair and the
//! null-pointer guard in `synthesize_witness`.
//!
//! These tests exercise the C ABI entry points directly (rlib path)
//! to verify that:
//!
//! 1. Zero-length allocation returns a non-null sentinel and the
//!    matching dealloc is a no-op (no crash, no double-free).
//! 2. A round-trip alloc(N) → write → read → dealloc preserves bytes
//!    and does not produce UB under address sanitizer / valgrind.
//! 3. `synthesize_witness` with a null request pointer returns `-1`
//!    and populates `LAST_ERROR`.

// The workspace lint set denies `unsafe_code`; this integration test
// necessarily calls `unsafe extern "C"` FFI entry points and raw
// pointer helpers directly — allow it here, same justification as
// the crate root.
#![allow(unsafe_code)]

use zkap_witness_gen_wasm::{wg_alloc, wg_dealloc, wg_last_error_len, wg_last_error_ptr};

/// Verify that `wg_alloc(0)` returns a non-null sentinel and that
/// the matching `wg_dealloc(ptr, 0)` does not crash or double-free.
#[test]
fn wg_alloc_zero_len_returns_non_null_and_dealloc_is_safe() {
    let ptr = wg_alloc(0);
    assert!(!ptr.is_null(), "wg_alloc(0) must return non-null sentinel");

    // wg_dealloc with len == 0 must be a no-op — calling it twice
    // must also be safe (no real memory was allocated).
    // SAFETY: ptr came from wg_alloc(0); len matches.
    unsafe { wg_dealloc(ptr, 0) };
    // Second call to confirm idempotent no-op (len == 0 path).
    unsafe { wg_dealloc(ptr, 0) };
}

/// Verify that a normal alloc / write / read / dealloc round-trip
/// preserves every byte written and does not corrupt the allocator.
#[test]
fn wg_alloc_roundtrip_preserves_bytes() {
    const N: usize = 256;
    let ptr = wg_alloc(N);
    assert!(!ptr.is_null(), "wg_alloc({N}) must return non-null");

    // Write a recognisable pattern into the allocation.
    // SAFETY: ptr is valid for N bytes (guaranteed by wg_alloc
    // contract); we write exactly N bytes within bounds.
    unsafe {
        for i in 0..N {
            ptr.add(i).write((i & 0xFF) as u8);
        }
    }

    // Read back and verify.
    // SAFETY: same region, still within the allocation lifetime.
    for i in 0..N {
        let byte = unsafe { ptr.add(i).read() };
        assert_eq!(
            byte,
            (i & 0xFF) as u8,
            "byte at offset {i} was corrupted"
        );
    }

    // Release — must not crash and must not double-free when the
    // allocator uses exact-size Layout bookkeeping.
    // SAFETY: ptr from wg_alloc(N), len == N matches allocation.
    unsafe { wg_dealloc(ptr, N) };
}

/// Verify that passing a null request pointer to `synthesize_witness`
/// returns a negative value and populates `LAST_ERROR` with the
/// expected sentinel message.
#[test]
fn synthesize_witness_null_request_returns_error() {
    // We need a minimally valid-looking cfg pointer. We use a small
    // stack buffer; the null-pointer guard fires before any JSON
    // parsing, so the content does not matter.
    let cfg_json = b"{}";
    let cfg_ptr = cfg_json.as_ptr();
    let cfg_len = cfg_json.len();

    // SAFETY: req_ptr is intentionally null to exercise the guard
    // path. cfg_ptr points to a valid stack buffer for cfg_len
    // bytes. synthesize_witness must detect the null req_ptr before
    // dereferencing it.
    let ret = unsafe {
        zkap_witness_gen_wasm::synthesize_witness(
            core::ptr::null(), // null req_ptr — triggers the guard
            0,
            cfg_ptr,
            cfg_len,
        )
    };

    assert!(ret < 0, "expected negative return for null req_ptr, got {ret}");

    // Verify that LAST_ERROR was populated with the sentinel message.
    let err_len = wg_last_error_len();
    assert!(err_len > 0, "LAST_ERROR must be non-empty after null-pointer error");

    let err_ptr = wg_last_error_ptr();
    // SAFETY: wg_last_error_ptr() is valid for wg_last_error_len()
    // bytes until the next synthesize_witness call.
    let err_bytes = unsafe { core::slice::from_raw_parts(err_ptr, err_len) };
    let err_str = core::str::from_utf8(err_bytes).expect("LAST_ERROR must be UTF-8");
    assert!(
        err_str.contains("null input pointer"),
        "expected 'null input pointer' in LAST_ERROR, got: {err_str:?}"
    );
}
