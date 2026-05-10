//! Wasm witness-generator runtime abstraction.
//!
//! The host loads a `.wasm` artifact built from the matching circuit, hands
//! it raw V1 input bytes (postcard-encoded [`zkap_input_types::ZkapInputV1`])
//! plus the paired `.arzkey`'s `ar1cs_blake3`, and reads back a serialized
//! `ArwtnsFile`. The wasm side enforces the blake3 pair-check internally;
//! callers just pass `arzkey.header.ar1cs_blake3` through.
//!
//! The trait-based seam keeps the door open for a `wasmtime` backend
//! (server-side, JIT) without touching call sites — see plan §6.3 and the
//! `runtime-wasmi` / `runtime-wasmtime` features in `Cargo.toml`.

#[cfg(feature = "runtime-wasmi")]
pub mod wasmi_backend;

#[cfg(feature = "runtime-wasmi")]
pub use wasmi_backend::WasmiRuntime as DefaultRuntime;

/// Errors returned by every [`WasmWitnessRuntime`] implementation. The
/// variants intentionally lump backend-specific failure modes (memory
/// access, function-call traps) into broad categories so callers can
/// react uniformly without binding to a concrete runtime.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// Module compilation, linker setup, or instantiation failed.
    #[error("instantiation failed: {0}")]
    Instantiation(String),

    /// A typed-function call into the wasm boundary trapped or could not
    /// resolve.
    #[error("call failed: {0}")]
    Call(String),

    /// `wasm_alloc` returned null, or a memory read/write went out of
    /// bounds.
    #[error("memory error: {0}")]
    Memory(String),

    /// `witness_generator` returned a non-zero ABI status code.
    /// See `ark_ar1cs_wasm_witness::WitnessAbiCode` for the semantics.
    #[error("witness ABI error: code {0}")]
    AbiCode(i32),
}

/// Wasm witness-generator runtime contract.
///
/// Per-proof instantiation is the recommended pattern (see plan §2 — host
/// resets state between JWTs to avoid carrying allocator fragmentation
/// across proofs).
pub trait WasmWitnessRuntime: Sized {
    /// Compile and instantiate the wasm module. Stub all unknown imports
    /// so wasm-bindgen leftovers (`__wbindgen_*`) don't fail the link.
    fn instantiate(wasm: &[u8]) -> Result<Self, RuntimeError>;

    /// Call the wasm `embedded_ar1cs_blake3` export and copy the 32-byte
    /// result back.
    ///
    /// Returns the `ar1cs_blake3` embedded in the witness-generator wasm.
    /// The host calls this once per prove batch as a fail-fast pair
    /// check before witness generation, comparing against
    /// `arzkey.header.ar1cs_blake3`. The wasm-side `witness_generator`
    /// still enforces its own equality check as defense in depth.
    ///
    /// This check improves mismatch detection and UX (catches stale
    /// caches, wrong dist paths, accidental mis-pairings with a clear
    /// up-front error), but is **not** a complete supply-chain defense
    /// against malicious wasm — a hostile wasm can lie about its
    /// embedded blake3.
    fn embedded_ar1cs_blake3(&mut self) -> Result<[u8; 32], RuntimeError>;

    /// Drive `witness_generator` end-to-end: allocate input + host_blake3
    /// buffers in wasm memory, dispatch the call, copy the resulting
    /// `.arwtns` bytes out, free every wasm-side allocation.
    ///
    /// Returns `RuntimeError::AbiCode` for any non-zero status from the
    /// wasm export (`Blake3Mismatch`, `PostcardDecodeError`,
    /// `CircuitBuildError`, etc.).
    fn generate_witness(
        &mut self,
        input_postcard: &[u8],
        host_blake3: &[u8; 32],
    ) -> Result<Vec<u8>, RuntimeError>;
}
