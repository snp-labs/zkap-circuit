//! Thin wrapper around the wasmtime cranelift JIT for invoking the
//! `synthesize_witness` C ABI export from this crate's cdylib build.
//!
//! Hosts both the bench's wasm axis and the parity integration test.
//! The runner is deliberately minimal — no async, no WASI, no
//! resource limiter — so the measurement reflects witness-gen cost,
//! not engine overhead.

use std::path::Path;

use wasmtime::{Engine, Instance, Memory, Module, Store, TypedFunc};

/// Loaded wasm artifact ready to be turned into one or more
/// `WasmInstance`s. Engine + Module compilation happen once.
pub struct WasmModule {
    engine: Engine,
    module: Module,
}

/// A wasmtime instance + handles to the exports we drive.
pub struct WasmInstance {
    store: Store<()>,
    memory: Memory,
    wg_alloc: TypedFunc<i32, i32>,
    wg_dealloc: TypedFunc<(i32, i32), ()>,
    synthesize_witness: TypedFunc<(i32, i32, i32, i32), i64>,
    wg_last_output_ptr: TypedFunc<(), i32>,
    wg_last_error_ptr: TypedFunc<(), i32>,
    wg_last_error_len: TypedFunc<(), i32>,
}

impl WasmModule {
    /// Compile the wasm artifact at `path` under wasmtime's
    /// cranelift JIT. The returned `WasmModule` is cheap to clone-by-
    /// reference; spawning fresh instances reuses the compiled
    /// module.
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let engine = Engine::default();
        let module = Module::from_file(&engine, path)?;
        Ok(Self { engine, module })
    }

    /// Spin up a fresh instance — empty import object, default
    /// store. Cold-bench iterations construct a new instance per
    /// iteration; warm-bench iterations reuse one.
    pub fn instantiate(&self) -> anyhow::Result<WasmInstance> {
        let mut store = Store::new(&self.engine, ());
        let instance = Instance::new(&mut store, &self.module, &[])?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("wasm exports no `memory`"))?;

        let wg_alloc = instance.get_typed_func::<i32, i32>(&mut store, "wg_alloc")?;
        let wg_dealloc = instance.get_typed_func::<(i32, i32), ()>(&mut store, "wg_dealloc")?;
        let synthesize_witness = instance
            .get_typed_func::<(i32, i32, i32, i32), i64>(&mut store, "synthesize_witness")?;
        let wg_last_output_ptr =
            instance.get_typed_func::<(), i32>(&mut store, "wg_last_output_ptr")?;
        let wg_last_error_ptr =
            instance.get_typed_func::<(), i32>(&mut store, "wg_last_error_ptr")?;
        let wg_last_error_len =
            instance.get_typed_func::<(), i32>(&mut store, "wg_last_error_len")?;

        Ok(WasmInstance {
            store,
            memory,
            wg_alloc,
            wg_dealloc,
            synthesize_witness,
            wg_last_output_ptr,
            wg_last_error_ptr,
            wg_last_error_len,
        })
    }
}

/// Wasm spec page size in bytes (= 64 KiB).
///
/// `#[allow(dead_code)]`: this module is included via
/// `#[path = "..."]` by both the bench (`benches/synthesize.rs`),
/// the parity test (`tests/parity.rs`), and the memory profile test
/// (`tests/memory_profile.rs`). Only the last one references
/// `WASM_PAGE_SIZE` / `memory_pages`, so the bench / parity builds
/// would otherwise trip `-D dead_code`. The `allow` keeps the
/// shared module compile-clean for every consumer.
#[allow(dead_code)]
pub const WASM_PAGE_SIZE: usize = 65_536;

impl WasmInstance {
    /// Current linear-memory size in wasm pages (1 page = 64 KiB).
    ///
    /// Wasm linear memory only ever grows, so reading this after a
    /// synthesize call yields the per-instance peak. Used by
    /// `tests/memory_profile.rs`. See `WASM_PAGE_SIZE` above for the
    /// `#[allow(dead_code)]` rationale.
    #[allow(dead_code)]
    pub fn memory_pages(&self) -> usize {
        self.memory.data_size(&self.store) / WASM_PAGE_SIZE
    }

    /// Drive `synthesize_witness` end-to-end: allocate two host
    /// buffers, write the input JSON, call the export, read back the
    /// canonical-serialize bytes, and free the buffers.
    ///
    /// Returns the serialized `Vec<WitnessBundle>` bytes on success.
    pub fn synthesize(&mut self, req_json: &[u8], cfg_json: &[u8]) -> anyhow::Result<Vec<u8>> {
        let req_len = req_json.len() as i32;
        let cfg_len = cfg_json.len() as i32;

        let req_ptr = self.wg_alloc.call(&mut self.store, req_len)?;
        let cfg_ptr = self.wg_alloc.call(&mut self.store, cfg_len)?;

        self.memory
            .write(&mut self.store, req_ptr as usize, req_json)?;
        self.memory
            .write(&mut self.store, cfg_ptr as usize, cfg_json)?;

        let n = self
            .synthesize_witness
            .call(&mut self.store, (req_ptr, req_len, cfg_ptr, cfg_len))?;

        let result = if n >= 0 {
            let out_ptr = self.wg_last_output_ptr.call(&mut self.store, ())?;
            let mut buf = vec![0u8; n as usize];
            self.memory.read(&self.store, out_ptr as usize, &mut buf)?;
            Ok(buf)
        } else {
            let err_ptr = self.wg_last_error_ptr.call(&mut self.store, ())?;
            let err_len = self.wg_last_error_len.call(&mut self.store, ())?;
            let mut buf = vec![0u8; err_len as usize];
            self.memory.read(&self.store, err_ptr as usize, &mut buf)?;
            let msg = String::from_utf8_lossy(&buf).into_owned();
            Err(anyhow::anyhow!("synthesize_witness failed: {msg}"))
        };

        // Free the input buffers regardless of success/error so the
        // instance is reusable across iterations.
        self.wg_dealloc.call(&mut self.store, (req_ptr, req_len))?;
        self.wg_dealloc.call(&mut self.store, (cfg_ptr, cfg_len))?;

        result
    }
}
