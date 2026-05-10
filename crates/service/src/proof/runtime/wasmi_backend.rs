//! `wasmi`-based [`WasmWitnessRuntime`] backend.
//!
//! Drives the four ABI exports emitted by `ark_ar1cs_wasm_witness`'s macro
//! (`wasm_alloc`, `wasm_free`, `embedded_ar1cs_blake3`, `witness_generator`)
//! through the wasmi 0.38 typed-function interface. Unknown imports left
//! behind by the wasm-bindgen / `getrandom = "js"` toolchain are stubbed
//! with default-value functions so the linker can resolve them — the
//! witness pipeline never actually invokes them, but `Linker::instantiate`
//! refuses to proceed unless every import has a definition.

use wasmi::{
    core::ValType, Engine, ExternType, FuncType, Linker, Memory, Module, Store, TypedFunc, Val,
};

use super::{RuntimeError, WasmWitnessRuntime};

/// Owned wasmi instance + handles to the four exported functions and the
/// linear memory the host writes into. Each [`crate::proof::ProofGenerator`]
/// proof uses a fresh `WasmiRuntime` (per-proof reset — see plan §2 / §8).
pub struct WasmiRuntime {
    store: Store<()>,
    memory: Memory,
    alloc: TypedFunc<u32, u32>,
    free: TypedFunc<(u32, u32), ()>,
    blake3: TypedFunc<(u32, u32), i32>,
    witness: TypedFunc<(u32, u32, u32, u32, u32), i32>,
}

/// Default-value stub for an unknown wasm import. Returns zeros / null
/// references for every result type. The witness pipeline does not call
/// any of these (no rng, no JS interop, no time access), so emitting
/// zeroes is observationally equivalent to never being called — but the
/// linker requires *some* definition so module instantiation succeeds.
fn default_val_for(ty: ValType) -> Val {
    match ty {
        ValType::I32 => Val::I32(0),
        ValType::I64 => Val::I64(0),
        ValType::F32 => Val::F32(0.0f32.into()),
        ValType::F64 => Val::F64(0.0f64.into()),
        ValType::FuncRef => Val::FuncRef(wasmi::FuncRef::null()),
        ValType::ExternRef => Val::ExternRef(wasmi::ExternRef::null()),
    }
}

/// Iterate the module's imports and register a default-value stub for
/// every function-type import. Memory / global / table imports are not
/// expected from the witness wasm artifacts and are left to fail loudly
/// during instantiation if they appear (a host-side dep change rather
/// than a runtime input the host should silently absorb).
fn install_stub_imports(
    linker: &mut Linker<()>,
    module: &Module,
) -> Result<(), RuntimeError> {
    for import in module.imports() {
        if let ExternType::Func(func_ty) = import.ty() {
            let module_name = import.module().to_string();
            let field_name = import.name().to_string();
            let result_types: Vec<ValType> = func_ty.results().to_vec();
            let ty: FuncType = func_ty.clone();
            linker
                .func_new(
                    &module_name,
                    &field_name,
                    ty,
                    move |_caller, _params, results| {
                        for (slot, &ty) in results.iter_mut().zip(result_types.iter()) {
                            *slot = default_val_for(ty);
                        }
                        Ok(())
                    },
                )
                .map_err(|e| {
                    RuntimeError::Instantiation(format!(
                        "stub import `{}::{}` failed: {}",
                        module_name, field_name, e
                    ))
                })?;
        }
    }
    Ok(())
}

impl WasmiRuntime {
    /// Read four little-endian bytes at `offset` and return them as `u32`.
    fn read_u32(&self, offset: u32) -> Result<u32, RuntimeError> {
        let mut buf = [0u8; 4];
        self.memory
            .read(&self.store, offset as usize, &mut buf)
            .map_err(|e| RuntimeError::Memory(format!("read u32 @{}: {}", offset, e)))?;
        Ok(u32::from_le_bytes(buf))
    }

    fn write_bytes(&mut self, offset: u32, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.memory
            .write(&mut self.store, offset as usize, bytes)
            .map_err(|e| RuntimeError::Memory(format!("write @{}: {}", offset, e)))
    }

    fn read_bytes(&self, offset: u32, len: u32) -> Result<Vec<u8>, RuntimeError> {
        let mut out = vec![0u8; len as usize];
        self.memory
            .read(&self.store, offset as usize, &mut out)
            .map_err(|e| RuntimeError::Memory(format!("read @{}+{}: {}", offset, len, e)))?;
        Ok(out)
    }

    fn call_alloc(&mut self, size: u32) -> Result<u32, RuntimeError> {
        let ptr = self
            .alloc
            .call(&mut self.store, size)
            .map_err(|e| RuntimeError::Call(format!("wasm_alloc({}): {}", size, e)))?;
        if ptr == 0 {
            return Err(RuntimeError::Memory(format!(
                "wasm_alloc({}) returned null",
                size
            )));
        }
        Ok(ptr)
    }

    fn call_free(&mut self, ptr: u32, size: u32) -> Result<(), RuntimeError> {
        self.free
            .call(&mut self.store, (ptr, size))
            .map_err(|e| RuntimeError::Call(format!("wasm_free({}, {}): {}", ptr, size, e)))
    }
}

impl WasmWitnessRuntime for WasmiRuntime {
    fn instantiate(wasm: &[u8]) -> Result<Self, RuntimeError> {
        let engine = Engine::default();
        let module = Module::new(&engine, wasm)
            .map_err(|e| RuntimeError::Instantiation(format!("Module::new: {}", e)))?;
        let mut store = Store::new(&engine, ());

        let mut linker: Linker<()> = Linker::new(&engine);
        install_stub_imports(&mut linker, &module)?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| RuntimeError::Instantiation(format!("Linker::instantiate: {}", e)))?
            .start(&mut store)
            .map_err(|e| RuntimeError::Instantiation(format!("InstancePre::start: {}", e)))?;

        let memory = instance.get_memory(&store, "memory").ok_or_else(|| {
            RuntimeError::Instantiation("module does not export `memory`".into())
        })?;
        let alloc = instance
            .get_typed_func::<u32, u32>(&store, "wasm_alloc")
            .map_err(|e| RuntimeError::Instantiation(format!("wasm_alloc export: {}", e)))?;
        let free = instance
            .get_typed_func::<(u32, u32), ()>(&store, "wasm_free")
            .map_err(|e| RuntimeError::Instantiation(format!("wasm_free export: {}", e)))?;
        let blake3 = instance
            .get_typed_func::<(u32, u32), i32>(&store, "embedded_ar1cs_blake3")
            .map_err(|e| {
                RuntimeError::Instantiation(format!("embedded_ar1cs_blake3 export: {}", e))
            })?;
        let witness = instance
            .get_typed_func::<(u32, u32, u32, u32, u32), i32>(&store, "witness_generator")
            .map_err(|e| {
                RuntimeError::Instantiation(format!("witness_generator export: {}", e))
            })?;

        Ok(WasmiRuntime {
            store,
            memory,
            alloc,
            free,
            blake3,
            witness,
        })
    }

    fn embedded_ar1cs_blake3(&mut self) -> Result<[u8; 32], RuntimeError> {
        let out_ptr_slot = self.call_alloc(4)?;
        let out_len_slot = self.call_alloc(4)?;

        let rc = self
            .blake3
            .call(&mut self.store, (out_ptr_slot, out_len_slot))
            .map_err(|e| RuntimeError::Call(format!("embedded_ar1cs_blake3: {}", e)))?;
        if rc != 0 {
            // Best-effort cleanup before reporting.
            let _ = self.call_free(out_ptr_slot, 4);
            let _ = self.call_free(out_len_slot, 4);
            return Err(RuntimeError::AbiCode(rc));
        }

        let ptr = self.read_u32(out_ptr_slot)?;
        let len = self.read_u32(out_len_slot)?;
        if len != 32 {
            let _ = self.call_free(ptr, len);
            let _ = self.call_free(out_ptr_slot, 4);
            let _ = self.call_free(out_len_slot, 4);
            return Err(RuntimeError::Memory(format!(
                "embedded_ar1cs_blake3 returned {} bytes, expected 32",
                len
            )));
        }

        let bytes = self.read_bytes(ptr, len)?;
        self.call_free(ptr, len)?;
        self.call_free(out_ptr_slot, 4)?;
        self.call_free(out_len_slot, 4)?;

        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeError::Memory("blake3 length mismatch".into()))?;
        Ok(arr)
    }

    fn generate_witness(
        &mut self,
        input_postcard: &[u8],
        host_blake3: &[u8; 32],
    ) -> Result<Vec<u8>, RuntimeError> {
        let input_len = u32::try_from(input_postcard.len()).map_err(|_| {
            RuntimeError::Memory("postcard input larger than u32::MAX".into())
        })?;

        // 1. Allocate + write input buffer.
        let in_ptr = self.call_alloc(input_len)?;
        self.write_bytes(in_ptr, input_postcard)?;

        // 2. Allocate + write the host-side blake3 (32 bytes).
        let blake_ptr = self.call_alloc(32)?;
        self.write_bytes(blake_ptr, host_blake3)?;

        // 3. Allocate the (out_ptr, out_len) slot pair (8 bytes contiguous).
        //    out_ptr_out points at meta + 0; out_len_out points at meta + 4.
        let meta_ptr = self.call_alloc(8)?;

        // 4. Dispatch.
        let status = self
            .witness
            .call(
                &mut self.store,
                (in_ptr, input_len, blake_ptr, meta_ptr, meta_ptr + 4),
            )
            .map_err(|e| RuntimeError::Call(format!("witness_generator: {}", e)))?;

        // 5. Always free the input and host blake3 buffers; the wasm side
        //    has finished reading them regardless of `status`.
        self.call_free(in_ptr, input_len)?;
        self.call_free(blake_ptr, 32)?;

        if status != 0 {
            // No result buffer was allocated by the wasm side on failure
            // paths — only the meta slot needs to be freed.
            let _ = self.call_free(meta_ptr, 8);
            return Err(RuntimeError::AbiCode(status));
        }

        // 6. Read the (ptr, len) the wasm side wrote into the meta slot,
        //    pull the bytes out, then free both the result buffer and the
        //    meta slot.
        let out_ptr = self.read_u32(meta_ptr)?;
        let out_len = self.read_u32(meta_ptr + 4)?;
        let bytes = self.read_bytes(out_ptr, out_len)?;
        self.call_free(out_ptr, out_len)?;
        self.call_free(meta_ptr, 8)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Acceptance: malformed wasm bytes are rejected at the
    /// `instantiate` boundary as `RuntimeError::Instantiation`, never
    /// silently succeed and trap on a later call.
    #[test]
    fn instantiate_rejects_garbage_bytes() {
        match WasmiRuntime::instantiate(b"not a wasm module") {
            Err(RuntimeError::Instantiation(_)) => {}
            Err(other) => panic!("expected Instantiation error, got {:?}", other),
            Ok(_) => panic!("expected Instantiation error, got Ok"),
        }
    }

    /// Acceptance: an empty input slice is also rejected at instantiate.
    #[test]
    fn instantiate_rejects_empty_bytes() {
        match WasmiRuntime::instantiate(&[]) {
            Err(RuntimeError::Instantiation(_)) => {}
            Err(other) => panic!("expected Instantiation error, got {:?}", other),
            Ok(_) => panic!("expected Instantiation error, got Ok"),
        }
    }

    /// Acceptance: the seven `ValType` variants surfaced by wasmi 0.38
    /// each map to a non-panicking [`Val`]. This is the import-stub
    /// fallback path; correctness here is what lets `__wbindgen_*`
    /// imports linker-resolve without a hand-written stub per signature.
    #[test]
    fn default_val_for_covers_every_valtype() {
        for &ty in &[
            ValType::I32,
            ValType::I64,
            ValType::F32,
            ValType::F64,
            ValType::FuncRef,
            ValType::ExternRef,
        ] {
            // No panic + result type matches the input.
            let v = default_val_for(ty);
            assert_eq!(v.ty(), ty);
        }
    }
}
