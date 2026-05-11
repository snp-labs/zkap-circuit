//! End-to-end host integration test for the wasm witness-generator.
//!
//! Single-command flow (commit 4 of the circuit-first wasm pipeline):
//!
//! 1. Generate a fresh test `.arzkey` in-process from a satisfying
//!    `ZkapCircuit` (matrices via `Setup`-mode synthesis, Groth16 setup
//!    proving key, all wrapped via `ArzkeyFile::from_setup_output`).
//! 2. Rebuild this crate as `wasm32-unknown-unknown` against that arzkey
//!    using a separate `--target-dir` so the running `cargo test` lock
//!    isn't contended.
//! 3. Load the wasm with `wasmtime`, drive the four ABI exports, and
//!    walk the 10 host-flow steps from
//!    `.omc/plans/2026-05-04-circuit-first-witness-wasm.md` §"호스트 흐름 10단계".
//! 4. Cross-check the wasm-produced `.arwtns` bytes against the native
//!    `circuit_to_arwtns` path (byte-identical assertion).
//! 5. Run `prove` + `verify_proof` to close the pipeline.

mod common;

use std::path::{Path, PathBuf};

use ark_ar1cs_format::ConstraintMatrices;
use ark_ar1cs_format::{ArcsFile, CurveId};
use ark_ar1cs_prover::prove;
use ark_ar1cs_wasm_witness::circuit_to_arwtns;
use ark_ar1cs_wtns::ArwtnsFile;
use ark_ar1cs_zkey::ArzkeyFile;
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_std::rand::SeedableRng;
use wasmtime::{Engine, Linker, Memory, Module, Store, TypedFunc};
use zkap_witness_wasm::ZkapInputV1;

use common::{TestCircuit, V1FixtureBundle, build_v1_fixture_bundle};

/// Workspace root = parent of `crates/zkap-witness-wasm`.
fn workspace_root() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(Path::parent)
        .expect("CARGO_MANIFEST_DIR has a workspace root two levels up")
        .to_path_buf()
}

/// Mirror of the circuit crate's groth16_integration `collect_matrices`
/// helper — re-synthesize in `Setup` mode and pull `ConstraintMatrices`.
fn collect_matrices(circuit: TestCircuit) -> ConstraintMatrices<Fr> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .expect("generate_constraints failed in Setup mode");
    cs.finalize();
    ConstraintMatrices::from_cs(&cs).expect("ConstraintMatrices::from_cs failed")
}

/// Step 1 (test setup): build a satisfying `ZkapCircuit`, run Groth16
/// setup over it, materialize the matching `.arzkey` on disk, and return
/// both the in-memory ArzkeyFile and the matching V1 wire payload (the
/// canonical encoding the wasm-side `witness_generator` consumes).
///
/// `Groth16::setup` and the matrix-collection synthesizer both consume
/// the circuit value, so the helper rebuilds the V1 fixture bundle three
/// times. The first satisfying circuit is also returned (used by the
/// native byte-identical baseline at the end of the test).
fn generate_test_arzkey(out_path: &Path) -> (ArzkeyFile<Bn254>, ZkapInputV1, TestCircuit) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);

    let V1FixtureBundle {
        circuit_inputs: setup_inputs,
        ..
    } = build_v1_fixture_bundle();
    let setup_circuit = TestCircuit::from_input(setup_inputs[0].clone());
    let (pk, _vk) = Groth16::<Bn254>::setup(setup_circuit, &mut rng).expect("Groth16 setup failed");

    let V1FixtureBundle {
        circuit_inputs: matrix_inputs,
        ..
    } = build_v1_fixture_bundle();
    let matrix_circuit = TestCircuit::from_input(matrix_inputs[0].clone());
    let matrices = collect_matrices(matrix_circuit);
    let arcs = ArcsFile::<Fr>::from_matrices(CurveId::Bn254, &matrices);

    let arzkey = ArzkeyFile::<Bn254>::from_setup_output(arcs, pk);

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).expect("create test_fixtures dir");
    }
    let mut f = std::fs::File::create(out_path).expect("create arzkey file");
    arzkey.write(&mut f).expect("write arzkey");

    // Fresh build for the satisfying circuit + V1 payload pair shipped
    // through the wasm boundary (V1) and the native byte-identical
    // baseline (TestCircuit).
    let V1FixtureBundle {
        v1_inputs,
        circuit_inputs,
    } = build_v1_fixture_bundle();
    let v1_input = v1_inputs[0].clone();
    let satisfying_circuit = TestCircuit::from_input(circuit_inputs[0].clone());

    (arzkey, v1_input, satisfying_circuit)
}

/// Step 2 (test setup): rebuild this crate for `wasm32-unknown-unknown`
/// against the freshly-generated `.arzkey`. Uses a dedicated
/// `--target-dir` so the running `cargo test` host build doesn't fight
/// the wasm build for the workspace `target/` lock.
fn rebuild_wasm(arzkey_path: &Path) -> PathBuf {
    let workspace = workspace_root();
    let target_dir = workspace.join("target/test_wasm_build");

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    eprintln!(
        "[wasm-rebuild] cargo build -p zkap-witness-wasm --target wasm32-unknown-unknown \
         --release --target-dir {} (AR1CS_WITNESS_ARZKEY_PATH={})",
        target_dir.display(),
        arzkey_path.display(),
    );

    let status = std::process::Command::new(&cargo)
        .args([
            "build",
            "-p",
            "zkap-witness-wasm",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
        ])
        .arg("--target-dir")
        .arg(&target_dir)
        .env("AR1CS_WITNESS_ARZKEY_PATH", arzkey_path)
        .current_dir(&workspace)
        .status()
        .expect("spawn `cargo build` for wasm32-unknown-unknown");
    assert!(status.success(), "wasm rebuild failed (exit {:?})", status);

    target_dir.join("wasm32-unknown-unknown/release/zkap_witness_wasm.wasm")
}

/// Wasm linear-memory harness: typed function handles, the exported
/// `Memory`, and helpers for the `(ptr, len)` out-pointer dance every
/// witness-wasm export uses.
struct WasmHarness {
    store: Store<()>,
    memory: Memory,
    alloc: TypedFunc<u32, u32>,
    free: TypedFunc<(u32, u32), ()>,
    blake3: TypedFunc<(u32, u32), i32>,
    witness: TypedFunc<(u32, u32, u32, u32, u32), i32>,
}

impl WasmHarness {
    fn load(wasm_path: &Path) -> Self {
        let engine = Engine::default();
        let module = Module::from_file(&engine, wasm_path).expect("Module::from_file");
        let mut store = Store::new(&engine, ());

        // The wasm artifact has a few residual `__wbindgen_*` imports that
        // the `getrandom`-with-`js`-feature → wasm-bindgen toolchain leaves
        // behind even when no host-callable JS function is actually
        // invoked. The witness-generator code path is fully deterministic
        // (no rng), so stubbing every unknown import as a default-value
        // function is sound — calling one would only produce zeros, but
        // none of them are reached. A trap-based stub would be tighter,
        // but default-values keeps the test from depending on which
        // wasm-bindgen leftovers happen to be present in any given
        // toolchain build.
        let mut linker: Linker<()> = Linker::new(&engine);
        linker
            .define_unknown_imports_as_default_values(&mut store, &module)
            .expect("define_unknown_imports_as_default_values");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("Linker::instantiate");

        let memory = instance
            .get_memory(&mut store, "memory")
            .expect("wasm module exports `memory`");
        let alloc = instance
            .get_typed_func::<u32, u32>(&mut store, "wasm_alloc")
            .expect("wasm_alloc export");
        let free = instance
            .get_typed_func::<(u32, u32), ()>(&mut store, "wasm_free")
            .expect("wasm_free export");
        let blake3 = instance
            .get_typed_func::<(u32, u32), i32>(&mut store, "embedded_ar1cs_blake3")
            .expect("embedded_ar1cs_blake3 export");
        let witness = instance
            .get_typed_func::<(u32, u32, u32, u32, u32), i32>(&mut store, "witness_generator")
            .expect("witness_generator export");

        WasmHarness {
            store,
            memory,
            alloc,
            free,
            blake3,
            witness,
        }
    }

    fn alloc_and_write(&mut self, bytes: &[u8]) -> u32 {
        let len = u32::try_from(bytes.len()).expect("buffer fits in u32");
        let ptr = self
            .alloc
            .call(&mut self.store, len)
            .expect("wasm_alloc call");
        assert!(ptr != 0, "wasm_alloc returned null for {} bytes", len);
        self.memory
            .write(&mut self.store, ptr as usize, bytes)
            .expect("memory.write");
        ptr
    }

    /// Allocate a 4-byte slot in wasm memory (used as the host-side
    /// stand-in for `*mut *mut u8` / `*mut u32` out-parameters).
    fn alloc_u32_slot(&mut self) -> u32 {
        let ptr = self
            .alloc
            .call(&mut self.store, 4)
            .expect("wasm_alloc(4) call");
        assert!(ptr != 0, "wasm_alloc(4) returned null");
        ptr
    }

    fn read_u32(&mut self, ptr: u32) -> u32 {
        let mut buf = [0u8; 4];
        self.memory
            .read(&self.store, ptr as usize, &mut buf)
            .expect("memory.read u32");
        u32::from_le_bytes(buf)
    }

    fn read_outparams(&mut self, out_ptr_slot: u32, out_len_slot: u32) -> (u32, u32) {
        let ptr = self.read_u32(out_ptr_slot);
        let len = self.read_u32(out_len_slot);
        (ptr, len)
    }

    fn copy_out(&mut self, ptr: u32, len: u32) -> Vec<u8> {
        let mut out = vec![0u8; len as usize];
        self.memory
            .read(&self.store, ptr as usize, &mut out)
            .expect("memory.read body");
        out
    }

    fn free(&mut self, ptr: u32, len: u32) {
        self.free
            .call(&mut self.store, (ptr, len))
            .expect("wasm_free call");
    }

    fn call_blake3(&mut self, out_ptr_slot: u32, out_len_slot: u32) -> i32 {
        self.blake3
            .call(&mut self.store, (out_ptr_slot, out_len_slot))
            .expect("embedded_ar1cs_blake3 call")
    }

    fn call_witness(
        &mut self,
        input_ptr: u32,
        input_len: u32,
        host_blake3_ptr: u32,
        out_ptr_slot: u32,
        out_len_slot: u32,
    ) -> i32 {
        self.witness
            .call(
                &mut self.store,
                (
                    input_ptr,
                    input_len,
                    host_blake3_ptr,
                    out_ptr_slot,
                    out_len_slot,
                ),
            )
            .expect("witness_generator call")
    }
}

#[test]
fn wasm_to_prove_full_pipeline() {
    let workspace = workspace_root();
    let arzkey_path = workspace.join("target/test_fixtures/wasm_to_prove.arzkey");

    eprintln!(
        "[step 0] generating fresh test arzkey at {}",
        arzkey_path.display()
    );
    let (arzkey_in_mem, v1_input, satisfying_circuit) = generate_test_arzkey(&arzkey_path);

    eprintln!("[step 0] rebuilding zkap-witness-wasm against the test arzkey");
    let wasm_path = rebuild_wasm(&arzkey_path);
    let wasm_meta = std::fs::metadata(&wasm_path).expect("stat rebuilt wasm");
    eprintln!(
        "[step 0] rebuilt wasm at {} ({} bytes)",
        wasm_path.display(),
        wasm_meta.len()
    );

    // Step 1 — load the on-disk arzkey via the public format reader.
    eprintln!("[step 1] ArzkeyFile::read({})", arzkey_path.display());
    let mut arzkey_file = std::fs::File::open(&arzkey_path).expect("open arzkey for read");
    let arzkey: ArzkeyFile<Bn254> =
        ArzkeyFile::<Bn254>::read(&mut arzkey_file).expect("ArzkeyFile::read");
    assert_eq!(
        arzkey.header.ar1cs_blake3, arzkey_in_mem.header.ar1cs_blake3,
        "in-memory and on-disk arzkey blake3 must match",
    );

    // Step 2 — load wasm.
    eprintln!("[step 2] loading wasm via wasmtime");
    let mut harness = WasmHarness::load(&wasm_path);

    // Step 3 — call embedded_ar1cs_blake3, copy bytes out, free both
    // the result buffer and the two 4-byte out-slots.
    eprintln!("[step 3] embedded_ar1cs_blake3()");
    let blake_out_ptr_slot = harness.alloc_u32_slot();
    let blake_out_len_slot = harness.alloc_u32_slot();
    let rc = harness.call_blake3(blake_out_ptr_slot, blake_out_len_slot);
    assert_eq!(rc, 0, "embedded_ar1cs_blake3 returned non-zero {}", rc);
    let (blake_ptr, blake_len) = harness.read_outparams(blake_out_ptr_slot, blake_out_len_slot);
    assert_eq!(blake_len, 32, "embedded blake3 must be 32 bytes");
    let embedded_blake3 = harness.copy_out(blake_ptr, blake_len);
    harness.free(blake_ptr, blake_len);
    harness.free(blake_out_ptr_slot, 4);
    harness.free(blake_out_len_slot, 4);

    // Step 4 — pair check.
    eprintln!("[step 4] embedded == arzkey.header.ar1cs_blake3");
    let embedded_arr: [u8; 32] = embedded_blake3
        .as_slice()
        .try_into()
        .expect("32-byte blake3");
    assert_eq!(
        embedded_arr, arzkey.header.ar1cs_blake3,
        "wasm embedded blake3 mismatches arzkey header",
    );

    // Step 5 — call witness_generator with the V1 semantic input + arzkey blake3.
    eprintln!("[step 5] witness_generator(encoded_input, arzkey.ar1cs_blake3)");
    let postcard_bytes = postcard::to_allocvec(&v1_input).expect("postcard encode ZkapInputV1");

    let input_ptr = harness.alloc_and_write(&postcard_bytes);
    let host_blake3_ptr = harness.alloc_and_write(&arzkey.header.ar1cs_blake3);
    let wit_out_ptr_slot = harness.alloc_u32_slot();
    let wit_out_len_slot = harness.alloc_u32_slot();
    let rc = harness.call_witness(
        input_ptr,
        postcard_bytes.len() as u32,
        host_blake3_ptr,
        wit_out_ptr_slot,
        wit_out_len_slot,
    );
    assert_eq!(rc, 0, "witness_generator returned non-zero {}", rc);

    // Step 6 — copy result bytes out, free wasm buffers.
    eprintln!("[step 6] copy arwtns bytes out + wasm_free");
    let (wit_ptr, wit_len) = harness.read_outparams(wit_out_ptr_slot, wit_out_len_slot);
    let wasm_arwtns_bytes = harness.copy_out(wit_ptr, wit_len);
    harness.free(wit_ptr, wit_len);
    harness.free(wit_out_ptr_slot, 4);
    harness.free(wit_out_len_slot, 4);
    harness.free(input_ptr, postcard_bytes.len() as u32);
    harness.free(host_blake3_ptr, 32);

    // Step 7 — parse the wasm output as an ArwtnsFile.
    eprintln!(
        "[step 7] ArwtnsFile::read(wasm output, {} bytes)",
        wasm_arwtns_bytes.len()
    );
    let arwtns: ArwtnsFile<Fr> =
        ArwtnsFile::<Fr>::read(&mut std::io::Cursor::new(&wasm_arwtns_bytes))
            .expect("ArwtnsFile::read on wasm output");

    // Steps 8 + 9 — pair-check arwtns header against arzkey header.
    eprintln!("[step 8+9] arwtns.header.ar1cs_blake3 == arzkey.header.ar1cs_blake3 + curve_id");
    assert_eq!(
        arwtns.header.ar1cs_blake3, arzkey.header.ar1cs_blake3,
        "arwtns blake3 mismatches arzkey header",
    );
    assert_eq!(
        arwtns.header.curve_id as u8, arzkey.header.curve_id as u8,
        "arwtns curve_id mismatches arzkey header",
    );

    // Byte-identical assertion: native circuit_to_arwtns must produce
    // the same bytes for the same input + same blake3.
    eprintln!("[byte-identical] native circuit_to_arwtns vs wasm output");
    let native_arwtns = circuit_to_arwtns::<Fr, _>(
        satisfying_circuit.clone(),
        CurveId::Bn254,
        arzkey.header.ar1cs_blake3,
    )
    .expect("native circuit_to_arwtns");
    let mut native_bytes = Vec::new();
    native_arwtns
        .write(&mut native_bytes)
        .expect("native arwtns write");
    assert_eq!(
        native_bytes, wasm_arwtns_bytes,
        "native circuit_to_arwtns output must be byte-identical to wasm witness_generator output",
    );

    // Step 10 — full prove + verify on the wasm-produced arwtns.
    eprintln!("[step 10] prove(&arzkey, &arwtns, rng) + verify_proof");
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
    let proof = prove(&arzkey, &arwtns, &mut rng).expect("prove");
    let pvk = prepare_verifying_key(&arzkey.vk);
    let valid =
        Groth16::<Bn254>::verify_proof(&pvk, &proof, &arwtns.instance).expect("verify_proof");
    assert!(valid, "Groth16 verify_proof returned false");

    // === Wrong-pair coverage (verifies the pair contract holds in
    // both directions: wasm side via Blake3Mismatch ABI 5 and host side
    // via bind_check / preflight rejection before any cryptographic
    // work is done). Reuses the same wasm instance and the same
    // satisfying input — only the blake3 byte differs by 1 bit.

    eprintln!("[wrong-pair A] wasm host_blake3 tamper → expect ABI 5 (Blake3Mismatch)");
    let mut tampered_blake3 = arzkey.header.ar1cs_blake3;
    tampered_blake3[0] ^= 0x01;
    assert_ne!(tampered_blake3, arzkey.header.ar1cs_blake3);

    let bad_input_ptr = harness.alloc_and_write(&postcard_bytes);
    let bad_blake3_ptr = harness.alloc_and_write(&tampered_blake3);
    let bad_out_ptr_slot = harness.alloc_u32_slot();
    let bad_out_len_slot = harness.alloc_u32_slot();
    let bad_rc = harness.call_witness(
        bad_input_ptr,
        postcard_bytes.len() as u32,
        bad_blake3_ptr,
        bad_out_ptr_slot,
        bad_out_len_slot,
    );
    assert_eq!(
        bad_rc, 5,
        "host_blake3 tamper must return WitnessAbiCode::Blake3Mismatch (5), got {}",
        bad_rc
    );
    // No result buffer is allocated by the wasm side on the
    // Blake3Mismatch path — only the host-side scratch slots need to be
    // freed.
    harness.free(bad_input_ptr, postcard_bytes.len() as u32);
    harness.free(bad_blake3_ptr, 32);
    harness.free(bad_out_ptr_slot, 4);
    harness.free(bad_out_len_slot, 4);

    eprintln!(
        "[wrong-pair B] arwtns.header.ar1cs_blake3 tamper → expect prove error before SNARK work"
    );
    let mut tampered_arwtns = arwtns.clone();
    tampered_arwtns.header.ar1cs_blake3[0] ^= 0x01;
    assert_ne!(
        tampered_arwtns.header.ar1cs_blake3,
        arzkey.header.ar1cs_blake3
    );
    let mut rng_tamper = ark_std::rand::rngs::StdRng::seed_from_u64(8);
    let tampered_result = prove(&arzkey, &tampered_arwtns, &mut rng_tamper);
    assert!(
        tampered_result.is_err(),
        "tampered arwtns blake3 must be rejected by bind_check before prove succeeds",
    );

    eprintln!("[done] wasm_to_prove_full_pipeline OK");
}

/// This is intentionally a cross-layer integration test.
///
/// It verifies that a ZKAP witness-generator wasm and an unrelated but
/// otherwise valid `ArzkeyFile` are rejected by `zkap_service` *before*
/// witness generation or proving begins (the host-side `ar1cs_blake3`
/// fail-fast check in `ProofGenerator::generate`).
///
/// The test lives in this crate (rather than `zkap-service`) because
/// `zkap-witness-wasm` already owns the wasm rebuild fixture
/// (`generate_test_arzkey` + `rebuild_wasm`). `zkap-service` is pulled
/// in only as a `[dev-dependencies]` entry — it does NOT appear in the
/// production wasm32 build of `zkap-witness-wasm`.
///
/// Strategy A: build a *valid* second arzkey for a totally different
/// circuit (toy `x*y=z`), pair it with the zkap-witness-wasm artifact
/// rebuilt for the ZKAP main circuit, and call `zkap_service::prove`.
///
/// The toy arzkey's `header.ar1cs_blake3` necessarily differs from the
/// wasm's `embedded_ar1cs_blake3` (different matrices), so the new host-
/// side fail-fast check in `ProofGenerator::generate` must reject the
/// pair with `ApplicationError::InvalidFormat` whose Display contains
/// `"ar1cs_blake3 mismatch"`.
///
/// Strategy B (mutate `header.ar1cs_blake3` byte then re-write/re-read)
/// was rejected: `ArzkeyFile::read` enforces self-consistency
/// (`arzkey.arcs().body_blake3() == header.ar1cs_blake3`), so a
/// header-only mutation would fail at `load_arzkey()` *before* the new
/// host-side check ever runs.
#[test]
fn host_rejects_wasm_with_mismatched_ar1cs_blake3() {
    use ark_relations::gr1cs::{ConstraintSystemRef, LinearCombination, SynthesisError};
    use std::path::PathBuf;
    use zkap_service::{CircuitConfig, RawProofRequest, ZkapPerJwtFields, ZkapSharedFields};

    let workspace = workspace_root();

    // ── Step 0a: ensure the canonical fixture arzkey + matching wasm exist ──
    //
    // We reuse the same on-disk fixture path the happy-path test uses, so
    // running `cargo test -p zkap-witness-wasm --test wasm_to_prove`
    // against a clean target/ directory still produces a valid wasm.
    let arzkey_path_main = workspace.join("target/test_fixtures/wasm_to_prove.arzkey");
    eprintln!(
        "[mismatch test] ensuring fixture arzkey at {}",
        arzkey_path_main.display()
    );
    let _ = generate_test_arzkey(&arzkey_path_main);
    eprintln!("[mismatch test] (re)building zkap-witness-wasm against the fixture arzkey");
    let wasm_path = rebuild_wasm(&arzkey_path_main);

    // ── Step 0b: build a toy arzkey for a different circuit ──
    //
    // `x * y = z` over BN254 — entirely different matrices from the ZKAP
    // main circuit, so its `ar1cs_blake3` cannot collide with the wasm's
    // embedded value.
    #[derive(Clone)]
    struct ToyCircuit;
    impl ConstraintSynthesizer<Fr> for ToyCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let z = cs.new_input_variable(|| Ok(Fr::from(15u64)))?;
            let x = cs.new_witness_variable(|| Ok(Fr::from(3u64)))?;
            let y = cs.new_witness_variable(|| Ok(Fr::from(5u64)))?;
            cs.enforce_r1cs_constraint(
                || LinearCombination::from(x),
                || LinearCombination::from(y),
                || LinearCombination::from(z),
            )?;
            Ok(())
        }
    }

    let toy_arzkey_path: PathBuf =
        workspace.join("target/test_fixtures/wasm_to_prove_toy_mismatched.arzkey");

    eprintln!(
        "[mismatch test] generating toy arzkey at {}",
        toy_arzkey_path.display()
    );
    {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(99);
        let (toy_pk, _toy_vk) =
            Groth16::<Bn254>::setup(ToyCircuit, &mut rng).expect("toy Groth16 setup");

        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        ToyCircuit
            .generate_constraints(cs.clone())
            .expect("toy generate_constraints");
        cs.finalize();
        let toy_matrices =
            ConstraintMatrices::from_cs(&cs).expect("toy ConstraintMatrices::from_cs");
        let toy_arcs = ArcsFile::<Fr>::from_matrices(CurveId::Bn254, &toy_matrices);
        let toy_arzkey = ArzkeyFile::<Bn254>::from_setup_output(toy_arcs, toy_pk);

        if let Some(parent) = toy_arzkey_path.parent() {
            std::fs::create_dir_all(parent).expect("create test_fixtures dir");
        }
        let mut f = std::fs::File::create(&toy_arzkey_path).expect("create toy arzkey file");
        toy_arzkey.write(&mut f).expect("write toy arzkey");
    }

    // Sanity: the on-disk toy arzkey must be readable (i.e., the file
    // we just wrote passes `ArzkeyFile::read`'s self-consistency check
    // on its own — it just disagrees with the wasm's embedded blake3).
    {
        let mut f = std::fs::File::open(&toy_arzkey_path).expect("open toy arzkey");
        let parsed: ArzkeyFile<Bn254> =
            ArzkeyFile::<Bn254>::read(&mut f).expect("toy arzkey self-consistency must pass");
        // Sanity assert: toy's body must NOT collide with the main
        // fixture's, otherwise the mismatch test is vacuous.
        let main_arzkey_for_diff = {
            let mut f2 = std::fs::File::open(&arzkey_path_main).expect("open main fixture arzkey");
            ArzkeyFile::<Bn254>::read(&mut f2).expect("main arzkey read")
        };
        assert_ne!(
            parsed.header.ar1cs_blake3, main_arzkey_for_diff.header.ar1cs_blake3,
            "toy and main arzkey must have different ar1cs_blake3, otherwise the \
             mismatch test cannot exercise the new host-side check",
        );
    }

    // ── Step 1: minimal valid CircuitConfig + RawProofRequest (n=k=1) ──
    //
    // The shape only has to satisfy `RawProofRequest::validate(k=1, n=1)`
    // and reach `ProofGenerator::generate`. Field byte contents are
    // intentionally zero — the host pair-check fires *before* per-input
    // postcard encoding and witness generation, so semantic validity of
    // the JWT/anchor/Merkle data is irrelevant for this test.
    let cfg = CircuitConfig {
        max_jwt_b64_len: 256,
        max_payload_b64_len: 192,
        max_aud_len: 32,
        max_exp_len: 20,
        max_iss_len: 32,
        max_nonce_len: 32,
        max_sub_len: 32,
        n: 1,
        k: 1,
        tree_height: 1,
        num_audience_limit: 1,
        claims: vec![
            "aud".into(),
            "exp".into(),
            "iss".into(),
            "nonce".into(),
            "sub".into(),
        ],
        forbidden_string: "forbidden".into(),
    };

    let raw = RawProofRequest {
        pk_path: toy_arzkey_path.clone(),
        wasm_path: wasm_path.clone(),
        shared: ZkapSharedFields {
            random_be: [0u8; 32],
            h_sign_user_op_be: [0u8; 32],
            anchor_values_be: vec![[0u8; 32]; 1],
            anchor_known_x_be: vec![[0u8; 32]; 1],
            anchor_selector: vec![1u8],
            merkle_root_be: [0u8; 32],
        },
        per_jwt: vec![ZkapPerJwtFields {
            jwt_bytes: Vec::new(),
            rsa_modulus_be: vec![0u8; 256],
            rsa_signature_be: vec![0u8; 256],
            anchor_current_idx: 0,
            merkle_leaf_sibling_hash_be: [0u8; 32],
            merkle_auth_path_be: Vec::new(),
            merkle_leaf_idx: 0,
        }],
    };

    // ── Step 2: invoke zkap_service::prove and assert host-side rejection ──
    eprintln!("[mismatch test] zkap_service::prove(toy_arzkey, main_wasm)");
    let result = zkap_service::prove(&cfg, raw);
    let err = result.expect_err(
        "mismatched (wasm, arzkey) pair must be rejected by the host-side fail-fast check",
    );
    let msg = format!("{}", err);
    eprintln!("[mismatch test] error message: {}", msg);
    assert!(
        msg.contains("ar1cs_blake3 mismatch"),
        "expected error message to contain 'ar1cs_blake3 mismatch', got: {}",
        msg
    );
    eprintln!("[done] host_rejects_wasm_with_mismatched_ar1cs_blake3 OK");
}
