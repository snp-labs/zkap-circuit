# Performance

Benchmarks, resource requirements, and optimization guidance for zkap-circuit.

## How to Measure

Run the full lifecycle example and observe timing:

```bash
time cargo run -p zkap-service --example groth16_proof --release
```

The example prints step markers (`[Step 1]` through `[Step 7]`) that can be used for manual per-phase timing.

For detailed per-phase timing of arkworks internals (FFT, MSM, constraint synthesis, etc.), enable the `print-trace` feature:

```bash
time cargo run -p zkap-service --example groth16_proof --release --features print-trace
```

This activates `ark-std`'s built-in timer macros, which print elapsed time for each internal operation to stderr.

## Resource Requirements

### Memory

Groth16 setup and proving are memory-intensive operations. The peak memory usage depends on the circuit size, which is determined by the `max_jwt_b64_len` parameter.

Monitor memory during execution with `top`, `htop`, or Activity Monitor.

### CPU

Proving benefits from multiple cores. The arkworks `parallel` feature is enabled by default, using [Rayon](https://docs.rs/rayon) for work-stealing parallelism.

Control thread count with:

```bash
RAYON_NUM_THREADS=4 cargo run -p zkap-service --example groth16_proof --release
```

### Disk

CRS files (`pk.key`) can be large. The pre-built artifacts in `dist/` give an indication of expected sizes:

```bash
ls -lh dist/*/
```

Proof output (`ProofComponents`) is compact: 3 elliptic curve points (2 G1 + 1 G2), serialized as hex strings.

## Optimization Techniques

| Technique | How | Effect |
|-----------|-----|--------|
| Release mode | `--release` flag | **Required.** Debug mode is orders of magnitude slower |
| Streaming prover | `use-optimized` Cargo feature | Reduces peak memory during proving (designed for iOS/mobile) |
| Rayon thread count | `RAYON_NUM_THREADS=N` env var | Tune parallelism for your hardware |
| Smaller config | Reduce `max_jwt_b64_len`, `tree_height`, `n` | Fewer constraints = faster setup and proving |
| Pre-built CRS | Use `dist/` artifacts | Skip trusted setup entirely |

## Configuration vs. Performance

Constraint count (and therefore proving time) grows with these parameters. See [Circuit Design](CIRCUIT_DESIGN.md) for details on which constraint groups are affected.

| Parameter | Impact on constraint count |
|-----------|--------------------------|
| `max_jwt_b64_len` | High — controls SHA-256 block count |
| `tree_height` | Medium — one Poseidon hash per tree level |
| `n` / `k` | Medium — Vandermonde matrix operations |
| `num_audience_limit` | Low — linear hash comparisons |
| `max_*_len` (claim lengths) | Low — linear padding/packing |

## Proof Size

Groth16 proof size is constant regardless of circuit size:

| Component | Size |
|-----------|------|
| Proof (a, b, c) | 2 G1 points + 1 G2 point |
| Public inputs | 8 field elements |

This makes Groth16 suitable for on-chain verification where calldata cost matters.
