# Performance

Benchmarks, resource requirements, and optimization guidance for zkap-circuit.

## How to Measure

Measure setup through the CLI:

```bash
time cargo run --release -p zkap-cli --bin generate_setup -- \
  --config example.json \
  --output /tmp/zkap-perf-crs \
  --circuit-id zkap-perf
```

Measure loader cold-start cost with the timed artifact loaders
(`ArtifactSet::load_signed_with_timing` or
`ArtifactSet::load_unsigned_with_timing`) from the host that owns the bundle.

For detailed per-phase timing of arkworks internals (FFT, MSM, constraint synthesis, etc.), enable the `print-trace` feature:

```bash
time cargo run --release -p zkap-cli --features zkap-service/print-trace --bin generate_setup -- \
  --config example.json \
  --output /tmp/zkap-perf-crs \
  --circuit-id zkap-perf
```

This activates `ark-std`'s built-in timer macros, which print elapsed time for each internal operation to stderr.

## Resource Requirements

### Memory

Groth16 setup and proving are memory-intensive operations. The peak memory usage depends on the circuit size, which is determined by the `max_jwt_b64_len` parameter.

Monitor memory during execution with `top`, `htop`, or Activity Monitor.

### CPU

Proving benefits from multiple cores. The arkworks `parallel` feature is enabled by default, using [Rayon](https://docs.rs/rayon) for work-stealing parallelism.

Control thread count with setup/prove commands:

```bash
RAYON_NUM_THREADS=4 cargo run --release -p zkap-cli --bin generate_setup -- \
  --config example.json \
  --output /tmp/zkap-perf-crs \
  --circuit-id zkap-perf
```

### Disk

CRS files (`pk.bin`) can be large. The pre-built artifacts in `dist/` give an indication of expected sizes:

```bash
ls -lh dist/release-local/1-of-1/pk.bin
```

Proof output (`ProofComponents`) is compact: 3 elliptic curve points (2 G1 + 1 G2), serialized as hex strings.

## Optimization Techniques

| Technique | How | Effect |
|-----------|-----|--------|
| Release mode | `--release` flag | **Required.** Debug mode is orders of magnitude slower |
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
