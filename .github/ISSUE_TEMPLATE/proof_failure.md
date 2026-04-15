---
name: Proof Failure
about: Report a zero-knowledge proof generation or verification failure
labels: bug, proof-failure
---

## Description

What happened? (e.g. "prove() returns ProofGenerationFailed", "verify() returns false for a valid proof")

## Environment

- OS:
- Rust version (`rustc --version`):
- zkap-circuit version / commit:
- Binding (native Rust / napi / wasm / uniffi):
- Build mode (debug / release):

## Circuit Configuration

Paste your `CircuitConfig` JSON (from `example.json` or `config.json`):

```json

```

## Input Summary

- Number of JWTs (K):
- JWT issuer(s):
- Merkle tree height:
- Anchor parameters (N, K):

## Error Message

Full error output:

```

```

## Steps to Reproduce

1.
2.
3.

## CRS Information

- CRS source (fresh `setup()` / pre-built from `dist/` / other):
- CRS config matches proof config? (yes / unknown):

## Additional Context

Any additional context, logs, or observations.
