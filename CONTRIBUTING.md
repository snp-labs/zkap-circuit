# Contributing to zkap-circuit

Thank you for your interest in contributing. This document explains how to get started, build the project, and submit changes.

## Git Configuration

Before your first commit, configure Git to use your GitHub noreply email address.
This prevents your personal email from being permanently embedded in public git history.

```sh
git config user.email "username@users.noreply.github.com"
```

Replace `username` with your GitHub username. You can find your noreply address at
**GitHub → Settings → Emails**.

## Getting Started

Clone the repository and build:

```sh
git clone https://github.com/snp-labs/zkap-circuit.git
cd zkap-circuit
cargo build
```

## Development

### Prerequisites

- Rust 1.85 or later (`rustup update stable`) — required for edition 2024
- `cargo` (included with Rust)

### Building

```sh
cargo build --release
```

`Cargo.lock` is committed to the repository so that CI and contributors
reproduce the exact same dependency versions. Do not add `Cargo.lock` to
`.gitignore`. Update it intentionally with `cargo update` when upgrading
dependencies, and include the lock-file change in the same commit as the
`Cargo.toml` change.

### Testing

```sh
cargo test --release
```

To run tests for a specific crate:

```sh
cargo test -p circuit
cargo test -p gadget
cargo test -p zkap-service
```

### Documentation

Build and browse the API docs locally:

```sh
cargo doc --workspace --no-deps --open
```

### Running Examples

```sh
# Compile the in-tree examples (zkap-service ships none today; the
# canonical end-to-end exercise lives in
# `crates/service/tests/native_prove_e2e.rs` and the slow
# `circuit::tests::groth16_integration` suite).
cargo build --workspace --examples --release
```

### Linting

All pull requests must pass Clippy without warnings:

```sh
cargo clippy -- -D warnings
```

Format your code before submitting:

```sh
cargo fmt
```

## Project Structure

```
zkap-circuit/
├── crates/
│   ├── ark-utils/  # R1CS helpers, field arithmetic, EVM codegen
│   ├── circuit/    # Main ZK circuit definitions (ZkapCircuit, CircuitConfig)
│   ├── cli/        # CLI binaries (generate_setup, generate_hash)
│   ├── gadget/     # Reusable circuit gadgets (anchors, signatures, matrix ops)
│   └── service/    # Proof generation service
│       ├── src/
│       │   ├── witness/  # Native input shaping (ProofRequest → ZkapInputV1 → ZkapCircuitInput)
│       │   ├── artifact/ # Manifest-validated CRS bundle loader (ArtifactSet::load)
│       │   ├── prover/   # Native ar1cs prover (Prover::from_artifact + Prover::prove)
│       │   ├── proof/    # Trusted setup (setup, SetupOutput)
│       │   ├── anchor_host/  # Anchor generation (Poseidon anchor scheme)
│       │   ├── hash/     # Hash utilities (Poseidon hash, audience hash, leaf hash)
│       │   ├── jwt/      # JWT parsing and witness construction
│       │   ├── dto/      # Platform-agnostic DTOs for bindings
│       │   └── manifest.rs   # Manifest schema + ManifestBuilder
│       └── tests/        # Integration tests
└── dist/           # Pre-built CRS bundles (1-of-1, 3-of-3 in 7-file layout)
```

## Branch and Review

### Branch Strategy

- Create branches from `main`.
- Use the naming convention: `<type>/<short-description>`
  (e.g. `feat/poseidon-cache`, `fix/anchor-length`, `docs/contributing-guide`).

### Review Expectations

- All pull requests require at least one approving review before merge.
- CI must pass: `cargo clippy`, `cargo test --release`, `cargo fmt --check`.
- Changes to circuit constraints or cryptographic logic may require additional review.

## Pull Request Process

### Checklist

Before opening a pull request, confirm all of the following:

- [ ] `cargo clippy -- -D warnings` passes with no errors
- [ ] `cargo test --release` passes
- [ ] `cargo fmt` has been run and the diff is clean
- [ ] New public items include doc comments
- [ ] Any new cryptographic logic includes references to the relevant specification or paper

### Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

Format: `<type>(<scope>): <description>`

Common types:

| Type       | When to use                                |
|------------|--------------------------------------------|
| `feat`     | A new feature or circuit gadget            |
| `fix`      | A bug fix                                  |
| `refactor` | Code change that is not a fix or feature   |
| `test`     | Adding or updating tests                   |
| `docs`     | Documentation only changes                 |
| `chore`    | Build scripts, CI, dependency updates      |
| `security` | Security-related fixes                     |

Examples:

```
feat(gadget): add Poseidon hash constraints for BN254
fix(circuit): correct witness assignment in anchor gadget
test(circuit): add Groth16 integration tests with K=3
```

## Contributing Documentation and Examples

Documentation and example improvements are welcome. When contributing:

- Verify that code examples compile: `cargo build` and, if runnable, `cargo run`.
- Do not include real JWT tokens, private keys, or secrets in examples or docs.
- Keep examples self-contained — no external services or files outside the repo.
- Update `README.md` if your change affects the public API or build instructions.

## Reporting Issues

Before filing an issue, search existing issues to avoid duplicates.

When reporting a bug, include:

- Rust version (`rustc --version`)
- Operating system and architecture
- Minimal reproduction steps or code
- Expected vs actual behavior

For security vulnerabilities, do **not** open a public issue. See [SECURITY.md](./SECURITY.md) for the responsible disclosure process.
