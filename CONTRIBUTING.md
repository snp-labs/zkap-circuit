# Contributing to zkap-circuit

Thank you for your interest in contributing. This document explains how to get started, build the project, and submit changes.

## Getting Started

Clone the repository and build:

```sh
git clone https://github.com/snp-labs/zkap-circuit.git
cd zkap-circuit
cargo build
```

## Development

### Prerequisites

- Rust 1.75 or later (`rustup update stable`)
- `cargo` (included with Rust)

### Building

```sh
cargo build --release
```

### Testing

```sh
cargo test --release
```

To run tests for a specific crate:

```sh
cargo test --release -p zkap-circuit
cargo test --release -p zkap-gadget
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
│   ├── circuit/    # Main ZK circuit definitions
│   ├── gadget/     # Reusable circuit gadgets (anchors, signatures, matrix ops)
│   └── service/    # Service layer and bindings
├── bindings/       # Language bindings (e.g., WASM, FFI)
├── packages/       # Additional packages
└── docs/           # Documentation
```

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

## Reporting Issues

Before filing an issue, search existing issues to avoid duplicates.

When reporting a bug, include:

- Rust version (`rustc --version`)
- Operating system and architecture
- Minimal reproduction steps or code
- Expected vs actual behavior

For security vulnerabilities, do **not** open a public issue. See [SECURITY.md](./SECURITY.md) for the responsible disclosure process.
