## Summary

Brief description of changes.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation
- [ ] Refactor
- [ ] Circuit constraint change

## Checklist

### Required
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo nextest run --cargo-profile release-tests` passes
- [ ] `cargo fmt --check` passes

### If circuit constraints changed
- [ ] `cargo nextest run --cargo-profile release-tests -p circuit --features integration-tests --test groth16_integration --locked` passes
- [ ] Soundness argument reviewed (no weakening of existing security properties)
- [ ] [Circuit Design](docs/CIRCUIT_DESIGN.md) updated (if applicable)

### If public API changed
- [ ] [API Reference](docs/API_REFERENCE.md) updated
- [ ] Example code still compiles (`cargo build --examples`)

### If applicable
- [ ] CHANGELOG.md updated
- [ ] Performance impact measured or confirmed negligible
