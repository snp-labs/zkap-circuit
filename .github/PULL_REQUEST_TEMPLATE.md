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
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] `cargo fmt --check` passes

### If circuit constraints changed
- [ ] `cargo test -p circuit --test groth16_integration -- --ignored` passes
- [ ] Soundness argument reviewed (no weakening of existing security properties)
- [ ] [Circuit Design](docs/CIRCUIT_DESIGN.md) updated (if applicable)

### If public API changed
- [ ] [API Reference](docs/API_REFERENCE.md) updated
- [ ] Example code still compiles (`cargo build --examples`)

### If applicable
- [ ] CHANGELOG.md updated
- [ ] Performance impact measured or confirmed negligible
