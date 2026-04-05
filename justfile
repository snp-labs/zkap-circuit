# zkup-baerae build commands

# Basic commands
check:
    cargo check --workspace

test:
    cargo test --release --package test

# Feature combination verification
check-features:
    cargo check -p gadget --no-default-features --features anchor
    cargo check -p gadget --no-default-features --features base64
    cargo check -p gadget --no-default-features --features hashes-poseidon
    cargo check -p gadget --no-default-features --features rsa
    cargo check -p gadget --no-default-features --features full
    cargo check -p zkap-wasm --target wasm32-unknown-unknown

# WASM
build-wasm:
    wasm-pack build bindings/wasm --target web --release

# NAPI
build-napi:
    cd bindings/napi && npm run build

# iOS (requires: rustup target add aarch64-apple-ios)
build-ios:
    cargo build --release --target aarch64-apple-ios -p uniffi-bindings

# Android (requires: cargo-ndk, ANDROID_NDK_HOME)
build-android:
    cargo build --release --target aarch64-linux-android -p uniffi-bindings

# CRS generation
setup:
    cargo run --release -p zkap-cli --bin generate_crs -- --output ./dist --config example.json

# Debug with constraint logging
test-debug:
    cargo test --release --features print-trace,constraints-logging --package test

# Prove
prove:
    cargo test --release --package test --test snark_v4_test test_generate_proof_single -- --nocapture

# Build all targets
build-all: build-wasm build-napi build-ios build-android

# Clean
clean:
    cargo clean
