pub mod api;
mod app;
pub mod dto;
pub mod error;
pub mod manifest;

pub use circuit::constants;
pub use circuit::field_parser;
pub use circuit::error as common_error;
pub use circuit::evm;
pub use circuit::io;
pub use circuit::text;

pub use api::anchor::create_poseidon_anchor;
pub use api::hash::poseidon_hash;
pub use api::snark::generate_baerae_proof;
pub use app::anchor::types::Secret;
pub use app::snark::RawProofRequest;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(target_os = "android")]
pub fn init_android_logging() {
    use log::LevelFilter;

    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("ZKAP")
            .with_max_level(LevelFilter::Info),
    );
}

#[cfg(not(target_os = "android"))]
pub fn init_android_logging() {
    // No-op when not on Android (or initialize env_logger, etc.)
}
