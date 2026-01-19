pub mod api;
mod app;
pub mod error;

pub use api::anchor::create_poseidon_anchor;
pub use api::hash::poseidon_hash;
pub use api::snark::generate_baerae_proof;
pub use app::anchor::types::Secret;

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
    // Android가 아니면 no-op (또는 env_logger 초기화 등)
}
