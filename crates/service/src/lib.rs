pub mod app;
pub mod error;
pub mod types;
pub mod utils;
pub mod api;

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
