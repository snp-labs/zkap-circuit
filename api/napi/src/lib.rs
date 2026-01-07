#![deny(clippy::all)]

#[cfg(target_os = "android")]
use android_logger::{Config, FilterBuilder};

pub mod api;
pub mod dto;

// Initialize Android logging when the library is loaded
#[cfg(target_os = "android")]
#[ctor::ctor]
fn init_logging() {
    android_logger::init_once(
        Config::default()
            .with_max_level(log::LevelFilter::Trace)
            .with_tag("ZKAP")
            .with_filter(FilterBuilder::new().parse("debug,zkpasskey=trace").build())
    );
}
