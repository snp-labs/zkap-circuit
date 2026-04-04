//! Anchor generation DTOs

pub use crate::anchor::types::Secret;

/// Anchor generation request (platform-agnostic core type)
#[derive(Debug, Clone)]
pub struct GenerateAnchorReqCore {
    pub secrets: Vec<Secret>,
}

/// Anchor generation response (platform-agnostic core type)
#[derive(Debug, Clone)]
pub struct GenerateAnchorResCore {
    pub anchor: Vec<String>,
}
