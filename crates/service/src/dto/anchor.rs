//! Anchor generation DTOs

/// Anchor generation response (platform-agnostic core type)
#[derive(Debug, Clone)]
pub struct GenerateAnchorResCore {
    pub anchor: Vec<String>,
}
