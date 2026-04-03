use circuit::constants::F;

/// Computed context for audience verification
#[derive(Clone)]
pub struct AudienceContext {
    /// Padded audience list (length Config::NUM_AUDIENCE_LIMIT)
    pub padded_list: Vec<F>,

    /// H(padded_aud_list)
    pub h_aud_list: F,
}

impl AudienceContext {
    /// Creates a new AudienceContext
    pub fn new(padded_list: Vec<F>, h_aud_list: F) -> Self {
        Self {
            padded_list,
            h_aud_list,
        }
    }
}
