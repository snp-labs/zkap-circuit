use circuit::constants::F;

/// Computed context for anchor verification
#[derive(Clone)]
pub struct AnchorContext {
    /// Selector vector (marks the currently selected JWT token positions)
    pub selector: Vec<u8>,

    /// Vector a for <a, anchor> * random = <b, h_known> * random
    pub a: Vec<F>,

    /// H(a, random) value
    pub h_a: F,

    /// <a, anchor> * random - LHS value
    pub lhs: F,

    /// Partial RHS values for each proof
    pub partial_rhs_list: Vec<F>,

    /// Selected indices (i where selector[i] == 1)
    pub current_idx_list: Vec<usize>,
}

impl AnchorContext {
    /// Creates a new AnchorContext
    pub fn new(
        selector: Vec<u8>,
        a: Vec<F>,
        h_a: F,
        lhs: F,
        partial_rhs_list: Vec<F>,
        current_idx_list: Vec<usize>,
    ) -> Self {
        Self {
            selector,
            a,
            h_a,
            lhs,
            partial_rhs_list,
            current_idx_list,
        }
    }

    /// Partial RHS value for the i-th proof
    pub fn partial_rhs_for(&self, proof_index: usize) -> F {
        self.partial_rhs_list[proof_index]
    }

    /// Current index for the i-th proof
    pub fn current_idx_for(&self, proof_index: usize) -> usize {
        self.current_idx_list[proof_index]
    }
}
