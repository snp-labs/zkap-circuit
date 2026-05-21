//! Arkworks parity bench — C4 rows 7·8.
//!
//! Measures constraint cost of `enforce_boolean_selectors` (anchor module,
//! Row 7) and `MerkleCircuitInputVar::enforce_membership` (merkletree module,
//! Row 8) against their cheaper equivalents.
//!
//! **Apples-to-apples discipline** (constraint-audit.md §Step 5):
//! - Every CS uses `SynthesisMode::Setup` + `OptimizationGoal::Constraints`.
//! - Inputs are pre-allocated before the gadget-delta baseline is recorded.
//! - `cs.finalize()` is called before reading counts.
//!
//! Run with:
//! ```
//! cargo test --profile release-tests -p gadget \
//!   --features "anchor,merkletree" \
//!   --test arkworks_parity_bench -- --nocapture
//! ```

#![cfg(all(feature = "anchor", feature = "merkletree"))]
#![allow(missing_docs)]
// Bench tests use explicit indexed loops for clarity at fixture-construction
// time; the equivalent iterator chain would obscure the per-row mapping that
// the audit documentation references.
#![allow(clippy::needless_range_loop)]

use ark_bn254::Fr;
use ark_crypto_primitives::{
    crh::{
        CRHScheme,
        poseidon::{CRH, constraints::CRHParametersVar},
    },
    merkle_tree::{MerkleTree, Path, constraints::PathVar},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{Boolean, ToBitsGadget},
    uint16::UInt16,
};
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, SynthesisMode};
use gadget::{
    anchor::poseidon::constraints::enforce_boolean_selectors,
    hashes::poseidon::get_poseidon_params,
    merkletree::{
        MerkleCircuitInput,
        constraints::MerkleCircuitInputVar,
        tree_config::{MerkleTreeParams, MerkleTreeParamsVar},
    },
};

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a Merkle tree of `tree_height` with `n_leaves` sequential field
/// elements `[0, 1, ..., n_leaves-1]` as leaves, and returns the root, the
/// authentication path for leaf at `idx`, and the leaf digest.
///
/// Mirrors the private `generate_merkle_tree_input` helper used in
/// `gadget::merkletree::constraints` unit tests.
fn generate_merkle_tree_input<F: PrimeField + Absorb>(
    tree_height: usize,
    n_leaves: usize,
    idx: usize,
) -> (F, Path<MerkleTreeParams<F>>, F) {
    let leaf_hash_param = get_poseidon_params::<F>();
    let two_to_one_param = get_poseidon_params::<F>();

    let mut digests = vec![F::zero(); 1 << (tree_height - 1)];
    for i in 0..n_leaves {
        let leaf = F::from(i as u64);
        digests[i] = CRH::evaluate(&leaf_hash_param, [leaf]).unwrap();
    }

    let mt = MerkleTree::<MerkleTreeParams<F>>::new_with_leaf_digest(
        &leaf_hash_param,
        &two_to_one_param,
        digests.clone(),
    )
    .unwrap();

    let root = mt.root();
    let path = mt.generate_proof(idx).unwrap();
    (root, path, digests[idx])
}

// ─────────────────────────────────────────────────────────────────────────────
// ROW 7 — enforce_boolean_selectors(&fps)  vs  Boolean::new_witness × k
// ─────────────────────────────────────────────────────────────────────────────
//
// `enforce_boolean_selectors` takes k FpVars already allocated, then adds
// `s*(s-1)=0` per element = k constraints as a gadget.
//
// The upstream alternative: allocate k `Boolean::new_witness` directly.
// Each `Boolean::new_witness` adds `b*(b-1)=0` during allocation → same
// booleanity constraint but it's *in the alloc cost*, not post-hoc.
//
// Net cost is identical for both (k constraints total), but the custom path
// wastefully repeats the constraint for already-allocated FpVars.
// The difference is visible in the gadget-delta column: custom=k, ark=0.

/// Row 7: `enforce_boolean_selectors` vs `Boolean::new_witness × k`
/// at k=16 and k=64.
#[test]
fn bench_row_7_enforce_boolean_selectors() {
    for k in [16_usize, 64] {
        // ── CUSTOM SIDE ──────────────────────────────────────────────────────
        // Allocate k FpVars (0 range constraint each), then call the gadget.
        let cs_custom = ConstraintSystem::<Fr>::new_ref();
        cs_custom.set_mode(SynthesisMode::Setup);
        cs_custom.set_optimization_goal(OptimizationGoal::Constraints);

        let fps: Vec<FpVar<Fr>> = (0..k)
            .map(|i| {
                FpVar::new_witness(cs_custom.clone(), || Ok(Fr::from((i % 2) as u64))).unwrap()
            })
            .collect();

        let alloc_cs_custom = cs_custom.num_constraints();
        let alloc_w_custom = cs_custom.num_witness_variables();

        // Gadget: adds k constraints for s*(s-1)=0.
        enforce_boolean_selectors(&fps).unwrap();
        cs_custom.finalize();
        let custom_cs = cs_custom.num_constraints();
        let custom_w = cs_custom.num_witness_variables();

        // ── ARKWORKS SIDE ────────────────────────────────────────────────────
        // Boolean::new_witness enforces b*(b-1)=0 at allocation — booleanity
        // is in the alloc cost; no further gadget needed.
        let cs_ark = ConstraintSystem::<Fr>::new_ref();
        cs_ark.set_mode(SynthesisMode::Setup);
        cs_ark.set_optimization_goal(OptimizationGoal::Constraints);

        let _bools: Vec<Boolean<Fr>> = (0..k)
            .map(|i| Boolean::new_witness(cs_ark.clone(), || Ok((i % 2) == 0)).unwrap())
            .collect();

        // No gadget call needed — booleanity already enforced.
        cs_ark.finalize();
        let ark_cs = cs_ark.num_constraints();
        let ark_w = cs_ark.num_witness_variables();

        let custom_gadget_cs = custom_cs as i64 - alloc_cs_custom as i64;
        let custom_gadget_w = custom_w as i64 - alloc_w_custom as i64;
        // Ark: gadget delta = 0 (constraint is in alloc).
        let ark_gadget_cs = 0_i64;
        let ark_gadget_w = 0_i64;
        let delta_cs = custom_gadget_cs - ark_gadget_cs;

        println!(
            "ROW7::enforce_boolean_selectors@k={k}: \
             custom_cs={custom_cs}, custom_witness={custom_w}, \
             ark_cs={ark_cs}, ark_witness={ark_w}, delta_cs={delta_cs} \
             [alloc_baseline: custom_cs={alloc_cs_custom},w={alloc_w_custom}; \
             ark_cs={ark_cs},w={ark_w} (range-in-alloc); \
             gadget_delta: custom_cs={custom_gadget_cs},w={custom_gadget_w}; \
             ark_cs={ark_gadget_cs},w={ark_gadget_w}]"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ROW 8 — MerkleCircuitInputVar::enforce_membership  vs  inline PathVar path
// ─────────────────────────────────────────────────────────────────────────────
//
// `enforce_membership` is a thin wrapper that calls:
//   1. `self.path.set_leaf_position(self.leaf_idx.to_bits_le()?)`
//   2. `self.path.verify_membership(hash, hash, root, &[leaf])?`
//   3. `membership.enforce_equal(&Boolean::TRUE)?`
//
// Expected: delta ≈ 0 since the wrapper adds no extra constraints.
//
// Both sides allocate identically: leaf FpVar + UInt16 leaf_idx + PathVar.
// The "ark" inline side calls the same three steps manually.

/// Row 8: `MerkleCircuitInputVar::enforce_membership` (custom wrapper) vs
/// identical inline `set_leaf_position` + `verify_membership` + `enforce_equal`.
/// Tree height = 5, 5 leaves, leaf at index 2.
#[test]
fn bench_row_8_enforce_membership() {
    let tree_height = 5_usize;
    let n_leaves = 5_usize;
    let idx = 2_usize;

    let (root_val, path_val, leaf_digest_val) =
        generate_merkle_tree_input::<Fr>(tree_height, n_leaves, idx);

    let poseidon_params = get_poseidon_params::<Fr>();

    // ── CUSTOM SIDE ──────────────────────────────────────────────────────────
    let cs_custom = ConstraintSystem::<Fr>::new_ref();
    cs_custom.set_mode(SynthesisMode::Setup);
    cs_custom.set_optimization_goal(OptimizationGoal::Constraints);

    let hash_params_custom =
        CRHParametersVar::<Fr>::new_constant(cs_custom.clone(), poseidon_params.clone()).unwrap();

    let root_var_custom = FpVar::<Fr>::new_witness(cs_custom.clone(), || Ok(root_val)).unwrap();

    let input = MerkleCircuitInput::<Fr> {
        leaf: leaf_digest_val,
        leaf_idx: idx,
        path: path_val.clone(),
    };
    let mut input_var =
        MerkleCircuitInputVar::<Fr>::new_witness(cs_custom.clone(), || Ok(input)).unwrap();

    let alloc_cs_custom = cs_custom.num_constraints();
    let alloc_w_custom = cs_custom.num_witness_variables();

    // Gadget: thin wrapper around set_leaf_position + verify_membership + enforce_equal.
    input_var
        .enforce_membership(&hash_params_custom, &root_var_custom)
        .unwrap();
    cs_custom.finalize();
    let custom_cs = cs_custom.num_constraints();
    let custom_w = cs_custom.num_witness_variables();

    // ── ARKWORKS SIDE (inline) ────────────────────────────────────────────────
    let cs_ark = ConstraintSystem::<Fr>::new_ref();
    cs_ark.set_mode(SynthesisMode::Setup);
    cs_ark.set_optimization_goal(OptimizationGoal::Constraints);

    let hash_params_ark =
        CRHParametersVar::<Fr>::new_constant(cs_ark.clone(), poseidon_params.clone()).unwrap();

    let root_var_ark = FpVar::<Fr>::new_witness(cs_ark.clone(), || Ok(root_val)).unwrap();

    // Allocate the same components as MerkleCircuitInputVar manually.
    let leaf_var = FpVar::<Fr>::new_witness(cs_ark.clone(), || Ok(leaf_digest_val)).unwrap();
    let leaf_idx_var = UInt16::<Fr>::new_witness(cs_ark.clone(), || Ok(idx as u16)).unwrap();
    let mut path_var = PathVar::<MerkleTreeParams<Fr>, Fr, MerkleTreeParamsVar<Fr>>::new_witness(
        cs_ark.clone(),
        || Ok(path_val),
    )
    .unwrap();

    let alloc_cs_ark = cs_ark.num_constraints();
    let alloc_w_ark = cs_ark.num_witness_variables();

    // Inline the same three steps that enforce_membership calls.
    path_var.set_leaf_position(leaf_idx_var.to_bits_le().unwrap());
    let membership = path_var
        .verify_membership(
            &hash_params_ark,
            &hash_params_ark,
            &root_var_ark,
            std::slice::from_ref(&leaf_var),
        )
        .unwrap();
    membership.enforce_equal(&Boolean::TRUE).unwrap();

    cs_ark.finalize();
    let ark_cs = cs_ark.num_constraints();
    let ark_w = cs_ark.num_witness_variables();

    let custom_gadget_cs = custom_cs as i64 - alloc_cs_custom as i64;
    let custom_gadget_w = custom_w as i64 - alloc_w_custom as i64;
    let ark_gadget_cs = ark_cs as i64 - alloc_cs_ark as i64;
    let ark_gadget_w = ark_w as i64 - alloc_w_ark as i64;
    let delta_cs = custom_gadget_cs - ark_gadget_cs;
    let delta_w = custom_gadget_w - ark_gadget_w;

    println!(
        "ROW8::enforce_membership@height={tree_height}: \
         custom_cs={custom_cs}, custom_witness={custom_w}, \
         ark_cs={ark_cs}, ark_witness={ark_w}, delta_cs={delta_cs}, delta_w={delta_w} \
         [alloc_baseline: custom_cs={alloc_cs_custom},w={alloc_w_custom}; \
         ark_cs={alloc_cs_ark},w={alloc_w_ark}; \
         gadget_delta: custom_cs={custom_gadget_cs},w={custom_gadget_w}; \
         ark_cs={ark_gadget_cs},w={ark_gadget_w}]"
    );
}
