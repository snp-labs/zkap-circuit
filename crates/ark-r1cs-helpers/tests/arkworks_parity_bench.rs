//! Arkworks parity bench — C4 rows 1·2·6.
//!
//! Measures constraint cost of custom `ark-r1cs-helpers` comparison gadgets
//! against their ark-r1cs-std 0.6 equivalents. Row 6 is upstream-only (the
//! custom `UInt32Ext` trait was removed in AC-7; the C4 bench Δ=0 evidence
//! it produced is preserved as upstream baseline measurements).
//!
//! **Apples-to-apples discipline** (constraint-audit.md §Step 5):
//! - Every CS is configured with `SynthesisMode::Setup` +
//!   `OptimizationGoal::Constraints` before any allocation.
//! - Inputs are pre-allocated as Boolean witnesses (rows 1·2) or `UInt32`
//!   witnesses (row 6) on a FRESH cs for each side; allocation cost is
//!   reported separately.
//! - `cs.finalize()` is called before reading `cs.num_constraints()` /
//!   `cs.num_witness_variables()`.
//! - Both sides receive identical concrete values; the custom side takes
//!   `Boolean<Fr>` slices, the arkworks side operates on the same data via
//!   operators.
//!
//! **Row 1 & 2 — API-divergent:**
//! `FpVar::enforce_cmp` / `FpVar::is_cmp` (ark-r1cs-std 0.5.0 API) do NOT
//! exist in ark-r1cs-std 0.6.0.  The 0.6 `CmpGadget` trait (cmp.rs) only
//! provides `is_lt/is_le/is_ge/is_gt` for `UInt<N,T,F>` and slices; `FpVar`
//! implements none of these.  Custom-side constraint counts are reported;
//! arkworks-side is recorded as `API-divergent`.
//!
//! Run with:
//! ```
//! cargo test --profile release-tests -p ark-r1cs-helpers arkworks_parity_bench -- --nocapture
//! ```
//!
//! Output is captured to `.omc/state/c4-early-bench-rows.txt`.

#![allow(missing_docs)]

use ark_bn254::Fr;
use ark_ff::PrimeField;
use core::cmp::Ordering;
use ark_r1cs_helpers::{
    enforce_less_than, is_less_than, pack_decompose_bytes_checked, select_array_element_be,
    single_multiplexer,
};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{Boolean, ToBitsGadget},
    select::CondSelectGadget,
    uint8::UInt8,
    uint32::UInt32,
};
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, SynthesisMode};

// ─────────────────────────────────────────────────────────────────────────────
// ROW 1 — enforce_less_than(a_bits, b_bits) vs FpVar::enforce_cmp  [FpVar-level]
// ─────────────────────────────────────────────────────────────────────────────
//
// CORRECTION from early-bench: `FpVar::enforce_cmp` DOES exist in ark-r1cs-std
// 0.6.0 (confirmed by T1 reproducer crates/circuit/tests/r1cs_std_enforce_cmp_repro.rs).
// It lives in `ark_r1cs_std::fields::fp::FpVar` (not via a CmpGadget trait) and
// is callable as `a.enforce_cmp(&b, Ordering::Less, false)`.
//
// True apples-to-apples at the FpVar level (option a from team-lead):
//   - Both sides take 2 FpVar witnesses as allocation baseline.
//   - Custom: wraps `a.to_bits_le()` + `b.to_bits_le()` + `enforce_less_than(&bits, &bits)`
//   - Ark:    `a.enforce_cmp(&b, Ordering::Less, false)` (strict <)
//
// Both algorithms start from FpVars and both decompose to bits internally.
//
// `enforce_cmp` internals (0.6.0 fields/fp/cmp.rs):
//   1. `enforce_smaller_or_equal_than_mod_minus_one_div_two` × 2  (range check each input)
//   2. `(a - b).double().to_bits_le()` — decomposes the doubled difference
//   3. `bits[0].enforce_equal(&Boolean::TRUE)` — checks the sign bit

/// Row 1: `enforce_less_than` (custom, FpVar-wrapped) vs `FpVar::enforce_cmp`
/// (upstream ark-r1cs-std 0.6.0). Both take FpVar inputs; decomposition is
/// inside the gadget call for both sides.
#[test]
fn bench_row_1_enforce_less_than() {
    // a < b and both < (p-1)/2 (required by enforce_cmp).
    let a_val: u64 = 12345;
    let b_val: u64 = 67890;

    // ── CUSTOM SIDE: FpVar → to_bits_le → enforce_less_than ──────────────────
    let cs_custom = ConstraintSystem::<Fr>::new_ref();
    cs_custom.set_mode(SynthesisMode::Setup);
    cs_custom.set_optimization_goal(OptimizationGoal::Constraints);

    let a_custom = FpVar::<Fr>::new_witness(cs_custom.clone(), || Ok(Fr::from(a_val))).unwrap();
    let b_custom = FpVar::<Fr>::new_witness(cs_custom.clone(), || Ok(Fr::from(b_val))).unwrap();

    let alloc_cs_custom = cs_custom.num_constraints();
    let alloc_w_custom = cs_custom.num_witness_variables();

    // Wrap: decompose both FpVars then call the bit-slice gadget.
    // to_bits_le() for BN254 Fr returns 254 Boolean witnesses.
    let a_bits = a_custom.to_bits_le().unwrap();
    let b_bits = b_custom.to_bits_le().unwrap();
    enforce_less_than(&a_bits, &b_bits).unwrap();
    cs_custom.finalize();

    let custom_cs = cs_custom.num_constraints();
    let custom_w = cs_custom.num_witness_variables();
    let custom_gadget_cs = custom_cs as i64 - alloc_cs_custom as i64;
    let custom_gadget_w = custom_w as i64 - alloc_w_custom as i64;

    // ── ARKWORKS SIDE: FpVar::enforce_cmp ────────────────────────────────────
    // enforce_cmp(Less, false) = strict a < b.  Requires a, b <= (p-1)/2.
    // Internally: 2× range checks via to_non_unique_bits_le + 1× diff decomp.
    let cs_ark = ConstraintSystem::<Fr>::new_ref();
    cs_ark.set_mode(SynthesisMode::Setup);
    cs_ark.set_optimization_goal(OptimizationGoal::Constraints);

    let a_ark = FpVar::<Fr>::new_witness(cs_ark.clone(), || Ok(Fr::from(a_val))).unwrap();
    let b_ark = FpVar::<Fr>::new_witness(cs_ark.clone(), || Ok(Fr::from(b_val))).unwrap();

    let alloc_cs_ark = cs_ark.num_constraints();
    let alloc_w_ark = cs_ark.num_witness_variables();

    a_ark.enforce_cmp(&b_ark, Ordering::Less, false).unwrap();
    cs_ark.finalize();

    let ark_cs = cs_ark.num_constraints();
    let ark_w = cs_ark.num_witness_variables();
    let ark_gadget_cs = ark_cs as i64 - alloc_cs_ark as i64;
    let ark_gadget_w = ark_w as i64 - alloc_w_ark as i64;
    let delta_cs = custom_gadget_cs - ark_gadget_cs;
    let delta_w = custom_gadget_w - ark_gadget_w;

    println!(
        "ROW1::enforce_less_than@FpVar(254bits): \
         custom_cs={custom_cs}, custom_witness={custom_w}, \
         ark_cs={ark_cs}, ark_witness={ark_w}, delta_cs={delta_cs}, delta_w={delta_w} \
         [alloc_baseline: custom_cs={alloc_cs_custom},w={alloc_w_custom}; \
         ark_cs={alloc_cs_ark},w={alloc_w_ark}; \
         gadget_delta: custom_cs={custom_gadget_cs},w={custom_gadget_w}; \
         ark_cs={ark_gadget_cs},w={ark_gadget_w}]"
    );
    println!(
        "ROW1 NOTE: FpVar::enforce_cmp EXISTS in ark-r1cs-std 0.6.0 \
         (confirmed by T1 reproducer). Earlier 'API-divergent' report was wrong — \
         the method is on FpVar directly, not via a CmpGadget trait."
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ROW 2 — is_less_than(a_bits, b_bits)  vs  FpVar::is_cmp
// ─────────────────────────────────────────────────────────────────────────────

/// Row 2: `is_less_than` custom gadget constraint cost.
///
/// Arkworks equivalent (`FpVar::is_cmp`) is **API-divergent** in
/// ark-r1cs-std 0.6.0: same reason as Row 1.  Attempted upstream symbol =
/// `ark_r1cs_std::fields::fp::FpVar::is_cmp` — method does not exist.
#[test]
fn bench_row_2_is_less_than() {
    let a_val: u64 = 0;
    let b_val: u64 = 100;

    for n_bits in [32_usize, 64, 254] {
        // ── CUSTOM SIDE ──────────────────────────────────────────────────────
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Setup);
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        let a_bits: Vec<Boolean<Fr>> = (0..n_bits)
            .map(|i| {
                Boolean::new_witness(cs.clone(), || Ok((a_val >> i) & 1 == 1)).unwrap()
            })
            .collect();
        let b_bits: Vec<Boolean<Fr>> = (0..n_bits)
            .map(|i| {
                Boolean::new_witness(cs.clone(), || Ok((b_val >> i) & 1 == 1)).unwrap()
            })
            .collect();

        let alloc_cs = cs.num_constraints();
        let alloc_witnesses = cs.num_witness_variables();

        // Gadget under measurement.
        let _result = is_less_than(&a_bits, &b_bits).unwrap();
        cs.finalize();

        let custom_cs_total = cs.num_constraints();
        let custom_witness_total = cs.num_witness_variables();
        let custom_gadget_cs = custom_cs_total - alloc_cs;
        let custom_gadget_witnesses = custom_witness_total - alloc_witnesses;

        println!(
            "ROW2::is_less_than@{n_bits}bits: \
             custom_cs={custom_cs_total}, custom_witness={custom_witness_total}, \
             ark_cs=API-divergent, ark_witness=API-divergent, delta=N/A \
             [alloc_baseline: cs={alloc_cs}, witnesses={alloc_witnesses}; \
             gadget_delta: cs={custom_gadget_cs}, witnesses={custom_gadget_witnesses}]"
        );
    }
    println!(
        "ROW2 NOTE: API-divergent — attempted upstream symbol = \
         ark_r1cs_std::fields::fp::FpVar::is_cmp, \
         compile error = method not found in `FpVar<Fr>` \
         (CmpGadget not implemented for FpVar in ark-r1cs-std 0.6.0)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ROW 6 — upstream UInt32 ops (shr / not / bitand) baseline
// ─────────────────────────────────────────────────────────────────────────────
//
// In ark-r1cs-std 0.6, UInt32 = UInt<32, u32, F> which implements:
//   - `Shr<T2>` trait  →  `>>` operator  (shr.rs)
//   - `Not` trait      →  `!` operator   (not.rs)
//   - `BitAnd` trait   →  `&` operator   (and.rs)
//
// These ops operate directly on the internal `bits: [Boolean<F>; 32]`. Prior
// to AC-7 the custom `UInt32Ext` trait wrapped each op with a redundant
// `to_bits_le()` call; the C4 bench measured Δ=0 (per-op) and the trait was
// removed. These tests are kept as upstream-only baselines so any future
// regression in the upstream ops is still caught.

/// Row 6a: upstream `>> 8u8` baseline (custom side removed in AC-7).
#[test]
fn bench_row_6a_uint32_shr() {
    let input_val: u32 = 0xFF00_0000;

    let cs_ark = ConstraintSystem::<Fr>::new_ref();
    cs_ark.set_mode(SynthesisMode::Setup);
    cs_ark.set_optimization_goal(OptimizationGoal::Constraints);

    let val_ark =
        UInt32::<Fr>::new_witness(cs_ark.clone(), || Ok(input_val)).unwrap();
    let alloc_cs_ark = cs_ark.num_constraints();
    let alloc_w_ark = cs_ark.num_witness_variables();

    // Operator syntax resolves to Shr<u8>::shr on UInt<32, u32, F>.
    let _ = &val_ark >> 8u8;
    cs_ark.finalize();
    let ark_cs = cs_ark.num_constraints();
    let ark_w = cs_ark.num_witness_variables();

    let ark_gadget_cs = ark_cs as i64 - alloc_cs_ark as i64;
    let ark_gadget_w = ark_w as i64 - alloc_w_ark as i64;

    println!(
        "ROW6a::UInt32::shr(8) [upstream-only baseline, custom removed in AC-7]: \
         ark_cs={ark_cs}, ark_witness={ark_w} \
         [ark_gadget_delta: cs={ark_gadget_cs}, w={ark_gadget_w}]"
    );
}

/// Row 6b: upstream `!` operator baseline (custom side removed in AC-7).
#[test]
fn bench_row_6b_uint32_not() {
    let input_val: u32 = 0xABCD_1234;

    let cs_ark = ConstraintSystem::<Fr>::new_ref();
    cs_ark.set_mode(SynthesisMode::Setup);
    cs_ark.set_optimization_goal(OptimizationGoal::Constraints);

    let val_ark =
        UInt32::<Fr>::new_witness(cs_ark.clone(), || Ok(input_val)).unwrap();
    let alloc_cs_ark = cs_ark.num_constraints();
    let alloc_w_ark = cs_ark.num_witness_variables();

    let _ = !&val_ark;
    cs_ark.finalize();
    let ark_cs = cs_ark.num_constraints();
    let ark_w = cs_ark.num_witness_variables();

    let ark_gadget_cs = ark_cs as i64 - alloc_cs_ark as i64;
    let ark_gadget_w = ark_w as i64 - alloc_w_ark as i64;

    println!(
        "ROW6b::UInt32::not [upstream-only baseline, custom removed in AC-7]: \
         ark_cs={ark_cs}, ark_witness={ark_w} \
         [ark_gadget_delta: cs={ark_gadget_cs}, w={ark_gadget_w}]"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ROW 3 — single_multiplexer(arr, idx_fp)  vs  FpVar::conditionally_select_power_of_two_vector
// ─────────────────────────────────────────────────────────────────────────────
//
// The two gadgets have different input shapes:
//   - custom: FpVar index (arbitrary integer) → internally builds a one-hot
//     vector via n `is_eq` calls + 1 sum enforce, then n-1 CondSelects.
//   - ark:    BE Boolean[] position (log2(n) bits pre-decomposed) → binary
//     tree of n-1 CondSelects.
//
// Allocation baselines differ by design:
//   - custom side: n FpVars (array) + 1 FpVar (index)
//   - ark side:    n FpVars (array) + log2(n) Boolean witnesses (position)
//
// This makes the gadget deltas the correct apples-to-apples comparison.

/// Row 3: `single_multiplexer` (custom) vs
/// `FpVar::conditionally_select_power_of_two_vector` (upstream ark 0.6).
#[test]
fn bench_row_3_single_multiplexer() {
    for log_n in [6_usize, 8] {
        // n = 64 or 256
        let n: usize = 1 << log_n;
        let idx_val: u64 = (n / 3) as u64; // arbitrary in-range index

        // ── CUSTOM SIDE ──────────────────────────────────────────────────────
        let cs_custom = ConstraintSystem::<Fr>::new_ref();
        cs_custom.set_mode(SynthesisMode::Setup);
        cs_custom.set_optimization_goal(OptimizationGoal::Constraints);

        // Allocate n FpVar array + 1 FpVar index (inputs).
        let arr_custom: Vec<FpVar<Fr>> = (0..n)
            .map(|i| FpVar::new_witness(cs_custom.clone(), || Ok(Fr::from(i as u64))).unwrap())
            .collect();
        let idx_fp =
            FpVar::new_witness(cs_custom.clone(), || Ok(Fr::from(idx_val))).unwrap();

        let alloc_cs_custom = cs_custom.num_constraints();
        let alloc_w_custom = cs_custom.num_witness_variables();

        // Gadget under measurement: one-hot mux.
        let _ = single_multiplexer(&arr_custom, &idx_fp).unwrap();
        cs_custom.finalize();
        let custom_cs = cs_custom.num_constraints();
        let custom_w = cs_custom.num_witness_variables();

        // ── ARKWORKS SIDE ────────────────────────────────────────────────────
        // `conditionally_select_power_of_two_vector` takes BE Boolean[] + [Self].
        let cs_ark = ConstraintSystem::<Fr>::new_ref();
        cs_ark.set_mode(SynthesisMode::Setup);
        cs_ark.set_optimization_goal(OptimizationGoal::Constraints);

        let arr_ark: Vec<FpVar<Fr>> = (0..n)
            .map(|i| FpVar::new_witness(cs_ark.clone(), || Ok(Fr::from(i as u64))).unwrap())
            .collect();
        // Allocate log2(n) BE Boolean bits for the position.
        let pos_bits_be: Vec<Boolean<Fr>> = (0..log_n)
            .rev()
            .map(|bit_pos| {
                Boolean::new_witness(cs_ark.clone(), || Ok((idx_val >> bit_pos) & 1 == 1))
                    .unwrap()
            })
            .collect();

        let alloc_cs_ark = cs_ark.num_constraints();
        let alloc_w_ark = cs_ark.num_witness_variables();

        let _ = FpVar::<Fr>::conditionally_select_power_of_two_vector(&pos_bits_be, &arr_ark)
            .unwrap();
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
            "ROW3::single_multiplexer@n={n}: \
             custom_cs={custom_cs}, custom_witness={custom_w}, \
             ark_cs={ark_cs}, ark_witness={ark_w}, delta_cs={delta_cs}, delta_w={delta_w} \
             [alloc_baseline: custom_cs={alloc_cs_custom},w={alloc_w_custom}; \
             ark_cs={alloc_cs_ark},w={alloc_w_ark}; \
             gadget_delta: custom_cs={custom_gadget_cs},w={custom_gadget_w}; \
             ark_cs={ark_gadget_cs},w={ark_gadget_w}]"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ROW 4 — select_array_element_be(arr, pos_bits_be)  vs  conditionally_select_power_of_two_vector
// ─────────────────────────────────────────────────────────────────────────────
//
// Both gadgets take IDENTICAL inputs: n FpVars (power-of-2 array) + log2(n)
// BE Boolean bits (position).  Both implement a binary-tree CondSelect recursion.
// Expected: delta ≈ 0 (semantically equivalent implementations).

/// Row 4: `select_array_element_be` (custom) vs
/// `FpVar::conditionally_select_power_of_two_vector` (upstream). Identical inputs.
#[test]
fn bench_row_4_select_array_element_be() {
    for log_n in [6_usize, 8] {
        let n: usize = 1 << log_n;
        let idx_val: u64 = (n / 3) as u64;

        // ── CUSTOM SIDE ──────────────────────────────────────────────────────
        let cs_custom = ConstraintSystem::<Fr>::new_ref();
        cs_custom.set_mode(SynthesisMode::Setup);
        cs_custom.set_optimization_goal(OptimizationGoal::Constraints);

        let arr_custom: Vec<FpVar<Fr>> = (0..n)
            .map(|i| FpVar::new_witness(cs_custom.clone(), || Ok(Fr::from(i as u64))).unwrap())
            .collect();
        let pos_bits_custom: Vec<Boolean<Fr>> = (0..log_n)
            .rev()
            .map(|bit_pos| {
                Boolean::new_witness(cs_custom.clone(), || Ok((idx_val >> bit_pos) & 1 == 1))
                    .unwrap()
            })
            .collect();

        let alloc_cs_custom = cs_custom.num_constraints();
        let alloc_w_custom = cs_custom.num_witness_variables();

        let _ = select_array_element_be(&arr_custom, &pos_bits_custom).unwrap();
        cs_custom.finalize();
        let custom_cs = cs_custom.num_constraints();
        let custom_w = cs_custom.num_witness_variables();

        // ── ARKWORKS SIDE ────────────────────────────────────────────────────
        let cs_ark = ConstraintSystem::<Fr>::new_ref();
        cs_ark.set_mode(SynthesisMode::Setup);
        cs_ark.set_optimization_goal(OptimizationGoal::Constraints);

        let arr_ark: Vec<FpVar<Fr>> = (0..n)
            .map(|i| FpVar::new_witness(cs_ark.clone(), || Ok(Fr::from(i as u64))).unwrap())
            .collect();
        let pos_bits_ark: Vec<Boolean<Fr>> = (0..log_n)
            .rev()
            .map(|bit_pos| {
                Boolean::new_witness(cs_ark.clone(), || Ok((idx_val >> bit_pos) & 1 == 1))
                    .unwrap()
            })
            .collect();

        let alloc_cs_ark = cs_ark.num_constraints();
        let alloc_w_ark = cs_ark.num_witness_variables();

        let _ = FpVar::<Fr>::conditionally_select_power_of_two_vector(&pos_bits_ark, &arr_ark)
            .unwrap();
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
            "ROW4::select_array_element_be@n={n}: \
             custom_cs={custom_cs}, custom_witness={custom_w}, \
             ark_cs={ark_cs}, ark_witness={ark_w}, delta_cs={delta_cs}, delta_w={delta_w} \
             [alloc_baseline: custom_cs={alloc_cs_custom},w={alloc_w_custom}; \
             ark_cs={alloc_cs_ark},w={alloc_w_ark}; \
             gadget_delta: custom_cs={custom_gadget_cs},w={custom_gadget_w}; \
             ark_cs={ark_gadget_cs},w={ark_gadget_w}]"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ROW 5 — pack_decompose_bytes_checked  vs  UInt8::new_witness × n
// ─────────────────────────────────────────────────────────────────────────────
//
// C1 audit finding: `pack_decompose_bytes_checked` enforces the 8-bit range by
// calling `FpVar::to_bits_le()` which decomposes the *full* ~254-bit field
// element and then takes only the first 8 bits. This is ~32× more expensive
// than allocating a `UInt8::new_witness`, which enforces range at allocation.
//
// Comparison:
//   - custom: alloc n FpVars (0 range constraint) → call pack_decompose_bytes_checked
//             → adds 254-bit decomposition per byte + enforce_equal + pack arithmetic
//   - ark:    alloc n UInt8 witnesses → range enforced via 8 Boolean allocs per byte
//             (b*(b-1)=0 each) → gadget_delta = 0 for any further conversion
//
// Note: pack_decompose_bytes_checked requires len % limb_width == 0.
// For BN254 Fr: limb_width = (254-1)/8 = 31 bytes.
// Secondary test uses 16 bytes with only the inline range-check loop (no pack step).

/// Row 5a: `pack_decompose_bytes_checked` (31 bytes) vs `UInt8::new_witness × 31`.
#[test]
fn bench_row_5a_pack_decompose_bytes_checked_31() {
    // BN254 Fr limb_width = floor((MODULUS_BIT_SIZE-1)/8) = 31
    let limb_width = ((Fr::MODULUS_BIT_SIZE - 1) / 8) as usize; // = 31
    let n_bytes = limb_width; // 1 chunk

    // ── CUSTOM SIDE ──────────────────────────────────────────────────────────
    let cs_custom = ConstraintSystem::<Fr>::new_ref();
    cs_custom.set_mode(SynthesisMode::Setup);
    cs_custom.set_optimization_goal(OptimizationGoal::Constraints);

    // Allocate n FpVars (no range check at alloc — baseline).
    let byte_fps: Vec<FpVar<Fr>> = (0..n_bytes)
        .map(|i| {
            FpVar::new_witness(cs_custom.clone(), || Ok(Fr::from((i % 256) as u64))).unwrap()
        })
        .collect();

    let alloc_cs_custom = cs_custom.num_constraints();
    let alloc_w_custom = cs_custom.num_witness_variables();

    // Gadget: enforces 8-bit range via 254-bit FpVar decomposition per byte.
    let _ = pack_decompose_bytes_checked(&byte_fps).unwrap();
    cs_custom.finalize();
    let custom_cs = cs_custom.num_constraints();
    let custom_w = cs_custom.num_witness_variables();

    // ── ARKWORKS SIDE ────────────────────────────────────────────────────────
    // `UInt8::new_witness` allocates 8 Boolean witnesses per byte, each
    // enforcing booleanity via b*(b-1)=0 — range check is IN the allocation.
    let cs_ark = ConstraintSystem::<Fr>::new_ref();
    cs_ark.set_mode(SynthesisMode::Setup);
    cs_ark.set_optimization_goal(OptimizationGoal::Constraints);

    let _uint8s: Vec<UInt8<Fr>> = (0..n_bytes)
        .map(|i| {
            UInt8::new_witness(cs_ark.clone(), || Ok((i % 256) as u8)).unwrap()
        })
        .collect();

    cs_ark.finalize();
    let ark_cs = cs_ark.num_constraints();
    let ark_w = cs_ark.num_witness_variables();

    let custom_gadget_cs = custom_cs as i64 - alloc_cs_custom as i64;
    let custom_gadget_w = custom_w as i64 - alloc_w_custom as i64;
    // Ark side: range check IS the alloc; gadget_delta = 0.
    let ark_gadget_cs = 0_i64;
    let ark_gadget_w = 0_i64;
    let delta_cs = custom_gadget_cs - ark_gadget_cs;

    println!(
        "ROW5a::pack_decompose_bytes_checked@{n_bytes}bytes: \
         custom_cs={custom_cs}, custom_witness={custom_w}, \
         ark_cs={ark_cs}, ark_witness={ark_w}, delta_cs={delta_cs} \
         [alloc_baseline: custom_cs={alloc_cs_custom},w={alloc_w_custom}; \
         ark_cs={ark_cs},w={ark_w} (range-in-alloc); \
         gadget_delta: custom_cs={custom_gadget_cs},w={custom_gadget_w}; \
         ark_cs={ark_gadget_cs},w={ark_gadget_w}]"
    );
}

/// Row 5b: inline range-check loop (16 bytes) — the per-byte overhead of
/// `pack_decompose_bytes_checked` extracted for a non-limb-width-aligned size.
///
/// Mirrors the inner loop of `pack_decompose_bytes_checked` without the final
/// `pack_decompose_bytes_unchecked` step (which requires len % 31 == 0).
#[test]
fn bench_row_5b_inline_range_check_16() {
    let n_bytes = 16_usize;

    // ── CUSTOM SIDE: inline range-check loop ─────────────────────────────────
    let cs_custom = ConstraintSystem::<Fr>::new_ref();
    cs_custom.set_mode(SynthesisMode::Setup);
    cs_custom.set_optimization_goal(OptimizationGoal::Constraints);

    let byte_fps: Vec<FpVar<Fr>> = (0..n_bytes)
        .map(|i| {
            FpVar::new_witness(cs_custom.clone(), || Ok(Fr::from((i % 256) as u64))).unwrap()
        })
        .collect();

    let alloc_cs_custom = cs_custom.num_constraints();
    let alloc_w_custom = cs_custom.num_witness_variables();

    // Inline the range-check loop from pack_decompose_bytes_checked.
    for byte_fp in &byte_fps {
        let bits = byte_fp.to_bits_le().unwrap();
        let reconstructed = Boolean::le_bits_to_fp(&bits[..8]).unwrap();
        reconstructed.enforce_equal(byte_fp).unwrap();
    }
    cs_custom.finalize();
    let custom_cs = cs_custom.num_constraints();
    let custom_w = cs_custom.num_witness_variables();

    // ── ARKWORKS SIDE ────────────────────────────────────────────────────────
    let cs_ark = ConstraintSystem::<Fr>::new_ref();
    cs_ark.set_mode(SynthesisMode::Setup);
    cs_ark.set_optimization_goal(OptimizationGoal::Constraints);

    let _uint8s: Vec<UInt8<Fr>> = (0..n_bytes)
        .map(|i| UInt8::new_witness(cs_ark.clone(), || Ok((i % 256) as u8)).unwrap())
        .collect();

    cs_ark.finalize();
    let ark_cs = cs_ark.num_constraints();
    let ark_w = cs_ark.num_witness_variables();

    let custom_gadget_cs = custom_cs as i64 - alloc_cs_custom as i64;
    let custom_gadget_w = custom_w as i64 - alloc_w_custom as i64;
    let delta_cs = custom_gadget_cs; // ark gadget_delta = 0

    println!(
        "ROW5b::inline_range_check@{n_bytes}bytes: \
         custom_cs={custom_cs}, custom_witness={custom_w}, \
         ark_cs={ark_cs}, ark_witness={ark_w}, delta_cs={delta_cs} \
         [alloc_baseline: custom_cs={alloc_cs_custom},w={alloc_w_custom}; \
         ark_cs={ark_cs},w={ark_w} (range-in-alloc); \
         gadget_delta: custom_cs={custom_gadget_cs},w={custom_gadget_w}; ark_cs=0,w=0]"
    );
}

/// Row 6c: upstream `&a & &b` baseline (custom side removed in AC-7).
#[test]
fn bench_row_6c_uint32_bitand() {
    let a_val: u32 = 0xFF00_FF00;
    let b_val: u32 = 0x00FF_00FF;

    let cs_ark = ConstraintSystem::<Fr>::new_ref();
    cs_ark.set_mode(SynthesisMode::Setup);
    cs_ark.set_optimization_goal(OptimizationGoal::Constraints);

    let a_ark =
        UInt32::<Fr>::new_witness(cs_ark.clone(), || Ok(a_val)).unwrap();
    let b_ark =
        UInt32::<Fr>::new_witness(cs_ark.clone(), || Ok(b_val)).unwrap();
    let alloc_cs_ark = cs_ark.num_constraints();
    let alloc_w_ark = cs_ark.num_witness_variables();

    let _ = &a_ark & &b_ark;
    cs_ark.finalize();
    let ark_cs = cs_ark.num_constraints();
    let ark_w = cs_ark.num_witness_variables();

    let ark_gadget_cs = ark_cs as i64 - alloc_cs_ark as i64;
    let ark_gadget_w = ark_w as i64 - alloc_w_ark as i64;

    println!(
        "ROW6c::UInt32::bitand [upstream-only baseline, custom removed in AC-7]: \
         ark_cs={ark_cs}, ark_witness={ark_w} \
         [ark_gadget_delta: cs={ark_gadget_cs}, w={ark_gadget_w}]"
    );
}
