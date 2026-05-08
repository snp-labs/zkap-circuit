use std::{borrow::Borrow, ops::BitXor};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget, ToBytesGadget},
    select::CondSelectGadget,
    uint8::UInt8,
    uint16::UInt16,
    uint32::UInt32,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use ark_utils::{
    UInt32Ext,
    comparison::{enforce_less_than, is_greater_or_equal, is_less_than},
    slice_efficient,
};

use crate::hashes::sha256::{H, K, utils::conditionally_select_vec};

#[derive(Clone)]
pub struct SHA256Gadget<F: PrimeField> {
    pub state: Vec<UInt32<F>>,
    pub completed_data_blocks: u64,
    pub pending: Vec<UInt8<F>>,
    pub num_pending: usize,
}

#[derive(Clone, Debug)]
pub struct DigestVar<F: PrimeField>(pub Vec<UInt8<F>>);

impl<F: PrimeField> SHA256Gadget<F> {
    /// Consumes the given data and updates the internal state
    pub fn update(&mut self, data: &[UInt8<F>]) -> Result<(), SynthesisError> {
        let mut offset = 0;
        if self.num_pending > 0 && self.num_pending + data.len() >= 64 {
            offset = 64 - self.num_pending;
            // If the inputted data pushes the pending buffer over the chunk size, process it all
            self.pending[self.num_pending..].clone_from_slice(&data[..offset]);
            Self::update_state(&mut self.state, &self.pending)?;

            self.completed_data_blocks += 1;
            self.num_pending = 0;
        }

        for chunk in data[offset..].chunks(64) {
            let chunk_size = chunk.len();

            if chunk_size == 64 {
                // If it's a full chunk, process it
                Self::update_state(&mut self.state, chunk)?;
                self.completed_data_blocks += 1;
            } else {
                // Otherwise, add the bytes to the `pending` buffer
                self.pending[self.num_pending..self.num_pending + chunk_size]
                    .clone_from_slice(chunk);
                self.num_pending += chunk_size;
            }
        }

        Ok(())
    }

    /// Outputs the final digest of all the inputted data
    pub fn finalize(mut self) -> Result<DigestVar<F>, SynthesisError> {
        // Encode the number of processed bits as a u64, then serialize it to 8 big-endian bytes
        let data_bitlen = self.completed_data_blocks * 512 + self.num_pending as u64 * 8;
        let encoded_bitlen: Vec<UInt8<F>> = {
            let bytes = data_bitlen.to_be_bytes();
            bytes.iter().map(|&b| UInt8::constant(b)).collect()
        };

        // Padding starts with a 1 followed by some number of zeros (SHA256_PAD_MARKER = 0x80 = 0b10000000)
        let mut pending = vec![UInt8::constant(0); 72];
        pending[0] = UInt8::constant(crate::constants::SHA256_PAD_MARKER);

        // We'll either append to the 56+8 = 64 byte boundary or the 120+8 = 128 byte boundary,
        // depending on whether we have at least 56 unprocessed bytes
        let offset = if self.num_pending < 56 {
            56 - self.num_pending
        } else {
            120 - self.num_pending
        };

        // Write the bitlen to the end of the padding. Then process all the padding
        pending[offset..offset + 8].clone_from_slice(&encoded_bitlen);
        self.update(&pending[..offset + 8])?;

        // Collect the state into big-endian bytes
        let bytes = self
            .state
            .iter()
            .flat_map(UInt32::to_bytes_be)
            .flatten()
            .collect();
        Ok(DigestVar(bytes))
    }

    fn update_state(state: &mut [UInt32<F>], data: &[UInt8<F>]) -> Result<(), SynthesisError> {
        assert_eq!(data.len(), 64);

        let mut w = vec![UInt32::constant(0); 64];
        for (word, chunk) in w.iter_mut().zip(data.chunks(4)) {
            *word = UInt32::from_bytes_be(chunk)?;
        }

        for i in 16..64 {
            let s0 = {
                let x1 = w[i - 15].rotate_right(7);
                let x2 = w[i - 15].rotate_right(18);
                let x3 = w[i - 15].shr(3);
                x1 ^ (x2 ^ x3)
            };
            let s1 = {
                let x1 = w[i - 2].rotate_right(17);
                let x2 = w[i - 2].rotate_right(19);
                let x3 = w[i - 2].shr(10);
                x1 ^ (x2 ^ x3)
            };

            w[i] = UInt32::<F>::wrapping_add_many(&[s0, s1, w[i - 16].clone(), w[i - 7].clone()])?;
        }

        let mut h = state.to_vec();
        for i in 0..64 {
            let ch = ch_selector_u32(&h[4], &h[5], &h[6])?;
            // Ma(a,b,c) = (a & b) ^ (a & c) ^ (b & c) -> (a & b) ^ (c & (a ^ b))
            // a, b, c = h[0], h[1], h[2]
            let ma = {
                let a_xor_b = h[0].clone().bitxor(h[1].clone());
                let c_and_a_xor_b = h[2].bitand(&a_xor_b)?;
                let a_and_b = h[0].bitand(&h[1])?;
                a_and_b.bitxor(&c_and_a_xor_b)
            };

            let s0 = {
                // x1 ^ &x2 ^ &x3
                let x1 = h[0].rotate_right(2);
                let x2 = h[0].rotate_right(13);
                let x3 = h[0].rotate_right(22);
                x1 ^ (x2 ^ x3)
            };
            let s1 = {
                // x1 ^ &x2 ^ &x3
                let x1 = h[4].rotate_right(6);
                let x2 = h[4].rotate_right(11);
                let x3 = h[4].rotate_right(25);
                x1 ^ (x2 ^ x3)
            };
            let t0 = UInt32::<F>::wrapping_add_many(&[
                h[7].clone(),
                ch,
                s1,
                UInt32::constant(K[i]),
                w[i].clone(),
            ])?;

            h[7] = h[6].clone();
            h[6] = h[5].clone();
            h[5] = h[4].clone();
            h[4] = t0.wrapping_add(&h[3]);
            h[3] = h[2].clone();
            h[2] = h[1].clone();
            h[1] = h[0].clone();
            h[0] = UInt32::<F>::wrapping_add_many(&[t0, ma, s0])?;
        }

        for (s, hi) in state.iter_mut().zip(h.iter()) {
            *s = s.wrapping_add(hi);
        }
        Ok(())
    }

    /// Computes the digest of the given data. This is a shortcut for `default()` followed by
    /// `update()` followed by `finalize()`.
    pub fn digest(data: &[UInt8<F>]) -> Result<DigestVar<F>, SynthesisError> {
        let mut sha256_var = Self::default();
        sha256_var.update(data)?;
        sha256_var.finalize()
    }

    // Input data must be padded according to the SHA256 standard.
    pub fn digest_with_pad(
        &mut self,
        data: &[UInt8<F>],
        nblocks: FpVar<F>,
    ) -> Result<DigestVar<F>, SynthesisError> {
        assert_eq!(data.len() % 64, 0);
        // Hash results are stored for each block up to nblocks.
        let mut hash_results = Vec::new();
        let zero = UInt32::<F>::constant(0u32);
        let mut output = vec![zero.clone(); 8];

        for chunk in data.chunks(64) {
            Self::update_state(&mut self.state, chunk)?;
            hash_results.push(self.state.clone());
        }

        let mut flags = Vec::with_capacity(hash_results.len());
        for (i, _state) in hash_results.iter().enumerate() {
            let i_fp = FpVar::<F>::Constant(F::from(i as u64));
            let is_eq = i_fp.is_eq(&nblocks)?;
            flags.push(is_eq);
        }

        // nblocks must be one of 0..=len-1
        let one = FpVar::<F>::one();
        let sum_flags = flags.iter().fold(FpVar::<F>::zero(), |acc, b| {
            acc + FpVar::<F>::from(b.clone())
        });
        sum_flags.enforce_equal(&one)?;

        for (flag, state) in flags.iter().zip(hash_results.iter()) {
            // output = flag ? state : output
            output = conditionally_select_vec(flag, state, &output)?;
        }

        // Collect the state into big-endian bytes
        let bytes: Vec<ark_r1cs_std::uint::UInt<8, u8, F>> = output
            .iter()
            .flat_map(UInt32::to_bytes_be)
            .flatten()
            .collect();
        Ok(DigestVar(bytes))
    }

    pub fn enforce_sha2_pad_verifier(
        sha_pad_payload_b64: &[UInt8<F>],
        nblocks_idx: &FpVar<F>,
        prefix_blocks: &UInt16<F>,
        total_len_wo_pad_bytes: &UInt16<F>,
        pad_start_in_suffix: &UInt16<F>,
    ) -> Result<(), SynthesisError> {
        // SHA-256 operates on 64-byte blocks
        assert!(sha_pad_payload_b64.len().is_multiple_of(64));
        let max_blocks = sha_pad_payload_b64.len() / 64;

        // ------------------------------------------------------------
        // 0) Generate one-hot flags for selecting the final block
        //    flags[b] == 1  <=>  nblocks_idx == b
        // ------------------------------------------------------------
        let mut flags: Vec<FpVar<F>> = Vec::with_capacity(max_blocks);
        for i in 0..max_blocks {
            let i_fp = FpVar::<F>::constant(F::from(i as u64));
            flags.push(i_fp.is_eq(nblocks_idx)?.into());
        }

        // one-hot: directly enforce sum(flags) == 1
        let sum_flags = flags
            .iter()
            .fold(FpVar::<F>::zero(), |acc, f| acc + f.clone());
        sum_flags.enforce_equal(&FpVar::<F>::one())?;

        // ------------------------------------------------------------
        // 1) Calculate total message length (in bits)
        //    total_len_bits = total_len_wo_pad_bytes * 8
        // ------------------------------------------------------------
        let total_len_bits_fp =
            total_len_wo_pad_bytes.to_fp()? * FpVar::<F>::constant(F::from(8u64));

        // ------------------------------------------------------------
        // 2) Verify SHA-256 length field
        //    The value of bytes [56..63] of the selected final block interpreted as big-endian
        //    == total_len_bits
        // ------------------------------------------------------------
        let mut enc_bytes: [FpVar<F>; 8] = core::array::from_fn(|_| FpVar::<F>::zero());
        for (b, flag) in flags.iter().enumerate() {
            let base = b * 64 + 56;
            for j in 0..8 {
                enc_bytes[j] += flag.clone() * sha_pad_payload_b64[base + j].to_fp()?;
            }
        }

        let mut enc_fp = FpVar::<F>::zero();
        let mut base = F::from(1u64);
        for j in (0..8).rev() {
            enc_fp += enc_bytes[j].clone() * FpVar::<F>::constant(base);
            base *= F::from(256u64);
        }

        // Directly enforce enc_fp == total_len_bits_fp
        enc_fp.enforce_equal(&total_len_bits_fp)?;

        // ------------------------------------------------------------
        // 3) Verify pad_start position (FIXED, underflow-free)
        //
        // Valid pad_start positions:
        //  (A) Within final block:       b*64 <= pad_start < b*64+56
        //  (B) Previous block tail:      (b-1)*64+56 <= pad_start < b*64  (only if b>0)
        //
        // Enforce that (A or B) holds for the b selected by one-hot flags
        // ------------------------------------------------------------
        let pad_start_fp = pad_start_in_suffix.to_fp()?;
        let pad_bits = pad_start_fp.to_bits_le_with_top_bits_zero(16)?.0;

        // in_last_block (branch condition for Step 5): pad_start >= block_start ?
        // block_start = sum_b flags[b] * (b*64)
        let mut block_start_fp = FpVar::<F>::zero();
        let mut lenfield_start_fp = FpVar::<F>::zero(); // = block_start + 56
        for (b, flag) in flags.iter().enumerate() {
            block_start_fp += flag.clone() * FpVar::<F>::constant(F::from((b * 64) as u64));
            lenfield_start_fp += flag.clone() * FpVar::<F>::constant(F::from((b * 64 + 56) as u64));
        }

        let block_start_bits = block_start_fp.to_bits_le_with_top_bits_zero(16)?.0;
        let in_last_block = is_greater_or_equal(&pad_bits, &block_start_bits)?;

        // pos_ok_acc = Σ flags[b] * 1{cond_b}
        let mut pos_ok_acc = FpVar::<F>::zero();
        for (b, flag_b) in flags.iter().enumerate().take(max_blocks) {
            let flag_b = flag_b.clone();

            // cond_last: b*64 <= pad_start < b*64+56
            let last_lo_bits = UInt16::constant((b * 64) as u16).to_bits_le()?;
            let last_hi_bits = UInt16::constant((b * 64 + 56) as u16).to_bits_le()?;
            let ge_last_lo = is_greater_or_equal(&pad_bits, &last_lo_bits)?;
            let lt_last_hi = is_less_than(&pad_bits, &last_hi_bits)?;
            let cond_last = ge_last_lo & lt_last_hi;
            // cond_prev: (b-1)*64+56 <= pad_start < b*64   (b>0 only)
            let cond_prev = if b == 0 {
                Boolean::<F>::FALSE
            } else {
                let prev_lo_bits = UInt16::constant(((b - 1) * 64 + 56) as u16).to_bits_le()?;
                let prev_hi_bits = UInt16::constant((b * 64) as u16).to_bits_le()?;
                let ge_prev_lo = is_greater_or_equal(&pad_bits, &prev_lo_bits)?;
                let lt_prev_hi = is_less_than(&pad_bits, &prev_hi_bits)?;
                ge_prev_lo & lt_prev_hi
            };

            let cond_b = cond_last | cond_prev;
            let cond_b_fp: FpVar<F> = cond_b.into();

            pos_ok_acc += flag_b * cond_b_fp;
        }

        // cond_b must be true for the selected b
        pos_ok_acc.enforce_equal(&FpVar::<F>::one())?;

        // ------------------------------------------------------------
        // 4) Verify length linking equation
        //    total_len = prefix_blocks*64 + pad_start
        // ------------------------------------------------------------
        let prefix_len_bytes_fp = prefix_blocks.to_fp()? * FpVar::<F>::constant(F::from(64u64));
        let total_len_fp = total_len_wo_pad_bytes.to_fp()?;
        (prefix_len_bytes_fp + &pad_start_fp).enforce_equal(&total_len_fp)?;

        // ------------------------------------------------------------
        // 5) Verify padding bytes
        //    padding_len = lenfield_start - pad_start
        //    - in_last_block:      padding_len ∈ [1..56]
        //    - in_prev_block_tail: padding_len ∈ [57..64]
        // ------------------------------------------------------------
        let padding_len_fp = &lenfield_start_fp - &pad_start_fp;
        let padding_len_bits = padding_len_fp.to_bits_le_with_top_bits_zero(16)?.0;

        // [OPT-2] enforce 0 < padding_len directly (~17 vs ~81 constraints)
        let zero_bits = UInt16::constant(0u16).to_bits_le()?;
        enforce_less_than(&zero_bits, &padding_len_bits)?;

        // [OPT-3] enforce padding_len < 65 directly (~17 vs ~81 constraints)
        let sixty_five_bits = UInt16::constant(65u16).to_bits_le()?;
        enforce_less_than(&padding_len_bits, &sixty_five_bits)?;

        // If in_last_block, padding_len < 57; otherwise padding_len >= 57
        let fifty_seven_bits = UInt16::constant(57u16).to_bits_le()?;
        let padding_lt_57 = is_less_than(&padding_len_bits, &fifty_seven_bits)?;
        padding_lt_57.enforce_equal(&in_last_block)?;

        let padding_len_u16 = UInt16::from_bits_le(&padding_len_bits);

        // Convert slice_efficient input to an FpVar vector
        let sha_pad_fp: Vec<FpVar<F>> = sha_pad_payload_b64
            .iter()
            .map(|b| b.to_fp())
            .collect::<Result<Vec<_>, _>>()?;

        // Check up to 64 bytes max (prev-block tail case is at most 64)
        const PAD_REGION_MAX: usize = 64;
        let pad_region = slice_efficient(
            &sha_pad_fp,
            pad_start_in_suffix,
            &padding_len_u16,
            PAD_REGION_MAX,
        )?;

        // First byte must be SHA256_PAD_MARKER (0x80)
        pad_region[0].enforce_equal(&FpVar::<F>::constant(F::from(
            crate::constants::SHA256_PAD_MARKER as u64,
        )))?;

        // All remaining bytes must be 0
        for item in pad_region.iter().take(PAD_REGION_MAX).skip(1) {
            item.enforce_equal(&FpVar::<F>::zero())?;
        }

        // ------------------------------------------------------------
        // 6) All bytes after the final block must be zero
        //    (trailing zero verification after suffix padding)
        // ------------------------------------------------------------
        let mut prefix_sum = FpVar::<F>::zero();
        for (b, flag) in flags.iter().enumerate().take(max_blocks) {
            let after_mask = prefix_sum.clone();
            for off in 0..64 {
                let idx = b * 64 + off;
                let byte_fp = sha_pad_payload_b64[idx].to_fp()?;
                // [OPT-4] Single R1CS constraint: after_mask × byte = 0 (was 2 constraints)
                after_mask.mul_equals(&byte_fp, &FpVar::<F>::zero())?;
            }
            prefix_sum += flag.clone();
        }

        Ok(())
    }

    pub fn digest_with_pad_checked(
        &mut self,
        data: &[UInt8<F>],
        nblocks_idx: FpVar<F>,
        prefix_blocks: &UInt16<F>,
        total_len_wo_pad_bytes: &UInt16<F>,
        pad_start_in_suffix: &UInt16<F>,
    ) -> Result<DigestVar<F>, ark_relations::r1cs::SynthesisError> {
        Self::enforce_sha2_pad_verifier(
            data,
            &nblocks_idx,
            prefix_blocks,
            total_len_wo_pad_bytes,
            pad_start_in_suffix,
        )?;
        self.digest_with_pad(data, nblocks_idx)
    }

    /// Process full input from initial SHA-256 state (H constants) with padding verification.
    ///
    /// Unlike `digest_with_pad_checked()` which continues from a midstate,
    /// this method starts from the initial H constants and processes all blocks.
    ///
    /// # Arguments
    /// * `data` - Full message with SHA256 padding applied (must be 64-byte aligned)
    /// * `nblocks_idx` - Index of the block containing the final hash (0-indexed, i.e., total_blocks - 1)
    /// * `total_len_wo_pad_bytes` - Original message length in bytes (before padding)
    /// * `pad_start_byte_idx` - Byte index where padding starts (position of 0x80)
    ///
    /// # Returns
    /// * `DigestVar<F>` - The SHA256 digest
    ///
    /// # SHA256 Padding Format
    /// ```text
    /// <==message==> <==sha2 padding==>
    /// 0101010101....101010 1 00...00 01010101
    /// <--------L---------> 1 <--K--> <--64-->
    /// ```
    /// Where:
    /// - L = message length in bits
    /// - K = smallest non-negative integer such that L + 1 + K + 64 ≡ 0 (mod 512)
    pub fn digest_full_with_pad_checked(
        data: &[UInt8<F>],
        nblocks_idx: FpVar<F>,
        total_len_wo_pad_bytes: &UInt16<F>,
        pad_start_byte_idx: &UInt16<F>,
    ) -> Result<DigestVar<F>, SynthesisError> {
        // Verify SHA256 padding for full message (no prefix blocks)
        Self::enforce_sha2_pad_verifier_full(
            data,
            &nblocks_idx,
            total_len_wo_pad_bytes,
            pad_start_byte_idx,
        )?;

        // Create gadget with initial H state and process all blocks
        let mut gadget = Self::default();
        gadget.digest_with_pad(data, nblocks_idx)
    }

    /// Verify SHA256 padding is correct for full message (starting from initial H).
    ///
    /// This is a simplified version of `enforce_sha2_pad_verifier` that doesn't
    /// require `prefix_blocks` since we always start from the initial state.
    ///
    /// # Verification checks:
    /// 1. Length encoding: last 8 bytes of final block encode (total_len * 8) in big-endian
    /// 2. Padding marker: byte at pad_start_byte_idx == 0x80
    /// 3. Zero padding: bytes between pad_start+1 and length field are all 0x00
    /// 4. Trailing zeros: all bytes after the final block are 0x00
    fn enforce_sha2_pad_verifier_full(
        data: &[UInt8<F>],
        nblocks_idx: &FpVar<F>,
        total_len_wo_pad_bytes: &UInt16<F>,
        pad_start_byte_idx: &UInt16<F>,
    ) -> Result<(), SynthesisError> {
        // SHA-256 uses 64-byte blocks
        assert!(data.len().is_multiple_of(64));
        let max_blocks = data.len() / 64;

        // ------------------------------------------------------------
        // 0) Create one-hot flags for selecting the final block
        //    flags[b] == 1 <=> nblocks_idx == b
        // ------------------------------------------------------------
        let mut flags: Vec<FpVar<F>> = Vec::with_capacity(max_blocks);
        for i in 0..max_blocks {
            let i_fp = FpVar::<F>::constant(F::from(i as u64));
            flags.push(i_fp.is_eq(nblocks_idx)?.into());
        }

        // Enforce one-hot: sum(flags) == 1
        let sum_flags = flags
            .iter()
            .fold(FpVar::<F>::zero(), |acc, f| acc + f.clone());
        sum_flags.enforce_equal(&FpVar::<F>::one())?;

        // ------------------------------------------------------------
        // 1) Calculate total message length in bits
        //    total_len_bits = total_len_wo_pad_bytes * 8
        // ------------------------------------------------------------
        let total_len_bits_fp =
            total_len_wo_pad_bytes.to_fp()? * FpVar::<F>::constant(F::from(8u64));

        // ------------------------------------------------------------
        // 2) Verify SHA-256 length field encoding
        //    The last 8 bytes of the selected block should encode total_len_bits in big-endian
        // ------------------------------------------------------------
        let mut enc_bytes: [FpVar<F>; 8] = core::array::from_fn(|_| FpVar::<F>::zero());
        for (b, flag) in flags.iter().enumerate() {
            let base = b * 64 + 56;
            for j in 0..8 {
                enc_bytes[j] += flag.clone() * data[base + j].to_fp()?;
            }
        }

        // Convert big-endian bytes to integer
        let mut enc_fp = FpVar::<F>::zero();
        let mut base = F::from(1u64);
        for j in (0..8).rev() {
            enc_fp += enc_bytes[j].clone() * FpVar::<F>::constant(base);
            base *= F::from(256u64);
        }

        // Enforce: encoded_length == total_len_bits
        enc_fp.enforce_equal(&total_len_bits_fp)?;

        // ------------------------------------------------------------
        // 3) Verify pad_start position is valid
        //
        // Valid pad_start positions:
        //  (A) Within final block:       b*64 <= pad_start < b*64+56
        //  (B) In previous block tail:   (b-1)*64+56 <= pad_start < b*64 (only if b>0)
        // ------------------------------------------------------------
        let pad_start_fp = pad_start_byte_idx.to_fp()?;
        let pad_bits = pad_start_fp.to_bits_le_with_top_bits_zero(16)?.0;

        // Calculate block_start and lenfield_start for the selected block
        let mut block_start_fp = FpVar::<F>::zero();
        let mut lenfield_start_fp = FpVar::<F>::zero();
        for (b, flag) in flags.iter().enumerate() {
            block_start_fp += flag.clone() * FpVar::<F>::constant(F::from((b * 64) as u64));
            lenfield_start_fp += flag.clone() * FpVar::<F>::constant(F::from((b * 64 + 56) as u64));
        }

        let block_start_bits = block_start_fp.to_bits_le_with_top_bits_zero(16)?.0;
        let in_last_block = is_greater_or_equal(&pad_bits, &block_start_bits)?;

        // Verify position is valid for the selected block
        let mut pos_ok_acc = FpVar::<F>::zero();
        for (b, flag_b) in flags.iter().enumerate().take(max_blocks) {
            let flag_b = flag_b.clone();

            // cond_last: b*64 <= pad_start < b*64+56
            let last_lo_bits = UInt16::constant((b * 64) as u16).to_bits_le()?;
            let last_hi_bits = UInt16::constant((b * 64 + 56) as u16).to_bits_le()?;
            let ge_last_lo = is_greater_or_equal(&pad_bits, &last_lo_bits)?;
            let lt_last_hi = is_less_than(&pad_bits, &last_hi_bits)?;
            let cond_last = ge_last_lo & lt_last_hi;

            // cond_prev: (b-1)*64+56 <= pad_start < b*64 (b>0 only)
            let cond_prev = if b == 0 {
                Boolean::<F>::FALSE
            } else {
                let prev_lo_bits = UInt16::constant(((b - 1) * 64 + 56) as u16).to_bits_le()?;
                let prev_hi_bits = UInt16::constant((b * 64) as u16).to_bits_le()?;
                let ge_prev_lo = is_greater_or_equal(&pad_bits, &prev_lo_bits)?;
                let lt_prev_hi = is_less_than(&pad_bits, &prev_hi_bits)?;
                ge_prev_lo & lt_prev_hi
            };

            let cond_b = cond_last | cond_prev;
            let cond_b_fp: FpVar<F> = cond_b.into();

            pos_ok_acc += flag_b * cond_b_fp;
        }

        // Enforce: position is valid for selected block
        pos_ok_acc.enforce_equal(&FpVar::<F>::one())?;

        // ------------------------------------------------------------
        // 4) Verify pad_start == total_len (for full message, no prefix blocks)
        //    This ensures the padding starts immediately after the message
        // ------------------------------------------------------------
        let total_len_fp = total_len_wo_pad_bytes.to_fp()?;
        pad_start_fp.enforce_equal(&total_len_fp)?;

        // ------------------------------------------------------------
        // 5) Verify padding bytes
        //    padding_len = lenfield_start - pad_start
        //    - in_last_block:      padding_len ∈ [1..56]
        //    - in_prev_block_tail: padding_len ∈ [57..64]
        // ------------------------------------------------------------
        let padding_len_fp = &lenfield_start_fp - &pad_start_fp;
        let padding_len_bits = padding_len_fp.to_bits_le_with_top_bits_zero(16)?.0;

        // [OPT-2] enforce 0 < padding_len directly (~17 vs ~81 constraints)
        let zero_bits = UInt16::constant(0u16).to_bits_le()?;
        enforce_less_than(&zero_bits, &padding_len_bits)?;

        // [OPT-3] enforce padding_len < 65 directly (~17 vs ~81 constraints)
        let sixty_five_bits = UInt16::constant(65u16).to_bits_le()?;
        enforce_less_than(&padding_len_bits, &sixty_five_bits)?;

        // in_last_block implies padding_len < 57, otherwise padding_len >= 57
        let fifty_seven_bits = UInt16::constant(57u16).to_bits_le()?;
        let padding_lt_57 = is_less_than(&padding_len_bits, &fifty_seven_bits)?;
        padding_lt_57.enforce_equal(&in_last_block)?;

        let padding_len_u16 = UInt16::from_bits_le(&padding_len_bits);

        // Convert to FpVar for slice_efficient
        let data_fp: Vec<FpVar<F>> = data
            .iter()
            .map(|b| b.to_fp())
            .collect::<Result<Vec<_>, _>>()?;

        // Extract padding region (max 64 bytes)
        const PAD_REGION_MAX: usize = 64;
        let pad_region = slice_efficient(
            &data_fp,
            pad_start_byte_idx,
            &padding_len_u16,
            PAD_REGION_MAX,
        )?;

        // First byte must be SHA256_PAD_MARKER (0x80)
        pad_region[0].enforce_equal(&FpVar::<F>::constant(F::from(
            crate::constants::SHA256_PAD_MARKER as u64,
        )))?;

        // Remaining padding bytes must be 0
        for item in pad_region.iter().take(PAD_REGION_MAX).skip(1) {
            item.enforce_equal(&FpVar::<F>::zero())?;
        }

        // ------------------------------------------------------------
        // 6) Verify all bytes after the final block are 0
        //    (trailing zero verification)
        // ------------------------------------------------------------
        let mut prefix_sum = FpVar::<F>::zero();
        for (b, flag) in flags.iter().enumerate().take(max_blocks) {
            let after_mask = prefix_sum.clone();
            for off in 0..64 {
                let idx = b * 64 + off;
                let byte_fp = data[idx].to_fp()?;
                // [OPT-4] Single R1CS constraint: after_mask × byte = 0 (was 2 constraints)
                after_mask.mul_equals(&byte_fp, &FpVar::<F>::zero())?;
            }
            prefix_sum += flag.clone();
        }

        Ok(())
    }
}

fn ch_selector_u32<F: PrimeField>(
    e: &UInt32<F>,
    f: &UInt32<F>,
    g: &UInt32<F>,
) -> Result<UInt32<F>, SynthesisError> {
    let eb = e.to_bits_le()?;
    let fb = f.to_bits_le()?;
    let gb = g.to_bits_le()?;

    // bitwise select: e ? f : g
    let mut out = Vec::with_capacity(32);
    for i in 0..32 {
        let bi = Boolean::select(&eb[i], &fb[i], &gb[i])?;
        out.push(bi);
    }
    Ok(UInt32::from_bits_le(&out))
}

impl<F: PrimeField> Default for SHA256Gadget<F> {
    fn default() -> Self {
        Self {
            state: H.iter().cloned().map(UInt32::constant).collect(),
            completed_data_blocks: 0,
            pending: std::iter::repeat_n(0u8, 64).map(UInt8::constant).collect(),
            num_pending: 0,
        }
    }
}

impl<F: PrimeField> AllocVar<Vec<u32>, F> for SHA256Gadget<F> {
    fn new_variable<T: Borrow<Vec<u32>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let state = val.borrow().clone();

            let state = Vec::<UInt32<F>>::new_variable(cs.clone(), || Ok(state), mode)?;

            Ok(Self {
                state,
                completed_data_blocks: 0,
                pending: Vec::<UInt8<F>>::new_constant(cs.clone(), vec![0u8; 64])?,
                num_pending: 0,
            })
        })
    }
}

impl<ConstraintF> EqGadget<ConstraintF> for DigestVar<ConstraintF>
where
    ConstraintF: PrimeField,
{
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.0.is_eq(&other.0)
    }
}

impl<ConstraintF: PrimeField> ToBytesGadget<ConstraintF> for DigestVar<ConstraintF> {
    fn to_bytes_le(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        Ok(self.0.clone())
    }
}

impl<ConstraintF: PrimeField> CondSelectGadget<ConstraintF> for DigestVar<ConstraintF>
where
    Self: Sized,
    Self: Clone,
{
    fn conditionally_select(
        cond: &Boolean<ConstraintF>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let bytes: Result<Vec<_>, _> = true_value
            .0
            .iter()
            .zip(false_value.0.iter())
            .map(|(t, f)| UInt8::conditionally_select(cond, t, f))
            .collect();
        bytes.map(DigestVar)
    }
}

impl<ConstraintF: PrimeField> AllocVar<Vec<u8>, ConstraintF> for DigestVar<ConstraintF> {
    // Allocates 32 UInt8s
    fn new_variable<T: Borrow<Vec<u8>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let native_bytes = f();

        if native_bytes
            .as_ref()
            .map(|b| b.borrow().len())
            .unwrap_or(32)
            != 32
        {
            panic!("DigestVar must be allocated with precisely 32 bytes");
        }

        // For each i, allocate the i-th byte
        let var_bytes: Result<Vec<_>, _> = (0..32)
            .map(|i| {
                UInt8::new_variable(
                    cs.clone(),
                    || native_bytes.as_ref().map(|v| v.borrow()[i]).map_err(|e| *e),
                    mode,
                )
            })
            .collect();

        var_bytes.map(DigestVar)
    }
}

impl<ConstraintF: PrimeField> R1CSVar<ConstraintF> for DigestVar<ConstraintF> {
    type Value = [u8; 32];

    fn cs(&self) -> ConstraintSystemRef<ConstraintF> {
        let mut result = ConstraintSystemRef::None;
        for var in &self.0 {
            result = var.cs().or(result);
        }
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let mut buf = [0u8; 32];
        for (b, var) in buf.iter_mut().zip(self.0.iter()) {
            *b = var.value()?;
        }

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_update_state_constraints() -> Result<(), SynthesisError> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let mut gadget =
            SHA256Gadget::new_variable(cs.clone(), || Ok(H.to_vec()), AllocationMode::Witness)?;

        let data = [0u8; 64];
        let data_vars: Vec<UInt8<Fr>> = data
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        gadget.update(&data_vars)?;

        println!("state: {:?}", gadget.state.value()?);

        let num_constraints = cs.num_constraints();
        println!(
            "Number of constraints after update_state: {}",
            num_constraints
        );

        Ok(())
    }

    #[test]
    fn test_digest_full_with_pad_checked() -> Result<(), SynthesisError> {
        use crate::hashes::sha256::utils::sha256_pad_with_len;

        // Test message (simulating JWT header.payload)
        let message = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        let message_len = message.len();

        // Compute expected digest using native SHA256
        let mut hasher = Sha256::new();
        hasher.update(message);
        let expected_digest: [u8; 32] = hasher.finalize().into();

        // Apply SHA256 padding
        let padded = sha256_pad_with_len(message, message_len);
        assert_eq!(padded.len() % 64, 0);
        let nblocks = padded.len() / 64 - 1; // 0-indexed

        // Extend to circuit buffer size (e.g., 1024 bytes)
        let mut circuit_data = padded.clone();
        circuit_data.resize(1024, 0);

        // Create constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Allocate witnesses
        let data_vars: Vec<UInt8<Fr>> = circuit_data
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        let nblocks_idx = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(nblocks as u64)))?;
        let total_len = UInt16::<Fr>::new_witness(cs.clone(), || Ok(message_len as u16))?;
        let pad_start = UInt16::<Fr>::new_witness(cs.clone(), || Ok(message_len as u16))?;

        // Call the new method
        let digest = SHA256Gadget::digest_full_with_pad_checked(
            &data_vars,
            nblocks_idx,
            &total_len,
            &pad_start,
        )?;

        // Verify constraints are satisfied
        assert!(cs.is_satisfied()?, "Constraints not satisfied");

        // Verify digest matches expected
        let circuit_digest = digest.value()?;
        assert_eq!(
            circuit_digest, expected_digest,
            "Digest mismatch!\nExpected: {:?}\nGot: {:?}",
            expected_digest, circuit_digest
        );

        println!("test_digest_full_with_pad_checked passed!");
        println!("Message length: {} bytes", message_len);
        println!(
            "Padded length: {} bytes ({} blocks)",
            padded.len(),
            padded.len() / 64
        );
        println!("Number of constraints: {}", cs.num_constraints());
        println!("Digest: {:?}", hex::encode(circuit_digest));

        Ok(())
    }

    #[test]
    fn test_digest_full_with_pad_checked_jwt() -> Result<(), SynthesisError> {
        use crate::hashes::sha256::utils::sha256_pad_with_len;

        // Synthetic JWT header.payload for testing (fake claims, no real user data)
        // Claims: iss=https://test.example.com, sub=test_user_000000000000, email=test@example.com
        let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkLTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Rlc3QuZXhhbXBsZS5jb20iLCJhenAiOiJ0ZXN0LWNsaWVudC1pZCIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwic3ViIjoidGVzdF91c2VyXzAwMDAwMDAwMDAwMCIsImhkIjoiZXhhbXBsZS5jb20iLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiLCJub25jZSI6IjB4MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAzNjAwfQ";
        let parts: Vec<&str> = jwt.split('.').collect();
        let header_payload = format!("{}.{}", parts[0], parts[1]);
        let message = header_payload.as_bytes();
        let message_len = message.len();

        // Compute expected digest using native SHA256
        let mut hasher = Sha256::new();
        hasher.update(message);
        let expected_digest: [u8; 32] = hasher.finalize().into();

        // Apply SHA256 padding
        let padded = sha256_pad_with_len(message, message_len);
        assert_eq!(padded.len() % 64, 0);
        let nblocks = padded.len() / 64 - 1;

        // Extend to circuit buffer size
        let mut circuit_data = padded.clone();
        circuit_data.resize(2048, 0); // Larger buffer for full JWT

        // Create constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Allocate witnesses
        let data_vars: Vec<UInt8<Fr>> = circuit_data
            .iter()
            .map(|&b| UInt8::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        let nblocks_idx = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(nblocks as u64)))?;
        let total_len = UInt16::<Fr>::new_witness(cs.clone(), || Ok(message_len as u16))?;
        let pad_start = UInt16::<Fr>::new_witness(cs.clone(), || Ok(message_len as u16))?;

        // Call the new method
        let digest = SHA256Gadget::digest_full_with_pad_checked(
            &data_vars,
            nblocks_idx,
            &total_len,
            &pad_start,
        )?;

        // Verify constraints are satisfied
        assert!(cs.is_satisfied()?, "Constraints not satisfied");

        // Verify digest matches expected
        let circuit_digest = digest.value()?;
        assert_eq!(
            circuit_digest, expected_digest,
            "Digest mismatch for real JWT!"
        );

        println!("test_digest_full_with_pad_checked_jwt passed!");
        println!("JWT header.payload length: {} bytes", message_len);
        println!(
            "Padded length: {} bytes ({} blocks)",
            padded.len(),
            padded.len() / 64
        );
        println!("Number of constraints: {}", cs.num_constraints());
        println!("Digest: {}", hex::encode(circuit_digest));

        Ok(())
    }
}
