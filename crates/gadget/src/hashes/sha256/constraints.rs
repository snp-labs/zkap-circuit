use std::{
    borrow::Borrow,
    iter,
    ops::{BitXor, Not},
};

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

use crate::{
    hashes::sha256::{H, K, utils::conditionally_select_vec},
    utils::{
        UInt32Ext,
        comparison_v2::{is_greater_or_equal, is_less_than},
        slice_v2,
    },
};

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

        // Padding starts with a 1 followed by some number of zeros (0x80 = 0b10000000)
        let mut pending = vec![UInt8::constant(0); 72];
        pending[0] = UInt8::constant(0x80);

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

    // 입력 데이터는 SHA256 표준에 따라 패딩된 상태여야 한다.
    pub fn digest_with_pad(
        &mut self,
        data: &[UInt8<F>],
        nblocks: FpVar<F>,
    ) -> Result<DigestVar<F>, SynthesisError> {
        assert_eq!(data.len() % 64, 0);
        // nblocks 횟수 만큼의 해시 결과가 저장된다.
        let mut hash_results = Vec::new();
        let zero = UInt32::<F>::constant(0u32);
        let mut output = vec![zero.clone(); 8];

        for chunk in data.chunks(64) {
            Self::update_state(&mut self.state, chunk)?;
            // let bytes = Vec::from_iter(self.state.iter().flat_map(|i| i.to_bytes_be().unwrap()));
            // println!("{} chunk {:?}", i, bytes.value().unwrap());
            // if let Ok(value) = bytes.value() {
            //     println!("{} chunk {:?}", i, value);
            // }

            hash_results.push(self.state.clone());
        }

        let mut flags = Vec::with_capacity(hash_results.len());
        for (i, _state) in hash_results.iter().enumerate() {
            let i_fp = FpVar::<F>::Constant(F::from(i as u64));
            let is_eq = i_fp.is_eq(&nblocks)?;
            flags.push(is_eq);
        }

        // nblocks는 반드시 0..=len-1 중 하나여야 한다
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
        // SHA-256은 64바이트 블록 단위
        assert!(sha_pad_payload_b64.len() % 64 == 0);
        let max_blocks = sha_pad_payload_b64.len() / 64;

        // ------------------------------------------------------------
        // 0) 마지막 블록 선택을 위한 one-hot 플래그 생성
        //    flags[b] == 1  <=>  nblocks_idx == b
        // ------------------------------------------------------------
        let mut flags: Vec<FpVar<F>> = Vec::with_capacity(max_blocks);
        for i in 0..max_blocks {
            let i_fp = FpVar::<F>::constant(F::from(i as u64));
            flags.push(i_fp.is_eq(nblocks_idx)?.into());
        }

        // one-hot: sum(flags) == 1 을 직접 enforce
        let sum_flags = flags
            .iter()
            .fold(FpVar::<F>::zero(), |acc, f| acc + f.clone());
        sum_flags.enforce_equal(&FpVar::<F>::one())?;

        // ------------------------------------------------------------
        // 1) 전체 메시지 길이(bit 단위) 계산
        //    total_len_bits = total_len_wo_pad_bytes * 8
        // ------------------------------------------------------------
        let total_len_bits_fp =
            total_len_wo_pad_bytes.to_fp()? * FpVar::<F>::constant(F::from(8u64));

        // ------------------------------------------------------------
        // 2) SHA-256 length field 검증
        //    선택된 마지막 블록의 [56..63] 바이트를 big-endian으로 해석한 값
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

        // enc_fp == total_len_bits_fp 를 직접 enforce
        enc_fp.enforce_equal(&total_len_bits_fp)?;

        // ------------------------------------------------------------
        // 3) pad_start 위치 검증 (FIXED, underflow-free)
        //
        // 허용되는 pad_start 위치:
        //  (A) 마지막 블록 내부:      b*64 <= pad_start < b*64+56
        //  (B) 마지막-1 블록 tail: (b-1)*64+56 <= pad_start < b*64   (단, b>0)
        //
        // one-hot flags로 선택된 b에 대해 (A or B)가 참이어야 함을 enforce
        // ------------------------------------------------------------
        let pad_start_fp = pad_start_in_suffix.to_fp()?;
        let pad_bits = pad_start_fp.to_bits_le_with_top_bits_zero(16)?.0;

        // in_last_block (Step5의 분기용): pad_start >= block_start ?
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
        for b in 0..max_blocks {
            let flag_b = flags[b].clone();

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

        // 선택된 b에 대해 cond_b가 참이어야 함
        pos_ok_acc.enforce_equal(&FpVar::<F>::one())?;

        // ------------------------------------------------------------
        // 4) 길이 연결식 검증
        //    total_len = prefix_blocks*64 + pad_start
        // ------------------------------------------------------------
        let prefix_len_bytes_fp = prefix_blocks.to_fp()? * FpVar::<F>::constant(F::from(64u64));
        let total_len_fp = total_len_wo_pad_bytes.to_fp()?;
        (prefix_len_bytes_fp + &pad_start_fp).enforce_equal(&total_len_fp)?;

        // ------------------------------------------------------------
        // 5) 패딩 바이트 검증
        //    padding_len = lenfield_start - pad_start
        //    - in_last_block:      padding_len ∈ [1..56]
        //    - in_prev_block_tail: padding_len ∈ [57..64]
        // ------------------------------------------------------------
        let padding_len_fp = &lenfield_start_fp - &pad_start_fp;
        let padding_len_bits = padding_len_fp.to_bits_le_with_top_bits_zero(16)?.0;

        // padding_len >= 1
        let one_bits = UInt16::constant(1u16).to_bits_le()?;
        let lt_one = is_less_than(&padding_len_bits, &one_bits)?;
        lt_one.not().enforce_equal(&Boolean::TRUE)?;

        // padding_len <= 64  <=> padding_len < 65
        let sixty_five_bits = UInt16::constant(65u16).to_bits_le()?;
        is_less_than(&padding_len_bits, &sixty_five_bits)?.enforce_equal(&Boolean::TRUE)?;

        // in_last_block 이면 padding_len < 57, 아니면 padding_len >= 57
        let fifty_seven_bits = UInt16::constant(57u16).to_bits_le()?;
        let padding_lt_57 = is_less_than(&padding_len_bits, &fifty_seven_bits)?;
        padding_lt_57.enforce_equal(&in_last_block)?;

        let padding_len_u16 = UInt16::from_bits_le(&padding_len_bits);

        // slice_efficient 입력을 FpVar 벡터로 변환
        let sha_pad_fp: Vec<FpVar<F>> = sha_pad_payload_b64
            .iter()
            .map(|b| b.to_fp())
            .collect::<Result<Vec<_>, _>>()?;

        // 최대 64바이트까지 검사 (prev-block tail 케이스는 최대 64)
        const PAD_REGION_MAX: usize = 64;
        let pad_region = slice_v2::slice_efficient(
            &sha_pad_fp,
            pad_start_in_suffix,
            &padding_len_u16,
            PAD_REGION_MAX,
        )?;

        // 첫 바이트는 0x80
        pad_region[0].enforce_equal(&FpVar::<F>::constant(F::from(0x80u64)))?;

        // 나머지 바이트는 모두 0
        for i in 1..PAD_REGION_MAX {
            pad_region[i].enforce_equal(&FpVar::<F>::zero())?;
        }

        // ------------------------------------------------------------
        // 6) 마지막 블록 이후의 모든 바이트는 0이어야 함
        //    (suffix padding 이후의 trailing zero 검증)
        // ------------------------------------------------------------
        let mut prefix_sum = FpVar::<F>::zero();
        for b in 0..max_blocks {
            // prefix_sum == 1 이면 b > last_block
            let after_mask = prefix_sum.clone();

            for off in 0..64 {
                let idx = b * 64 + off;
                let byte_fp = sha_pad_payload_b64[idx].to_fp()?;
                let prod = after_mask.clone() * byte_fp;
                prod.enforce_equal(&FpVar::<F>::zero())?;
            }

            prefix_sum += flags[b].clone();
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
            pending: iter::repeat(0u8).take(64).map(UInt8::constant).collect(),
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

    #[test]
    fn test_update_state_constraints() -> Result<(), SynthesisError> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let mut gadget = SHA256Gadget::new_variable(
            cs.clone(),
            || Ok(H.iter().cloned().collect::<Vec<u32>>()),
            AllocationMode::Witness,
        )?;

        let data = vec![0u8; 64];
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
}
