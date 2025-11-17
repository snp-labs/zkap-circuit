use std::{borrow::Borrow, iter};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{Boolean, ToBytesGadget},
    select::CondSelectGadget,
    uint8::UInt8,
    uint32::UInt32,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use core::ops::BitXor;

use crate::{
    hashes::sha256::{
        H, K,
        utils::{add_many_vec, conditionally_select_vec},
    },
    utils::UInt32Ext,
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
            let ch = {
                let f_xor_g = h[5].clone().bitxor(h[6].clone());
                let e_and_f_xor_g = h[4].bitand(&f_xor_g)?;
                h[6].clone().bitxor(&e_and_f_xor_g)
            };

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
        num_sha2_blocks: FpVar<F>,
    ) -> Result<DigestVar<F>, SynthesisError> {
        assert_eq!(data.len() % 64, 0);
        // num_sha2_blocks 횟수 만큼의 해시 결과가 저장된다.
        let mut hash_results = Vec::new();
        let zero = UInt32::<F>::constant(0u32);
        let mut output = Vec::new();
        for _ in 0..8 {
            output.push(zero.clone());
        }
        let zero_value = output.clone();
        for (_i, chunk) in data.chunks(64).enumerate() {
            Self::update_state(&mut self.state, chunk)?;
            // let bytes = Vec::from_iter(self.state.iter().flat_map(|i| i.to_bytes_be().unwrap()));
            // println!("{} chunk {:?}", i, bytes.value().unwrap());
            // if let Ok(value) = bytes.value() {
            //     println!("{} chunk {:?}", i, value);
            // }

            hash_results.push(self.state.clone());
        }

        for i in 0..hash_results.len() {
            let i_fp = FpVar::<F>::Constant(F::from(i as u64));
            let is_eq = i_fp.is_eq(&num_sha2_blocks)?;
            let value = conditionally_select_vec(&is_eq, &hash_results[i], &zero_value.clone())?;
            output = add_many_vec(&output, &value);
        }

        // Collect the state into big-endian bytes
        let bytes = output
            .iter()
            .flat_map(UInt32::to_bytes_be)
            .flatten()
            .collect();
        Ok(DigestVar(bytes))
    }
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
