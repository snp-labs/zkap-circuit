use ark_ff::PrimeField;
use ark_r1cs_std::{prelude::Boolean, select::CondSelectGadget, uint32::UInt32};
use ark_relations::r1cs::SynthesisError;

use crate::hashes::sha256::{H, K};

pub fn conditionally_select_vec<F: PrimeField>(
    condition: &Boolean<F>,
    a: &[UInt32<F>],
    b: &[UInt32<F>],
) -> Result<Vec<UInt32<F>>, SynthesisError> {
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| UInt32::conditionally_select(&condition, a, b))
        .collect()
}


pub fn sha256_pad_with_len(input: &[u8], max_len: usize) -> Vec<u8> {
    let block_size = 64; // Block size in bytes
    let mut padded = input.to_vec();

    // Append the '1' bit as SHA256_PAD_MARKER (0x80)
    padded.push(crate::constants::SHA256_PAD_MARKER);

    // Calculate the number of zero bytes to add
    let zero_pad_len = (block_size - ((padded.len() + 8) % block_size)) % block_size;
    padded.extend(vec![0; zero_pad_len]);

    // Append the length in bits as a 64-bit big-endian integer
    let bit_length = (max_len as u64) * 8;
    padded.extend(&bit_length.to_be_bytes());

    padded
}

pub fn stretch(buffer: &[u8], max_len: usize) -> Vec<u8> {
    if buffer.len() < max_len {
        let mut stretched = Vec::with_capacity(max_len);
        stretched.extend_from_slice(buffer);
        stretched.resize(max_len, 0);
        stretched
    } else {
        buffer.to_vec()
    }
}

pub fn sha256_block_len(len: usize) -> usize {
    // 1 is for 0x80, 8 is for the 64-bit length appended at the end
    ((len + 1 + 8) as f64 / 64.0).ceil() as usize
}
pub fn to_units<F: PrimeField>(buffer: &[u8], max_len: usize, num_bytes: usize) -> Vec<F> {
    let stretched = stretch(buffer, max_len);
    stretched
        .chunks(num_bytes)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect()
}

pub fn update(data: &[u8]) -> [u32; 8] {
    assert!(data.len() % 64 == 0);
    let state = H;

    let result = data
        .chunks_exact(64)
        .fold(state, |state, chunk| update_with_state(state, chunk));

    result
    // for chunk in data.chunks_exact(64) {
    //     let new_state = update_with_state(state, chunk);
    // }
}

pub fn update_with_state(state: [u32; 8], data: &[u8]) -> [u32; 8] {
    assert!(data.len() == 64);

    let mut w = [0u32; 64];

    // Prepare the message schedule
    for (i, word) in data.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    }

    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    // Initialize working variables
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // Compression function main loop
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    let mut new_state = [0u32; 8];

    // Add the compressed chunk to the current hash value
    new_state[0] = a.wrapping_add(state[0]);
    new_state[1] = b.wrapping_add(state[1]);
    new_state[2] = c.wrapping_add(state[2]);
    new_state[3] = d.wrapping_add(state[3]);
    new_state[4] = e.wrapping_add(state[4]);
    new_state[5] = f.wrapping_add(state[5]);
    new_state[6] = g.wrapping_add(state[6]);
    new_state[7] = h.wrapping_add(state[7]);

    new_state
}

pub fn finalize_with_state(state: [u32; 8], data: &[u8], len: usize) -> [u32; 8] {
    let padded_input = sha256_pad_with_len(data, len);
    let reuslt = update_with_state(state, &padded_input);

    reuslt
}
