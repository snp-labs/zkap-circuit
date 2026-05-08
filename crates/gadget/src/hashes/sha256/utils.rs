//! Native and in-circuit SHA-256 utility functions.
//!
//! [`sha256_pad_with_len`] produces a padded message buffer (standard SHA-256 Merkle-Damgård
//! padding) for use in both native and circuit contexts. [`conditionally_select_vec`] is
//! an in-circuit conditional select over `UInt32` word vectors. [`to_units`] splits a
//! byte slice into 32-bit words, and `update` / `finalize_with_state` drive the native
//! SHA-256 compression round used in witness generation.

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
        .map(|(a, b)| UInt32::conditionally_select(condition, a, b))
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
    assert!(data.len().is_multiple_of(64));
    let state = H;

    data.chunks_exact(64).fold(state, update_with_state)
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

    update_with_state(state, &padded_input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_pad_with_len_alignment() {
        let input = b"hello";
        let padded = sha256_pad_with_len(input, input.len());
        assert_eq!(
            padded.len() % 64,
            0,
            "Padded output must be 64-byte aligned"
        );
        assert_eq!(padded[input.len()], 0x80, "First padding byte must be 0x80");
    }

    #[test]
    fn test_sha256_pad_with_len_length_field() {
        let input = b"test data";
        let padded = sha256_pad_with_len(input, input.len());
        // Last 8 bytes = bit length in big-endian
        let bit_len = u64::from_be_bytes(padded[padded.len() - 8..].try_into().unwrap());
        assert_eq!(bit_len, (input.len() as u64) * 8);
    }

    #[test]
    fn test_sha256_block_len() {
        assert_eq!(sha256_block_len(0), 1); // 0+1+8 = 9 → ceil(9/64) = 1
        assert_eq!(sha256_block_len(55), 1); // 55+1+8 = 64 → 1
        assert_eq!(sha256_block_len(56), 2); // 56+1+8 = 65 → 2
        assert_eq!(sha256_block_len(64), 2); // 64+1+8 = 73 → 2
        assert_eq!(sha256_block_len(119), 2); // 119+1+8 = 128 → 2
        assert_eq!(sha256_block_len(120), 3); // 120+1+8 = 129 → 3
    }

    #[test]
    fn test_stretch_shorter() {
        let buf = vec![1, 2, 3];
        let stretched = stretch(&buf, 8);
        assert_eq!(stretched.len(), 8);
        assert_eq!(&stretched[..3], &[1, 2, 3]);
        assert_eq!(&stretched[3..], &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_stretch_equal() {
        let buf = vec![1, 2, 3];
        let stretched = stretch(&buf, 3);
        assert_eq!(stretched, buf);
    }

    #[test]
    fn test_stretch_longer() {
        let buf = vec![1, 2, 3, 4, 5];
        let stretched = stretch(&buf, 3);
        assert_eq!(stretched, buf); // returns original if >= max_len
    }

    #[test]
    fn test_update_known_vector() {
        // SHA256("") with padding: 0x80 followed by zeros, then 0x00..00 (length = 0 bits)
        let mut block = vec![0x80u8];
        block.resize(56, 0);
        block.extend(&0u64.to_be_bytes());
        assert_eq!(block.len(), 64);

        let state = update(&block);
        // SHA256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(state[0], 0xe3b0c442);
        assert_eq!(state[1], 0x98fc1c14);
        assert_eq!(state[2], 0x9afbf4c8);
        assert_eq!(state[7], 0x7852b855);
    }

    #[test]
    fn test_update_with_state_deterministic() {
        let data = [0u8; 64];
        let r1 = update_with_state(H, &data);
        let r2 = update_with_state(H, &data);
        assert_eq!(r1, r2);
    }

    #[test]
    #[should_panic]
    fn test_update_with_state_wrong_size() {
        let data = [0u8; 32]; // not 64
        update_with_state(H, &data);
    }

    #[test]
    fn test_to_units() {
        type F = ark_bn254::Fr;
        let buffer = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let units = to_units::<F>(&buffer, 8, 4);
        assert_eq!(units.len(), 2);
        // First 4 bytes [0,1,2,3] as BE → 0x00010203
        assert_eq!(units[0], F::from(0x00010203u64));
    }
}
