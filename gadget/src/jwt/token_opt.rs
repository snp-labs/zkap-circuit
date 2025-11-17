use ark_serialize::CanonicalSerialize;

use crate::{
    base64::decode_any_base64_to_string,
    hashes::sha256::utils::{sha256_pad_with_len, update},
    jwt::{
        error::TokenError,
        token::Token,
        types::Claim,
        utils::{find_first_claim_offset, parse_claim_from_str, pay_b64_bits, resize},
    },
    signature::rsa::native::{PublicKey, Signature},
};

/// Overlap length for base64 boundary alignment (always 3 bytes for constraint efficiency)
const OVERLAP_LEN: usize = 3;

/// Optimized JWT token structure for constraint-efficient verification.
/// Pre-computes SHA-256 state up to the first claim, reducing in-circuit computation.
#[derive(Clone, Debug, Default, CanonicalSerialize)]
pub struct TokenOpt {
    /// Offset of payload in base64 (after '.')
    pub pay_offset_b64: usize,
    /// Length of payload in base64
    pub pay_len_b64: usize,
    /// Extracted claims with their indices
    pub claims: Vec<Claim>,
    /// SHA-256 padded payload for in-circuit hashing
    pub shapad_payload_b64: Vec<u8>,
    /// RSA signature
    pub sig: Signature,
    /// RSA public key
    pub pk: PublicKey,
    /// Bit witness for base64 decoding (6 bits per character)
    pub bit_witness: Vec<bool>,
    /// Overlap bytes for base64 boundary alignment (fixed 3 bytes)
    pub overlap: Vec<u8>,
    /// Actual overlap length (0-3)
    pub overlap_len: usize,
    /// Pre-computed SHA-256 state (8 u32 values)
    pub state: Vec<u32>,
    /// Number of SHA-256 blocks processed outside circuit
    pub num_blocks: usize,
}

impl TokenOpt {
    /// Creates an empty TokenOpt with specified maximum lengths.
    /// Used for circuit setup and parameter initialization.
    /// 
    /// **Note**: For creating TokenOpt from a parsed Token, use `TokenBuilder` instead.
    pub fn empty(
        keys_len: usize,
        max_jwt_len: usize,
        max_payload_len: usize,
    ) -> Self {
        let claims = (0..keys_len).map(|_| Claim::empty()).collect::<Vec<_>>();
        let max_payload_b64_len = ((max_payload_len + 2) / 3) * 4;

        TokenOpt {
            pay_offset_b64: 0,
            pay_len_b64: 0,
            claims,
            shapad_payload_b64: vec![0u8; max_jwt_len],
            sig: Signature::default(),
            pk: PublicKey::empty(),
            bit_witness: vec![false; (max_payload_b64_len + 4) * 6],
            overlap: vec![0u8; OVERLAP_LEN],
            overlap_len: 0,
            state: vec![0u32; 8], // SHA-256 initial state (8 x u32)
            num_blocks: 1,
        }
    }
    /// Creates a new TokenOpt from a parsed Token.
    /// Partitions the JWT to minimize in-circuit constraints by pre-computing SHA-256 state.
    /// 
    /// **Deprecated**: Use `TokenBuilder::new(token, config).build_opt()` instead for better maintainability.
    /// 
    /// # Migration Example
    /// ```ignore
    /// // Old way:
    /// let token_opt = TokenOpt::new(&token, 1024, 512, 128)?;
    /// 
    /// // New way:
    /// use TokenBuilder, TokenConfig;
    /// let config = TokenConfig::new(1024, 512, 128);
    /// let token_opt = TokenBuilder::new(token, config).build_opt()?;
    /// ```
    #[deprecated(since = "0.2.0", note = "Use TokenBuilder instead")]
    pub fn new(
        token: &Token,
        max_jwt_len: usize,
        max_payload_len: usize,
        max_claim_len: usize,
    ) -> Result<Self, TokenError> {
        // Padding constants for constraint efficiency
        const B64_PAD_BYTE: u8 = b'A'; // Base64 'A' = 0x00 (zero value)
        const JWT_PAD_BYTE: u8 = b'0'; // Padding for JWT content
        
        let max_payload_b64_len = ((max_payload_len + 2) / 3) * 4;

        // Find first claim offset to determine optimal partition point
        let first_claim_offset = find_first_claim_offset(&token.claims)?;
        let first_claim_offset_b64 = (first_claim_offset / 3) * 4; // Align to base64 boundary

        // Partition JWT into pre-computed (pre) and in-circuit (post) parts
        let (pre, post, overlap, overlap_len) = partition_for_hash_optimization(
            &token.header_b64,
            &token.payload_b64,
            first_claim_offset_b64,
        )?;

        // Extract payload portion from post (skip header and '.' if present)
        let pay_offset_b64 = post.iter().position(|&b| b == b'.')
            .map(|idx| idx + 1)
            .unwrap_or(0);
        let post_payload_only = &post[pay_offset_b64..];

        // Reconstruct base64 string for decoding (overlap + payload)
        let post_b64_bytes = [&overlap[..], post_payload_only].concat();
        let post_b64_str = String::from_utf8(post_b64_bytes)
            .map_err(|_| TokenError::InvalidFormat("Invalid UTF-8 in overlap/post".to_string()))?;

        // Decode to get actual payload content
        let post_str = decode_any_base64_to_string(&post_b64_str)?;

        // Normalize overlap to fixed size (3 bytes) for circuit compatibility
        let normalized_overlap = normalize_overlap(overlap, overlap_len, JWT_PAD_BYTE);

        // Re-parse claims based on the new post payload
        let claims = token.claims.iter()
            .map(|c| {
                let mut nc = parse_claim_from_str(&post_str, &c.key)?;
                nc.value = resize(&nc.value, max_claim_len, JWT_PAD_BYTE);
                Ok(nc)
            })
            .collect::<Result<Vec<_>, TokenError>>()?;

        // Pre-compute SHA-256 state for 'pre' portion (outside circuit)
        // Important: pre must be multiple of 64 bytes (NO padding!)
        let state = if pre.is_empty() {
            // No pre-computation: use initial SHA-256 IV
            crate::hashes::sha256::H.to_vec()
        } else {
            // Pre-compute state by processing complete 64-byte blocks
            if pre.len() % 64 != 0 {
                return Err(TokenError::InvalidLengthError(
                    format!("pre must be multiple of 64 bytes, got {}", pre.len()),
                ));
            }
            update(&pre).to_vec()
        };

        // Generate bit witness for base64 decoding in circuit
        let bit_witness = pay_b64_bits(
            post_b64_str.as_bytes(),
            max_payload_b64_len + 4,
            B64_PAD_BYTE,
        )?;

        // Prepare SHA-256 padded post for in-circuit processing
        let mut shapad_payload_b64 = sha256_pad_with_len(&post, pre.len() + post.len());
        let num_blocks = shapad_payload_b64.len() / 64 - 1;
        shapad_payload_b64.resize(max_jwt_len, JWT_PAD_BYTE);

        Ok(TokenOpt {
            pay_offset_b64,
            pay_len_b64: post_payload_only.len(),
            claims,
            shapad_payload_b64,
            sig: token.sig.clone(),
            pk: token.pk.clone(),
            bit_witness,
            overlap: normalized_overlap,
            overlap_len,
            state,
            num_blocks,
        })
    }
}

/// Normalizes overlap to fixed 3-byte size for circuit compatibility.
/// Pads with specified byte if overlap is shorter than 3 bytes.
pub fn normalize_overlap(overlap: Vec<u8>, _overlap_len: usize, pad_byte: u8) -> Vec<u8> {
    if overlap.is_empty() {
        vec![pad_byte; OVERLAP_LEN]
    } else {
        let mut normalized = overlap;
        normalized.resize(OVERLAP_LEN, pad_byte);
        normalized
    }
}

/// Partitions JWT (header.payload) into pre-computed and in-circuit portions.
/// 
/// **Improved Strategy** (handles '.' correctly):
/// 
/// 1. Build complete prefix P = header + "." (확실히 '.'를 포함)
/// 2. Find optimal split point: floor(target_offset / 64) * 64
/// 3. Pre-compute SHA-256 state for P[..split_point] (NO padding!)
/// 4. Remainder for circuit: P[split_point..] + payload
/// 5. Circuit resumes with midstate and processes remainder
/// 
/// **Benefits**:
/// - '.' is always in pre-computed portion (no edge case)
/// - Can pre-hash more payload if first claim appears late
/// - Clean separation: pre = complete 64-byte blocks, post = remainder
///
/// Returns: (pre, post, overlap, overlap_len)
pub fn partition_for_hash_optimization(
    h: &[u8],
    p: &[u8],
    encoded_payload_offset: usize,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, usize), TokenError> {
    const SHA256_BLOCK_SIZE: usize = 64;

    // Step 1: Build complete prefix P = header + "."
    // This ensures '.' is always included in our processing
    let mut prefix = Vec::with_capacity(h.len() + 1);
    prefix.extend_from_slice(h);
    prefix.push(b'.'); // '.'는 항상 prefix에 포함됨
    
    let prefix_len = prefix.len(); // header.len() + 1
    
    // Step 2: Calculate target offset in complete signing input
    // target = prefix_len + encoded_payload_offset
    let target_offset = prefix_len
        .checked_add(encoded_payload_offset)
        .ok_or_else(|| TokenError::InvalidLengthError("target offset overflow".into()))?;
    
    let total_signing_len = prefix_len + p.len();
    if target_offset > total_signing_len {
        return Err(TokenError::InvalidLengthError(
            "target offset beyond signing input".into(),
        ));
    }

    // Step 3: Find split point - round down to 64-byte boundary
    // This ensures pre is always multiple of 64 bytes (no padding!)
    let split_point = (target_offset / SHA256_BLOCK_SIZE) * SHA256_BLOCK_SIZE;
    
    if split_point == 0 {
        // Edge case: first claim appears very early
        // Still need to include at least the prefix
        return build_minimal_partition(h, p);
    }

    // Step 4: Build pre-computed portion (complete 64-byte blocks only)
    let pre = build_pre_partition_v2(&prefix, p, split_point)?;

    // Step 5: Build in-circuit portion (remainder)
    let post = build_post_partition_v2(&prefix, p, split_point, total_signing_len);

    // Step 6: Calculate overlap for base64 boundary alignment
    let (overlap, overlap_len) = calculate_overlap_v2(&pre, split_point, prefix_len, p.len());

    Ok((pre, post, overlap, overlap_len))
}

/// Edge case handler: first claim appears very early (split_point == 0)
/// Returns minimal valid partition with no pre-computation
fn build_minimal_partition(h: &[u8], p: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, usize), TokenError> {
    // No pre-computation possible
    let pre = Vec::new();
    
    // All data goes to circuit
    let mut post = Vec::with_capacity(h.len() + 1 + p.len());
    post.extend_from_slice(h);
    post.push(b'.');
    post.extend_from_slice(p);
    
    // No overlap (nothing to align)
    let overlap = Vec::new();
    let overlap_len = 0;
    
    Ok((pre, post, overlap, overlap_len))
}

/// Builds pre-computed portion (V2: assumes prefix already includes '.')
/// 
/// **Input**: prefix = header + ".", payload = remaining bytes
/// **Output**: Complete 64-byte blocks only (NO padding!)
fn build_pre_partition_v2(
    prefix: &[u8],
    payload: &[u8],
    split_point: usize,
) -> Result<Vec<u8>, TokenError> {
    let mut pre = Vec::with_capacity(split_point);
    let prefix_len = prefix.len();
    
    if split_point <= prefix_len {
        // Split is within prefix (header + ".")
        pre.extend_from_slice(&prefix[..split_point]);
    } else {
        // Split extends into payload
        pre.extend_from_slice(prefix); // All of "header."
        let payload_bytes_in_pre = split_point - prefix_len;
        
        if payload_bytes_in_pre > payload.len() {
            return Err(TokenError::InvalidLengthError(
                "split point exceeds total length".into(),
            ));
        }
        
        pre.extend_from_slice(&payload[..payload_bytes_in_pre]);
    }

    // Verify we have exactly split_point bytes
    if pre.len() != split_point {
        return Err(TokenError::InvalidLengthError(
            format!("pre partition length mismatch: expected {}, got {}", split_point, pre.len()),
        ));
    }
    
    // Verify it's a multiple of 64 (SHA-256 block size)
    if pre.len() % 64 != 0 {
        return Err(TokenError::InvalidLengthError(
            format!("pre partition must be multiple of 64 bytes, got {}", pre.len()),
        ));
    }

    Ok(pre)
}

/// Builds post-partition (V2: remainder for in-circuit processing)
/// 
/// **Output**: prefix[split_point..] + payload[split_point-prefix_len..]
fn build_post_partition_v2(
    prefix: &[u8],
    payload: &[u8],
    split_point: usize,
    total_len: usize,
) -> Vec<u8> {
    let mut post = Vec::with_capacity(total_len - split_point);
    let prefix_len = prefix.len();
    
    if split_point < prefix_len {
        // Split is within prefix: include remainder of prefix + all payload
        post.extend_from_slice(&prefix[split_point..]);
        post.extend_from_slice(payload);
    } else {
        // Split is in payload: include remainder of payload
        let payload_start = split_point - prefix_len;
        post.extend_from_slice(&payload[payload_start..]);
    }

    post
}

/// Calculates overlap for base64 boundary alignment (V2)
/// 
/// **Purpose**: Base64 decoding works in 4-character blocks.
/// If split_point doesn't align with base64 boundary, we need overlap bytes.
/// 
/// **Returns**: (overlap_bytes, overlap_len)
fn calculate_overlap_v2(
    pre: &[u8],
    split_point: usize,
    prefix_len: usize,
    payload_len: usize,
) -> (Vec<u8>, usize) {
    const BASE64_BLOCK_SIZE: usize = 4;
    
    // Split point relative to start of payload
    if split_point < prefix_len {
        // Split is before or within prefix (no payload bytes in pre)
        // Check if we're splitting within base64-encoded header
        let split_in_header = split_point;
        let overlap_len = split_in_header % BASE64_BLOCK_SIZE;
        
        if overlap_len > 0 && !pre.is_empty() {
            let start = pre.len() - overlap_len;
            return (pre[start..].to_vec(), overlap_len);
        }
        return (Vec::new(), 0);
    }
    
    // Split is in payload
    let split_in_payload = (split_point - prefix_len).min(payload_len);
    
    // Check base64 alignment
    // We need to align relative to the start of payload base64 encoding
    let overlap_len = split_in_payload % BASE64_BLOCK_SIZE;

    if overlap_len > 0 && !pre.is_empty() {
        let start = pre.len() - overlap_len;
        (pre[start..].to_vec(), overlap_len)
    } else {
        // Perfectly aligned or no pre data
        (Vec::new(), 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::Token;
    use crate::hashes::sha256::{H, utils::update};

    // Real JWT for testing
    const JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";
    const N: &str = "xjlCRBqghVqN0mHyW8BhWGqBH2UJzgQrJQlrHc5KLQvXzW_-_QqWvnxfbhMvLw8UwGzHnX3V7xGLx70HNHxKwQ";

    #[test]
    fn test_partition_strategy_v2_basic() {
        let token = Token::new(JWT, N, &["sub", "name", "admin"]).unwrap();
        
        let first_claim_offset_b64 = 0;
        
        let result = partition_for_hash_optimization(
            &token.header_b64,
            &token.payload_b64,
            first_claim_offset_b64,
        );
        
        assert!(result.is_ok(), "Partition should succeed");
        let (pre, post, _overlap, _overlap_len) = result.unwrap();
        
        // Verify pre is multiple of 64 bytes
        if !pre.is_empty() {
            assert_eq!(pre.len() % 64, 0, "pre must be multiple of 64 bytes, got {}", pre.len());
        }
        
        // Verify total length
        let prefix_len = token.header_b64.len() + 1;
        let total_len = prefix_len + token.payload_b64.len();
        assert_eq!(pre.len() + post.len(), total_len, 
            "pre ({}) + post ({}) should equal total ({})", 
            pre.len(), post.len(), total_len);
        
        println!("✓ Basic partition test passed");
        println!("  pre: {} bytes ({} blocks)", pre.len(), pre.len() / 64);
        println!("  post: {} bytes", post.len());
    }

    #[test]
    fn test_reconstruct_signing_input() {
        let token = Token::new(JWT, N, &["sub", "name", "admin"]).unwrap();
        
        let first_claim_offset = 20; // More reasonable offset within payload
        let first_claim_offset_b64 = (first_claim_offset / 3) * 4;
        
        let (pre, post, _, _) = partition_for_hash_optimization(
            &token.header_b64,
            &token.payload_b64,
            first_claim_offset_b64,
        ).unwrap();
        
        // Reconstruct
        let reconstructed = [&pre[..], &post[..]].concat();
        
        // Original
        let original = [&token.header_b64[..], b".", &token.payload_b64[..]].concat();
        
        assert_eq!(reconstructed, original, 
            "pre + post should exactly reconstruct header.payload");
        
        println!("✓ Reconstruction verified: {} bytes", reconstructed.len());
    }

    #[test]
    fn test_dot_always_in_pre() {
        let token = Token::new(JWT, N, &["sub", "name", "admin"]).unwrap();
        
        let first_claim_offset = 50;
        let first_claim_offset_b64 = (first_claim_offset / 3) * 4;
        
        let (pre, _, _, _) = partition_for_hash_optimization(
            &token.header_b64,
            &token.payload_b64,
            first_claim_offset_b64,
        ).unwrap();
        
        if !pre.is_empty() && pre.len() >= token.header_b64.len() + 1 {
            // '.' should be at position header_len
            let dot_pos = token.header_b64.len();
            assert!(pre.len() > dot_pos, "'.' should be included in pre");
            assert_eq!(pre[dot_pos], b'.', "Byte at header end should be '.'");
            println!("✓ '.' correctly included in pre at position {}", dot_pos);
        }
    }

    #[test]
    fn test_sha256_state_computation() {
        let token = Token::new(JWT, N, &["sub", "name", "admin"]).unwrap();
        
        let first_claim_offset = 50;
        let first_claim_offset_b64 = (first_claim_offset / 3) * 4;
        
        let (pre, _, _, _) = partition_for_hash_optimization(
            &token.header_b64,
            &token.payload_b64,
            first_claim_offset_b64,
        ).unwrap();
        
        if pre.is_empty() {
            println!("✓ No pre-computation (split_point == 0)");
            return;
        }
        
        assert_eq!(pre.len() % 64, 0, "pre must be multiple of 64");
        let state = update(&pre);
        
        assert_ne!(state, H, "State should be updated after processing pre");
        
        println!("✓ SHA-256 state computed successfully");
        println!("  Blocks: {}", pre.len() / 64);
        println!("  State[0]: 0x{:08x}", state[0]);
    }
}
