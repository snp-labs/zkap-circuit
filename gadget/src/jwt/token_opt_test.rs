#[cfg(test)]
mod tests {
    use crate::{
        hashes::sha256::{H, utils::update},
        jwt::{Token, TokenOpt, partition_for_hash_optimization},
    };

    const JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibm9uY2UiOiJhYmMxMjMiLCJleHAiOjE1MTYyMzkwMjJ9.signature";
    const N: &str = "test_n_value";

    #[test]
    fn test_partition_strategy_v2() {
        // Test the new partitioning strategy
        let token = Token::new(JWT, N, &["sub", "nonce", "exp"]).unwrap();
        
        let first_claim_offset = 0; // Assume first claim at start of payload
        let first_claim_offset_b64 = (first_claim_offset / 3) * 4;
        
        let (pre, post, overlap, overlap_len) = partition_for_hash_optimization(
            &token.header_b64,
            &token.payload_b64,
            first_claim_offset_b64,
        ).unwrap();
        
        // Verify pre is multiple of 64 bytes
        if !pre.is_empty() {
            assert_eq!(pre.len() % 64, 0, "pre must be multiple of 64 bytes");
        }
        
        // Verify total length is preserved
        let prefix_len = token.header_b64.len() + 1; // +1 for '.'
        let total_len = prefix_len + token.payload_b64.len();
        assert_eq!(pre.len() + post.len(), total_len);
        
        // Verify '.' is in pre (unless split_point == 0)
        if !pre.is_empty() {
            let dot_pos = token.header_b64.len();
            assert!(pre.len() > dot_pos, "'.' should be in pre partition");
        }
        
        println!("Partition result:");
        println!("  pre length: {} bytes ({} blocks)", pre.len(), pre.len() / 64);
        println!("  post length: {} bytes", post.len());
        println!("  overlap length: {} bytes", overlap_len);
        println!("  total: {} bytes", pre.len() + post.len());
    }

    #[test]
    fn test_partition_with_late_claim() {
        // Test when first claim appears late in payload
        let token = Token::new(JWT, N, &["sub", "nonce", "exp"]).unwrap();
        
        // Simulate first claim appearing after 200 bytes
        let first_claim_offset = 200;
        let first_claim_offset_b64 = (first_claim_offset / 3) * 4;
        
        let (pre, post, _, _) = partition_for_hash_optimization(
            &token.header_b64,
            &token.payload_b64,
            first_claim_offset_b64,
        ).unwrap();
        
        // Should pre-hash more data
        println!("Late claim partition:");
        println!("  pre length: {} bytes ({} blocks)", pre.len(), pre.len() / 64);
        println!("  post length: {} bytes", post.len());
        
        // pre should be significant (more than just header)
        let header_with_dot = token.header_b64.len() + 1;
        if pre.len() >= 64 {
            assert!(pre.len() > header_with_dot, 
                "Should pre-hash some payload when claim is late");
        }
    }

    #[test]
    fn test_sha256_state_continuity() {
        // Verify SHA-256 state can be properly continued
        let token = Token::new(JWT, N, &["sub", "nonce", "exp"]).unwrap();
        
        let first_claim_offset = 50;
        let first_claim_offset_b64 = (first_claim_offset / 3) * 4;
        
        let (pre, post, _, _) = partition_for_hash_optimization(
            &token.header_b64,
            &token.payload_b64,
            first_claim_offset_b64,
        ).unwrap();
        
        if pre.is_empty() {
            println!("No pre-computation (split_point == 0)");
            return;
        }
        
        // Compute state from pre
        assert_eq!(pre.len() % 64, 0, "pre must be multiple of 64");
        let state = update(&pre);
        
        // Verify state is not initial IV
        assert_ne!(state, H, "State should be updated after processing pre");
        
        println!("SHA-256 state computed:");
        println!("  Input blocks: {}", pre.len() / 64);
        println!("  State: {:08x?}", state);
        println!("  Remaining bytes: {}", post.len());
    }

    #[test]
    fn test_token_opt_new_v2() {
        // Test TokenOpt::new with new partitioning strategy
        let token = Token::new(JWT, N, &["sub", "nonce", "exp"]).unwrap();
        
        #[allow(deprecated)]
        let token_opt = TokenOpt::new(&token, 1024, 512, 128).unwrap();
        
        // Verify state is computed correctly
        assert_eq!(token_opt.state.len(), 8, "SHA-256 state should have 8 u32 values");
        
        // If no pre-computation, state should be initial IV
        if token_opt.num_blocks == 0 {
            assert_eq!(token_opt.state, H.to_vec(), "No pre-computation should use IV");
        } else {
            // State should be different from IV
            assert_ne!(token_opt.state, H.to_vec(), "Pre-computed state should differ from IV");
        }
        
        println!("TokenOpt created:");
        println!("  State: {:08x?}", token_opt.state);
        println!("  Num blocks: {}", token_opt.num_blocks);
        println!("  Pay offset: {}", token_opt.pay_offset_b64);
        println!("  Pay length: {}", token_opt.pay_len_b64);
        println!("  Overlap length: {}", token_opt.overlap_len);
    }

    #[test]
    fn test_edge_case_very_early_claim() {
        // Test when claim appears at the very start
        let token = Token::new(JWT, N, &["sub", "nonce", "exp"]).unwrap();
        
        let first_claim_offset = 0; // First byte of payload
        let first_claim_offset_b64 = 0;
        
        let (pre, post, _, _) = partition_for_hash_optimization(
            &token.header_b64,
            &token.payload_b64,
            first_claim_offset_b64,
        ).unwrap();
        
        println!("Very early claim:");
        println!("  pre length: {} bytes", pre.len());
        println!("  post length: {} bytes", post.len());
        
        // Should handle gracefully (minimal or no pre-computation)
        assert_eq!(pre.len() % 64, 0, "pre must be multiple of 64 even when minimal");
    }

    #[test]
    fn test_reconstruct_signing_input() {
        // Verify that pre + post reconstructs original signing input
        let token = Token::new(JWT, N, &["sub", "nonce", "exp"]).unwrap();
        
        let first_claim_offset = 100;
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
        
        println!("Reconstruction verified: {} bytes", reconstructed.len());
    }
}
