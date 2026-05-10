//! Internal tests for `circuit::token::claimverifier`, extracted from the
//! inline `#[cfg(test)] mod tests` block in `src/token/claimverifier.rs`
//! (per-crate plan C10 / C-A6 V1).
//!
//! The tests exercise [`claim_extractor_v2`] against hand-crafted JSON
//! payloads and corrupted [`ClaimIndices`] inputs.  All symbols touched
//! here are part of the crate's public surface; this file is a literal
//! AST relocation of the inline tests with the only changes being the
//! `crate::` → `circuit::` import path adjustments required when moving
//! from `src/` to `tests/`.

use ark_bn254::Fr as F;
use ark_ff::PrimeField;
use ark_r1cs_std::{R1CSVar, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, uint16::UInt16};
use ark_relations::r1cs::ConstraintSystem;
use ark_utils::{slice_efficient, slice_from_start};

use circuit::token::claim_indices::ClaimIndicesVar;
use circuit::token::claimverifier::claim_extractor_v2;
use circuit::token::{Claim, ClaimIndices};

/// Test-local copy of parse_claim_from_str using pure std string operations.
fn parse_claim_from_str(s: &str, key: &str) -> Result<Claim, String> {
    let needle = format!("\"{}\"", key);
    let key_start = s
        .find(&needle)
        .ok_or_else(|| format!("Key '{}' not found", key))?;

    let mut offset = key_start;
    while offset > 0 && s.as_bytes()[offset - 1].is_ascii_whitespace() {
        offset -= 1;
    }

    let after_key = key_start + needle.len();
    let colon_rel = s[after_key..].find(':').ok_or("Colon not found")?;
    let colon_idx = (after_key + colon_rel) - offset;

    let after_colon = after_key + colon_rel + 1;
    let mut value_start = after_colon;
    while value_start < s.len() && s.as_bytes()[value_start].is_ascii_whitespace() {
        value_start += 1;
    }

    let value_end = if s.as_bytes()[value_start] == b'"' {
        let closing = s[value_start + 1..]
            .find('"')
            .ok_or("Unterminated string")?;
        value_start + 1 + closing + 1
    } else {
        s[value_start..]
            .find([',', '}'])
            .map(|i| value_start + i)
            .unwrap_or(s.len())
    };

    let value_str = s[value_start..value_end].to_string();
    let value_idx = value_start - offset;
    let value_len = value_end - value_start;

    let mut trail = value_end;
    while trail < s.len() && s.as_bytes()[trail].is_ascii_whitespace() {
        trail += 1;
    }
    let claim_len =
        if trail < s.len() && (s.as_bytes()[trail] == b',' || s.as_bytes()[trail] == b'}') {
            trail + 1 - offset
        } else {
            trail - offset
        };

    Ok(Claim {
        key: key.to_string(),
        value: value_str,
        indices: ClaimIndices {
            offset,
            claim_len,
            colon_idx,
            value_idx,
            value_len,
        },
    })
}

/// Helper function to extract string from FpVar result with proper length
fn extract_string(result: &[FpVar<F>], length: usize) -> String {
    let bytes: Vec<u8> = result
        .iter()
        .take(length)
        .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
        .collect();
    String::from_utf8(bytes).unwrap()
}

/// Helper function to create payload FpVar from string
fn create_payload(cs: ark_relations::r1cs::ConstraintSystemRef<F>, s: &str) -> Vec<FpVar<F>> {
    s.bytes()
        .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(byte))).unwrap())
        .collect()
}

/// Helper function to create ClaimIndicesVar
fn create_claim_indices_var(
    cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    indices: &ClaimIndices,
) -> ClaimIndicesVar<F> {
    ClaimIndicesVar {
        offset: UInt16::new_witness(cs.clone(), || Ok(indices.offset as u16)).unwrap(),
        claim_len: UInt16::new_witness(cs.clone(), || Ok(indices.claim_len as u16)).unwrap(),
        colon_idx: UInt16::new_witness(cs.clone(), || Ok(indices.colon_idx as u16)).unwrap(),
        value_idx: UInt16::new_witness(cs.clone(), || Ok(indices.value_idx as u16)).unwrap(),
        value_len: UInt16::new_witness(cs.clone(), || Ok(indices.value_len as u16)).unwrap(),
    }
}

#[test]
fn test_step_by_step_extraction() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload: {"sub":"user123","nonce":"0x1234"}
    let payload_str = r#"{"sub":"user123","nonce":"0x1234"}"#;
    let payload = create_payload(cs.clone(), payload_str);

    let claim = parse_claim_from_str(payload_str, "sub").unwrap();
    println!("Claim: {:?}", claim);

    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    // Step 1: Extract claim from payload
    println!("\n=== Step 1: Extract claim ===");
    let claim_extracted = slice_efficient(&payload, &pos.offset, &pos.claim_len, 50).unwrap();
    println!(
        "Constraints after claim extraction: {}",
        cs.num_constraints()
    );
    println!("Is satisfied: {}", cs.is_satisfied().unwrap());

    let claim_bytes: Vec<u8> = claim_extracted
        .iter()
        .take(claim.indices.claim_len)
        .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
        .collect();
    println!(
        "Extracted claim: {:?}",
        String::from_utf8(claim_bytes.clone()).unwrap()
    );

    // Step 2: Extract name from claim using slice_from_start
    println!("\n=== Step 2: Extract name (key) from claim ===");
    let key = "sub";
    let key_with_quotes = format!(r#""{}""#, key);
    let key_bytes = key_with_quotes
        .bytes()
        .map(|byte| FpVar::<F>::Constant(F::from(byte)))
        .collect::<Vec<_>>();
    let key_len = key_with_quotes.len();
    let key_len_uint = UInt16::constant(key_len as u16);
    let pad_char = FpVar::<F>::Constant(F::from(b'0'));

    let result_name = slice_from_start(
        &claim_extracted,
        &key_len_uint.to_fp().unwrap(),
        key_len,
        &pad_char,
    )
    .unwrap();
    println!(
        "Constraints after name extraction: {}",
        cs.num_constraints()
    );
    println!("Is satisfied: {}", cs.is_satisfied().unwrap());

    let name_bytes: Vec<u8> = result_name
        .iter()
        .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
        .collect();
    println!(
        "Extracted name: {:?}",
        String::from_utf8(name_bytes.clone()).unwrap()
    );

    // Step 3: Verify name equals key
    println!("\n=== Step 3: Verify name equals key ===");
    println!("Expected key (with quotes): {:?}", key_with_quotes);
    println!(
        "Extracted name: {:?}",
        String::from_utf8(name_bytes).unwrap()
    );

    // Verify name matches key
    result_name.enforce_equal(&key_bytes).unwrap();
    println!(
        "Constraints after name verification: {}",
        cs.num_constraints()
    );
    println!("Is satisfied: {}", cs.is_satisfied().unwrap());

    // Step 4: Extract value from claim
    println!("\n=== Step 4: Extract value from claim ===");
    let result_value =
        slice_efficient(&claim_extracted, &pos.value_idx, &pos.value_len, 50).unwrap();
    println!(
        "Constraints after value extraction: {}",
        cs.num_constraints()
    );
    println!("Is satisfied: {}", cs.is_satisfied().unwrap());

    let value_bytes: Vec<u8> = result_value
        .iter()
        .take(claim.indices.value_len)
        .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
        .collect();
    println!(
        "Extracted value: {:?}",
        String::from_utf8(value_bytes).unwrap()
    );

    println!("\n✓ Step-by-step extraction successful!");
}

#[test]
fn test_claim_extractor_v2_basic_string_value() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload: {"sub":"user123","nonce":"0x1234"}
    let payload_str = r#"{"sub":"user123","nonce":"0x1234"}"#;
    let payload = create_payload(cs.clone(), payload_str);

    // Extract "sub" claim
    let claim = parse_claim_from_str(payload_str, "sub").unwrap();
    println!("Claim: {:?}", claim);
    println!("Payload length: {}", payload_str.len());
    println!("Payload: {}", payload_str);

    // Debug: print the claim substring
    let claim_substr =
        &payload_str[claim.indices.offset..claim.indices.offset + claim.indices.claim_len];
    println!("Claim substring: {:?}", claim_substr);

    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    println!("Before extraction - constraints: {}", cs.num_constraints());

    let result = claim_extractor_v2("sub", &payload, &pos, 50);

    if let Err(e) = &result {
        println!("Error during extraction: {:?}", e);
        panic!("Extraction failed");
    }

    let result = result.unwrap();

    println!("After extraction - constraints: {}", cs.num_constraints());
    println!("Result length: {}", result.len());

    if !cs.is_satisfied().unwrap() {
        println!("❌ Constraints NOT satisfied!");
        println!("Total constraints: {}", cs.num_constraints());
        println!("Num instance variables: {}", cs.num_instance_variables());
        println!("Num witness variables: {}", cs.num_witness_variables());

        // Try to extract value anyway to see what we get
        let extracted_all: Vec<u8> = result
            .iter()
            .take(claim.indices.value_len)
            .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
            .collect();
        println!(
            "Extracted value (first {} bytes): {:?}",
            claim.indices.value_len,
            String::from_utf8_lossy(&extracted_all)
        );

        panic!("Constraints should be satisfied");
    }

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );

    // Verify extracted value - only take value_len bytes
    let extracted_str = extract_string(&result, claim.indices.value_len);
    println!("Extracted value: {:?}", extracted_str);
    assert_eq!(extracted_str, r#""user123""#);

    println!(
        "✓ Basic string value test - constraints: {}",
        cs.num_constraints()
    );
}

#[test]
fn test_claim_extractor_v2_hex_value() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload with hex nonce value
    let payload_str = r#"{"sub":"user123","nonce":"0xabcdef1234567890"}"#;
    let payload = create_payload(cs.clone(), payload_str);

    // Extract "nonce" claim
    let claim = parse_claim_from_str(payload_str, "nonce").unwrap();
    println!("Claim: {:?}", claim);

    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    let result = claim_extractor_v2("nonce", &payload, &pos, 60).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );

    // Verify extracted value - only take value_len bytes
    let extracted_str = extract_string(&result, claim.indices.value_len);
    println!("Extracted value: {:?}", extracted_str);
    assert_eq!(extracted_str, r#""0xabcdef1234567890""#);

    println!("✓ Hex value test - constraints: {}", cs.num_constraints());
}

#[test]
fn test_claim_extractor_v2_with_whitespace() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload with whitespace around colon and value
    let payload_str = r#"{"sub"  :   "user123"  ,"nonce":"0x1234"}"#;
    let payload = create_payload(cs.clone(), payload_str);

    // Extract "sub" claim
    let claim = parse_claim_from_str(payload_str, "sub").unwrap();
    println!("Claim: {:?}", claim);

    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    let result = claim_extractor_v2("sub", &payload, &pos, 60).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );

    // Verify extracted value
    let extracted_str = extract_string(&result, claim.indices.value_len);
    println!("Extracted value: {:?}", extracted_str);
    assert_eq!(extracted_str, r#""user123""#);

    println!("✓ Whitespace test - constraints: {}", cs.num_constraints());
}

#[test]
fn test_claim_extractor_v2_numeric_value() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload with numeric value
    let payload_str = r#"{"sub":"user123","exp":1234567890,"nonce":"0x1234"}"#;
    let payload = create_payload(cs.clone(), payload_str);

    // Extract "exp" claim (numeric value without quotes)
    let claim = parse_claim_from_str(payload_str, "exp").unwrap();
    println!("Claim: {:?}", claim);

    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    let result = claim_extractor_v2("exp", &payload, &pos, 70).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );
    println!("result: {:?}", result.value().unwrap());

    // Verify extracted value
    let extracted_str = extract_string(&result, claim.indices.value_len);
    println!("Extracted value: {:?}", extracted_str);
    assert_eq!(extracted_str, "1234567890");

    println!(
        "✓ Numeric value test - constraints: {}",
        cs.num_constraints()
    );
}

#[test]
fn test_claim_extractor_v2_last_claim_with_closing_brace() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload where claim ends with closing brace
    let payload_str = r#"{"sub":"user123","nonce":"0x1234"}"#;
    let payload = create_payload(cs.clone(), payload_str);

    // Extract "nonce" claim (last claim)
    let claim = parse_claim_from_str(payload_str, "nonce").unwrap();
    println!("Claim: {:?}", claim);

    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    let result = claim_extractor_v2("nonce", &payload, &pos, 60).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );

    // Verify extracted value
    let extracted_str = extract_string(&result, claim.indices.value_len);
    println!("Extracted value: {:?}", extracted_str);
    assert_eq!(extracted_str, r#""0x1234""#);

    println!(
        "✓ Last claim with closing brace test - constraints: {}",
        cs.num_constraints()
    );
}

#[test]
fn test_claim_extractor_v2_middle_claim() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload with claim in the middle
    let payload_str = r#"{"sub":"user123","nonce":"0x1234","exp":1234567890}"#;
    let payload = create_payload(cs.clone(), payload_str);

    // Extract "nonce" claim (middle claim)
    let claim = parse_claim_from_str(payload_str, "nonce").unwrap();
    println!("Claim: {:?}", claim);

    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    let result = claim_extractor_v2("nonce", &payload, &pos, 60).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );

    // Verify extracted value
    let extracted_str = extract_string(&result, claim.indices.value_len);
    println!("Extracted value: {:?}", extracted_str);
    assert_eq!(extracted_str, r#""0x1234""#);

    println!(
        "✓ Middle claim test - constraints: {}",
        cs.num_constraints()
    );
}

#[test]
#[should_panic(expected = "not satisfied")]
fn test_claim_extractor_v2_wrong_key() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload
    let payload_str = r#"{"sub":"user123","nonce":"0x1234"}"#;
    let payload = create_payload(cs.clone(), payload_str);

    // Parse claim for "sub" but try to extract "nonce"
    let claim = parse_claim_from_str(payload_str, "sub").unwrap();
    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    // This should fail because we're claiming to extract "nonce" but positions are for "sub"
    let _result = claim_extractor_v2("nonce", &payload, &pos, 50).unwrap();

    // This should fail due to key mismatch
    if !cs.is_satisfied().unwrap() {
        panic!("Constraints not satisfied - key mismatch detected");
    }
}

#[test]
#[should_panic(expected = "not satisfied")]
fn test_claim_extractor_v2_invalid_colon_position() {
    let cs = ConstraintSystem::<F>::new_ref();

    // Valid JSON payload
    let payload_str = r#"{"sub":"user123","nonce":"0x1234"}"#;
    let payload = create_payload(cs.clone(), payload_str);

    // Parse correct claim
    let mut claim = parse_claim_from_str(payload_str, "sub").unwrap();

    // Corrupt colon_idx to point to wrong position
    claim.indices.colon_idx += 2;

    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    let _result = claim_extractor_v2("sub", &payload, &pos, 50).unwrap();

    // This should fail due to invalid colon position
    if !cs.is_satisfied().unwrap() {
        panic!("Constraints not satisfied - invalid colon position detected");
    }
}

#[test]
fn test_claim_extractor_v2_value_length_with_extra_whitespace() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload with extra whitespace after value
    let payload_str = r#"{"sub":"user123"   ,"nonce":"0x1234"}"#;
    let payload = create_payload(cs.clone(), payload_str);

    // Parse correct claim - value is "user123" (9 chars including quotes)
    let claim = parse_claim_from_str(payload_str, "sub").unwrap();

    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    let result = claim_extractor_v2("sub", &payload, &pos, 50).unwrap();

    // Should succeed - whitespace after value is allowed
    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied with trailing whitespace"
    );

    let extracted_str = extract_string(&result, claim.indices.value_len);
    assert_eq!(extracted_str, r#""user123""#);

    println!(
        "✓ Value length with extra whitespace test - constraints: {}",
        cs.num_constraints()
    );
}

#[test]
#[should_panic]
fn test_claim_extractor_v2_missing_comma_or_brace() {
    let cs = ConstraintSystem::<F>::new_ref();

    // Invalid JSON - missing comma/brace at end
    let payload_str = r#"{"sub":"user123" "nonce":"0x1234"}"#; // Missing comma after user123"
    let payload = create_payload(cs.clone(), payload_str);

    // This will fail during parsing or constraint checking
    let indices = ClaimIndices {
        offset: 1,
        claim_len: 16, // "sub":"user123"
        colon_idx: 5,
        value_idx: 6,
        value_len: 9,
    };

    let pos = create_claim_indices_var(cs.clone(), &indices);

    let _result = claim_extractor_v2("sub", &payload, &pos, 50).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Should fail - missing comma or brace"
    );
}

#[test]
#[should_panic]
fn test_claim_extractor_v2_non_whitespace_after_key() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON with non-whitespace character between key and colon
    let payload_str = r#"{"sub"x:"user123","nonce":"0x1234"}"#; // 'x' between "sub" and :
    let payload = create_payload(cs.clone(), payload_str);

    let indices = ClaimIndices {
        offset: 1,
        claim_len: 17,
        colon_idx: 6, // Position of ':'
        value_idx: 7,
        value_len: 9,
    };

    let pos = create_claim_indices_var(cs.clone(), &indices);

    let _result = claim_extractor_v2("sub", &payload, &pos, 50).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Should fail - non-whitespace after key"
    );
}

#[test]
fn test_claim_extractor_v2_256bit_hex_value() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload with 256-bit hex nonce (64 hex digits)
    let hex_value = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let payload_str = format!(r#"{{"sub":"user","nonce":"{}"}}"#, hex_value);
    let payload = create_payload(cs.clone(), &payload_str);

    // Extract "nonce" claim
    let claim = parse_claim_from_str(&payload_str, "nonce").unwrap();
    println!("Claim: {:?}", claim);

    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    let result = claim_extractor_v2("nonce", &payload, &pos, 120).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );

    // Verify extracted value
    let extracted_str = extract_string(&result, claim.indices.value_len);
    println!("Extracted value: {:?}", extracted_str);
    assert!(extracted_str.contains(hex_value));

    println!(
        "✓ 256-bit hex value test - constraints: {}",
        cs.num_constraints()
    );
}

#[test]
fn test_claim_extractor_v2_empty_string_value() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload with empty string value
    let payload_str = r#"{"sub":"","nonce":"0x1234"}"#;
    let payload = create_payload(cs.clone(), payload_str);

    // Extract "sub" claim (empty value)
    let claim = parse_claim_from_str(payload_str, "sub").unwrap();
    println!("Claim: {:?}", claim);

    let pos = create_claim_indices_var(cs.clone(), &claim.indices);

    let result = claim_extractor_v2("sub", &payload, &pos, 40).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );

    // Verify extracted value (empty string = "")
    let extracted_str = extract_string(&result, claim.indices.value_len);
    println!("Extracted value: {:?}", extracted_str);
    assert_eq!(extracted_str, r#""""#);

    println!(
        "✓ Empty string value test - constraints: {}",
        cs.num_constraints()
    );
}

#[test]
fn test_claim_extractor_v2_multiple_extractions() {
    let cs = ConstraintSystem::<F>::new_ref();

    // JSON payload with multiple claims
    let payload_str = r#"{"sub":"alice","nonce":"0xabc","exp":123456}"#;
    let payload = create_payload(cs.clone(), payload_str);

    // Extract "sub"
    let claim_sub = parse_claim_from_str(payload_str, "sub").unwrap();
    let pos_sub = create_claim_indices_var(cs.clone(), &claim_sub.indices);
    let result_sub = claim_extractor_v2("sub", &payload, &pos_sub, 50).unwrap();

    // Extract "nonce"
    let claim_nonce = parse_claim_from_str(payload_str, "nonce").unwrap();
    let pos_nonce = create_claim_indices_var(cs.clone(), &claim_nonce.indices);
    let result_nonce = claim_extractor_v2("nonce", &payload, &pos_nonce, 50).unwrap();

    // Extract "exp"
    let claim_exp = parse_claim_from_str(payload_str, "exp").unwrap();
    let pos_exp = create_claim_indices_var(cs.clone(), &claim_exp.indices);
    let result_exp = claim_extractor_v2("exp", &payload, &pos_exp, 50).unwrap();

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );

    // Verify all extracted values
    assert_eq!(
        extract_string(&result_sub, claim_sub.indices.value_len),
        r#""alice""#
    );
    assert_eq!(
        extract_string(&result_nonce, claim_nonce.indices.value_len),
        r#""0xabc""#
    );
    assert_eq!(
        extract_string(&result_exp, claim_exp.indices.value_len),
        "123456"
    );

    println!(
        "✓ Multiple extractions test - constraints: {}",
        cs.num_constraints()
    );
}
