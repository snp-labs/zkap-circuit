use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    select::CondSelectGadget,
    uint16::UInt16,
};
use ark_relations::r1cs::SynthesisError;
use ark_utils::{is_less_than, single_multiplexer, slice_efficient, slice_from_start};

use crate::token::constraints::ClaimIndicesVar;

pub fn claim_extractor_v2<F: PrimeField>(
    key: &str,
    payload: &[FpVar<F>],
    pos: &ClaimIndicesVar<F>,
    max_len: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // Wrap key in double quotes to form "key"
    let key_with_quotes = format!(r#""{}""#, key);
    let key_bytes = key_with_quotes
        .bytes()
        .map(|byte| FpVar::<F>::Constant(F::from(byte)))
        .collect::<Vec<_>>();
    let key_len = key_with_quotes.len();
    let key_len_uint = UInt16::constant(key_len as u16);

    // Extract the entire claim from payload (needed for format verification)
    let claim = slice_efficient(payload, &pos.offset, &pos.claim_len, max_len)?;

    // Extract key name from claim using slice_from_start
    // Claim format: "key":value
    // slice_from_start extracts from position 0 with length key_len
    let pad_char = FpVar::<F>::Constant(F::from(b'0'));
    let result_name = slice_from_start(&claim, &key_len_uint.to_fp()?, key_len, &pad_char)?;

    // Extract value directly from payload using absolute offset
    // This eliminates one slice_efficient call (~50k constraints saved)
    // absolute_value_offset = pos.offset + pos.value_idx
    let absolute_value_offset =
        UInt16::<F>::wrapping_add_many(&[pos.offset.clone(), pos.value_idx.clone()])?;
    let result_value = slice_efficient(payload, &absolute_value_offset, &pos.value_len, max_len)?;

    // Verify that extracted name matches the key (with quotes)
    result_name.enforce_equal(&key_bytes)?;

    // Verify claim format
    claim_format_verifier_v2(
        &claim,
        &pos.claim_len,
        &key_len_uint,
        &pos.colon_idx,
        &pos.value_idx,
        &pos.value_len,
        max_len,
    )?;

    Ok(result_value)
}

fn claim_format_verifier_v2<F: PrimeField>(
    claim: &[FpVar<F>],
    claim_len: &UInt16<F>,
    name_len: &UInt16<F>,
    colon_idx: &UInt16<F>,
    value_idx: &UInt16<F>,
    value_len: &UInt16<F>,
    max_claim_len: usize,
) -> Result<(), SynthesisError> {
    let value_len = Boolean::le_bits_to_fp(&value_len.to_bits_le()?)?;
    let claim_len = Boolean::le_bits_to_fp(&claim_len.to_bits_le()?)?;

    // check1: name length must be less than or equal to colon index.
    // name_len.enforce_cmp(&colon_idx, Ordering::Less, true)?;
    // Changed due to a bug in enforce_cmp in r1cs-std "0.5.0".
    let name_len_boolean = name_len.to_bits_le()?;
    let colon_idx_boolean = colon_idx.to_bits_le()?;
    let result =
        is_less_than(&name_len_boolean, &colon_idx_boolean)? | name_len.is_eq(colon_idx)?;
    result.enforce_equal(&Boolean::TRUE)?;

    // check2: colon index must be less than value index.
    // colon_idx.enforce_cmp(&value_idx, Ordering::Less, true)?;
    // Changed due to a bug in enforce_cmp in r1cs-std "0.5.0".
    let value_idx_boolean = value_idx.to_bits_le()?;
    let result = is_less_than(&colon_idx_boolean, &value_idx_boolean)?;
    result.enforce_equal(&Boolean::TRUE)?;

    // Compute flags once: 1 if not whitespace, 0 if whitespace.
    let is_not_whitespace_flags = claim
        .iter()
        .map(|byte| Ok(FpVar::from(!is_whitespace(byte)?)))
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    let name_len = name_len.to_fp()?;
    let colon_idx = colon_idx.to_fp()?;
    let value_idx = value_idx.to_fp()?;

    // check3: no non-whitespace characters between key and colon. (name_len-1 < i < colon_idx)
    enforce_range_is_whitespace_v2(
        &(name_len - F::ONE),
        &colon_idx,
        &is_not_whitespace_flags,
        max_claim_len,
    )?;

    // check4: no non-whitespace characters between colon_idx and value_idx. (colon_idx < i < value_idx)
    enforce_range_is_whitespace_v2(
        &colon_idx,
        &value_idx,
        &is_not_whitespace_flags,
        max_claim_len,
    )?;

    // check5: no non-whitespace characters between end of value and end of claim.
    let value_end_idx = value_idx + value_len; // last index of value + 1
    let claim_end_idx = claim_len.clone() - F::ONE; // last character index of claim
    enforce_range_is_whitespace_v2(
        &value_end_idx,
        &claim_end_idx,
        &is_not_whitespace_flags,
        max_claim_len,
    )?;
    // Note: the original check5 logic `&(value_idx + value_len + F::ONE)` appears to start the range one position later.
    // Adjust `value_end_idx` to `value_idx + value_len` or `value_idx + value_len + F::ONE` as intended.

    // check6: verify that colon is at colon_idx position.
    let colon_var = single_multiplexer(claim, &colon_idx)?;
    colon_var.enforce_equal(&FpVar::<F>::Constant(F::from(b':')))?;

    // check7: verify that the last character is a comma or closing brace.
    let last_char_var = single_multiplexer(claim, &(claim_len - F::ONE))?;
    let is_closing_brace = last_char_var.is_eq(&FpVar::constant(F::from(b'}')))?;
    let is_comma = last_char_var.is_eq(&FpVar::constant(F::from(b',')))?;
    (is_closing_brace | is_comma).enforce_equal(&Boolean::TRUE)?;
    // Using or may be clearer than the original mul_equals logic.

    Ok(())
}

fn enforce_range_is_whitespace_v2<F: PrimeField>(
    start_idx: &FpVar<F>,
    end_idx: &FpVar<F>,
    is_not_whitespace_flags: &[FpVar<F>],
    max_len: usize,
) -> Result<(), SynthesisError> {
    // Build prefix sums: prefix[i] = sum(is_not_whitespace_flags[0..i])
    // prefix[0] = 0, prefix[1] = flags[0], ..., prefix[max_len] = sum of all flags
    let mut prefix_sums = Vec::with_capacity(max_len + 1);
    prefix_sums.push(FpVar::<F>::zero());
    let mut running_sum = FpVar::<F>::zero();
    for flag in is_not_whitespace_flags.iter().take(max_len) {
        running_sum += flag;
        prefix_sums.push(running_sum.clone());
    }

    // We want sum of flags[i] for i in the open interval (start_idx, end_idx).
    // That equals prefix[end_idx] - prefix[start_idx + 1].
    //
    // When the range is empty (end_idx <= start_idx), we must produce 0.
    // We clamp the lower lookup index: use end_idx instead of start_idx+1 when
    // end_idx <= start_idx, making both lookups identical and the difference 0.
    //
    // Compute: is_nonempty = (start_idx + 1 <= end_idx), i.e., start_idx < end_idx.
    // Then: lookup_start = if is_nonempty { start_idx + 1 } else { end_idx }
    let start_idx_plus_1 = start_idx + FpVar::one();

    // Use 16-bit LE representation (indices fit in 16 bits since max_len <= ~500)
    let start_plus_1_bits = start_idx_plus_1.to_bits_le()?;
    let end_bits = end_idx.to_bits_le()?;
    let bits_16 = 16usize;
    let start_plus_1_bits_16 = &start_plus_1_bits[..bits_16];
    let end_bits_16 = &end_bits[..bits_16];

    // is_nonempty = start_idx + 1 <= end_idx  (equivalently: start_idx + 1 < end_idx OR equal)
    let is_lt = is_less_than(start_plus_1_bits_16, end_bits_16)?;
    let is_eq_end = start_idx_plus_1.is_eq(end_idx)?;
    let is_nonempty = is_lt | is_eq_end;

    // Clamp: if nonempty use start_idx+1, else use end_idx (range sum becomes 0)
    let lookup_start = FpVar::conditionally_select(&is_nonempty, &start_idx_plus_1, end_idx)?;

    let prefix_at_lookup_start = single_multiplexer(&prefix_sums, &lookup_start)?;
    let prefix_at_end = single_multiplexer(&prefix_sums, end_idx)?;

    // range_sum = prefix[end] - prefix[lookup_start]; enforced to be 0
    let range_sum = prefix_at_end - prefix_at_lookup_start;
    range_sum.enforce_equal(&FpVar::zero())?;

    Ok(())
}

fn is_whitespace<F: PrimeField>(byte: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
    let is_tab = byte.is_eq(&FpVar::constant(F::from(0x09u8)))?;
    let is_newline = byte.is_eq(&FpVar::constant(F::from(0x0Au8)))?;
    let is_carriage_return = byte.is_eq(&FpVar::constant(F::from(0x0Du8)))?;
    let is_space = byte.is_eq(&FpVar::constant(F::from(0x20u8)))?;

    Ok(is_tab | is_newline | is_carriage_return | is_space)
}

#[cfg(test)]
mod tests {
    use crate::token::{Claim, ClaimIndices};

    use super::*;

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
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;

    type F = ark_bn254::Fr;

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
}
