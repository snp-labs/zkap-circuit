use std::{cmp::min, collections::BTreeMap};

use crate::{
    base64::decode_any_base64_to_string,
    hashes::sha256::utils::{sha256_block_len, update},
};

use super::{ClaimIndices, JwtMetadata, JwtParserError, claim_indices_from_payload};

pub fn create_jwt_metadata(
    header_b64: &str,
    payload_b64: &str,
    keys: &[&str],
) -> Result<JwtMetadata, JwtParserError> {
    let payload = decode_any_base64_to_string(payload_b64)?;

    let first_claim_offset = keys
        .iter()
        .filter_map(|key| payload.find(key).map(|offset| offset))
        .min_by_key(|offset| *offset)
        .ok_or_else(|| JwtParserError::NotFoundKeyError("any key".to_string()))?;

    let (post_b64, num_sha256_blocks, overlap, overlap_len, state) =
        create_optimized_data(header_b64, payload_b64, &first_claim_offset)?;

    let overlap_post_b64 = [overlap.clone(), post_b64.clone()].concat();

    let post_b64_str = String::from_utf8(overlap_post_b64.clone())?;
    let post_str = decode_any_base64_to_string(&post_b64_str)?;

    let claims: BTreeMap<String, ClaimIndices> = keys
        .iter()
        .map(|key| {
            claim_indices_from_payload(&post_str, key).map(|indices| (key.to_string(), indices))
        })
        .collect::<Result<BTreeMap<String, ClaimIndices>, JwtParserError>>()?;

    Ok(JwtMetadata {
        pay_offset_b64: 0,
        pay_len_b64: post_b64.len(),
        claims,
        overlap,
        overlap_len,
        state,
        post_b64,
        num_sha256_blocks,
    })
}

// (post_b64, num_sha256_blocks, overlap, state)
fn create_optimized_data(
    header_b64: &str,
    payload_b64: &str,
    first_key: &usize,
) -> Result<(Vec<u8>, usize, Vec<u8>, usize, Vec<u32>), JwtParserError> {
    // 전역 인코딩 오프셋 계산
    let encoded_payload_offset = (first_key / 3) * 4;

    // 문자열 분리
    let (pre_b64_string, post_b64, overlap, overlap_len) =
        partition_for_hash_optimization_optimized(header_b64, payload_b64, encoded_payload_offset)?;

    let num_sha256_blocks = sha256_block_len(post_b64.len()) - 1;

    // 해시 상태 업데이트
    let state = update(&pre_b64_string).to_vec();

    Ok((post_b64, num_sha256_blocks, overlap, overlap_len, state))
}

fn partition_for_hash_optimization_optimized(
    header_b64: &str,
    payload_b64: &str,
    encoded_payload_offset: usize,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, usize), JwtParserError> {
    const CHUNK_SIZE: usize = 64;

    // 1. 전체 길이를 미리 계산하여 한 번만 할당합니다.
    let signing_input_len = header_b64.len() + 1 + payload_b64.len();
    let global_encoded_offset = header_b64.len() + 1 + encoded_payload_offset;

    // 2. 분리 지점을 바이트 인덱스로 직접 계산합니다.
    let actual_split_point = (global_encoded_offset / CHUNK_SIZE) * CHUNK_SIZE;

    // 3. 필요한 만큼만 메모리를 할당하고 데이터를 직접 채웁니다.
    let mut pre_b64_bytes = Vec::with_capacity(actual_split_point);
    let mut post_b64_bytes = Vec::with_capacity(signing_input_len - actual_split_point);

    // pre_b64_bytes 채우기
    let pre_header_len = min(actual_split_point, header_b64.len());
    pre_b64_bytes.extend_from_slice(&header_b64.as_bytes()[..pre_header_len]);

    if actual_split_point > header_b64.len() {
        pre_b64_bytes.push(b'.');
        let pre_payload_len = actual_split_point - (header_b64.len() + 1);
        pre_b64_bytes.extend_from_slice(&payload_b64.as_bytes()[..pre_payload_len]);
    }

    // post_b64_bytes 채우기
    if actual_split_point <= header_b64.len() {
        post_b64_bytes.extend_from_slice(&header_b64.as_bytes()[actual_split_point..]);
        post_b64_bytes.push(b'.');
        post_b64_bytes.extend_from_slice(payload_b64.as_bytes());
    } else {
        let post_payload_start = actual_split_point - (header_b64.len() + 1);
        post_b64_bytes.extend_from_slice(&payload_b64.as_bytes()[post_payload_start..]);
    }

    // 4. Overlap 계산 및 추출
    let payload_start_offset = header_b64.len() + 1;

    let (overlap, overlap_len) = if actual_split_point >= payload_start_offset {
        let split_point_in_payload = actual_split_point - payload_start_offset;
        let overlap_len = split_point_in_payload % 4;
        if overlap_len > 0 {
            // pre_b64_bytes의 마지막 부분에서 overlap을 가져옵니다.
            (
                pre_b64_bytes[pre_b64_bytes.len() - overlap_len..].to_vec(),
                overlap_len,
            )
        } else {
            (vec![0u8; 3], 0) // Overlap이 없을 경우 3바이트의 0으로 채웁니다.
        }
    } else {
        return Err(JwtParserError::InvalidLengthError(
            "The split point is before the payload starts.".to_string(),
        ));
    };

    Ok((pre_b64_bytes, post_b64_bytes, overlap, overlap_len))
}

#[cfg(test)]
mod tests {
    use crate::gadget::jwt::create_jwt_metadata;

    #[test]
    fn test_jwt_builder() {
        let jwt = JWT;
        let (h, p, _) = {
            let parts = jwt.split('.').collect::<Vec<_>>();
            (parts[0], parts[1], parts[2])
        };

        let jwt_circuit_input = create_jwt_metadata(h, p, &vec!["sub", "nonce", "exp"]).unwrap();
        println!("{:?}", jwt_circuit_input);
    }

    #[test]
    fn test_token_no_opt() {
        use crate::gadget::jwt::TokenNoOpt;

        let jwt = JWT;
        let n = N;
        let token = crate::gadget::jwt::Token::new(jwt, n, &["sub", "nonce", "exp"]).unwrap();
        let token_no_opt = TokenNoOpt::new(&token, 1024, 512, 128).unwrap();

        println!("{:?}", token_no_opt);
    }

    #[test]
    fn test_token_opt() {
        use crate::gadget::jwt::TokenOpt;

        let jwt = JWT;
        let n = N;
        let token = crate::gadget::jwt::Token::new(jwt, n, &["sub", "nonce", "exp"]).unwrap();
        let token_opt = TokenOpt::new(&token, 1024, 512, 128).unwrap();

        println!("{:?}", token_opt);
    }

    const JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3NTM2NzY2NTg3NjciLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3MTM4NTEzMDI2ODYtNmczdG84OTAyaW9oZ2lwMWl2ZHZwZXBhajUyZTdzMGkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3MTM4NTEzMDI2ODYtc3ZsdWVqZDhsaTFsNXFkOXNwODA2dGJtazNsa2I0aGouYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDUwNDM4ODExNzc4ODQ3MzgyMjciLCJlbWFpbCI6ImtpbS5reXVuZ2tvb0BnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibm9uY2UiOiIweGEyYjkxZjgwMzA2MGIxNWUwMzVhM2Y2OTJmNDQ5ZThlODVmNjA1ZWRhYmMyZWFmNWM1ZWEzZDUwOTE5NWNmNCIsIm5hbWUiOiJLeXVuZ0tvbyBLaW0iLCJnaXZlbl9uYW1lIjoiS3l1bmdLb28iLCJmYW1pbHlfbmFtZSI6IktpbSIsImlhdCI6MTc1MzY3NjY1OCwiZXhwIjoxNzUzNjgwMjU5fQ.KkRxVTqJTOSggbMTZG_UpTSg29LrdObuS_3iiXAXbAtL9wDI94w4SwlEQsa8mMF4LjCJXVd7RRTghaM--PeYyh8KQmmB68_YW8tKAQfoqZYI73-WEJMHMEI8UheogumnDRgtRy8AYshB8xZTnF_JYJdJ2YzzgoRAn23VHnRqUTgNiqCSh9PAvPKv_K-f-jdQ_uV2i3e4AiYX0Y_Ve9Pt0XdEpEi8h-Ga6JZ2cadOlAoqrdjUovYBEsdQ9-J4nQl7Zoi0nnaCQL50GZP96BeiR7dTw0T36Ua45z1OzZCAhvbX_Ad_Hr-JZcJe0beQEUobrCor5Chc9DLfUQuciHRj1A";

    const N: &str = "tsQsUV8QpqrygsY-2-JCQ6Fw8_omM71IM2N_R8pPbzbgOl0p78MZGsgPOQ2HSznjD0FPzsH8oO2B5Uftws04LHb2HJAYlz25-lN5cqfHAfa3fgmC38FfwBkn7l582UtPWZ_wcBOnyCgb3yLcvJrXyrt8QxHJgvWO23ITrUVYszImbXQ67YGS0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0NfFdfsZhTT8YbxBvA8FdODgEwx7u_vf3J9qbi4-Kv8cvqyJuleIRSjVXPsIMnoejIn04APPKIjpMyQdnWlby7rNyQtE4-CV-jcFjqJbE_Xilcvqxt6DirjFCvYeKYl1uHLw";
}
