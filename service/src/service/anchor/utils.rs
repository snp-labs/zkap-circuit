use crate::{error::error::ApplicationError, interface::anchor::Secret};

impl Secret {
    /// 개별 SecretDto를 패딩 및 연결하여 문자열로 반환합니다.
    pub fn concatenate(
        &self,
        max_aud_len: usize,
        max_iss_len: usize,
        max_sub_len: usize,
        pad_char: char,
    ) -> Result<String, ApplicationError> {
        let aud_processed = Self::pad(&self.aud, max_aud_len, pad_char)?;
        let iss_processed = Self::pad(&self.iss, max_iss_len, pad_char)?;
        let sub_processed = Self::pad(&self.sub, max_sub_len, pad_char)?;

        Ok([aud_processed, iss_processed, sub_processed].concat())
    }

    /// 내부 헬퍼 함수: 옵션 필드 패딩 처리
    fn pad_field(
        &self,
        field: &Option<String>,
        target_len: usize,
        pad_char: char,
    ) -> Result<String, ApplicationError> {
        match field {
            Some(s) => Self::pad(s, target_len, pad_char),
            None => Ok(String::new()), // 혹은 빈 문자열도 패딩이 필요하다면 로직 수정 필요
        }
    }

    /// 문자열 패딩 로직
    fn pad(s: &str, target_len: usize, pad_char: char) -> Result<String, ApplicationError> {
        if s.len() > target_len {
            return Err(ApplicationError::InvalidFormat(format!(
                "String length exceeds target length: {} > {}",
                s.len(),
                target_len
            )));
        }

        let mut result = String::with_capacity(target_len);
        result.push_str(s);
        let pad_needed = target_len - s.len();
        result.extend(std::iter::repeat(pad_char).take(pad_needed));

        Ok(result)
    }
}
