use crate::error::TextError;

pub fn pad(s: &str, target_len: usize, pad_char: char) -> Result<String, TextError> {
    if s.len() > target_len {
        return Err(TextError::InvalidFormat(format!(
            "String length {} exceeds target length {}",
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
