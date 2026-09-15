//! 整数与字节的互转,以及 ASCII 字节大小写翻转。

/// 将 `i64` 转为 8 字节大端表示。
pub fn int_to_bytes(n: i64) -> [u8; 8] {
    n.to_be_bytes()
}

/// 将字节数组按大端读取为 `i64`;不足 8 字节高位补零,超出部分忽略。
pub fn bytes_to_int(bytes: &[u8]) -> i64 {
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    buf[8 - n..].copy_from_slice(&bytes[..n]);
    i64::from_be_bytes(buf)
}

/// ASCII 大写字母转小写,其余不变。
pub fn byte_to_lower(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

/// ASCII 小写字母转大写,其余不变。
pub fn byte_to_upper(b: u8) -> u8 {
    b.to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_bytes_roundtrip() {
        assert_eq!(int_to_bytes(0), [0; 8]);
        assert_eq!(int_to_bytes(1), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(bytes_to_int(&int_to_bytes(123456789)), 123456789);
        assert_eq!(bytes_to_int(&int_to_bytes(-42)), -42);
    }

    #[test]
    fn test_bytes_to_int_short_input() {
        assert_eq!(bytes_to_int(&[1]), 1);
        assert_eq!(bytes_to_int(&[]), 0);
    }

    #[test]
    fn test_byte_case() {
        assert_eq!(byte_to_lower(b'A'), b'a');
        assert_eq!(byte_to_lower(b'a'), b'a');
        assert_eq!(byte_to_lower(b'5'), b'5');
        assert_eq!(byte_to_upper(b'a'), b'A');
        assert_eq!(byte_to_upper(b'A'), b'A');
    }
}
