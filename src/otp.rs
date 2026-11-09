//! 一次性验证码：RFC 6238 TOTP（SHA-1，6 位数字，30s 步长，±1 窗口）
//! 与 RFC 4648 base32（无填充大写字母表）编解码。
//!
//! otpauth 密钥的承载字母表就是 base32——两件放一起是因为它们互为消费方
//! （TOTP 的 secret 以 base32 形态存储）。时间以 `now_unix` 入参注入而非
//! 内部取钟：纯函数形态可钉死向量测试，调用方自取钟。

use hmac::Mac;
use sha1::Sha1;

/// RFC 4648 base32（无填充大写字母表 + 234567 数字尾），otpauth secret 字母表。
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut bits = 0u32;
    let mut acc = 0u32;
    for &byte in data {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[(acc >> bits) as usize & 31] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[(acc << (5 - bits)) as usize & 31] as char);
    }
    out
}

/// base32 解码：容忍小写与 `=` 填充尾巴；非法字母返回 None。
pub fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let mut bits = 0u32;
    let mut acc = 0u32;
    for ch in input.trim_end_matches('=').bytes() {
        let upper = ch.to_ascii_uppercase();
        let value = ALPHABET.iter().position(|&a| a == upper)? as u32;
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// TOTP at counter（RFC 6238，SHA-1，6 位十进制，动态截位）。
pub fn totp_at(secret: &[u8], counter: u64) -> String {
    let mut mac = hmac::Hmac::<Sha1>::new_from_slice(secret).expect("hmac sha1 accepts any key");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | digest[offset + 3] as u32;
    format!("{:06}", binary % 1_000_000)
}

/// TOTP 校验：码长 6 位数字、±1 窗口（30s 步长）。
/// `now_unix` 由调用方注入。恶意慢算无利可图（30s 过期窗）。
pub fn totp_verify(secret_base32: &str, code: &str, now_unix: i64) -> bool {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(secret) = base32_decode(secret_base32) else {
        return false;
    };
    for drift in [-1i64, 0, 1] {
        let counter = (now_unix / 30 + drift) as u64;
        if totp_at(&secret, counter) == code {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip_all_padding_remainders() {
        for sample in [
            b"hello world".to_vec(),
            vec![0u8, 1, 2, 250, 251, 255],
            b"K".to_vec(),
            b"KK".to_vec(),
            b"KKK".to_vec(),
            b"KKKK".to_vec(),
            b"KKKKK".to_vec(),
        ] {
            let encoded = base32_encode(&sample);
            let decoded = base32_decode(&encoded).unwrap();
            assert_eq!(decoded, sample, "{encoded}");
            assert!(encoded
                .bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)));
        }
        // 小写解码容错（otpauth 密钥常以小写出现）与垃圾拒绝
        let upper = base32_encode(b"secret!");
        assert_eq!(base32_decode(&upper.to_lowercase()).unwrap(), b"secret!");
        assert!(base32_decode("!!!!").is_none());
    }

    /// RFC 6238 附录 B 的 SHA-1 测试向量（secret = "12345678901234567890"）。
    #[test]
    fn totp_rfc6238_vectors() {
        let secret = b"12345678901234567890";
        // (unix_time, expected TOTP)
        for (now, want) in [
            (59i64, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ] {
            assert_eq!(totp_at(secret, (now / 30) as u64), want, "t={now}");
        }
    }

    #[test]
    fn totp_verify_window_and_shape() {
        let secret = base32_encode(b"12345678901234567890");
        let now = 59i64;
        // 本窗/前窗/后窗都过（±1）
        assert!(totp_verify(&secret, "287082", now));
        let next = totp_at(b"12345678901234567890", ((now / 30) + 1) as u64);
        assert!(totp_verify(&secret, &next, now));
        // 两个窗口之外拒
        let far = totp_at(b"12345678901234567890", ((now / 30) + 2) as u64);
        assert!(!totp_verify(&secret, &far, now));
        // 形状：5 位 / 非数字 / 坏 base32 全拒
        assert!(!totp_verify(&secret, "28708", now));
        assert!(!totp_verify(&secret, "28708a", now));
        assert!(!totp_verify("!!!!", "287082", now));
    }
}
