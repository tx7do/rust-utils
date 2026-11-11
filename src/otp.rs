//! 一次性验证码：RFC 4226 HOTP、RFC 6238 TOTP（SHA-1/SHA-256/SHA-512 三摘要、
//! 6~8 位、可配窗口）与 RFC 4648 base32（无填充大写字母表）编解码、
//! `otpauth://` URI（Google Authenticator Key URI Format）构造与解析。
//!
//! otpauth 密钥的承载字母表就是 base32——几件放一起是因为它们互为消费方
//! （TOTP 的 secret 以 base32 形态存储，URI 是密钥在扫码场景的传输形态）。
//! 时间以 `now_unix` 入参注入而非内部取钟：纯函数形态可钉死向量测试，
//! 调用方自取钟。
//!
//! 兼容入口 [`totp_at`]/[`totp_verify`] 保持最早行为（SHA-1、6 位、±1 窗）；
//! 新代码建议直接用带 `Digest`/`digits`/`window` 参数的全量形态。

use hmac::Mac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// TOTP/HOTP 的摘要算法（RFC 6238 定义的三件套）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digest {
    Sha1,
    Sha256,
    Sha512,
}

impl Digest {
    /// 宽松名称解析：`"SHA1"` / `"SHA-1"` / `"sha1"` 等均可（otpauth 的
    /// `algorithm` 参数与各家导出大小写不一）。
    pub fn from_name(name: &str) -> Option<Digest> {
        let normalized: String = name
            .bytes()
            .filter(|b| b.is_ascii_alphanumeric())
            .map(|b| b.to_ascii_uppercase() as char)
            .collect();
        match normalized.as_str() {
            "SHA1" => Some(Digest::Sha1),
            "SHA256" => Some(Digest::Sha256),
            "SHA512" => Some(Digest::Sha512),
            _ => None,
        }
    }

    /// otpauth URI 规范名（`SHA1`/`SHA256`/`SHA512`）。
    pub fn name(&self) -> &'static str {
        match self {
            Digest::Sha1 => "SHA1",
            Digest::Sha256 => "SHA256",
            Digest::Sha512 => "SHA512",
        }
    }
}

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

fn hmac_digest(digest: Digest, secret: &[u8], data: &[u8]) -> Vec<u8> {
    macro_rules! run {
        ($ty:ty) => {{
            let mut mac =
                hmac::Hmac::<$ty>::new_from_slice(secret).expect("hmac accepts any key length");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    match digest {
        Digest::Sha1 => run!(Sha1),
        Digest::Sha256 => run!(Sha256),
        Digest::Sha512 => run!(Sha512),
    }
}

/// RFC 4226 动态截位：取摘要末字节低 4 位为偏移，自偏移起 4 字节去符号位
/// 后对 10^digits 取模。
fn truncate_hotp(digest_bytes: &[u8], digits: u32) -> String {
    let offset = (digest_bytes[digest_bytes.len() - 1] & 0x0f) as usize;
    let binary = ((digest_bytes[offset] as u64 & 0x7f) << 24)
        | ((digest_bytes[offset + 1] as u64) << 16)
        | ((digest_bytes[offset + 2] as u64) << 8)
        | digest_bytes[offset + 3] as u64;
    format!(
        "{:0width$}",
        binary % 10u64.pow(digits),
        width = digits as usize
    )
}

/// HOTP at counter（RFC 4226，动态截位，`digits` 取 6~8）。
pub fn hotp_at(secret: &[u8], counter: u64, digest: Digest, digits: u32) -> String {
    let mac = hmac_digest(digest, secret, &counter.to_be_bytes());
    truncate_hotp(&mac, digits)
}

/// TOTP at counter（30s 步长，RFC 6238 把 HOTP 的 counter 换成
/// `floor(unix_time / 30)`，余下与 RFC 4226 全同）。
pub fn totp_at_digest(secret: &[u8], counter: u64, digest: Digest, digits: u32) -> String {
    hotp_at(secret, counter, digest, digits)
}

/// TOTP at counter（SHA-1、6 位 —— 兼容入口）。
pub fn totp_at(secret: &[u8], counter: u64) -> String {
    totp_at_digest(secret, counter, Digest::Sha1, 6)
}

/// TOTP 校验（SHA-1、6 位、±1 窗口 —— 兼容入口）。
/// `now_unix` 由调用方注入。恶意慢算无利可图（30s 过期窗）。
pub fn totp_verify(secret_base32: &str, code: &str, now_unix: i64) -> bool {
    totp_verify_digest(secret_base32, code, now_unix, Digest::Sha1, 6, 1)
}

/// TOTP 校验全量形态：指定摘要、位数与 ±`window` 窗口（30s 步长）。
/// `window` 允许时钟漂移；0 表示只比对本窗。码长与位数必须一致。
pub fn totp_verify_digest(
    secret_base32: &str,
    code: &str,
    now_unix: i64,
    digest: Digest,
    digits: u32,
    window: i64,
) -> bool {
    if digits == 0 || digits > 8 {
        return false;
    }
    let digit_len = digits as usize;
    if code.len() != digit_len || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(secret) = base32_decode(secret_base32) else {
        return false;
    };
    for drift in -window..=window {
        let counter = (now_unix / 30 + drift) as u64;
        if totp_at_digest(&secret, counter, digest, digits) == code {
            return true;
        }
    }
    false
}

/// HOTP 校验：按 counter 顺序扫 `[counter, counter + lookahead]`
/// （RFC 4226 §7.3 的推荐做法），命中返回实际用掉的 counter。
pub fn hotp_verify(
    secret_base32: &str,
    code: &str,
    counter: u64,
    lookahead: u64,
    digest: Digest,
    digits: u32,
) -> Option<u64> {
    if digits == 0 || digits > 8 {
        return None;
    }
    let digit_len = digits as usize;
    if code.len() != digit_len || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secret = base32_decode(secret_base32)?;
    (counter..=counter.saturating_add(lookahead))
        .find(|c| hotp_at(&secret, *c, digest, digits) == code)
}

// ---------------------------------------------------------------------------
// otpauth:// URI(Google Authenticator Key URI Format)
// ---------------------------------------------------------------------------

/// otpauth URI 的类型段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    Totp,
    Hotp,
}

impl OtpKind {
    fn as_str(&self) -> &'static str {
        match self {
            OtpKind::Totp => "totp",
            OtpKind::Hotp => "hotp",
        }
    }

    fn from_str(s: &str) -> Option<OtpKind> {
        match s.to_ascii_lowercase().as_str() {
            "totp" => Some(OtpKind::Totp),
            "hotp" => Some(OtpKind::Hotp),
            _ => None,
        }
    }
}

/// 一条 otpauth 密钥的完整参数面。
///
/// 约定与缺省值对齐 Google Authenticator：`algorithm` 缺省 SHA1、
/// `digits` 缺省 6、`period` 缺省 30、HOTP 的 `counter` 缺省 0。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpauthParams {
    pub kind: OtpKind,
    /// label 的 issuer 段（`Issuer:account` 前半；可为空串，见 RFC 缺省约定）。
    pub issuer: String,
    /// label 的 account 段（一般是用户邮箱/用户名）。
    pub account: String,
    /// base32（无填充）形态的密钥。
    pub secret_base32: String,
    pub algorithm: Digest,
    pub digits: u32,
    /// 仅 totp 有意义；hotp 场景被构造器置 0、序列化时忽略。
    pub period: u32,
    /// 仅 hotp 有意义。
    pub counter: u64,
}

impl OtpauthParams {
    /// TOTP 参数的便捷构造（SHA-1、6 位、30s 周期）。
    pub fn totp(issuer: &str, account: &str, secret_base32: &str) -> OtpauthParams {
        OtpauthParams {
            kind: OtpKind::Totp,
            issuer: issuer.to_string(),
            account: account.to_string(),
            secret_base32: secret_base32.to_string(),
            algorithm: Digest::Sha1,
            digits: 6,
            period: 30,
            counter: 0,
        }
    }

    /// HOTP 参数的便捷构造（SHA-1、6 位、起始 counter）。
    pub fn hotp(issuer: &str, account: &str, secret_base32: &str, counter: u64) -> OtpauthParams {
        OtpauthParams {
            kind: OtpKind::Hotp,
            issuer: issuer.to_string(),
            account: account.to_string(),
            secret_base32: secret_base32.to_string(),
            algorithm: Digest::Sha1,
            digits: 6,
            period: 0,
            counter,
        }
    }

    /// 构造 `otpauth://` URI。issuer/account 按规范做百分号编码；
    /// 缺省值（SHA1/6/30/counter=0）不写出参数，保持 URI 短小。
    pub fn to_uri(&self) -> String {
        let label = if self.issuer.is_empty() {
            encode_uri_component(&self.account)
        } else {
            format!(
                "{}:{}",
                encode_uri_component(&self.issuer),
                encode_uri_component(&self.account)
            )
        };
        let mut uri = format!(
            "otpauth://{}/{}?secret={}",
            self.kind.as_str(),
            label,
            self.secret_base32
        );
        if !self.issuer.is_empty() {
            uri.push_str("&issuer=");
            uri.push_str(&encode_uri_component(&self.issuer));
        }
        if self.algorithm != Digest::Sha1 {
            uri.push_str("&algorithm=");
            uri.push_str(self.algorithm.name());
        }
        if self.digits != 6 {
            uri.push_str(&format!("&digits={}", self.digits));
        }
        match self.kind {
            OtpKind::Totp => {
                if self.period != 30 && self.period > 0 {
                    uri.push_str(&format!("&period={}", self.period));
                }
            }
            OtpKind::Hotp => {
                uri.push_str(&format!("&counter={}", self.counter));
            }
        }
        uri
    }

    /// 解析 `otpauth://` URI（宽容大小写与缺省参数）；密钥不可解码或
    /// 参数非法时返回 None。
    pub fn parse(uri: &str) -> Option<OtpauthParams> {
        let rest = uri.strip_prefix("otpauth://")?;
        let (kind_str, rest) = rest.split_once('/')?;
        let kind = OtpKind::from_str(kind_str)?;
        let (label, query) = rest.split_once('?')?;

        // label:`issuer:account`。issuer 内含冒号的场景规范不推荐,
        // 取第一个冒号切分;无冒号则整段为 account。
        let label = percent_decode(label)?;
        let (mut issuer, account) = match label.split_once(':') {
            Some((issuer, account)) => (issuer.to_string(), account.to_string()),
            None => (String::new(), label),
        };

        let mut secret_base32 = String::new();
        let mut algorithm = Digest::Sha1;
        let mut digits = 6u32;
        let mut period = 30u32;
        let mut counter = 0u64;
        let mut saw_counter = false;
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=')?;
            let value = percent_decode(value)?;
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret_base32 = value,
                "issuer" => {
                    if issuer.is_empty() {
                        issuer = value;
                    }
                }
                "algorithm" => algorithm = Digest::from_name(&value)?,
                "digits" => digits = value.parse().ok()?,
                "period" => period = value.parse().ok()?,
                "counter" => {
                    counter = value.parse().ok()?;
                    saw_counter = true;
                }
                _ => {} // 未知参数宽容跳过(各家实现常塞自定义键)
            }
        }
        if secret_base32.is_empty() || base32_decode(&secret_base32).is_none() {
            return None;
        }
        if digits == 0 || digits > 10 || period == 0 {
            return None;
        }
        let _ = saw_counter; // hotp 缺 counter 按规范缺省 0,无需特判
        let period = match kind {
            OtpKind::Totp => period,
            OtpKind::Hotp => 0,
        };
        Some(OtpauthParams {
            kind,
            issuer,
            account,
            secret_base32,
            algorithm,
            digits,
            period,
            counter,
        })
    }
}

// ---------------------------------------------------------------------------
// 百分号编码(只依赖 std;unreserved = ALPHA / DIGIT / `-` `.` `_` `~`)
// ---------------------------------------------------------------------------

fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = (bytes.get(i + 1))?.to_ascii_uppercase();
                let lo = (bytes.get(i + 2))?.to_ascii_uppercase();
                let hex = |b: u8| -> Option<u8> {
                    match b {
                        b'0'..=b'9' => Some(b - b'0'),
                        b'A'..=b'F' => Some(b - b'A' + 10),
                        _ => None,
                    }
                };
                out.push(hex(hi)? * 16 + hex(lo)?);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
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

    /// RFC 6238 附录 B 的 SHA-256 / SHA-512 测试向量（8 位形态原样钉死）。
    #[test]
    fn totp_rfc6238_sha256_sha512_vectors() {
        let sha256_secret = b"12345678901234567890123456789012"; // 32 bytes
        let sha512_secret = b"1234567890123456789012345678901234567890123456789012345678901234"; // 64 bytes
                                                                                                 // (unix_time, sha256 期望, sha512 期望) —— RFC 6238 附录 B 8 位数字
        for (now, want256, want512) in [
            (59i64, "46119246", "90693936"),
            (1111111109, "68084774", "25091201"),
            (1111111111, "67062674", "99943326"),
            (1234567890, "91819424", "93441116"),
            (2000000000, "90698825", "38618901"),
            (20000000000, "77737706", "47863826"),
        ] {
            assert_eq!(
                totp_at_digest(sha256_secret, (now / 30) as u64, Digest::Sha256, 8),
                want256,
                "sha256 t={now}"
            );
            assert_eq!(
                totp_at_digest(sha512_secret, (now / 30) as u64, Digest::Sha512, 8),
                want512,
                "sha512 t={now}"
            );
        }
    }

    /// RFC 4226 附录 D 的 HOTP 测试向量（SHA-1、6 位）。
    #[test]
    fn hotp_rfc4226_vectors() {
        let secret = b"12345678901234567890";
        let wants = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in wants.iter().enumerate() {
            assert_eq!(
                hotp_at(secret, counter as u64, Digest::Sha1, 6),
                *want,
                "counter={counter}"
            );
        }
        // counter 与 SHA-1 的 HOTP 同源:TOTP t=59 即 counter=1 → 287082
        assert_eq!(totp_at_digest(secret, 1, Digest::Sha1, 6), "287082");
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

    #[test]
    fn totp_verify_digest_window_zero_and_digits() {
        let secret = base32_encode(b"12345678901234567890123456789012");
        let now = 59i64;
        let code = totp_at_digest(
            b"12345678901234567890123456789012",
            now as u64 / 30,
            Digest::Sha256,
            8,
        );
        assert_eq!(code, "46119246");
        // window=0 只对本窗
        assert!(totp_verify_digest(
            &secret,
            &code,
            now,
            Digest::Sha256,
            8,
            0
        ));
        let next = totp_at_digest(
            b"12345678901234567890123456789012",
            ((now / 30) + 1) as u64,
            Digest::Sha256,
            8,
        );
        assert!(!totp_verify_digest(
            &secret,
            &next,
            now,
            Digest::Sha256,
            8,
            0
        ));
        assert!(totp_verify_digest(
            &secret,
            &next,
            now,
            Digest::Sha256,
            8,
            1
        ));
        // 位数不一致拒绝;SHA-1 校验端拒绝 SHA-256 产出的码
        assert!(!totp_verify_digest(
            &secret,
            &code,
            now,
            Digest::Sha256,
            6,
            1
        ));
        assert!(!totp_verify_digest(&secret, &code, now, Digest::Sha1, 8, 1));
    }

    #[test]
    fn hotp_verify_lookahead_returns_consumed_counter() {
        let secret = base32_encode(b"12345678901234567890");
        // counter=3 的码在 lookahead=2 内命中,返回 3
        assert_eq!(
            hotp_verify(&secret, "969429", 1, 2, Digest::Sha1, 6),
            Some(3)
        );
        // lookahead 之外不命中
        assert_eq!(hotp_verify(&secret, "969429", 1, 1, Digest::Sha1, 6), None);
        // 非法码长/密钥
        assert_eq!(hotp_verify(&secret, "96942", 0, 1, Digest::Sha1, 6), None);
        assert_eq!(hotp_verify("!!!!", "969429", 0, 1, Digest::Sha1, 6), None);
    }

    #[test]
    fn digest_name_roundtrip() {
        assert_eq!(Digest::from_name("SHA1"), Some(Digest::Sha1));
        assert_eq!(Digest::from_name("sha-1"), Some(Digest::Sha1));
        assert_eq!(Digest::from_name("SHA256"), Some(Digest::Sha256));
        assert_eq!(Digest::from_name("sha_512"), Some(Digest::Sha512));
        assert_eq!(Digest::from_name("md5"), None);
        assert_eq!(Digest::Sha1.name(), "SHA1");
        assert_eq!(Digest::Sha256.name(), "SHA256");
        assert_eq!(Digest::Sha512.name(), "SHA512");
    }

    // -------------------------------------------------------------------
    // otpauth URI
    // -------------------------------------------------------------------

    #[test]
    fn otpauth_build_defaults_omitted() {
        let params = OtpauthParams::totp("Example Co", "alice@example.com", "JBSWY3DPEHPK3PXP");
        assert_eq!(
            params.to_uri(),
            "otpauth://totp/Example%20Co:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co"
        );
        // 非缺省值全部写出
        let mut p = OtpauthParams::totp("Example Co", "bob@example.com", "JBSWY3DPEHPK3PXP");
        p.algorithm = Digest::Sha256;
        p.digits = 8;
        p.period = 60;
        assert_eq!(
            p.to_uri(),
            "otpauth://totp/Example%20Co:bob%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co&algorithm=SHA256&digits=8&period=60"
        );
        // hotp 带 counter
        let h = OtpauthParams::hotp("Example Co", "carol", "JBSWY3DPEHPK3PXP", 42);
        assert_eq!(
            h.to_uri(),
            "otpauth://hotp/Example%20Co:carol?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co&counter=42"
        );
    }

    #[test]
    fn otpauth_parse_roundtrip() {
        // Google Authenticator 风格完整 URI
        let uri = "otpauth://totp/Example%20Co:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co&algorithm=SHA256&digits=8&period=60";
        let params = OtpauthParams::parse(uri).unwrap();
        assert_eq!(params.kind, OtpKind::Totp);
        assert_eq!(params.issuer, "Example Co");
        assert_eq!(params.account, "alice@example.com");
        assert_eq!(params.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(params.algorithm, Digest::Sha256);
        assert_eq!(params.digits, 8);
        assert_eq!(params.period, 60);

        // 构造 → 解析回环(两种类型、各种非缺省参数)
        let mut built = OtpauthParams::totp("我的银行", "测试用户", "JBSWY3DPEHPK3PXP");
        built.algorithm = Digest::Sha512;
        built.digits = 7;
        let reparsed = OtpauthParams::parse(&built.to_uri()).unwrap();
        assert_eq!(reparsed, built);

        let hotp = OtpauthParams::hotp("ACME", "dan", "JBSWY3DPEHPK3PXP", 7);
        let reparsed = OtpauthParams::parse(&hotp.to_uri()).unwrap();
        assert_eq!(reparsed, hotp);
        assert_eq!(reparsed.period, 0);
        assert_eq!(reparsed.counter, 7);
    }

    #[test]
    fn otpauth_parse_defaults_and_tolerance() {
        // 缺省参数(SHA1/6/30)与省略 issuer 的裸 label
        let params = OtpauthParams::parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(params.issuer, "");
        assert_eq!(params.account, "alice");
        assert_eq!(params.algorithm, Digest::Sha1);
        assert_eq!(params.digits, 6);
        assert_eq!(params.period, 30);
        // issuer 只在 query:label 与 query 并存时以 label 优先
        let params = OtpauthParams::parse(
            "otpauth://totp/LabelIssuer:alice?secret=JBSWY3DPEHPK3PXP&issuer=QueryIssuer",
        )
        .unwrap();
        assert_eq!(params.issuer, "LabelIssuer");
        // 类型大小写宽容、未知参数跳过
        let params = OtpauthParams::parse(
            "otpauth://TOTP/alice?secret=JBSWY3DPEHPK3PXP&image=https%3A%2F%2Fx.example%2Fa.png",
        )
        .unwrap();
        assert_eq!(params.kind, OtpKind::Totp);
        assert_eq!(params.account, "alice");
        // hotp 缺 counter 按规范缺省 0
        let params = OtpauthParams::parse("otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(params.counter, 0);
    }

    #[test]
    fn otpauth_parse_rejects_garbage() {
        // secret 缺失 / 密钥不可 base32 解码
        assert!(OtpauthParams::parse("otpauth://totp/alice?issuer=x").is_none());
        assert!(OtpauthParams::parse("otpauth://totp/alice?secret=!!!").is_none());
        // 非 otpauth scheme / 坏类型 / 坏算法 / 坏数字参数
        assert!(OtpauthParams::parse("https://totp/alice?secret=JBSWY3DPEHPK3PXP").is_none());
        assert!(OtpauthParams::parse("otpauth://ocra/alice?secret=JBSWY3DPEHPK3PXP").is_none());
        assert!(
            OtpauthParams::parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")
                .is_none()
        );
        assert!(
            OtpauthParams::parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=99")
                .is_none()
        );
        assert!(
            OtpauthParams::parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&period=0").is_none()
        );
        assert!(OtpauthParams::parse("otpauth://totp/alice").is_none());
        assert!(OtpauthParams::parse("").is_none());
    }

    #[test]
    fn percent_encoding_roundtrip() {
        // 保留字母表 + 任意字节回环(含 UTF-8 多字节)
        for sample in [
            "",
            "plain-._~text",
            "with space",
            "中文+测试",
            "a/b?c=d&e",
            "100%",
        ] {
            assert_eq!(
                percent_decode(&encode_uri_component(sample)).as_deref(),
                Some(sample),
                "{sample}"
            );
        }
        // 坏转义拒绝
        assert!(percent_decode("%ZZ").is_none());
        assert!(percent_decode("%A").is_none());
    }
}
