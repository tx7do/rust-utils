//! 密码哈希策略,feature `password`。
//!
//! 统一的 [`Crypto`] 接口:`encrypt` 输出可自校验的字符串
//! (bcrypt/argon2 为标准 PHC 格式,pbkdf2 为自定义分段格式),
//! `verify` 用明文比对。
//!
//! ```
//! use rust_utils::password::{Argon2Crypto, Crypto};
//!
//! let algo = Argon2Crypto::default();
//! let hash = algo.encrypt("s3cret!").unwrap();
//! assert_ne!(hash, "s3cret!");
//! assert!(algo.verify("s3cret!", &hash).unwrap());
//! assert!(!algo.verify("wrong", &hash).unwrap());
//! ```

use sha2::{Digest, Sha256, Sha512};

/// 密码哈希策略接口。
pub trait Crypto: Send + Sync {
    /// 加密(哈希)明文。
    fn encrypt(&self, plain: &str) -> Result<String, String>;
    /// 校验明文与密文是否匹配。
    fn verify(&self, plain: &str, encrypted: &str) -> Result<bool, String>;
}

fn random_bytes(n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| format!("generate random failed: {e}"))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// 复杂度策略
// ---------------------------------------------------------------------------

/// 校验明文口令复杂度:长度(按字节,对齐上游 `len` 语义)达到 `min_len`,
/// 且至少包含 小写/大写/数字/符号 四类中的三类。
/// `min_len` 传 0 时按 1 处理(仅校验字符类别)。符号类按
/// "非字母数字且非空白/控制字符"判定。
pub fn validate_complexity(plain: &str, min_len: usize) -> Result<(), String> {
    let min_len = min_len.max(1);
    if plain.len() < min_len {
        return Err(format!("密码过短:最小长度为 {min_len}"));
    }
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    for c in plain.chars() {
        if c.is_lowercase() {
            has_lower = true;
        } else if c.is_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if !c.is_alphanumeric() && !c.is_whitespace() && !c.is_control() {
            has_symbol = true;
        }
    }
    let classes =
        has_lower as usize + has_upper as usize + has_digit as usize + has_symbol as usize;
    if classes < 3 {
        return Err("密码复杂度不足:需至少包含 小写/大写/数字/符号 四类中的三类".to_string());
    }
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.as_bytes();
    if s.len() % 2 != 0 {
        return Err("invalid hex string".to_string());
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(std::str::from_utf8(&s[i * 2..i * 2 + 2]).unwrap(), 16)
                .map_err(|e| format!("invalid hex string: {e}"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// PBKDF2
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA256(默认 100_000 轮)。
pub struct PBKDF2Crypto {
    rounds: u32,
}

impl Default for PBKDF2Crypto {
    fn default() -> Self {
        PBKDF2Crypto { rounds: 100_000 }
    }
}

impl PBKDF2Crypto {
    pub fn new(rounds: u32) -> Self {
        PBKDF2Crypto { rounds }
    }
}

impl Crypto for PBKDF2Crypto {
    fn encrypt(&self, plain: &str) -> Result<String, String> {
        let salt = random_bytes(16)?;
        let mut out = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(plain.as_bytes(), &salt, self.rounds, &mut out);
        Ok(format!(
            "pbkdf2_sha256${}${}${}",
            self.rounds,
            to_hex(&salt),
            to_hex(&out)
        ))
    }

    fn verify(&self, plain: &str, encrypted: &str) -> Result<bool, String> {
        let parts: Vec<&str> = encrypted.split('$').collect();
        if parts.len() != 4 || parts[0] != "pbkdf2_sha256" {
            return Err("invalid pbkdf2 hash format".to_string());
        }
        let rounds: u32 = parts[1].parse().map_err(|e| format!("bad rounds: {e}"))?;
        let salt = from_hex(parts[2])?;
        let expect = from_hex(parts[3])?;
        let mut out = vec![0u8; expect.len()];
        pbkdf2::pbkdf2_hmac::<Sha256>(plain.as_bytes(), &salt, rounds, &mut out);
        Ok(out == expect)
    }
}

/// PBKDF2-HMAC-SHA512。
pub struct PBKDF2Sha512Crypto {
    rounds: u32,
}

impl Default for PBKDF2Sha512Crypto {
    fn default() -> Self {
        PBKDF2Sha512Crypto { rounds: 100_000 }
    }
}

impl Crypto for PBKDF2Sha512Crypto {
    fn encrypt(&self, plain: &str) -> Result<String, String> {
        let salt = random_bytes(16)?;
        let mut out = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<Sha512>(plain.as_bytes(), &salt, self.rounds, &mut out);
        Ok(format!(
            "pbkdf2_sha512${}${}${}",
            self.rounds,
            to_hex(&salt),
            to_hex(&out)
        ))
    }

    fn verify(&self, plain: &str, encrypted: &str) -> Result<bool, String> {
        let parts: Vec<&str> = encrypted.split('$').collect();
        if parts.len() != 4 || parts[0] != "pbkdf2_sha512" {
            return Err("invalid pbkdf2 hash format".to_string());
        }
        let rounds: u32 = parts[1].parse().map_err(|e| format!("bad rounds: {e}"))?;
        let salt = from_hex(parts[2])?;
        let expect = from_hex(parts[3])?;
        let mut out = vec![0u8; expect.len()];
        pbkdf2::pbkdf2_hmac::<Sha512>(plain.as_bytes(), &salt, rounds, &mut out);
        Ok(out == expect)
    }
}

// ---------------------------------------------------------------------------
// bcrypt / argon2 / HMAC / SHA
// ---------------------------------------------------------------------------

/// bcrypt(默认 cost 10)。
pub struct BCryptCrypto {
    cost: u32,
}

impl Default for BCryptCrypto {
    fn default() -> Self {
        BCryptCrypto { cost: 10 }
    }
}

impl BCryptCrypto {
    pub fn new(cost: u32) -> Self {
        BCryptCrypto { cost }
    }
}

impl Crypto for BCryptCrypto {
    fn encrypt(&self, plain: &str) -> Result<String, String> {
        bcrypt::hash(plain, self.cost).map_err(|e| format!("bcrypt hash failed: {e}"))
    }

    fn verify(&self, plain: &str, encrypted: &str) -> Result<bool, String> {
        bcrypt::verify(plain, encrypted).map_err(|e| format!("bcrypt verify failed: {e}"))
    }
}

/// argon2id(默认参数,输出标准 PHC 字符串)。
#[derive(Default)]
pub struct Argon2Crypto;

impl Crypto for Argon2Crypto {
    fn encrypt(&self, plain: &str) -> Result<String, String> {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        argon2::Argon2::default()
            .hash_password(plain.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| format!("argon2 hash failed: {e}"))
    }

    fn verify(&self, plain: &str, encrypted: &str) -> Result<bool, String> {
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        let parsed =
            PasswordHash::new(encrypted).map_err(|e| format!("invalid argon2 hash: {e}"))?;
        Ok(argon2::Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok())
    }
}

/// HMAC-SHA256(密钥模式)。
pub struct HmacCrypto {
    secret_key: String,
}

impl HmacCrypto {
    pub fn new(secret_key: impl Into<String>) -> Self {
        HmacCrypto {
            secret_key: secret_key.into(),
        }
    }
}

impl Crypto for HmacCrypto {
    fn encrypt(&self, plain: &str) -> Result<String, String> {
        use hmac::Mac;
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(self.secret_key.as_bytes())
            .map_err(|e| format!("bad hmac key: {e}"))?;
        mac.update(plain.as_bytes());
        Ok(to_hex(&mac.finalize().into_bytes()))
    }

    fn verify(&self, plain: &str, encrypted: &str) -> Result<bool, String> {
        Ok(self.encrypt(plain)? == encrypted.to_lowercase())
    }
}

/// SHA-256 固定哈希(无盐,适合校验场景,不适合存密码)。
#[derive(Default)]
pub struct SHA256Crypto;

impl Crypto for SHA256Crypto {
    fn encrypt(&self, plain: &str) -> Result<String, String> {
        Ok(to_hex(&Sha256::digest(plain.as_bytes())))
    }

    fn verify(&self, plain: &str, encrypted: &str) -> Result<bool, String> {
        Ok(self.encrypt(plain)? == encrypted.to_lowercase())
    }
}

/// SHA-512 固定哈希。
#[derive(Default)]
pub struct SHA512Crypto;

impl Crypto for SHA512Crypto {
    fn encrypt(&self, plain: &str) -> Result<String, String> {
        Ok(to_hex(&Sha512::digest(plain.as_bytes())))
    }

    fn verify(&self, plain: &str, encrypted: &str) -> Result<bool, String> {
        Ok(self.encrypt(plain)? == encrypted.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(algo: &dyn Crypto, plain: &str) {
        let hash = algo.encrypt(plain).unwrap();
        assert_ne!(hash, plain);
        assert!(!hash.is_empty());
        assert!(algo.verify(plain, &hash).unwrap(), "verify correct: {hash}");
        assert!(!algo.verify("wrong-password", &hash).unwrap());
    }

    #[test]
    fn test_pbkdf2() {
        roundtrip(&PBKDF2Crypto::default(), "hello123");
        // 两次加密结果不同(随机盐)
        let algo = PBKDF2Crypto::default();
        assert_ne!(algo.encrypt("x").unwrap(), algo.encrypt("x").unwrap());
        assert!(PBKDF2Crypto::default().verify("x", "garbage").is_err());
    }

    #[test]
    fn test_pbkdf2_sha512() {
        roundtrip(&PBKDF2Sha512Crypto::default(), "hello123");
    }

    #[test]
    fn test_bcrypt() {
        roundtrip(&BCryptCrypto::default(), "hello123");
    }

    #[test]
    fn test_argon2() {
        roundtrip(&Argon2Crypto, "hello123");
        // PHC 格式
        let hash = Argon2Crypto.encrypt("x").unwrap();
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn test_hmac() {
        roundtrip(&HmacCrypto::new("key-123"), "hello123");
    }

    #[test]
    fn test_sha() {
        roundtrip(&SHA256Crypto, "hello123");
        roundtrip(&SHA512Crypto, "hello123");
        // 确定性
        assert_eq!(
            SHA256Crypto.encrypt("abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // ---------------------------------------------------------------------------
    // RSA 密码策略(加密/解密,非哈希)
    // ---------------------------------------------------------------------------

    /// RSA-OAEP-SHA256 加密/解密策略(输出标准 base64)。
    ///
    /// 注意:这是可逆加密而非哈希,不实现 [`Crypto`] 验证接口,
    /// 而是提供成对的 [`decrypt`](Self::decrypt)。
    pub struct RSACrypto {
        private: rsa::RsaPrivateKey,
    }

    impl RSACrypto {
        /// 生成新的 RSA 密钥对(如 `key_size = 2048`)。
        pub fn new(key_size: usize) -> Result<Self, String> {
            let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, key_size)
                .map_err(|e| format!("rsa keygen failed: {e}"))?;
            Ok(RSACrypto { private })
        }

        /// 公钥加密,输出 base64。
        pub fn encrypt(&self, plain: &str) -> Result<String, String> {
            let pub_key = rsa::RsaPublicKey::from(&self.private);
            let sealed = pub_key
                .encrypt(
                    &mut rsa::rand_core::OsRng,
                    rsa::Oaep::new::<Sha256>(),
                    plain.as_bytes(),
                )
                .map_err(|e| format!("rsa encrypt failed: {e}"))?;
            Ok(to_b64(&sealed))
        }

        /// 私钥解密 base64 密文。
        pub fn decrypt(&self, encrypted: &str) -> Result<String, String> {
            let sealed = from_b64(encrypted)?;
            let plain = self
                .private
                .decrypt(rsa::Oaep::new::<Sha256>(), &sealed)
                .map_err(|e| format!("rsa decrypt failed: {e}"))?;
            String::from_utf8(plain).map_err(|e| format!("invalid utf-8: {e}"))
        }

        /// 导出私钥 PKCS#1 PEM。
        pub fn export_private_key(&self) -> Result<String, String> {
            use rsa::pkcs1::EncodeRsaPrivateKey as _;
            self.private
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .map(|p| p.to_string())
                .map_err(|e| format!("export private key failed: {e}"))
        }

        /// 导出公钥 SPKI PEM(标签 `RSA PUBLIC KEY`)。
        pub fn export_public_key(&self) -> Result<String, String> {
            use rsa::pkcs8::EncodePublicKey as _;
            let pub_key = rsa::RsaPublicKey::from(&self.private);
            pub_key
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .map(|p| {
                    p.replace("BEGIN PUBLIC KEY", "BEGIN RSA PUBLIC KEY")
                        .replace("END PUBLIC KEY", "END RSA PUBLIC KEY")
                })
                .map_err(|e| format!("export public key failed: {e}"))
        }
    }

    fn to_b64(bytes: &[u8]) -> String {
        // base64 编码
        bytes
            .chunks(3)
            .map(|c| {
                let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
                let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
                format!(
                    "{}{}{}{}",
                    B64[(n >> 18 & 63) as usize] as char,
                    B64[(n >> 12 & 63) as usize] as char,
                    if c.len() > 1 {
                        B64[(n >> 6 & 63) as usize] as char
                    } else {
                        '='
                    },
                    if c.len() > 2 {
                        B64[(n & 63) as usize] as char
                    } else {
                        '='
                    },
                )
            })
            .collect()
    }

    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn from_b64(s: &str) -> Result<Vec<u8>, String> {
        let mut vals = Vec::with_capacity(s.len());
        for c in s.bytes() {
            match c {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
                    vals.push(B64.iter().position(|a| *a == c).unwrap() as u32)
                }
                b'=' => {}
                _ => return Err(format!("invalid base64 character: {}", c as char)),
            }
        }
        let mut out = Vec::with_capacity(vals.len() * 3 / 4);
        for chunk in vals.chunks(4) {
            let n = match chunk.len() {
                4 => (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6) | chunk[3],
                3 => (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6),
                2 => (chunk[0] << 18) | (chunk[1] << 12),
                _ => return Err("invalid base64 length".to_string()),
            };
            out.push((n >> 16 & 0xFF) as u8);
            if chunk.len() >= 3 {
                out.push((n >> 8 & 0xFF) as u8);
            }
            if chunk.len() == 4 {
                out.push((n & 0xFF) as u8);
            }
        }
        Ok(out)
    }

    // ---------------------------------------------------------------------------
    // ECDSA 密码策略(签名式校验)
    // ---------------------------------------------------------------------------

    /// 大端字节串的十进制表示(反复除 10 取余)。
    fn be32_to_dec(bytes: &[u8]) -> String {
        let mut n = [0u8; 32];
        n[32 - bytes.len()..].copy_from_slice(bytes);
        let mut digits = Vec::new();
        loop {
            let mut rem: u32 = 0;
            for byte in n.iter_mut() {
                let cur = (rem << 8) | *byte as u32;
                *byte = (cur / 10) as u8;
                rem = cur % 10;
            }
            digits.push(b'0' + rem as u8);
            if n.iter().all(|&b| b == 0) {
                break;
            }
        }
        digits.reverse();
        let s = String::from_utf8(digits).expect("decimal digits");
        let trimmed = s.trim_start_matches('0');
        if trimmed.is_empty() {
            "0".to_string()
        } else {
            trimmed.to_string()
        }
    }

    /// 十进制串转 32 字节大端(反复乘 10 加位);超 256 位报错。
    fn dec_to_be32(s: &str) -> Result<[u8; 32], String> {
        let mut out = [0u8; 32];
        for c in s.bytes() {
            if !c.is_ascii_digit() {
                return Err(format!("invalid decimal digit: {}", c as char));
            }
            let mut carry = (c - b'0') as u16;
            for byte in out.iter_mut().rev() {
                let cur = (*byte as u16) * 10 + carry;
                *byte = cur as u8;
                carry = cur >> 8;
            }
            if carry != 0 {
                return Err("value exceeds 256 bits".to_string());
            }
        }
        Ok(out)
    }

    /// 基于 ECDSA P-256 签名的密码策略:encrypt 输出签名
    /// `ecdsa$<r十进制>$<s十进制>`,verify 用公钥验签。
    /// 注意:签名取 RFC 6979 确定性随机数,同一密码两次 encrypt 产生相同签名。
    pub struct ECDSACrypto {
        signing: p256::ecdsa::SigningKey,
    }

    impl Default for ECDSACrypto {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ECDSACrypto {
        /// 生成新的 P-256 密钥对。
        pub fn new() -> Self {
            ECDSACrypto {
                signing: p256::ecdsa::SigningKey::random(
                    &mut p256::elliptic_curve::rand_core::OsRng,
                ),
            }
        }
    }

    impl Crypto for ECDSACrypto {
        fn encrypt(&self, plain: &str) -> Result<String, String> {
            use p256::ecdsa::signature::Signer;
            if plain.is_empty() {
                return Err("密码不能为空".to_string());
            }
            let sig: p256::ecdsa::Signature = self.signing.sign(plain.as_bytes());
            let bytes = sig.to_bytes();
            Ok(format!(
                "ecdsa${}${}",
                be32_to_dec(&bytes[..32]),
                be32_to_dec(&bytes[32..])
            ))
        }

        fn verify(&self, plain: &str, encrypted: &str) -> Result<bool, String> {
            if plain.is_empty() || encrypted.is_empty() {
                return Err("密码或加密字符串不能为空".to_string());
            }
            let parts: Vec<&str> = encrypted.splitn(3, '$').collect();
            if parts.len() != 3 || parts[0] != "ecdsa" {
                return Err("加密字符串格式无效".to_string());
            }
            let r = dec_to_be32(parts[1]).map_err(|e| format!("invalid r: {e}"))?;
            let s = dec_to_be32(parts[2]).map_err(|e| format!("invalid s: {e}"))?;
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&r);
            sig[32..].copy_from_slice(&s);
            let sig = p256::ecdsa::Signature::from_slice(&sig)
                .map_err(|e| format!("invalid signature: {e}"))?;
            use p256::ecdsa::signature::Verifier;
            let verifying = p256::ecdsa::VerifyingKey::from(&self.signing);
            Ok(verifying.verify(plain.as_bytes(), &sig).is_ok())
        }
    }

    // ---------------------------------------------------------------------------
    // ECDH 密码策略(密钥协商式校验)
    // ---------------------------------------------------------------------------

    /// 基于 ECDH P-256 的密码策略:encrypt 返回 `"ecdh$"+base64(本方公钥)`。
    /// verify 校验对端(encrypt 返回的)公钥有效且能与其推导出共享密钥;
    /// plain 仅作非空确认位,不参与密钥推导。返回 true 表示握手可继续,
    /// 后续共享密钥用 [`ECDHCrypto::derive_shared_secret`](双方对该结果一致)。
    pub struct ECDHCrypto {
        secret: p256::SecretKey,
    }

    impl Default for ECDHCrypto {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ECDHCrypto {
        /// 生成新的 P-256 密钥对。
        pub fn new() -> Self {
            ECDHCrypto {
                secret: p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng),
            }
        }

        fn pubkey_b64(&self) -> String {
            use p256::elliptic_curve::sec1::ToEncodedPoint as _;
            let point = self.secret.public_key().to_encoded_point(false);
            to_b64(point.as_bytes())
        }

        /// 推导与对端的共享密钥(共享点 X 坐标 32 字节)。
        /// 兼容 encrypt 返回的 `"ecdh$<base64>"` 形态与裸 base64 两种输入。
        pub fn derive_shared_secret(&self, peer_public_key: &str) -> Result<Vec<u8>, String> {
            use p256::elliptic_curve::sec1::FromEncodedPoint as _;
            let bare = match peer_public_key.split_once('$') {
                Some(("ecdh", rest)) => rest,
                Some((prefix, _)) => return Err(format!("加密字符串格式无效: {prefix}")),
                None => peer_public_key,
            };
            let bytes = from_b64(bare)?;
            let point = p256::EncodedPoint::from_bytes(&bytes)
                .map_err(|e| format!("invalid public key: {e}"))?;
            let peer = p256::PublicKey::from_encoded_point(&point)
                .into_option()
                .ok_or("无效的公钥")?;
            let shared = p256::elliptic_curve::ecdh::diffie_hellman(
                self.secret.to_nonzero_scalar(),
                peer.as_affine(),
            );
            Ok(shared.raw_secret_bytes().to_vec())
        }
    }

    impl Crypto for ECDHCrypto {
        fn encrypt(&self, plain: &str) -> Result<String, String> {
            if plain.is_empty() {
                return Err("密码不能为空".to_string());
            }
            Ok(format!("ecdh${}", self.pubkey_b64()))
        }

        fn verify(&self, plain: &str, encrypted: &str) -> Result<bool, String> {
            if plain.is_empty() || encrypted.is_empty() {
                return Err("密码或加密字符串不能为空".to_string());
            }
            let parts: Vec<&str> = encrypted.splitn(2, '$').collect();
            if parts.len() != 2 || parts[0] != "ecdh" {
                return Err("加密字符串格式无效".to_string());
            }
            // 对端公钥必须有效(在曲线上),且能完成一次共享密钥推导
            self.derive_shared_secret(parts[1])?;
            Ok(true)
        }
    }

    #[test]
    fn test_rsa_crypto() {
        let algo = RSACrypto::new(2048).unwrap();
        let plain = "rsa-password-123";
        let sealed = algo.encrypt(plain).unwrap();
        assert_ne!(sealed, plain);
        assert_eq!(algo.decrypt(&sealed).unwrap(), plain);
        assert!(algo
            .export_private_key()
            .unwrap()
            .contains("BEGIN RSA PRIVATE KEY"));
        assert!(algo
            .export_public_key()
            .unwrap()
            .contains("BEGIN RSA PUBLIC KEY"));
    }

    #[test]
    fn test_ecdsa_crypto() {
        let algo = ECDSACrypto::new();
        let sealed = algo.encrypt("my-password").unwrap();
        assert!(sealed.starts_with("ecdsa$"));
        // RFC 6979 确定性签名:同一密码两次签名一致,验签均通过
        let sealed2 = algo.encrypt("my-password").unwrap();
        assert_eq!(sealed, sealed2);
        assert!(algo.verify("my-password", &sealed).unwrap());
        assert!(algo.verify("my-password", &sealed2).unwrap());
        assert!(!algo.verify("wrong", &sealed).unwrap());
        assert!(algo.encrypt("",).is_err());
        assert!(algo.verify("", &sealed).is_err());
    }

    #[test]
    fn test_ecdh_crypto() {
        let alice = ECDHCrypto::new();
        let bob = ECDHCrypto::new();
        let sealed = bob.encrypt("shared-secret").unwrap();
        assert!(sealed.starts_with("ecdh$"));

        // verify 校验对端公钥有效且共享密钥可推导:明文不参与比较,
        // 任意明文均通过(握手语义),公钥无效则报错
        assert!(bob.verify("shared-secret", &sealed).unwrap());
        assert!(bob.verify("其他明文也通过", &sealed).unwrap());
        assert!(bob
            .verify("x", &format!("ecdh${}", bob.pubkey_b64()))
            .is_ok());
        // 前缀不符 / 坏公钥
        assert!(bob.verify("x", "nope$abc").is_err());
        assert!(bob.verify("x", "ecdh$!!!").is_err());

        // derive_shared_secret:裸公钥与 "ecdh$" 前缀形态结果一致,双方一致
        let bare = bob.pubkey_b64();
        let sa = alice.derive_shared_secret(&bare).unwrap();
        let sa_prefixed = alice.derive_shared_secret(&sealed).unwrap();
        let sb = bob.derive_shared_secret(&alice.pubkey_b64()).unwrap();
        assert_eq!(sa, sa_prefixed);
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 32);
        // 错误前缀直接拒绝
        assert!(alice.derive_shared_secret("oops$abc").is_err());
    }

    #[test]
    fn test_validate_complexity() {
        // 三类齐全 + 长度达标
        assert!(validate_complexity("abcdef1!", 8).is_ok());
        assert!(validate_complexity("a1!", 3).is_ok());
        assert!(validate_complexity("Abcdefg1", 8).is_ok());
        // 类别不足(仅两类)
        assert!(validate_complexity("abcdefgh", 8).is_err());
        assert!(validate_complexity("Abcdefg", 8).is_err());
        assert!(validate_complexity("12345678", 8).is_err());
        // 长度不足
        assert!(validate_complexity("a1!xyz", 8).is_err());
        // 长度按字节计:"a1!密码" 共 9 字节(≥8)且三类齐全
        assert!(validate_complexity("a1!密码", 8).is_ok());
        assert!(validate_complexity("a1!密", 8).is_err()); // 6 字节
                                                           // 纯 CJK 字符类别为 0,长度再够也拒绝
        assert!(validate_complexity("密码密码", 1).is_err());
        // min_len 0 按 1 处理,仅校验类别
        assert!(validate_complexity("abc", 0).is_err());
    }
}
