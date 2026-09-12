//! 密码哈希策略(移植自 go-utils/password),feature `password`。
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
}
