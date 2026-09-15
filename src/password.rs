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
            Ok(to_hex_noop(&sealed))
        }

        /// 私钥解密 base64 密文。
        pub fn decrypt(&self, encrypted: &str) -> Result<String, String> {
            let sealed = from_hex_str(encrypted)?;
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

    fn to_hex_noop(bytes: &[u8]) -> String {
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

    fn from_hex_str(s: &str) -> Result<Vec<u8>, String> {
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

    /// 基于 ECDSA P-256 签名的密码策略:encrypt 输出签名
    /// `ecdsa$<r十进制>$<s十进制>`,verify 用公钥验签。
    /// 注意:同一密码两次 encrypt 产生不同签名(签名含随机数)。
    pub struct ECDSACrypto {
        signing: p256::ecdsa::SigningKey,
    }

    impl Default for ECDSACrypto {
        fn default() -> Self {
            Self::new().expect("p256 keygen")
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
            let r = p256::elliptic_curve::bigint::U256::from_be_slice(&bytes[..32]);
            let s = p256::elliptic_curve::bigint::U256::from_be_slice(&bytes[32..]);
            Ok(format!(
                "ecdsa${}${}",
                r.to_str_radix(10),
                s.to_str_radix(10)
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
            let r = p256::elliptic_curve::bigint::U256::from_str_radix(parts[1], 10)
                .map_err(|e| format!("invalid r: {e}"))?;
            let s = p256::elliptic_curve::bigint::U256::from_str_radix(parts[2], 10)
                .map_err(|e| format!("invalid s: {e}"))?;
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&r.to_be_bytes());
            sig[32..].copy_from_slice(&s.to_be_bytes());
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

    /// 基于 ECDH P-256 的密码策略:encrypt 返回 `"ecdh$"+base64(本方公钥)`,
    /// verify 用对端公钥推导共享密钥,比对 `sha256(共享X) == sha256(明文)`。
    /// "密钥协商式"设计:同一明文可被任意持私钥方验证。
    pub struct ECDHCrypto {
        secret: p256::SecretKey,
    }

    impl Default for ECDHCrypto {
        fn default() -> Self {
            Self::new().expect("p256 keygen")
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
            to_hex_noop(point.as_bytes())
        }

        /// 推导与对端(base64 公钥)的共享密钥(共享点 X 坐标 32 字节)。
        pub fn derive_shared_secret(&self, peer_public_key: &str) -> Result<Vec<u8>, String> {
            use p256::elliptic_curve::sec1::{FromEncodedPoint as _, ToEncodedPoint as _};
            let bytes = from_hex_str(peer_public_key)?;
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
            use sha2::Digest as _;
            if plain.is_empty() || encrypted.is_empty() {
                return Err("密码或加密字符串不能为空".to_string());
            }
            let parts: Vec<&str> = encrypted.splitn(2, '$').collect();
            if parts.len() != 2 || parts[0] != "ecdh" {
                return Err("加密字符串格式无效".to_string());
            }
            let shared = self.derive_shared_secret(parts[1])?;
            let expected = Sha256::digest(&shared);
            let actual = Sha256::digest(plain.as_bytes());
            Ok(expected == actual)
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
        // 同一密码两次签名不同(随机数),但都能验证通过
        let sealed2 = algo.encrypt("my-password").unwrap();
        assert_ne!(sealed, sealed2);
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
        // alice 用 bob 的公钥封装密码
        let sealed = {
            let token = bob.encrypt("shared-secret").unwrap();
            // 替换公钥为 bob 的:encrypt 本身就返回自己公钥,直接用
            token
        };
        assert!(sealed.starts_with("ecdh$"));
        // bob 能验证自己签发的
        assert!(bob.verify("shared-secret", &sealed).unwrap());
        assert!(!bob.verify("other", &sealed).unwrap());

        // 跨方:alice 用 bob 公钥的 sealed 无法被 alice 验证(密钥不同)
        // 但 DeriveSharedSecret 双方一致
        let sa = alice.derive_shared_secret(&bob.pubkey_b64()).unwrap();
        let sb = bob.derive_shared_secret(&alice.pubkey_b64()).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 32);
    }
}
