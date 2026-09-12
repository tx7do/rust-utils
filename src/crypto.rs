//! 对称加密与哈希原语(移植自 go-utils/crypto 的 AES/HMAC/SHA 部分),
//! feature `crypto`。
//!
//! RSA / ECDSA / SM2/SM3/SM4 未移植;如需可接 RustCrypto 的
//! `rsa` / `p256` 等crate。
//!
//! ```
//! use rust_utils::crypto::{AesGcmCipher, Cipher};
//!
//! let key = AesGcmCipher::generate_key().unwrap();
//! let cipher = AesGcmCipher::new(key).unwrap();
//! let sealed = cipher.encrypt(b"attack at dawn").unwrap();
//! assert_ne!(sealed, b"attack at dawn");
//! assert_eq!(cipher.decrypt(&sealed).unwrap(), b"attack at dawn");
//! ```

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha2::{Digest, Sha256, Sha512};

/// 统一的对称加密接口。
pub trait Cipher {
    fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>, String>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String>;
    /// 算法名。
    fn name(&self) -> &'static str;
}

fn random_bytes(n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| format!("generate random failed: {e}"))?;
    Ok(buf)
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err("invalid hex string".to_string());
    }
    (0..b.len() / 2)
        .map(|i| {
            u8::from_str_radix(std::str::from_utf8(&b[i * 2..i * 2 + 2]).unwrap(), 16)
                .map_err(|e| format!("invalid hex string: {e}"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// PKCS#7(Go 语境下的 "PKCS5")填充
// ---------------------------------------------------------------------------

/// PKCS#7 填充(Go 版接口名为 PKCS5Padding,块大小由调用方给定)。
pub fn pkcs5_padding(plaintext: &[u8], block_size: usize) -> Vec<u8> {
    let pad = block_size - plaintext.len() % block_size;
    let mut out = plaintext.to_vec();
    out.extend(std::iter::repeat(pad as u8).take(pad));
    out
}

/// PKCS#7 去填充;非法填充报错。
pub fn pkcs5_un_padding(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let pad = *data.last().unwrap() as usize;
    if pad == 0 || pad > data.len() {
        return Err("invalid padding".to_string());
    }
    if data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err("invalid padding".to_string());
    }
    Ok(data[..data.len() - pad].to_vec())
}

// ---------------------------------------------------------------------------
// AES-CBC
// ---------------------------------------------------------------------------

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// AES-128-CBC,key 必须为 16 字节,iv 必须为 16 字节。
pub struct AesCipher {
    key: Vec<u8>,
    iv: [u8; 16],
}

impl AesCipher {
    /// `key` 16 字节,`iv` 16 字节。
    pub fn new(key: Vec<u8>, iv: [u8; 16]) -> Result<Self, String> {
        if key.len() != 16 {
            return Err("AES-128 key must be 16 bytes".to_string());
        }
        Ok(AesCipher { key, iv })
    }

    pub fn from_hex(key_hex: &str, iv_hex: &str) -> Result<Self, String> {
        let key = from_hex(key_hex)?;
        let iv_bytes = from_hex(iv_hex)?;
        let iv: [u8; 16] = iv_bytes
            .try_into()
            .map_err(|_| "iv must be 16 bytes".to_string())?;
        AesCipher::new(key, iv)
    }
}

impl Cipher for AesCipher {
    fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        // 预留一个完整块给填充
        let mut buf = vec![0u8; plain.len() + 16];
        buf[..plain.len()].copy_from_slice(plain);
        let out = Aes128CbcEnc::new_from_slices(&self.key, &self.iv)
            .map_err(|e| format!("bad key/iv: {e}"))?
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plain.len())
            .map_err(|e| format!("aes-cbc encrypt failed: {e}"))?;
        Ok(out.to_vec())
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.is_empty() || data.len() % 16 != 0 {
            return Err("ciphertext length must be a multiple of 16".to_string());
        }
        let mut buf = data.to_vec();
        let out = Aes128CbcDec::new_from_slices(&self.key, &self.iv)
            .map_err(|e| format!("bad key/iv: {e}"))?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| format!("aes-cbc decrypt failed: {e}"))?;
        Ok(out.to_vec())
    }

    fn name(&self) -> &'static str {
        "AES-128-CBC"
    }
}

// ---------------------------------------------------------------------------
// AES-GCM(随机 nonce 前置)
// ---------------------------------------------------------------------------

/// AES-256-GCM;加密时生成随机 12 字节 nonce 并前置到密文。
pub struct AesGcmCipher {
    key: Vec<u8>,
}

impl AesGcmCipher {
    /// `key` 必须为 16 或 32 字节。
    pub fn new(key: Vec<u8>) -> Result<Self, String> {
        if key.len() != 16 && key.len() != 32 {
            return Err("AES-GCM key must be 16 or 32 bytes".to_string());
        }
        Ok(AesGcmCipher { key })
    }

    /// 生成 32 字节随机密钥。
    pub fn generate_key() -> Result<Vec<u8>, String> {
        random_bytes(32)
    }

    pub fn encrypt_with_nonce(&self, plain: &[u8], nonce: [u8; 12]) -> Result<Vec<u8>, String> {
        use aes::cipher::KeyInit;
        use aes_gcm::aead::Aead;
        let result = if self.key.len() == 32 {
            let c = aes_gcm::Aes256Gcm::new_from_slice(&self.key)
                .map_err(|e| format!("bad key: {e}"))?;
            c.encrypt(&nonce.into(), plain)
        } else {
            let c = aes_gcm::Aes128Gcm::new_from_slice(&self.key)
                .map_err(|e| format!("bad key: {e}"))?;
            c.encrypt(&nonce.into(), plain)
        };
        result.map_err(|e| format!("aes-gcm encrypt failed: {e}"))
    }

    pub fn decrypt_with_nonce(&self, data: &[u8], nonce: [u8; 12]) -> Result<Vec<u8>, String> {
        use aes::cipher::KeyInit;
        use aes_gcm::aead::Aead;
        let result = if self.key.len() == 32 {
            let c = aes_gcm::Aes256Gcm::new_from_slice(&self.key)
                .map_err(|e| format!("bad key: {e}"))?;
            c.decrypt(&nonce.into(), data)
        } else {
            let c = aes_gcm::Aes128Gcm::new_from_slice(&self.key)
                .map_err(|e| format!("bad key: {e}"))?;
            c.decrypt(&nonce.into(), data)
        };
        result.map_err(|e| format!("aes-gcm decrypt failed: {e}"))
    }
}

impl Cipher for AesGcmCipher {
    fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        let nonce_bytes = random_bytes(12)?;
        let nonce: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| "nonce length".to_string())?;
        let mut sealed = self.encrypt_with_nonce(plain, nonce)?;
        let mut out = nonce.to_vec();
        out.append(&mut sealed);
        Ok(out)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 {
            return Err("ciphertext too short".to_string());
        }
        let (nonce, body) = data.split_at(12);
        self.decrypt_with_nonce(body, nonce.try_into().unwrap())
    }

    fn name(&self) -> &'static str {
        "AES-GCM"
    }
}

// ---------------------------------------------------------------------------
// HMAC 与 SHA
// ---------------------------------------------------------------------------

/// HMAC-SHA256。
pub struct Hmac {
    key: Vec<u8>,
}

impl Hmac {
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Hmac { key: key.into() }
    }

    /// 计算摘要(原始字节)。
    pub fn sum(&self, data: &[u8]) -> Vec<u8> {
        use hmac::Mac;
        let mut mac =
            <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(&self.key).expect("hmac key");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// 校验十六进制签名。
    pub fn verify(&self, data: &[u8], hex_sig: &str) -> bool {
        match from_hex(hex_sig) {
            Ok(sig) => self.sum(data) == sig,
            Err(_) => false,
        }
    }

    pub fn set_key(&mut self, key: impl Into<Vec<u8>>) {
        self.key = key.into();
    }
}

/// SHA-256 摘要。
pub fn sha256_sum(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-512 摘要。
pub fn sha512_sum(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs5_padding() {
        let padded = pkcs5_padding(b"abcd", 8);
        assert_eq!(padded, b"abcd\x04\x04\x04\x04");
        assert_eq!(pkcs5_un_padding(&padded).unwrap(), b"abcd");
        // 整块时补满块
        assert_eq!(pkcs5_padding(b"12345678", 8).len(), 16);
        assert!(pkcs5_un_padding(&[0, 0, 9]).is_err());
    }

    #[test]
    fn test_aes_cbc_roundtrip() {
        let key = vec![1u8; 16];
        let iv = [2u8; 16];
        let cipher = AesCipher::new(key, iv).unwrap();
        let plain = b"hello world, aes-cbc!!";
        let sealed = cipher.encrypt(plain).unwrap();
        assert_ne!(sealed, plain.to_vec());
        assert_eq!(sealed.len() % 16, 0);
        assert_eq!(cipher.decrypt(&sealed).unwrap(), plain.to_vec());
        assert!(AesCipher::new(vec![1; 15], [0; 16]).is_err());
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = AesGcmCipher::generate_key().unwrap();
        let cipher = AesGcmCipher::new(key).unwrap();
        let plain = b"attack at dawn";
        let sealed = cipher.encrypt(plain).unwrap();
        assert_eq!(sealed.len(), 12 + 14 + 16); // nonce + 明文 + tag
        assert_eq!(cipher.decrypt(&sealed).unwrap(), plain.to_vec());
        // 篡改检测
        let mut tampered = sealed.clone();
        tampered[13] ^= 0xff;
        assert!(cipher.decrypt(&tampered).is_err());
    }

    #[test]
    fn test_hmac_sha() {
        let mac = Hmac::new("secret");
        let sig = mac.sum(b"data");
        assert!(mac.verify(b"data", &to_hex(&sig)));
        assert!(!mac.verify(b"data2", &to_hex(&sig)));

        assert_eq!(
            to_hex(&sha256_sum(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha512_sum(b"abc").len(), 64);
    }
}
