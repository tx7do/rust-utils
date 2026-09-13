//! 国密算法(对应 Go 版 crypto 包的 SM2/SM3/SM4 部分),feature `sm`。
//!
//! 基于 `libsm` crate 提供 SM3 哈希与 SM4 分组密码(CBC 模式 +
//! PKCS#7 填充,在本模块内基于单块原语实现)。SM2 非对称算法暂未
//! 内置,需要时可直接依赖 `libsm` 的 `sm2` 模块。
//!
//! ```
//! use rust_utils::crypto::Cipher;
//! use rust_utils::sm::{sm3_sum, Sm4Cipher};
//!
//! assert_eq!(sm3_sum(b"abc").len(), 32);
//!
//! let key = [7u8; 16];
//! let iv = [9u8; 16];
//! let cipher = Sm4Cipher::new(&key, &iv);
//! let sealed = cipher.encrypt(b"sm4 secret data").unwrap();
//! assert_eq!(cipher.decrypt(&sealed).unwrap(), b"sm4 secret data");
//! ```

use crate::crypto::{pkcs5_padding, pkcs5_un_padding, Cipher};

/// SM3 摘要(32 字节,国标 GB/T 32905-2016)。
pub fn sm3_sum(data: &[u8]) -> [u8; 32] {
    let mut hasher = libsm::sm3::hash::Sm3Hash::new(data);
    hasher.get_hash()
}

/// SM4-CBC 加解密(单块原语之上实现 CBC 链接与 PKCS#7 填充,
/// 国标 GB/T 32907-2016)。
pub struct Sm4Cipher {
    key: [u8; 16],
    iv: [u8; 16],
}

impl Sm4Cipher {
    /// 创建 SM4-CBC 实例;`key` 与 `iv` 均须为 16 字节。
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Sm4Cipher { key: *key, iv: *iv }
    }
}

impl Cipher for Sm4Cipher {
    fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        let padded = pkcs5_padding(plain, 16);
        let cipher = libsm::sm4::cipher::Sm4Cipher::new(&self.key)
            .map_err(|e| format!("sm4 init failed: {e:?}"))?;
        let mut out = Vec::with_capacity(padded.len());
        let mut prev = self.iv;
        for block in padded.chunks_exact(16) {
            let mut input = [0u8; 16];
            for (i, b) in block.iter().enumerate() {
                input[i] = b ^ prev[i];
            }
            let encrypted = cipher
                .encrypt(&input)
                .map_err(|e| format!("sm4 encrypt failed: {e:?}"))?;
            out.extend_from_slice(&encrypted);
            prev = encrypted;
        }
        Ok(out)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.is_empty() || data.len() % 16 != 0 {
            return Err("ciphertext length must be a multiple of 16".to_string());
        }
        let cipher = libsm::sm4::cipher::Sm4Cipher::new(&self.key)
            .map_err(|e| format!("sm4 init failed: {e:?}"))?;
        let mut out = Vec::with_capacity(data.len());
        let mut prev = self.iv;
        for block in data.chunks_exact(16) {
            let decrypted = cipher
                .decrypt(block)
                .map_err(|e| format!("sm4 decrypt failed: {e:?}"))?;
            let mut plain = [0u8; 16];
            for (i, d) in decrypted.iter().enumerate() {
                plain[i] = d ^ prev[i];
            }
            out.extend_from_slice(&plain);
            prev.copy_from_slice(block);
        }
        pkcs5_un_padding(&out)
    }

    fn name(&self) -> &'static str {
        "SM4-CBC"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm3_known_vector() {
        // GB/T 32905-2016 标准测试向量 "abc"
        let sum = sm3_sum(b"abc");
        assert_eq!(
            sum.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
        // 空串
        let empty = sm3_sum(b"");
        assert_eq!(
            empty.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
        );
    }

    #[test]
    fn test_sm4_cbc_roundtrip() {
        let key = [
            0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let iv = [0u8; 16];
        let cipher = Sm4Cipher::new(&key, &iv);
        for plain in [
            b"16bytes-block!!".as_slice(),
            b"variable length data".as_slice(),
            b"".as_slice(),
        ] {
            let sealed = cipher.encrypt(plain).unwrap();
            if !plain.is_empty() {
                assert_eq!(sealed.len() % 16, 0);
                assert_ne!(sealed, plain.to_vec());
            }
            assert_eq!(cipher.decrypt(&sealed).unwrap(), plain.to_vec());
        }
        // 长度非法
        assert!(cipher.decrypt(&[0u8; 15]).is_err());
    }

    #[test]
    fn test_sm4_cbc_different_iv_differs() {
        let key = [3u8; 16];
        let c1 = Sm4Cipher::new(&key, &[1u8; 16]);
        let c2 = Sm4Cipher::new(&key, &[2u8; 16]);
        let sealed1 = c1.encrypt(b"same plaintext").unwrap();
        let sealed2 = c2.encrypt(b"same plaintext").unwrap();
        assert_ne!(sealed1, sealed2);
    }
}
