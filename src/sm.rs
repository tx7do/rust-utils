//! 国密算法(对应 Go 版 crypto 包的 SM2/SM3/SM4 部分),feature `sm`。
//!
//! 基于 `libsm` crate:SM3 哈希、SM4 分组密码(CBC 模式 + PKCS#7
//! 填充,在本模块内基于单块原语实现)、SM2 非对称加解密与签名
//! 验签([`Sm2Cipher`],加解密保持上游 gmsm 的 C1C3C2 拼接布局与
//! DER 包装格式,签名验签与上游 `SignDigitToSignData`/
//! `SignDataToSignDigit` 对应的 DER 形态一致)。
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

// ---------------------------------------------------------------------------
// SM2
// ---------------------------------------------------------------------------

use crate::base64util;
use libsm::sm2::ecc::Point;
use libsm::sm2::encrypt::{DecryptCtx, EncryptCtx};
use libsm::sm2::signature::{SigCtx, Signature};
use num_bigint::BigUint;

/// SM2 非对称加解密与签名验签(对应 Go 版 `SM2Cipher`,libsm 后端)。
///
/// 加解密维持上游 gmsm `Encrypt`/`Decrypt`(`C1C3C2` 模式)的拼接
/// 布局:`0x04 ‖ X ‖ Y ‖ C3 ‖ C2`(`X`/`Y` 为 32 字节大端,`C3`
/// 为 32 字节 SM3 摘要,`C2` 为密文)。`encrypt_asn1`/`decrypt_asn1`
/// 对应上游 `EncryptAsn1`/`DecryptAsn1`:同一数据的
/// `SEQUENCE { INTEGER x, INTEGER y, OCTET STRING hash, OCTET
/// STRING cipherText }` DER 包装(上游 `CipherMarshal`/
/// `CipherUnmarshal`)。签名验签经上游 `SignDigitToSignData`/
/// `SignDataToSignDigit` 对应的 DER 编解码,并以 base64 传输;
/// ZA 摘要使用上游默认 UID `1234567812345678`。
///
/// 仅适用于小数据块加密(如密钥交换),不适合大数据流;生产环境
/// 请妥善管理私钥。
///
/// ```
/// use rust_utils::crypto::Cipher;
/// use rust_utils::sm::Sm2Cipher;
///
/// let cipher = Sm2Cipher::new().unwrap();
/// let sealed = cipher.encrypt(b"hello, sm2 cipher test!").unwrap();
/// assert_eq!(cipher.decrypt(&sealed).unwrap(), b"hello, sm2 cipher test!");
/// ```
pub struct Sm2Cipher {
    sk: BigUint,
    pk: Point,
}

impl Sm2Cipher {
    /// 生成新密钥对(上游 `NewSM2Cipher`)。
    pub fn new() -> Result<Self, String> {
        let (pk, sk) = SigCtx::new()
            .new_keypair()
            .map_err(|e| format!("sm2 keygen failed: {e:?}"))?;
        Ok(Self { sk, pk })
    }

    /// 由序列化密钥对恢复(上游 `NewSM2CipherFromKey` 的字节形态;
    /// 私钥为大整数表示,公钥为 65 字节非压缩点)。
    pub fn from_keys(priv_bytes: &[u8], pub_bytes: &[u8]) -> Result<Self, String> {
        let ctx = SigCtx::new();
        let sk = ctx
            .load_seckey(priv_bytes)
            .map_err(|e| format!("sm2 load private key failed: {e:?}"))?;
        let pk = ctx
            .load_pubkey(pub_bytes)
            .map_err(|e| format!("sm2 load public key failed: {e:?}"))?;
        Ok(Self { sk, pk })
    }

    /// 公钥序列化(上游 `PublicKey()` 的导出形态;65 字节非压缩点)。
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, String> {
        SigCtx::new()
            .serialize_pubkey(&self.pk, false)
            .map_err(|e| format!("sm2 serialize public key failed: {e:?}"))
    }

    /// 私钥序列化(上游 `PrivateKey()`;仅用于安全存储,禁止对外泄露)。
    pub fn private_key_bytes(&self) -> Result<Vec<u8>, String> {
        SigCtx::new()
            .serialize_seckey(&self.sk)
            .map_err(|e| format!("sm2 serialize private key failed: {e:?}"))
    }

    /// ASN.1(DER)包装的加密(上游 `EncryptAsn1`)。
    pub fn encrypt_asn1(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        let raw = Cipher::encrypt(self, plain)?;
        cipher_marshal(&raw, plain.len())
    }

    /// ASN.1(DER)包装的解密(上游 `DecryptAsn1`)。
    pub fn decrypt_asn1(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let raw = cipher_unmarshal(data)?;
        Cipher::decrypt(self, &raw)
    }

    /// 签名(上游 `Sign`:DER 编码的 `r‖s`,base64 传输)。
    pub fn sign(&self, data: &[u8]) -> Result<String, String> {
        let sig = SigCtx::new()
            .sign(data, &self.sk, &self.pk)
            .map_err(|e| format!("sm2 sign failed: {e:?}"))?;
        Ok(base64util::encode(&sig.der_encode()))
    }

    /// 验签(上游 `Verify`)。
    pub fn verify(&self, data: &[u8], signature: &str) -> Result<bool, String> {
        let der = base64util::decode(signature)?;
        let sig = Signature::der_decode(&der)
            .map_err(|e| format!("sm2 signature decode failed: {e:?}"))?;
        SigCtx::new()
            .verify(data, &self.pk, &sig)
            .map_err(|e| format!("sm2 verify failed: {e:?}"))
    }
}

impl Cipher for Sm2Cipher {
    fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        let klen = plain.len();
        let raw = EncryptCtx::new(klen, self.pk)
            .encrypt(plain)
            .map_err(|e| format!("sm2 encrypt failed: {e:?}"))?;
        // libsm 布局(C1‖C2‖C3)→ 上游 C1C3C2 布局(C1‖C3‖C2)
        let mut out = Vec::with_capacity(raw.len());
        out.extend_from_slice(&raw[..65]);
        out.extend_from_slice(&raw[65 + klen..]);
        out.extend_from_slice(&raw[65..65 + klen]);
        Ok(out)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        // 上游 C1C3C2 布局 → libsm 布局
        if data.len() < 97 {
            return Err("sm2 invalid ciphertext length".to_string());
        }
        let klen = data.len() - 97;
        let mut raw = Vec::with_capacity(data.len());
        raw.extend_from_slice(&data[..65]);
        raw.extend_from_slice(&data[97..]);
        raw.extend_from_slice(&data[65..97]);
        DecryptCtx::new(klen, self.sk.clone())
            .decrypt(&raw)
            .map_err(|e| format!("sm2 decrypt failed: {e:?}"))
    }

    fn name(&self) -> &'static str {
        "SM2"
    }
}

/// 上游 `CipherMarshal`:C1C3C2 拼接布局 → DER
/// `SEQUENCE { INTEGER x, INTEGER y, OCTET STRING hash, OCTET STRING cipherText }`。
fn cipher_marshal(raw: &[u8], klen: usize) -> Result<Vec<u8>, String> {
    if raw.len() != 97 + klen {
        return Err("sm2 invalid ciphertext length".to_string());
    }
    let x = BigUint::from_bytes_be(&raw[1..33]);
    let y = BigUint::from_bytes_be(&raw[33..65]);
    let mut body = Vec::new();
    der_integer(&x, &mut body);
    der_integer(&y, &mut body);
    der_octet_string(&raw[65..97], &mut body);
    der_octet_string(&raw[97..], &mut body);
    let mut out = vec![0x30];
    der_length(body.len(), &mut out);
    out.extend_from_slice(&body);
    Ok(out)
}

/// 上游 `CipherUnmarshal`:DER 包装 → C1C3C2 拼接布局。
/// (上游对 X/Y 不补齐 32 字节,此处补齐以匹配原始布局。)
fn cipher_unmarshal(der: &[u8]) -> Result<Vec<u8>, String> {
    let mut outer = 0usize;
    let seq = parse_tlv(der, &mut outer, 0x30)?; // 外层 SEQUENCE
    let mut pos = 0usize;
    let x = parse_integer(seq, &mut pos)?;
    let y = parse_integer(seq, &mut pos)?;
    let hash = parse_octet_string(seq, &mut pos)?;
    let cipher_text = parse_octet_string(seq, &mut pos)?;
    if outer != der.len() || pos != seq.len() || hash.len() != 32 {
        return Err("sm2 invalid asn.1 ciphertext".to_string());
    }
    let mut out = Vec::with_capacity(97 + cipher_text.len());
    out.push(0x04);
    out.extend_from_slice(&padded32(&x)?);
    out.extend_from_slice(&padded32(&y)?);
    out.extend_from_slice(hash);
    out.extend_from_slice(cipher_text);
    Ok(out)
}

/// 大整数按 32 字节大端前导补零(超长视为非法)。
fn padded32(v: &BigUint) -> Result<[u8; 32], String> {
    let bytes = v.to_bytes_be();
    if bytes.len() > 32 {
        return Err("sm2 invalid asn.1 integer".to_string());
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

fn der_integer(v: &BigUint, out: &mut Vec<u8>) {
    let mut bytes = v.to_bytes_be();
    if bytes.first().is_some_and(|b| *b & 0x80 != 0) {
        bytes.insert(0, 0);
    } else if bytes.is_empty() {
        bytes.push(0);
    }
    out.push(0x02);
    der_length(bytes.len(), out);
    out.extend_from_slice(&bytes);
}

fn der_octet_string(data: &[u8], out: &mut Vec<u8>) {
    out.push(0x04);
    der_length(data.len(), out);
    out.extend_from_slice(data);
}

fn der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
}

fn parse_integer(buf: &[u8], pos: &mut usize) -> Result<BigUint, String> {
    let body = parse_tlv(buf, pos, 0x02)?;
    Ok(BigUint::from_bytes_be(body))
}

fn parse_octet_string<'a>(buf: &'a [u8], pos: &mut usize) -> Result<&'a [u8], String> {
    parse_tlv(buf, pos, 0x04)
}

fn parse_tlv<'a>(buf: &'a [u8], pos: &mut usize, tag: u8) -> Result<&'a [u8], String> {
    if *pos + 2 > buf.len() || buf[*pos] != tag {
        return Err("sm2 invalid asn.1 structure".to_string());
    }
    let mut idx = *pos + 1;
    let mut len = buf[idx] as usize;
    idx += 1;
    if len == 0x81 {
        if idx >= buf.len() {
            return Err("sm2 invalid asn.1 length".to_string());
        }
        len = buf[idx] as usize;
        idx += 1;
    } else if len == 0x82 {
        if idx + 1 >= buf.len() {
            return Err("sm2 invalid asn.1 length".to_string());
        }
        len = (buf[idx] as usize) << 8 | buf[idx + 1] as usize;
        idx += 2;
    } else if len >= 0x80 {
        return Err("sm2 invalid asn.1 length".to_string());
    }
    if idx + len > buf.len() {
        return Err("sm2 invalid asn.1 length".to_string());
    }
    let out = &buf[idx..idx + len];
    *pos = idx + len;
    Ok(out)
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

    // ---------- SM2 ----------

    #[test]
    fn test_sm2_encrypt_decrypt_roundtrip() {
        // 上游 TestSM2Cipher_EncryptDecrypt
        let cipher = super::Sm2Cipher::new().unwrap();
        for plain in [
            b"hello, sm2 cipher test!".as_slice(),
            b"0123456789abcdef0123456789abcdef",
            b"x".as_slice(),
        ] {
            let sealed = cipher.encrypt(plain).unwrap();
            // 上游 C1C3C2 拼接布局:0x04 ‖ X(32) ‖ Y(32) ‖ C3(32) ‖ C2
            assert_eq!(sealed.len(), 97 + plain.len());
            assert_eq!(sealed[0], 0x04);
            assert_ne!(&sealed[97..], plain);
            assert_eq!(cipher.decrypt(&sealed).unwrap(), plain);
        }
        // 非法长度
        assert!(cipher.decrypt(&[0u8; 96]).is_err());
        assert!(cipher.decrypt(&[4u8; 97]).is_err());
    }

    #[test]
    fn test_sm2_encrypt_decrypt_asn1_roundtrip() {
        // 上游 TestSM2Cipher_EncryptDecryptAsn1
        let cipher = super::Sm2Cipher::new().unwrap();
        let plain = b"hello, sm2 asn1 test!".to_vec();
        let sealed = cipher.encrypt_asn1(&plain).unwrap();
        assert_eq!(sealed[0], 0x30); // DER SEQUENCE
        assert_ne!(&sealed, &plain);
        assert_eq!(cipher.decrypt_asn1(&sealed).unwrap(), plain);
        // 任意字节篡改均应失败(解析失败或 C3 哈希不符)
        for i in [0usize, 1, sealed.len() / 2, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert!(cipher.decrypt_asn1(&tampered).is_err());
        }
        // 非 DER 输入
        assert!(cipher.decrypt_asn1(b"garbage").is_err());
        assert!(cipher.decrypt_asn1(&[]).is_err());
    }

    #[test]
    fn test_sm2_sign_verify() {
        // 上游 TestSM2Cipher_SignVerify
        let cipher = super::Sm2Cipher::new().unwrap();
        let data = b"hello, sm2 sign test!";
        let sig = cipher.sign(data).unwrap();
        assert!(cipher.verify(data, &sig).unwrap());
        // 篡改数据 / 换密钥 → false
        assert!(!cipher.verify(b"tampered", &sig).unwrap());
        let other = super::Sm2Cipher::new().unwrap();
        assert!(!other.verify(data, &sig).unwrap());
        // 非 base64 签名 → Err
        assert!(cipher.verify(data, "!!!not-base64!!!").is_err());
    }

    #[test]
    fn test_sm2_from_keys_roundtrip() {
        let a = super::Sm2Cipher::new().unwrap();
        let priv_bytes = a.private_key_bytes().unwrap();
        let pub_bytes = a.public_key_bytes().unwrap();
        let b = super::Sm2Cipher::from_keys(&priv_bytes, &pub_bytes).unwrap();
        // 同一密钥的两实例互解
        let sealed = b.encrypt(b"cross-instance").unwrap();
        assert_eq!(a.decrypt(&sealed).unwrap(), b"cross-instance");
        // 非法密钥材料
        assert!(super::Sm2Cipher::from_keys(&[0u8; 3], &[0u8; 3]).is_err());
    }
}
