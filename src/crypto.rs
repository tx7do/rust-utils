//! 对称加密与哈希原语,feature `crypto`。
//!
//! 覆盖 AES-CBC / AES-GCM / HMAC-SHA256 / SHA-2 / RSA / ECDSA / ECDH;
//! 应用层门面:[`Encryptor`](`enc:` 前缀 AES-256-GCM)、全局单例、
//! payload 整包加密信封、HMAC 数据签名;国密 SM2/SM3/SM4 由 `sm`
//! 模块(feature `sm`)提供。
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
// PKCS#7 填充
// ---------------------------------------------------------------------------

/// PKCS#7 填充(块大小由调用方给定)。
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

// ---------------------------------------------------------------------------
// base64(标准字母表,带填充)—— RSA/ECDSA 输出格式需要
// ---------------------------------------------------------------------------

pub use crate::base64util::{decode as from_base64, encode as to_base64};

// ---------------------------------------------------------------------------
// RSA(RSA-OAEP-SHA256,PEM 导出)
// ---------------------------------------------------------------------------

/// RSA 密钥对:公钥加密 / 私钥解密(RSA-OAEP-SHA256 填充)。
pub struct RsaCipher {
    private: rsa::RsaPrivateKey,
}

impl RsaCipher {
    /// 生成新的 RSA 密钥对(如 `bits = 2048`;密钥生成可能需要数百毫秒)。
    pub fn new(bits: usize) -> Result<Self, String> {
        let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits)
            .map_err(|e| format!("rsa keygen failed: {e}"))?;
        Ok(RsaCipher { private })
    }

    /// 公钥加密(RSA-OAEP-SHA256)。
    pub fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        let pub_key = rsa::RsaPublicKey::from(&self.private);
        pub_key
            .encrypt(
                &mut rsa::rand_core::OsRng,
                rsa::Oaep::new::<Sha256>(),
                plain,
            )
            .map_err(|e| format!("rsa encrypt failed: {e}"))
    }

    /// 私钥解密(RSA-OAEP-SHA256)。
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.private
            .decrypt(rsa::Oaep::new::<Sha256>(), data)
            .map_err(|e| format!("rsa decrypt failed: {e}"))
    }

    /// 导出私钥 PKCS#1 PEM(`RSA PRIVATE KEY` 标签)。
    pub fn export_private_key_pem(&self) -> Result<String, String> {
        use rsa::pkcs1::EncodeRsaPrivateKey as _;
        self.private
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map(|p| p.to_string())
            .map_err(|e| format!("export private key failed: {e}"))
    }

    /// 导出公钥 SPKI PEM(PEM 标签改写为 `RSA PUBLIC KEY`)。
    pub fn export_public_key_pem(&self) -> Result<String, String> {
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

    /// 算法名。
    pub fn name(&self) -> &'static str {
        "RSA"
    }
}

// ---------------------------------------------------------------------------
// ECDSA P-256(签名/验签,签名为 `base64(r)$base64(s)` 格式)
// ---------------------------------------------------------------------------

/// ECDSA P-256 数字签名。
pub struct EcdsaCipher {
    signing: Option<p256::ecdsa::SigningKey>,
    verifying: p256::ecdsa::VerifyingKey,
}

impl Default for EcdsaCipher {
    fn default() -> Self {
        Self::new().expect("p256 keygen")
    }
}

impl EcdsaCipher {
    /// 生成新的 P-256 密钥对。
    pub fn new() -> Result<Self, String> {
        let signing = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let verifying = *signing.verifying_key();
        Ok(EcdsaCipher {
            signing: Some(signing),
            verifying,
        })
    }

    /// 从 SEC1 非压缩公钥构造仅验签的实例:可验任意持私钥方的签名,
    /// [`EcdsaCipher::sign`] 返回 Err。
    pub fn from_public_key_bytes(public_key: &[u8]) -> Result<Self, String> {
        let point = p256::EncodedPoint::from_bytes(public_key)
            .map_err(|e| format!("ecdsa public key: {e}"))?;
        let verifying = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
            .map_err(|_| "ecdsa public key: invalid point".to_string())?;
        Ok(EcdsaCipher {
            signing: None,
            verifying,
        })
    }

    /// 签名,输出 `base64(r)$base64(s)`(r/s 固定 32 字节)。
    /// 仅验签构造的实例无私钥,返回 Err。
    pub fn sign(&self, data: &[u8]) -> Result<String, String> {
        use p256::ecdsa::signature::Signer;
        let signing = self.signing.as_ref().ok_or("no signing key")?;
        let sig: p256::ecdsa::Signature = signing.sign(data);
        let bytes = sig.to_bytes();
        Ok(format!(
            "{}${}",
            to_base64(&bytes[..32]),
            to_base64(&bytes[32..])
        ))
    }

    /// 验签;r/s 分量不足 32 字节时左侧补零,故去零的变长格式同样接受。
    pub fn verify(&self, data: &[u8], signature: &str) -> Result<bool, String> {
        use p256::ecdsa::signature::Verifier;
        let parts: Vec<&str> = signature.split('$').collect();
        if parts.len() != 2 {
            return Err("invalid signature format".to_string());
        }
        let r = pad32(&from_base64(parts[0])?)?;
        let s = pad32(&from_base64(parts[1])?)?;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r);
        sig[32..].copy_from_slice(&s);
        let sig = p256::ecdsa::Signature::from_slice(&sig)
            .map_err(|e| format!("invalid signature: {e}"))?;
        Ok(self.verifying.verify(data, &sig).is_ok())
    }

    /// 公钥 SEC1 非压缩编码(65 字节,`04 || X || Y`)。
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying.to_encoded_point(false).as_bytes().to_vec()
    }

    /// 算法名。
    pub fn name(&self) -> &'static str {
        "ECDSA"
    }
}

fn pad32(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() > 32 {
        return Err("signature component too long".to_string());
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// ECDH P-256(密钥协商)
// ---------------------------------------------------------------------------

/// ECDH P-256 密钥协商:双方交换公钥后各自推导出相同的共享密钥。
pub struct EcdhCipher {
    secret: p256::SecretKey,
}

impl Default for EcdhCipher {
    fn default() -> Self {
        Self::new().expect("p256 keygen")
    }
}

impl EcdhCipher {
    /// 生成新的 P-256 密钥对。
    pub fn new() -> Result<Self, String> {
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        Ok(EcdhCipher { secret })
    }

    /// 本方公钥 SEC1 非压缩编码(65 字节)。
    pub fn public_key_bytes(&self) -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        self.secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// 用对端公钥推导共享密钥(固定 32 字节,即共享点的 X 坐标)。
    pub fn derive_shared_secret(&self, peer_pub_bytes: &[u8]) -> Result<Vec<u8>, String> {
        use p256::elliptic_curve::sec1::FromEncodedPoint as _;
        let point = p256::EncodedPoint::from_bytes(peer_pub_bytes)
            .map_err(|e| format!("ecdh public key: {e}"))?;
        let peer = p256::PublicKey::from_encoded_point(&point)
            .into_option()
            .ok_or("ecdh public key: invalid point")?;
        let shared = p256::elliptic_curve::ecdh::diffie_hellman(
            self.secret.to_nonzero_scalar(),
            peer.as_affine(),
        );
        Ok(shared.raw_secret_bytes().to_vec())
    }

    /// 算法名。
    pub fn name(&self) -> &'static str {
        "ECDH"
    }
}

// ---------------------------------------------------------------------------
// 应用层加密门面:Encryptor / 全局单例 / payload 信封 / 数据签名
// ---------------------------------------------------------------------------

/// 密文前缀:`enc:`。带此前缀的字符串视为 [`Encryptor`] 密文。
pub const ENCRYPTED_PREFIX: &str = "enc:";

/// payload 信封:整包 JSON 加密后存放的键。
pub const ENCRYPTED_CONFIG_KEY: &str = "_encrypted_config";
/// payload 信封:是否已加密的标记键。
pub const IS_ENCRYPTED_KEY: &str = "_is_encrypted";

/// AES-256-GCM 应用层加密器:任意长度口令经 SHA-256 派生 32 字节密钥,
/// 输出 `enc:` + base64(nonce ‖ ciphertext ‖ tag)。
/// 未带前缀的输入在解密时原样返回(向后兼容明文)。
pub struct Encryptor {
    /// `None` 表示未启用(直通模式, encrypt/decrypt 原样返回)。
    key: Option<[u8; 32]>,
}

impl Encryptor {
    /// 以口令构造加密器(任意长度非空口令,SHA-256 派生密钥)。
    pub fn new(key: &str) -> Result<Self, String> {
        if key.is_empty() {
            return Err("invalid key: empty".to_string());
        }
        Ok(Encryptor {
            key: Some(Sha256::digest(key.as_bytes()).into()),
        })
    }

    /// 未启用的直通加密器(仅供全局单例在 disabled 时使用)。
    fn disabled() -> Self {
        Encryptor { key: None }
    }

    fn gcm(&self) -> Result<aes_gcm::Aes256Gcm, String> {
        use aes_gcm::KeyInit as _;
        let key = self.key.as_ref().ok_or("encryptor disabled")?;
        aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|e| format!("init gcm: {e}"))
    }

    /// 加密:空串原样返回;输出 `enc:` + base64(12 字节 nonce ‖ 密文含 tag)。
    pub fn encrypt(&self, plaintext: &str) -> Result<String, String> {
        use aes_gcm::aead::Aead;
        if plaintext.is_empty() {
            return Ok(String::new());
        }
        let Some(_) = self.key else {
            return Ok(plaintext.to_string());
        };
        let cipher = self.gcm()?;
        let nonce_bytes = random_bytes(12)?;
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| format!("encrypt: {e}"))?;
        let mut data = nonce.to_vec();
        data.extend(ciphertext);
        Ok(format!("{}{}", ENCRYPTED_PREFIX, to_base64(&data)))
    }

    /// 解密:空串或未带 `enc:` 前缀的输入原样返回(明文直通);
    /// 带前缀但解不开则报错。
    pub fn decrypt(&self, ciphertext: &str) -> Result<String, String> {
        use aes_gcm::aead::Aead;
        if ciphertext.is_empty() {
            return Ok(String::new());
        }
        let Some(_) = self.key else {
            return Ok(ciphertext.to_string());
        };
        let Some(encoded) = ciphertext.strip_prefix(ENCRYPTED_PREFIX) else {
            return Ok(ciphertext.to_string());
        };
        let data =
            from_base64(encoded).map_err(|_| "invalid ciphertext: bad base64".to_string())?;
        if data.len() < 12 {
            return Err("invalid ciphertext: too short".to_string());
        }
        let (nonce, body) = data.split_at(12);
        let cipher = self.gcm()?;
        let plain = cipher
            .decrypt(aes_gcm::Nonce::from_slice(nonce), body)
            .map_err(|_| "decryption failed".to_string())?;
        String::from_utf8(plain).map_err(|_| "decrypted bytes are not utf-8".to_string())
    }

    /// 便捷加密,失败即 panic(测试/脚本用)。
    pub fn must_encrypt(&self, plaintext: &str) -> String {
        self.encrypt(plaintext).expect("must_encrypt")
    }

    /// 便捷解密,失败即 panic(测试/脚本用)。
    pub fn must_decrypt(&self, ciphertext: &str) -> String {
        self.decrypt(ciphertext).expect("must_decrypt")
    }
}

/// 判断字符串是否为 [`Encryptor`] 密文(带 `enc:` 前缀)。
pub fn is_encrypted(data: &str) -> bool {
    data.starts_with(ENCRYPTED_PREFIX)
}

static GLOBAL_ENCRYPTOR: std::sync::OnceLock<Encryptor> = std::sync::OnceLock::new();
static NOOP_ENCRYPTOR: Encryptor = Encryptor { key: None };

/// 初始化全局加密器。进程内首次调用生效,后续调用为 no-op
/// (对齐上游 `sync.Once` 语义);`enabled=false` 时安装直通加密器。
pub fn init_global_encryptor(key: &str, enabled: bool) -> Result<(), String> {
    if GLOBAL_ENCRYPTOR.get().is_some() {
        return Ok(());
    }
    let encryptor = if enabled {
        Encryptor::new(key)?
    } else {
        Encryptor::disabled()
    };
    let _ = GLOBAL_ENCRYPTOR.set(encryptor);
    Ok(())
}

/// 取全局加密器;未初始化时返回直通实例。
pub fn get_global_encryptor() -> &'static Encryptor {
    GLOBAL_ENCRYPTOR.get().unwrap_or(&NOOP_ENCRYPTOR)
}

/// 未启用加密时原样返回,否则加密。
pub fn encrypt_if_needed(plaintext: &str) -> Result<String, String> {
    get_global_encryptor().encrypt(plaintext)
}

/// 未启用加密时原样返回,否则解密(明文无前缀同样原样返回)。
pub fn decrypt_if_needed(ciphertext: &str) -> Result<String, String> {
    get_global_encryptor().decrypt(ciphertext)
}

/// 用全局加密器密钥对 data 计算 HMAC-SHA256 签名(hex 编码)。
/// 全局加密器未配置(直通)时返回错误——签名能力不可用,调用方应拒绝
/// 生成签名 URL 而非降级为无签名。
pub fn sign_data(data: &str) -> Result<String, String> {
    let key = get_global_encryptor()
        .key
        .ok_or("global encryptor is not initialized: signing unavailable")?;
    use hmac::Mac as _;
    let mut mac = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(&key)
        .expect("hmac accepts any key length");
    mac.update(data.as_bytes());
    Ok(to_hex(&mac.finalize().into_bytes()))
}

/// 校验 [`sign_data`] 生成的签名(密钥缺失时恒 false;字节级常量时间比较)。
pub fn verify_data(data: &str, signature: &str) -> bool {
    use hmac::Mac as _;
    let Some(key) = get_global_encryptor().key else {
        return false;
    };
    let Ok(sig) = from_hex(signature) else {
        return false;
    };
    let mut mac = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(&key)
        .expect("hmac accepts any key length");
    mac.update(data.as_bytes());
    mac.verify_slice(&sig).is_ok()
}

/// 整包加密:payload 序列化为 JSON 后经 [`encrypt_if_needed`] 加密,
/// 返回 `{_encrypted_config: 密文, _is_encrypted: 是否真加密}`,
/// `reserved_keys` 声明的键以明文复制到外层供路由/调度层免解密读取。
///
/// 安全契约:仅当真完成加密时才置 `_is_encrypted = true`;全局加密器
/// 未配置时保持明文且不标记,避免解密侧误判。
pub fn encrypt_payload(
    payload: serde_json::Map<String, serde_json::Value>,
    reserved_keys: &[&str],
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let plain = serde_json::to_string(&payload).map_err(|e| format!("marshal payload: {e}"))?;
    let encrypted = encrypt_if_needed(&plain).map_err(|e| format!("encrypt payload: {e}"))?;

    let mut result = serde_json::Map::new();
    result.insert(
        ENCRYPTED_CONFIG_KEY.to_string(),
        serde_json::Value::String(encrypted.clone()),
    );
    result.insert(
        IS_ENCRYPTED_KEY.to_string(),
        serde_json::Value::Bool(encrypted != plain),
    );
    for key in reserved_keys {
        if let Some(v) = payload.get(*key) {
            result.insert((*key).to_string(), v.clone());
        }
    }
    Ok(result)
}

/// 整包解密:检测 `_is_encrypted` 标记,未加密原样返回(向后兼容明文)。
pub fn decrypt_payload(
    payload: serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let is_encrypted = matches!(
        payload.get(IS_ENCRYPTED_KEY),
        Some(serde_json::Value::Bool(true))
    );
    if !is_encrypted {
        return Ok(payload);
    }
    let encrypted = match payload.get(ENCRYPTED_CONFIG_KEY) {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return Err("encrypted config not found or invalid type".to_string()),
    };
    let decrypted = decrypt_if_needed(&encrypted).map_err(|e| format!("decrypt payload: {e}"))?;
    serde_json::from_str(&decrypted).map_err(|e| format!("unmarshal decrypted payload: {e}"))
}

/// payload 是否含已加密配置。
pub fn has_encrypted_payload(payload: &serde_json::Map<String, serde_json::Value>) -> bool {
    matches!(
        payload.get(IS_ENCRYPTED_KEY),
        Some(serde_json::Value::Bool(true))
    )
}

/// [`encrypt_payload`] 的 panic 变体(测试用)。
pub fn must_encrypt_payload(
    payload: serde_json::Map<String, serde_json::Value>,
    reserved_keys: &[&str],
) -> serde_json::Map<String, serde_json::Value> {
    encrypt_payload(payload, reserved_keys).expect("must_encrypt_payload")
}

/// [`decrypt_payload`] 的 panic 变体(测试用)。
pub fn must_decrypt_payload(
    payload: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    decrypt_payload(payload).expect("must_decrypt_payload")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryptor_round_trip() {
        let enc = Encryptor::new("my-secret-key").unwrap();
        assert!(Encryptor::new("").is_err());

        let sealed = enc.encrypt("hello world").unwrap();
        assert!(sealed.starts_with(ENCRYPTED_PREFIX));
        assert!(is_encrypted(&sealed));
        assert_eq!(enc.decrypt(&sealed).unwrap(), "hello world");
        // 空串原样往返;明文无前缀解密直通
        assert_eq!(enc.encrypt("").unwrap(), "");
        assert_eq!(enc.decrypt("plain-text").unwrap(), "plain-text");
        assert!(!is_encrypted("plain-text"));
        // 带前缀但内容损坏 → 报错
        assert!(enc
            .decrypt(&format!("{}{}", ENCRYPTED_PREFIX, "!!!"))
            .is_err());
        // 随机 nonce:同一明文两次密文不同
        assert_ne!(enc.encrypt("x").unwrap(), enc.encrypt("x").unwrap());
    }

    #[test]
    fn test_encryptor_disabled_passthrough() {
        let enc = Encryptor::disabled();
        assert_eq!(enc.encrypt("plain").unwrap(), "plain");
        assert_eq!(enc.decrypt("plain").unwrap(), "plain");
        assert_eq!(enc.must_encrypt("x"), "x");
    }

    #[test]
    fn test_global_encryptor_and_payload() {
        // 未初始化:直通,payload 不标记加密,签名不可用
        assert_eq!(encrypt_if_needed("raw").unwrap(), "raw");
        assert_eq!(decrypt_if_needed("raw").unwrap(), "raw");
        assert!(sign_data("x").is_err());
        assert!(!verify_data("x", "00"));

        let payload = serde_json::Map::from_iter([
            ("config".to_string(), serde_json::json!({"a": 1})),
            ("task_id".to_string(), serde_json::json!("t-1")),
        ]);
        let sealed = encrypt_payload(payload.clone(), &["task_id"]).unwrap();
        assert!(!has_encrypted_payload(&sealed));
        assert_eq!(sealed.get("task_id"), payload.get("task_id"));
        // 未加密:信封原样往返(不解包为原始 payload)
        let sealed_clone = sealed.clone();
        let back = decrypt_payload(sealed).unwrap();
        assert_eq!(back, sealed_clone);

        // 初始化后:真加密 + 标记 + 签名可用;重复初始化为 no-op(不覆盖已有实例)
        init_global_encryptor("global-key", true).unwrap();
        init_global_encryptor("other-key", true).unwrap();
        let sealed = encrypt_payload(payload.clone(), &["task_id"]).unwrap();
        assert!(has_encrypted_payload(&sealed));
        let plain_json = serde_json::to_string(&payload).unwrap();
        assert_ne!(
            sealed.get("_encrypted_config").unwrap(),
            &serde_json::json!(plain_json)
        );
        let back = decrypt_payload(sealed).unwrap();
        assert_eq!(back, payload);

        let sig = sign_data("signed-url").unwrap();
        assert!(verify_data("signed-url", &sig));
        assert!(!verify_data("tampered", &sig));
        assert!(!verify_data("signed-url", "zz"));

        // must 系列往返
        let sealed2 = must_encrypt_payload(payload.clone(), &[]);
        assert_eq!(must_decrypt_payload(sealed2), payload);
    }

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
    fn test_aes_cbc_from_hex() {
        let key_hex = "000102030405060708090a0b0c0d0e0f";
        let iv_hex = "101112131415161718191a1b1c1d1e1f";
        let cipher = AesCipher::from_hex(key_hex, iv_hex).unwrap();
        let sealed = cipher.encrypt(b"hex key").unwrap();
        assert_eq!(cipher.decrypt(&sealed).unwrap(), b"hex key");
        // 非法十六进制 / 错误长度
        assert!(AesCipher::from_hex("zz", iv_hex).is_err());
        assert!(AesCipher::from_hex("00", iv_hex).is_err());
    }

    #[test]
    fn test_hmac_set_key() {
        let mut mac = Hmac::new("key-one");
        let sig1 = to_hex(&mac.sum(b"data"));
        mac.set_key("key-two");
        let sig2 = to_hex(&mac.sum(b"data"));
        assert_ne!(sig1, sig2);
        assert!(mac.verify(b"data", &sig2));
        assert!(!mac.verify(b"data", &sig1));
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
    #[test]
    fn test_base64() {
        assert_eq!(to_base64(b"hello"), "aGVsbG8=");
        assert_eq!(from_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(to_base64(b"ab"), "YWI=");
        assert_eq!(from_base64("YWI=").unwrap(), b"ab");
        assert_eq!(to_base64(b"a"), "YQ==");
        assert_eq!(from_base64("YQ==").unwrap(), b"a");
        assert_eq!(to_base64(b""), "");
        assert_eq!(from_base64("").unwrap(), b"");
        assert!(from_base64("a!c=").is_err());
    }

    #[test]
    fn test_rsa_roundtrip() {
        let cipher = RsaCipher::new(2048).unwrap();
        let plain = b"rsa secret payload";
        let sealed = cipher.encrypt(plain).unwrap();
        assert_ne!(sealed, plain.to_vec());
        assert_eq!(cipher.decrypt(&sealed).unwrap(), plain.to_vec());
        assert_eq!(cipher.name(), "RSA");

        let priv_pem = cipher.export_private_key_pem().unwrap();
        let pub_pem = cipher.export_public_key_pem().unwrap();
        assert!(priv_pem.contains("BEGIN RSA PRIVATE KEY"));
        assert!(pub_pem.contains("BEGIN RSA PUBLIC KEY"));
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        let cipher = EcdsaCipher::new().unwrap();
        let sig = cipher.sign(b"signed message").unwrap();
        assert!(sig.contains('$'));
        assert!(cipher.verify(b"signed message", &sig).unwrap());
        assert!(!cipher.verify(b"tampered message", &sig).unwrap());
        assert!(cipher.verify(b"x", "bad-format").is_err());
        assert_eq!(cipher.public_key_bytes().len(), 65);
        assert_eq!(cipher.public_key_bytes()[0], 0x04);
    }

    #[test]
    fn test_ecdsa_verify_only_from_public_key() {
        let signer = EcdsaCipher::new().unwrap();
        // 公钥构造的仅验签实例可验持私钥方的签名,自身不可签名
        let verifier = EcdsaCipher::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let sig = signer.sign(b"cross verify").unwrap();
        assert!(verifier.verify(b"cross verify", &sig).unwrap());
        assert!(!verifier.verify(b"other payload", &sig).unwrap());
        assert!(verifier.sign(b"cross verify").is_err());
        // 公钥往返:再次构造行为一致
        let verifier2 = EcdsaCipher::from_public_key_bytes(&verifier.public_key_bytes()).unwrap();
        assert!(verifier2.verify(b"cross verify", &sig).unwrap());
        // 坏公钥拒绝
        assert!(EcdsaCipher::from_public_key_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_ecdh_shared_secret() {
        let a = EcdhCipher::new().unwrap();
        let b = EcdhCipher::new().unwrap();
        let secret_a = a.derive_shared_secret(&b.public_key_bytes()).unwrap();
        let secret_b = b.derive_shared_secret(&a.public_key_bytes()).unwrap();
        assert_eq!(secret_a, secret_b);
        assert_eq!(secret_a.len(), 32);
        assert!(a.derive_shared_secret(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_aes_gcm_with_nonce() {
        // 指定 nonce:同一密钥 + nonce 加密结果是确定性的
        let nonce = [7u8; 12];
        let plain = b"deterministic payload";
        for key_len in [16, 32] {
            let key = vec![0x42u8; key_len];
            let cipher = AesGcmCipher::new(key).unwrap();
            let c1 = cipher.encrypt_with_nonce(plain, nonce).unwrap();
            let c2 = cipher.encrypt_with_nonce(plain, nonce).unwrap();
            assert_eq!(c1, c2, "key_len: {key_len}");
            assert_eq!(
                cipher.decrypt_with_nonce(&c1, nonce).unwrap(),
                plain.to_vec()
            );
            // 密文长度 = 明文 + 16 字节 GCM tag
            assert_eq!(c1.len(), plain.len() + 16);
            // 换 nonce 解密失败(认证校验不过)
            assert!(cipher.decrypt_with_nonce(&c1, [8u8; 12]).is_err());
        }
        // 不同 nonce 产生不同密文
        let cipher = AesGcmCipher::new(vec![1u8; 32]).unwrap();
        assert_ne!(
            cipher.encrypt_with_nonce(plain, [1u8; 12]).unwrap(),
            cipher.encrypt_with_nonce(plain, [2u8; 12]).unwrap()
        );
    }
}

// —— 口令传输混合信封（P1-12，上游 go-utils/crypto EnvelopeCodec 同构）——
//
// 前端以随机 AES-256-GCM 会话密钥加密口令，再用 RSA-2048 OAEP(SHA-256) 包裹
// 会话密钥，信封格式：
//
//     "rsa-v1:<base64(wrappedKey)>:<base64(nonce)>:<base64(cipher)>"
//
// 公钥静态内置前端（公开值不降低安全性，无分发/替换通道），私钥仅服务端持有；
// 部署契约（私钥装载/env 覆盖/dev 默认对、旧形态过渡兼容的统一分发入口）
// 归应用侧——本模块只锁格式本体。格式由裸原语测试锁定。

use base64::Engine as _;

/// 信封格式版本前缀。
pub const ENVELOPE_PREFIX: &str = "rsa-v1:";

/// 口令传输混合信封编解码。
pub struct PasswordEnvelope;

impl PasswordEnvelope {
    /// 信封加密（服务端参考实现/单测/运维工具用；前端在 WebCrypto 里独立
    /// 实现同格式：RSA-OAEP(SHA-256) 包裹 AES-256-GCM 密钥）。加密走密钥对的
    /// 公钥半。
    pub fn encrypt(key: &RsaCipher, plain: &str) -> Result<String, String> {
        let mut session = [0u8; 32];
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut session).map_err(|e| e.to_string())?;
        getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
        let gcm = AesGcmCipher::new(session.to_vec())?;
        let cipher = gcm.encrypt_with_nonce(plain.as_bytes(), nonce)?;
        let wrapped = key
            .encrypt(&session)
            .map_err(|e| format!("envelope wrap: {e}"))?;
        Ok(format!(
            "{ENVELOPE_PREFIX}{}:{}:{}",
            base64::engine::general_purpose::STANDARD.encode(&wrapped),
            base64::engine::general_purpose::STANDARD.encode(nonce),
            base64::engine::general_purpose::STANDARD.encode(&cipher),
        ))
    }

    /// 信封解密：拆三段 base64，OAEP 解包裹会话密钥（32 字节硬校验）、
    /// AES-256-GCM 还原口令。格式/解密失败返回 Err——调用方以 400 语义透传。
    pub fn decrypt(key: &RsaCipher, envelope: &str) -> Result<String, String> {
        let rest = envelope
            .strip_prefix(ENVELOPE_PREFIX)
            .ok_or("passwordcrypto: malformed envelope (missing rsa-v1 prefix)")?;
        let parts: Vec<&str> = rest.split(':').collect();
        let [wrapped_b64, nonce_b64, cipher_b64] = parts.as_slice() else {
            return Err("passwordcrypto: malformed envelope".into());
        };
        let wrapped = base64::engine::general_purpose::STANDARD
            .decode(wrapped_b64)
            .map_err(|_| "passwordcrypto: invalid envelope base64")?;
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(nonce_b64)
            .map_err(|_| "passwordcrypto: invalid envelope base64")?;
        let cipher = base64::engine::general_purpose::STANDARD
            .decode(cipher_b64)
            .map_err(|_| "passwordcrypto: invalid envelope base64")?;

        let session = key
            .decrypt(&wrapped)
            .map_err(|_| "passwordcrypto: envelope unwrap".to_string())?;
        if session.len() != 32 {
            return Err("passwordcrypto: session key size".into());
        }
        if nonce.len() != 12 {
            return Err("passwordcrypto: nonce size".into());
        }
        let gcm = AesGcmCipher::new(session)?;
        let plain = gcm
            .decrypt_with_nonce(&cipher, nonce.try_into().expect("12 bytes checked"))
            .map_err(|_| "passwordcrypto: envelope decrypt".to_string())?;
        String::from_utf8(plain).map_err(|_| "passwordcrypto: envelope utf8".into())
    }
}

#[cfg(test)]
mod envelope_tests {
    use super::*;

    /// 信封往返：公钥加密 → 私钥解密还原明文（含 CJK 与单字符边界）。
    #[test]
    fn envelope_roundtrip() {
        let key = RsaCipher::new(2048).unwrap();
        for pw in ["Abcd@1234", "中文密码+符号!@#", "x"] {
            let envelope = PasswordEnvelope::encrypt(&key, pw).unwrap();
            assert!(envelope.starts_with(ENVELOPE_PREFIX));
            assert_eq!(PasswordEnvelope::decrypt(&key, &envelope).unwrap(), pw);
        }
    }

    /// 垃圾输入一律报错不恐慌（格式缺段 / base64 坏 / 长度异常）。
    #[test]
    fn envelope_garbage_rejected() {
        let key = RsaCipher::new(2048).unwrap();
        for bad in [
            "rsa-v1:!!!:???:**:",
            "not-envelope",
            "rsa-v1:AAAA:BBBB:CCCC",
            "",
        ] {
            assert!(PasswordEnvelope::decrypt(&key, bad).is_err(), "{bad:?}");
        }
    }
}
