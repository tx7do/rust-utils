//! 加密原语与应用层门面:Encryptor(`enc:` 信封)与统一 Signer 签名面。
//!
//! 运行:`cargo run --features crypto --example crypto`

use rust_utils::crypto::{self, Cipher, EcdsaCipher, Encryptor, Signer};

fn main() {
    // 1. 应用层门面:口令派生密钥,输出带 `enc:` 前缀的信封
    let enc = Encryptor::new("app-secret").unwrap();
    let sealed = enc.encrypt("attack at dawn").unwrap();
    assert!(crypto::is_encrypted(&sealed));
    assert_eq!(enc.decrypt(&sealed).unwrap(), "attack at dawn");
    println!("envelope: {sealed}");

    // 2. 原语层:AES-GCM(带 nonce)/ AES-CBC
    let gcm = crypto::AesGcmCipher::new(vec![0x42u8; 32]).unwrap();
    let sealed = gcm.encrypt(b"payload").unwrap();
    assert_eq!(gcm.decrypt(&sealed).unwrap(), b"payload");
    println!("aes-gcm sealed {} bytes", sealed.len());

    // 3. 统一 Signer 面:ECDSA(与 RSA/SM2 可互换,见各模块示例)
    let signer = EcdsaCipher::new().unwrap();
    let verifier = EcdsaCipher::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let sig = Signer::sign(&signer, b"audit entry #42").unwrap();
    assert!(Signer::verify(&verifier, b"audit entry #42", &sig).unwrap());
    assert!(!Signer::verify(&verifier, b"tampered entry", &sig).unwrap());
    assert_eq!(Signer::algorithm(&signer), "ECDSA");
    println!("ecdsa sig: {}…", &sig[..24]);

    println!("OK");
}
