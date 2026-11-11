//! OTP:RFC 6238 TOTP(三摘要)与 otpauth:// URI(扫码绑定两步验证)。
//!
//! 运行:`cargo run --example otp`

use rust_utils::otp::{self, Digest, OtpauthParams};

fn main() {
    // 1. 生成密钥(服务端随机 20 字节,base32 存储)
    let secret_bytes: Vec<u8> = (0..20u8).collect();
    let secret = otp::base32_encode(&secret_bytes);
    println!("secret(base32): {secret}");

    // 2. 产出 otpauth:// URI,前端转二维码展示给用户扫码
    let params = OtpauthParams::totp("Example Co", "alice@example.com", &secret);
    let uri = params.to_uri();
    println!("otpauth uri:    {uri}");

    // 3. 用户扫码后,服务端以同一密钥校验 6 位码(±1 窗口容忍时钟漂移)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let code = otp::totp_at(&secret_bytes, (now / 30) as u64);
    assert!(otp::totp_verify(&secret, &code, now));
    println!("totp code:      {code}(30s 有效,±1 窗)");

    // 4. SHA-256/512 摘要与 8 位形态(RFC 6238 三件套)
    let code8 = otp::totp_at_digest(&secret_bytes, (now / 30) as u64, Digest::Sha256, 8);
    assert!(otp::totp_verify_digest(
        &secret,
        &code8,
        now,
        Digest::Sha256,
        8,
        1
    ));
    println!("sha256/8digit:  {code8}");

    // 5. HOTP(计数器型,按序消费)
    let consumed = otp::hotp_verify(
        &secret,
        &otp::hotp_at(&secret_bytes, 0, Digest::Sha1, 6),
        0,
        5,
        Digest::Sha1,
        6,
    );
    assert_eq!(consumed, Some(0));
    println!("hotp counter:   {consumed:?}");

    // 6. URI 解析回环(容错大小写与缺省参数)
    let parsed = OtpauthParams::parse(&uri).unwrap();
    assert_eq!(parsed.secret_base32, secret);
    assert_eq!(parsed.algorithm, Digest::Sha1);
    assert_eq!(parsed.digits, 6);

    println!("OK");
}
