//! 密码哈希策略:统一 Crypto 接口下的多算法与复杂度校验。
//!
//! 运行:`cargo run --features password --example password`

use rust_utils::password::{self, Argon2Crypto, BCryptCrypto, Crypto, HmacCrypto, PBKDF2Crypto};

fn main() {
    const PLAIN: &str = "s3cret!Pass";

    let algos: Vec<(&str, Box<dyn Crypto>)> = vec![
        ("argon2", Box::new(Argon2Crypto)),
        ("bcrypt", Box::new(BCryptCrypto::new(10))),
        ("pbkdf2", Box::new(PBKDF2Crypto::new(100_000))),
        ("hmac", Box::new(HmacCrypto::new("pepper-key"))),
    ];
    for (name, algo) in &algos {
        let hash = algo.encrypt(PLAIN).unwrap();
        assert_ne!(hash, PLAIN);
        assert!(algo.verify(PLAIN, &hash).unwrap(), "{name} verify");
        assert!(!algo.verify("wrong", &hash).unwrap(), "{name} reject");
        println!("{name:<8} → {}…", &hash[..32.min(hash.len())]);
    }

    // 复杂度:长度 + 四类字符至少三类
    assert!(password::validate_complexity("Ab1!x", 5).is_ok());
    assert!(
        password::validate_complexity("abcdef", 5).is_err(),
        "只有小写一类"
    );
    println!("complexity checks OK");

    println!("OK");
}
