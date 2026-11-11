//! JWT 签发/校验/刷新:对称 HS256 与非对称 RS256(PEM)。
//!
//! 运行:`cargo run --example jwt`

use rust_utils::jwt::{self, Algorithm};
use serde_json::json;

const SECRET: &str = "demo-secret-please-rotate";

fn main() {
    let claims = json!({
        "sub": "u-1001",
        "role": "admin",
        "exp": 4102444800i64, // 2100-01-01,演示用
    });

    // 对称:HS256(同一 secret 签发与校验)
    let token = jwt::generate_jwt(claims.clone(), SECRET, Algorithm::HS256).unwrap();
    println!("HS256 token: {}…", &token[..48]);
    assert!(jwt::verify_jwt(&token, SECRET));
    assert!(!jwt::verify_jwt(&token, "wrong-secret"));

    let parsed = jwt::parse_jwt_payload(&token, SECRET).unwrap();
    assert_eq!(parsed["sub"], "u-1001");
    assert!(parsed["jti"].is_string(), "自动补 jti");
    println!("claims.sub:  {}", parsed["sub"]);

    // 刷新:保留 claims,重设 exp
    let refreshed = jwt::refresh_jwt(&token, SECRET, 4102444900i64).unwrap();
    assert_eq!(
        jwt::parse_jwt_payload(&refreshed, SECRET).unwrap()["exp"],
        4102444900i64
    );

    // 非对称:RS256(私钥签发、公钥校验;PEM 也可来自环境变量/配置)
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/jwt");
    let private_pem = std::fs::read_to_string(format!("{dir}/rsa_private.pem")).unwrap();
    let public_pem = std::fs::read_to_string(format!("{dir}/rsa_public.pem")).unwrap();
    let rs_token = jwt::generate_jwt_with_key(claims, &private_pem, Algorithm::RS256).unwrap();
    assert!(jwt::verify_jwt_with_key(
        &rs_token,
        &public_pem,
        Algorithm::RS256
    ));
    println!("RS256 token: {}…", &rs_token[..48]);

    // alg 混淆防护:校验端钉死算法,换算法声明即拒
    assert!(!jwt::verify_jwt_with_key(
        &rs_token,
        &public_pem,
        Algorithm::PS256
    ));

    println!("OK");
}
