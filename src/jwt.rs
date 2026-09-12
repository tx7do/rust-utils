//! JWT 辅助层(移植自 go-utils/jwtutil),feature `jwt`。
//!
//! 基于 `jsonwebtoken` v9,默认 HS256。载荷为 `serde_json::Value`
//! (即 claims 对象)。
//!
//! ```
//! use rust_utils::jwt;
//! use serde_json::json;
//!
//! let claims = json!({ "sub": "u123", "exp": 4102444800i64 });
//! let token = jwt::generate_jwt(claims.clone(), "secret", jwt::Algorithm::HS256).unwrap();
//!
//! let parsed = jwt::parse_jwt_payload(&token, "secret").unwrap();
//! assert_eq!(parsed["sub"], "u123");
//! assert!(jwt::verify_jwt(&token, "secret"));
//! assert!(!jwt::verify_jwt(&token, "bad-secret"));
//! ```

pub use jsonwebtoken::Algorithm;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde_json::{json, Value};

pub use jsonwebtoken::errors::Error as JwtError;

/// 生成 JWT(默认自带 `iat`/`jti`,claims 中的 `exp` 需自行提供)。
pub fn generate_jwt(claims: Value, secret: &str, alg: Algorithm) -> Result<String, JwtError> {
    let mut claims = claims;
    if !claims.is_object() {
        claims = json!({ "data": claims });
    }
    let obj = claims.as_object_mut().unwrap();
    obj.entry("iat").or_insert(now_ts());
    obj.entry("jti").or_insert_with(new_jwt_id);

    let header = match alg {
        Algorithm::HS256 => Header::default(),
        other => Header::new(other),
    };
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// 解析并校验 JWT,返回 claims 对象。
pub fn parse_jwt_payload(token: &str, secret: &str) -> Result<Value, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false; // 与 Go 版行为一致:Parse 不强制校验过期
    validation.required_spec_claims.clear();
    let data = jsonwebtoken::decode::<Value>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?;
    Ok(data.claims)
}

/// 校验签名是否有效。
pub fn verify_jwt(token: &str, secret: &str) -> bool {
    parse_jwt_payload(token, secret).is_ok()
}

/// 解析并校验 JWT,把 claims 反序列化为强类型。
pub fn parse_jwt_claims<T: serde::de::DeserializeOwned>(
    token: &str,
    secret: &str,
) -> Result<T, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    let data = jsonwebtoken::decode::<T>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?;
    Ok(data.claims)
}

/// 刷新 JWT:保留原 claims,重设 `exp`(Unix 秒)与 `iat`。
pub fn refresh_jwt(token: &str, secret: &str, new_exp: i64) -> Result<String, JwtError> {
    let mut claims = parse_jwt_payload(token, secret)?;
    if let Some(obj) = claims.as_object_mut() {
        obj.insert("exp".into(), json!(new_exp));
        obj.insert("iat".into(), now_ts());
    }
    generate_jwt(claims, secret, Algorithm::HS256)
}

/// 是否已过期(claims 缺少 `exp` 视为未过期)。
pub fn is_jwt_expired(token: &str) -> bool {
    parse_unverified_claims(token)
        .map(|claims| {
            claims
                .get("exp")
                .and_then(|e| e.as_i64())
                .map(|exp| exp < now_unix())
                .unwrap_or(false)
        })
        .unwrap_or(true)
}

/// 不校验签名地解析 claims(仅用于检查过期等场景)。
pub fn parse_unverified_claims(token: &str) -> Result<Value, JwtError> {
    let (_, claims) = split_token(token)?;
    serde_json::from_slice(&claims).map_err(Into::into)
}

fn split_token(token: &str) -> Result<(&str, Vec<u8>), JwtError> {
    let mut parts = token.split('.');
    let _header = parts.next().ok_or_else(err)?;
    let payload = parts.next().ok_or_else(err)?;
    let _sig = parts.next().ok_or_else(err)?;
    let payload = base64_decode_url(payload).ok_or_else(err)?;
    Ok((_header, payload))
}

fn err() -> JwtError {
    jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
}

fn now_ts() -> Value {
    json!(now_unix())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// JWT 使用的 URL-safe base64(无填充)解码。
fn base64_decode_url(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    for chunk in bytes.chunks(4) {
        let mut vals = [0u8; 4];
        for (v, c) in vals.iter_mut().zip(chunk) {
            {
                let idx = ALPHABET.iter().position(|a| a == c)?;
                *v = idx as u8
            }
        }
        out.push((vals[0] << 2) | (vals[1] >> 4));
        if chunk.len() > 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if chunk.len() > 3 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    Some(out)
}

/// 生成新的 JWT ID(16 位随机十六进制)。
pub fn new_jwt_id() -> Value {
    let mut buf = [0u8; 8];
    if getrandom::fill(&mut buf).is_err() {
        return json!(format!(
            "jti-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
    }
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    json!(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "test-secret";

    #[test]
    fn test_generate_parse_roundtrip() {
        let claims = json!({ "sub": "u123", "role": "admin", "exp": 4102444800i64 });
        let token = generate_jwt(claims, SECRET, Algorithm::HS256).unwrap();
        assert_eq!(token.split('.').count(), 3);

        let parsed = parse_jwt_payload(&token, SECRET).unwrap();
        assert_eq!(parsed["sub"], "u123");
        assert_eq!(parsed["role"], "admin");
        assert!(parsed["iat"].is_i64());
        assert!(parsed["jti"].is_string());

        assert!(verify_jwt(&token, SECRET));
        assert!(!verify_jwt(&token, "wrong"));
        assert!(!verify_jwt("not-a-jwt", SECRET));
    }

    #[test]
    fn test_typed_claims() {
        #[derive(serde::Deserialize)]
        struct MyClaims {
            sub: String,
        }
        let token = generate_jwt(json!({ "sub": "abc" }), SECRET, Algorithm::HS256).unwrap();
        let claims: MyClaims = parse_jwt_claims(&token, SECRET).unwrap();
        assert_eq!(claims.sub, "abc");
    }

    #[test]
    fn test_refresh_and_expiry() {
        let token = generate_jwt(
            json!({ "sub": "r1", "exp": 4102444800i64 }),
            SECRET,
            Algorithm::HS256,
        )
        .unwrap();
        assert!(!is_jwt_expired(&token));

        let refreshed = refresh_jwt(&token, SECRET, 1).unwrap();
        assert!(is_jwt_expired(&refreshed));

        let expired_now =
            generate_jwt(json!({ "sub": "r2", "exp": 1 }), SECRET, Algorithm::HS256).unwrap();
        assert!(is_jwt_expired(&expired_now));
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let token = generate_jwt(
            json!({ "sub": "t", "exp": 4102444800i64 }),
            SECRET,
            Algorithm::HS256,
        )
        .unwrap();
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        let sig = parts[2].clone();
        // 翻转签名末字符
        let last = sig.chars().last().unwrap();
        let flipped = if last == 'A' { 'B' } else { 'A' };
        parts[2] = format!("{}{}", &sig[..sig.len() - 1], flipped);
        let tampered = parts.join(".");
        assert_ne!(tampered, token);
        assert!(!verify_jwt(&tampered, SECRET));
        assert!(parse_jwt_payload(&tampered, SECRET).is_err());

        // 错误密钥同样失败
        assert!(!verify_jwt(&token, "other-secret"));
    }

    #[test]
    fn test_parse_unverified_claims() {
        let token = generate_jwt(
            json!({ "sub": "u", "exp": 4102444800i64 }),
            SECRET,
            Algorithm::HS256,
        )
        .unwrap();
        let claims = parse_unverified_claims(&token).unwrap();
        assert_eq!(claims["sub"], "u");
        assert!(parse_unverified_claims("garbage").is_err());
    }

    #[test]
    fn test_new_jwt_id() {
        let a = new_jwt_id();
        let b = new_jwt_id();
        assert!(a.is_string());
        assert_ne!(a, b);
    }
}
