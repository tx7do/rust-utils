//! JWT 辅助层,feature `jwt`。
//!
//! 基于 `jsonwebtoken` v9。两类签名方式:
//!
//! - 对称 HS256(默认):`generate_jwt` / `parse_jwt_payload` / `verify_jwt` 一族,
//!   载荷为 `serde_json::Value`(即 claims 对象)。
//! - 非对称(RS256/RS384/RS512/PS256/PS384/PS512/ES256/ES384):
//!   `generate_jwt_with_key` 一族,私钥/公钥以 PEM 字符串传入,底层仍是
//!   `jsonwebtoken` 的 RSA/EC 支持,不额外引入依赖。
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
    decode_with_key(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        Algorithm::HS256,
        |c| Ok(c.claims),
    )
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
    decode_with_key(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        Algorithm::HS256,
        |c| serde_json::from_value(c.claims).map_err(Into::into),
    )
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

// ---------------------------------------------------------------------------
// 非对称算法:PEM 私钥签发 / 公钥校验(RS*/PS*/ES*)。
// ---------------------------------------------------------------------------

/// 用 PEM 私钥签发 JWT(RS256/RS384/RS512/PS256/PS384/PS512/ES256/ES384)。
///
/// `claims` 非 object 时同 [`generate_jwt`] 包一层 `{"data": ...}`;
/// 自动补 `iat`/`jti`。RSA 系算法吃 PKCS#8/PKCS#1 私钥 PEM,ES 系吃
/// SEC1/PKCS#8 私钥 PEM(`jsonwebtoken` 侧统一由 `rsa`/`p256` 解析)。
pub fn generate_jwt_with_key(
    claims: Value,
    private_key_pem: &str,
    alg: Algorithm,
) -> Result<String, JwtError> {
    let encoding_key = encoding_key_from_pem(private_key_pem, alg)?;

    let mut claims = claims;
    if !claims.is_object() {
        claims = json!({ "data": claims });
    }
    let obj = claims.as_object_mut().unwrap();
    obj.entry("iat").or_insert(now_ts());
    obj.entry("jti").or_insert_with(new_jwt_id);

    jsonwebtoken::encode(&Header::new(alg), &claims, &encoding_key)
}

/// 用 PEM 公钥(或 X.509 证书 PEM)解析并校验 JWT,返回 claims 对象。
pub fn parse_jwt_payload_with_key(
    token: &str,
    public_key_pem: &str,
    alg: Algorithm,
) -> Result<Value, JwtError> {
    let decoding_key = decoding_key_from_pem(public_key_pem, alg)?;
    decode_with_key(token, &decoding_key, alg, |c| Ok(c.claims))
}

/// 用 PEM 公钥解析并校验 JWT,把 claims 反序列化为强类型。
pub fn parse_jwt_claims_with_key<T: serde::de::DeserializeOwned>(
    token: &str,
    public_key_pem: &str,
    alg: Algorithm,
) -> Result<T, JwtError> {
    let decoding_key = decoding_key_from_pem(public_key_pem, alg)?;
    decode_with_key(token, &decoding_key, alg, |c| {
        serde_json::from_value(c.claims).map_err(Into::into)
    })
}

/// 用 PEM 公钥校验签名是否有效。
pub fn verify_jwt_with_key(token: &str, public_key_pem: &str, alg: Algorithm) -> bool {
    parse_jwt_payload_with_key(token, public_key_pem, alg).is_ok()
}

/// 用 PEM 私钥刷新 JWT:保留原 claims,重设 `exp`(Unix 秒)与 `iat`。
///
/// 旧 token 的 claims 不验签读出(私钥→公钥的推导 `jsonwebtoken` 不导出,
/// 且持有私钥的调用方本身就是信任锚,重签安全性与 HS 版一致)。
pub fn refresh_jwt_with_key(
    token: &str,
    private_key_pem: &str,
    alg: Algorithm,
    new_exp: i64,
) -> Result<String, JwtError> {
    let mut claims = parse_unverified_claims(token)?;
    if let Some(obj) = claims.as_object_mut() {
        obj.insert("exp".into(), json!(new_exp));
        obj.insert("iat".into(), now_ts());
    }
    generate_jwt_with_key(claims, private_key_pem, alg)
}

/// RSA 系(RS*/PS*)还是 EC 系(ES*)。
fn is_rsa_alg(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
    )
}

fn is_es_alg(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::ES256 | Algorithm::ES384)
}

fn encoding_key_from_pem(pem: &str, alg: Algorithm) -> Result<EncodingKey, JwtError> {
    if is_rsa_alg(alg) {
        EncodingKey::from_rsa_pem(pem.as_bytes())
    } else if is_es_alg(alg) {
        EncodingKey::from_ec_pem(pem.as_bytes())
    } else {
        Err(err_kind(format!(
            "algorithm {alg:?} is not a PEM-key algorithm; use the secret-based helpers"
        )))
    }
}

fn decoding_key_from_pem(pem: &str, alg: Algorithm) -> Result<DecodingKey, JwtError> {
    if is_rsa_alg(alg) {
        DecodingKey::from_rsa_pem(pem.as_bytes())
    } else if is_es_alg(alg) {
        DecodingKey::from_ec_pem(pem.as_bytes())
    } else {
        Err(err_kind(format!(
            "algorithm {alg:?} is not a PEM-key algorithm; use the secret-based helpers"
        )))
    }
}

/// 统一的 decode 入口:校验算法钉死为入参 `alg`(防 alg 混淆),
/// 不强制校验 `exp`(过期交给 `is_jwt_expired` / 调用方),spec claims 不设必需项。
fn decode_with_key<T, F>(
    token: &str,
    key: &DecodingKey,
    alg: Algorithm,
    map: F,
) -> Result<T, JwtError>
where
    F: FnOnce(jsonwebtoken::TokenData<Value>) -> Result<T, JwtError>,
{
    let mut validation = Validation::new(alg);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    let data = jsonwebtoken::decode::<Value>(token, key, &validation)?;
    map(data)
}

fn err_kind(msg: impl std::fmt::Display) -> JwtError {
    // ErrorKind 的消息承载位只有 InvalidRsaKey(String) 公开可构造,
    // 借用它把「算法不支持 PEM」这类自述消息带出去。
    jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidRsaKey(
        msg.to_string(),
    ))
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

    // -------------------------------------------------------------------
    // 非对称算法(PEM 密钥)。测试密钥为一次性生成,只存在于本文件。
    // -------------------------------------------------------------------

    // 测试密钥对由 openssl 一次性生成,放在 assets/jwt/(见该目录 README);
    // 包发布时被 exclude,缺失时整组用例跳过 —— 与 assets/geoip 同款约定。
    const JWT_KEYS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/jwt");

    fn key_missing() -> bool {
        !std::path::Path::new(JWT_KEYS_DIR)
            .join("rsa_private.pem")
            .exists()
    }

    fn read_key(name: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(JWT_KEYS_DIR).join(name))
            .unwrap_or_else(|e| panic!("read {name}: {e}"))
    }

    #[test]
    fn test_pem_roundtrip_all_algs() {
        if key_missing() {
            eprintln!("skip: assets/jwt 缺失");
            return;
        }
        let rsa_priv = read_key("rsa_private.pem");
        let rsa_pub = read_key("rsa_public.pem");
        let ec_priv = read_key("ec_private.pem");
        let ec_pub = read_key("ec_public.pem");
        let claims = json!({ "sub": "asym", "exp": 4102444800i64 });
        for (alg, priv_pem, pub_pem) in [
            (Algorithm::RS256, &rsa_priv, &rsa_pub),
            (Algorithm::RS384, &rsa_priv, &rsa_pub),
            (Algorithm::RS512, &rsa_priv, &rsa_pub),
            (Algorithm::PS256, &rsa_priv, &rsa_pub),
            (Algorithm::ES256, &ec_priv, &ec_pub),
        ] {
            let token = generate_jwt_with_key(claims.clone(), priv_pem, alg)
                .unwrap_or_else(|e| panic!("{alg:?}: {e}"));
            // 不验签读 header,确认 alg 与请求一致
            let head_b64 = token.split('.').next().unwrap();
            let header: serde_json::Value = {
                let raw = base64_decode_url(head_b64).unwrap();
                serde_json::from_slice(&raw).unwrap()
            };
            assert_eq!(header["alg"], serde_json::to_value(alg).unwrap(), "{alg:?}");

            let parsed = parse_jwt_payload_with_key(&token, pub_pem, alg)
                .unwrap_or_else(|e| panic!("{alg:?} verify: {e}"));
            assert_eq!(parsed["sub"], "asym", "{alg:?}");
            assert_eq!(parsed["jti"].as_str().map(str::len), Some(16), "{alg:?}");

            assert!(verify_jwt_with_key(&token, pub_pem, alg), "{alg:?}");
        }
    }

    #[test]
    fn test_pem_rejects_wrong_key_and_tamper() {
        if key_missing() {
            eprintln!("skip: assets/jwt 缺失");
            return;
        }
        let rsa_priv = read_key("rsa_private.pem");
        let rsa_pub = read_key("rsa_public.pem");
        let ec_pub = read_key("ec_public.pem");
        let claims = json!({ "sub": "sec", "exp": 4102444800i64 });
        let token = generate_jwt_with_key(claims, &rsa_priv, Algorithm::RS256).unwrap();

        // 换成 EC 公钥 / 错算法都拒
        assert!(!verify_jwt_with_key(&token, &ec_pub, Algorithm::RS256));
        assert!(parse_jwt_payload_with_key(&token, &rsa_pub, Algorithm::ES256).is_err());

        // 篡改 payload 拒
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        parts[1] = "eyJzdWIiOiJoYWNrIn0".to_string();
        let tampered = parts.join(".");
        assert!(!verify_jwt_with_key(&tampered, &rsa_pub, Algorithm::RS256));

        // HS256 的 token 不能当 RS256 验
        let hs = generate_jwt(json!({ "sub": "x" }), SECRET, Algorithm::HS256).unwrap();
        assert!(parse_jwt_payload_with_key(&hs, &rsa_pub, Algorithm::RS256).is_err());
    }

    #[test]
    fn test_pem_alg_confusion_pinned() {
        if key_missing() {
            eprintln!("skip: assets/jwt 缺失");
            return;
        }
        let rsa_priv = read_key("rsa_private.pem");
        let rsa_pub = read_key("rsa_public.pem");
        // RS256 签发的 token,校验端把 alg 换成 PS256/RS512 时必须拒
        // (validation 钉死单一算法,防 alg 混淆攻击)
        let token =
            generate_jwt_with_key(json!({ "sub": "c" }), &rsa_priv, Algorithm::RS256).unwrap();
        assert!(parse_jwt_payload_with_key(&token, &rsa_pub, Algorithm::RS512).is_err());
        assert!(parse_jwt_payload_with_key(&token, &rsa_pub, Algorithm::PS256).is_err());
    }

    #[test]
    fn test_pem_non_object_claims_wrapped() {
        if key_missing() {
            eprintln!("skip: assets/jwt 缺失");
            return;
        }
        let ec_priv = read_key("ec_private.pem");
        let ec_pub = read_key("ec_public.pem");
        let token = generate_jwt_with_key(json!(["a", "b"]), &ec_priv, Algorithm::ES256).unwrap();
        let parsed = parse_jwt_payload_with_key(&token, &ec_pub, Algorithm::ES256).unwrap();
        assert_eq!(parsed["data"], json!(["a", "b"]));
    }

    #[test]
    fn test_pem_refresh_keeps_claims() {
        if key_missing() {
            eprintln!("skip: assets/jwt 缺失");
            return;
        }
        let rsa_priv = read_key("rsa_private.pem");
        let rsa_pub = read_key("rsa_public.pem");
        let token = generate_jwt_with_key(
            json!({ "sub": "r", "role": "admin", "exp": 4102444800i64 }),
            &rsa_priv,
            Algorithm::RS256,
        )
        .unwrap();
        let refreshed =
            refresh_jwt_with_key(&token, &rsa_priv, Algorithm::RS256, 4102445000i64).unwrap();
        let parsed = parse_jwt_payload_with_key(&refreshed, &rsa_pub, Algorithm::RS256).unwrap();
        assert_eq!(parsed["sub"], "r");
        assert_eq!(parsed["role"], "admin");
        assert_eq!(parsed["exp"], 4102445000i64);
    }

    #[test]
    fn test_pem_secret_algs_rejected() {
        if key_missing() {
            eprintln!("skip: assets/jwt 缺失");
            return;
        }
        let rsa_priv = read_key("rsa_private.pem");
        // HS 系不是 PEM 算法,必须报错而不是把 PEM 当 secret
        assert!(generate_jwt_with_key(json!({}), &rsa_priv, Algorithm::HS256).is_err());
        assert!(generate_jwt_with_key(json!({}), &rsa_priv, Algorithm::HS384).is_err());
    }

    #[test]
    fn test_pem_garbage_key_errors() {
        assert!(generate_jwt_with_key(json!({}), "not a pem", Algorithm::RS256).is_err());
        if key_missing() {
            eprintln!("skip: assets/jwt 缺失");
            return;
        }
        let ec_pub = read_key("ec_public.pem");
        let rsa_pub = read_key("rsa_public.pem");
        assert!(parse_jwt_payload_with_key("garbage", &ec_pub, Algorithm::ES256).is_err());
        // RSA 公钥喂给 ES256 解码端同样报错
        assert!(parse_jwt_payload_with_key("a.b.c", &rsa_pub, Algorithm::ES256).is_err());
    }
}
