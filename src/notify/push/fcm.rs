//! Firebase Cloud Messaging(HTTP v1 API),feature `notify`。对齐上游 `push/fcm.go`。
//!
//! service account 的 RS256 JWT 换 OAuth2 访问令牌(进程内缓存),逐台设备
//! POST `messages:send`。给 `Message::target`(FCM registration token)推一条通知:
//! `title`/`content` 进 notification 面板,`params` 进 data 面(安卓端
//! `onMessageReceived` 可读);令牌失效(404/410)归 [`NotifyError::InvalidToken`]。

use std::collections::HashMap;
use std::sync::Mutex;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

use crate::notify::{Message, NotifyError, Receipt, Service};

/// OAuth2 令牌端点缺省值。
pub const FCM_DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
/// FCM 发送 scope。
pub const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// 发送端点基地址缺省值。
pub const FCM_DEFAULT_API_BASE: &str = "https://fcm.googleapis.com";

/// 访问令牌签发有效期:JWT 自身 1 小时。
const JWT_TTL_SECS: i64 = 3600;

/// Firebase Cloud Messaging(HTTP v1 API)配置。
#[derive(Debug, Clone, Default)]
pub struct FcmConfig {
    /// Firebase 项目 ID。
    pub project_id: String,
    /// 服务账号 client_email(Firebase 控制台下载的 JSON 里的同名字段)。
    pub client_email: String,
    /// 服务账号私钥(同 JSON 的 private_key;PEM 支持 PKCS#8 与 PKCS#1)。
    pub private_key: String,
    /// OAuth2 令牌端点,留空用 Google 官方;测试可覆盖。
    pub token_uri: String,
    /// 发送端点基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// 缓存的访问令牌:按服务账号存,换账号即失效重取。
#[derive(Default)]
struct CachedToken {
    email: String,
    expiry_unix: i64,
    token: String,
}

/// FCM 推送渠道。单实例可复用(令牌按服务账号缓存),并发安全。
pub struct Fcm {
    agent: ureq::Agent,
    cfg: FcmConfig,
    cached: Mutex<Option<CachedToken>>,
}

impl Fcm {
    /// 构造 FCM 渠道(无错误路径;凭据问题留到 `send` 的拨号前自检)。
    pub fn new(allow_private: bool, cfg: FcmConfig) -> Self {
        Fcm {
            agent: crate::notify::new_client(allow_private),
            cfg,
            cached: Mutex::new(None),
        }
    }

    fn api_base(&self) -> &str {
        if self.cfg.api_base.is_empty() {
            FCM_DEFAULT_API_BASE
        } else {
            &self.cfg.api_base
        }
    }

    /// OAuth2 令牌端点(配置可覆盖)。
    pub fn token_uri(&self) -> &str {
        if self.cfg.token_uri.is_empty() {
            FCM_DEFAULT_TOKEN_URI
        } else {
            &self.cfg.token_uri
        }
    }

    /// 配置自检(拨号之前):项目 ID 与服务账号凭据缺一不可。
    fn check_config(&self) -> Result<(), NotifyError> {
        if self.cfg.project_id.is_empty() {
            return Err(NotifyError::NotConfigured(
                "fcm config incomplete: project_id required".into(),
            ));
        }
        if self.cfg.client_email.is_empty() || self.cfg.private_key.is_empty() {
            return Err(NotifyError::NotConfigured(
                "fcm config incomplete: client_email/private_key required".into(),
            ));
        }
        Ok(())
    }

    /// 取(缓存的)OAuth2 访问令牌:RS256 JWT assertion 换取。
    fn get_access_token(&self) -> Result<String, NotifyError> {
        let now = now_unix();
        {
            let cached = self.cached.lock().expect("fcm token 锁");
            if let Some(c) = cached.as_ref() {
                if c.email == self.cfg.client_email && now < c.expiry_unix {
                    return Ok(c.token.clone());
                }
            }
        }

        let (assertion, mint_expiry) = mint_fcm_jwt(
            &self.cfg.client_email,
            &self.cfg.private_key,
            self.token_uri(),
            now,
        )?;

        // assertion 是 base64url 串,无需再编码,与上游一样整串手拼。
        let form =
            format!("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={assertion}");
        let (status, body) = super::post(
            &self.agent,
            self.token_uri(),
            &[("Content-Type", "application/x-www-form-urlencoded")],
            &form,
        )?;
        if status != 200 {
            return Err(NotifyError::Delivery(format!(
                "fcm oauth token failed: http {status}: {}",
                super::err_snippet(&body)
            )));
        }
        #[derive(serde::Deserialize)]
        struct TokenResp {
            #[serde(default)]
            access_token: String,
            #[serde(default)]
            expires_in: i64,
        }
        let tok: TokenResp = serde_json::from_str(&body)
            .map_err(|_| NotifyError::Delivery("fcm oauth token response is not JSON".into()))?;
        if tok.access_token.is_empty() {
            return Err(NotifyError::Delivery(
                "fcm oauth token empty access_token".into(),
            ));
        }

        // 取厂商给的 expires_in 与 JWT 自身有效期的较早者。
        let mut expiry = mint_expiry;
        let with_grace = now + tok.expires_in;
        if tok.expires_in > 0 && with_grace < expiry {
            expiry = with_grace;
        }

        let mut cached = self.cached.lock().expect("fcm token 锁");
        *cached = Some(CachedToken {
            email: self.cfg.client_email.clone(),
            expiry_unix: expiry,
            token: tok.access_token.clone(),
        });
        Ok(tok.access_token)
    }
}

impl Service for Fcm {
    fn name(&self) -> &str {
        "fcm"
    }

    /// 给 Target(FCM registration token)推一条通知。
    /// Title/Content 进 notification 面板,Params 进 data 面。
    /// Receipt.ProviderID 带回消息 name 的尾段(厂商侧消息 ID)。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "fcm device token is empty".into(),
            ));
        }
        self.check_config()?;

        let access_token = self.get_access_token()?;
        let payload = build_send_payload(&msg.target, &msg.title, &msg.content, &msg.params);
        let endpoint = send_endpoint(self.api_base(), &self.cfg.project_id);
        let auth = format!("Bearer {access_token}");
        let (status, body) = super::post(
            &self.agent,
            &endpoint,
            &[
                ("Authorization", auth.as_str()),
                ("Content-Type", "application/json; charset=UTF-8"),
            ],
            &payload,
        )?;
        parse_answer(status, &body).map(|provider_id| Receipt {
            provider_id: provider_id.unwrap_or_default(),
        })
    }
}

/// 当前秒级 Unix 时间。
fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// 用服务账号私钥签 RS256 JWT(scope=FCM),返回 (assertion, 过期秒级时间戳)。
///
/// header+claims 各 base64url,RSA PKCS#1 v1.5 / SHA-256——与 golang.org/x/oauth2
/// 的 JWT 拨号同一形状,经 jsonwebtoken 实现避免引入 oauth2 依赖。
/// `now` 由调用方注入以便离线测试;PEM 解析失败归配置类。
pub fn mint_fcm_jwt(
    client_email: &str,
    private_key_pem: &str,
    token_uri: &str,
    now: i64,
) -> Result<(String, i64), NotifyError> {
    if client_email.is_empty() || private_key_pem.is_empty() {
        return Err(NotifyError::NotConfigured(
            "fcm service account incomplete (client_email/private_key required)".into(),
        ));
    }
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| NotifyError::NotConfigured(format!("private_key parse failed: {e}")))?;
    let expiry = now + JWT_TTL_SECS;
    let claims = FcmClaims {
        iss: client_email.to_string(),
        scope: FCM_SCOPE.to_string(),
        aud: token_uri.to_string(),
        iat: now,
        exp: expiry,
    };
    let assertion = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|e| NotifyError::NotConfigured(format!("mint fcm jwt failed: {e}")))?;
    Ok((assertion, expiry))
}

/// OAuth2 JWT-bearer 断言的 claims。
#[derive(Serialize)]
struct FcmClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: i64,
    exp: i64,
}

/// 构造发送端点:`<api_base>/v1/projects/<project_id>/messages:send`。
pub fn send_endpoint(api_base: &str, project_id: &str) -> String {
    format!("{api_base}/v1/projects/{project_id}/messages:send")
}

/// 构造发送 payload,可独立测试的纯函数:
/// `token` 是设备令牌,`notification` 进系统面板,`data` 携带业务自定义键,
/// 安卓侧固定 HIGH 优先级。
pub fn build_send_payload(
    token: &str,
    title: &str,
    body: &str,
    data: &HashMap<String, String>,
) -> String {
    serde_json::json!({
        "message": {
            "token": token,
            "notification": {"title": title, "body": body},
            "data": data,
            "android": {"priority": "HIGH"},
        }
    })
    .to_string()
}

/// 应答归类,可独立测试的纯函数。
///
/// 2xx 成功,应答 `{"name":"projects/x/messages/<id>"}` 尾段即厂商侧消息 ID;
/// 404/410 归令牌失效(应用卸载/实例删除,调用方删行自清理);其余投递失败。
pub fn parse_answer(status: u16, body: &str) -> Result<Option<String>, NotifyError> {
    if (200..300).contains(&status) {
        #[derive(serde::Deserialize)]
        struct Answer {
            #[serde(default)]
            name: String,
        }
        let name = serde_json::from_str::<Answer>(body)
            .map(|a| a.name)
            .unwrap_or_default();
        return Ok(name
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .map(str::to_string));
    }
    if status == 404 || status == 410 {
        // 令牌已从注册表除名:调用方删行自清理,不算投递失败重试。
        return Err(NotifyError::InvalidToken(format!("http {status}")));
    }
    Err(NotifyError::Delivery(format!(
        "fcm send failed: http {status}: {}",
        super::err_snippet(body)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试专用 RSA 私钥(进程内生成的固定测试密钥,绝非生产凭据)。
    const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2ExFpFgSNLyI3
1NmfKBA//1JNIFYG9gXCAcNK4JfFjZ9bJMxQXAkiSuMRzMWkvBZ6Qz7D/XaP91XH
R8bliumgRnmZTAN52izyzTFfmOEBRr9Z41ZN5X6cK+7sPVdrVfE1NFo6tdPiLVtR
nB1ZwF/alnuXjCcy5/HV05vAYAIA7oAR6JEqU/lUyxt7aE2B0FKZMDZUWtGjj4lx
e3VZlcyUrQ7T353krTjrCkNG1E40dpc8VmLO4KF9eb5jGTC+CjpvXP5smuERPZFY
G4SyRJGLaiQO50ss3B10w2f3L4UmCCurwCdvoFVRtBTiSTUFyjFd/P4tChNE3brd
uH5PaUV1AgMBAAECggEAE8Ec3fhwFPtcrI8Q73Yy0Sa8ALc17jpqJIL5c9nLTblQ
ZVyoOD3MFebnHQrJFNb9X1WFbVFGOFd+/IiamVQJhgSvc8TuCZ30y4EczsDxBKju
4OtL9Valdn9DxGjhX7lq2rlr4rvQmdUO99tGyfKX08kI7sfbhufocqkrWGNyRDRs
yQnGm8bmPva+mTFo0qpYeZm913orjsvVm3Q358VVBRxEEXy4mOx/qWvC4/0avszJ
mlQDVR8xlDEfxZCcX6Q12soD89XTKjR/JT/3JbUfqc7EHOH81w7n4l1RCstlI33A
272Saf89I3OWuRklWJ5R7dH5JYkCNgfDoO2CYcDX0QKBgQD9URfc+J7TraPermeW
u0tTo/is1zmRy1eWKWOuPgxTBPxFplWGt09ldI1+ux8T/XB3gkWFqH3RJQEvZ9v3
wjUS+Wxu3MrZ8hNufllKmJQ3T5gQW58okIPClMzLpRSktoFioECtvsIzvDnaoJHZ
PIhMXKlJtuSd5/TMsNZ87wtKOQKBgQC4AMphS467H+0N5Bk2p9/z44y0V7RI5o06
JLCrgvchOtIsGvOO/YPS/2jv1JirJF+F6t0oWwWFyYyhrZ7mtSM1gH5HPKdKUgf5
fgA1wXi230Ja/8RIqhJLhx5TTW1FrjGbgE//7QqXErlaSvAQvwbLNDPu8r9YRWH8
LHIh8yTFHQKBgBabmy6cfchUkfB4zkP0mUdwtevvFXM+m6WKMhxF62Gpaz5oFu/8
AjkCyvIJjz+Aef4ggUXpgLkevVlWwpn9GjGEUzoduHj1Eujkm+F9dpTtJJwpIS5E
n43JK/Hs3MfKhgegV8Vp5fkqDlvFwt6JeXyfNHiguwygvAdcrPffebl5AoGBAKXV
CJChoTSitGoVjmfE6sEK7s/GT5R4PQYO9S7ObN4E/lCDxci0UO+EA1ZK+4Ea2gB+
yO1LA3ItUNKSAKkazW21rZmUX41K2ycPWS8ZfCsMkegjpQp8RNrPHxSirn3jXZAx
F2ingSjg1i47ZZsiHwRauwd6vdrXRVUZ1Y8lbJk9AoGAROa44NBBfAf30dnZw/MH
fBzkfsJE4RcU64DYc4TqDe+cvJD+m9RSowPN4jeubmn/hwdSfD4GaM6r07MEe9vT
O5je4GHHY3J6h7rIU4EwrJFBIHkahS3qSGmg0PSijUb0HDr4SDxSr7/UVSas8734
9dW/SqPG4w6gvZ7el5oq3ZA=
-----END PRIVATE KEY-----
";

    /// 对齐上游 fcm_test 的 token 拨号断言:assertion 是三段式 JWT,claims 携带
    /// 服务账号(iss)与 FCM scope;签名算法 RS256;过期时间 = now + 1h。
    #[test]
    fn test_mint_fcm_jwt_claims() {
        let now = 1_760_000_000_i64;
        let (assertion, expiry) = mint_fcm_jwt(
            "sa@proj-x.iam.gserviceaccount.com",
            TEST_RSA_PEM,
            FCM_DEFAULT_TOKEN_URI,
            now,
        )
        .expect("测试私钥应可签发");

        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT 三段式");

        // header:RS256 + typ JWT
        let header: serde_json::Value = serde_json::from_slice(&jwt_b64_decode(parts[0])).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");

        // claims:iss/scope/aud/iat/exp
        let claims: serde_json::Value = serde_json::from_slice(&jwt_b64_decode(parts[1])).unwrap();
        assert_eq!(claims["iss"], "sa@proj-x.iam.gserviceaccount.com");
        assert!(
            claims["scope"]
                .as_str()
                .unwrap()
                .contains("firebase.messaging"),
            "{claims}"
        );
        assert_eq!(claims["aud"], FCM_DEFAULT_TOKEN_URI);
        assert_eq!(claims["iat"], now);
        assert_eq!(claims["exp"], now + 3600);
        assert_eq!(expiry, now + 3600);

        // 缺凭据:拨号之前拒绝
        let err = mint_fcm_jwt("", TEST_RSA_PEM, FCM_DEFAULT_TOKEN_URI, now).unwrap_err();
        assert!(err.is_not_configured());
        // 坏 PEM 同样归配置类
        let err = mint_fcm_jwt("sa@x", "not a pem", FCM_DEFAULT_TOKEN_URI, now).unwrap_err();
        assert!(err.is_not_configured(), "{err}");
    }

    /// base64url(无填充)解码(仅测试用)。
    fn jwt_b64_decode(seg: &str) -> Vec<u8> {
        let mut vals = Vec::with_capacity(seg.len());
        for c in seg.bytes() {
            vals.push(match c {
                b'A'..=b'Z' => (c - b'A') as u32,
                b'a'..=b'z' => (c - b'a' + 26) as u32,
                b'0'..=b'9' => (c - b'0' + 52) as u32,
                b'-' => 62,
                b'_' => 63,
                _ => panic!("非 base64url 字符: {c}"),
            });
        }
        let mut out = Vec::new();
        for chunk in vals.chunks(4) {
            let mut n = chunk.iter().fold(0u32, |acc, &v| (acc << 6) | v);
            for _ in chunk.len()..4 {
                n <<= 6;
            }
            let bytes = n.to_be_bytes();
            out.extend_from_slice(&bytes[1..chunk.len()]);
        }
        out
    }

    /// 消息形状与端点对齐上游 send 断言:token/notification/data/android 优先级。
    #[test]
    fn test_send_payload_and_endpoint() {
        let mut data = HashMap::new();
        data.insert("conversation_id".to_string(), "42".to_string());
        let payload = build_send_payload("reg-token-1", "重置验证码", "您的验证码是 123456", &data);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["message"]["token"], "reg-token-1");
        assert_eq!(v["message"]["notification"]["title"], "重置验证码");
        assert_eq!(v["message"]["notification"]["body"], "您的验证码是 123456");
        assert_eq!(v["message"]["data"]["conversation_id"], "42");
        assert_eq!(v["message"]["android"]["priority"], "HIGH");

        assert_eq!(
            send_endpoint(FCM_DEFAULT_API_BASE, "proj-x"),
            "https://fcm.googleapis.com/v1/projects/proj-x/messages:send",
            "端点要带项目 ID"
        );
    }

    /// 令牌失效码归类:404/410 归 InvalidToken(调用方删行自清理);
    /// 429 等是投递失败;成功时 name 尾段进回执。
    #[test]
    fn test_parse_answer_classification() {
        // 对齐上游 TestFCMSendInvalidToken:404 = 令牌已除名
        let err = parse_answer(404, r#"{"error":{"status":"NOT_FOUND"}}"#).unwrap_err();
        assert!(err.is_invalid_token(), "{err}");
        let err = parse_answer(410, r#"{"error":{"status":"UNREGISTERED"}}"#).unwrap_err();
        assert!(err.is_invalid_token(), "{err}");

        // 对齐上游 TestFCMSendPeerError:429 不是令牌失效,文案带状态码
        let err = parse_answer(429, r#"{"error":"quota exceeded"}"#).unwrap_err();
        assert!(!err.is_invalid_token());
        assert!(matches!(err, NotifyError::Delivery(_)));
        assert!(err.to_string().contains("429"));

        // 成功:name 尾段进回执
        let id = parse_answer(200, r#"{"name":"projects/proj-x/messages/2026101508"}"#)
            .unwrap()
            .unwrap();
        assert_eq!(id, "2026101508");
    }

    /// 拨号前的配置自检:缺项目 ID / 缺服务账号分别点名。
    #[test]
    fn test_check_config() {
        let svc = Fcm::new(
            false,
            FcmConfig {
                project_id: "p".into(),
                ..Default::default()
            },
        );
        let err = svc.check_config().unwrap_err();
        assert!(
            err.to_string().contains("client_email/private_key"),
            "{err}"
        );

        let svc = Fcm::new(false, FcmConfig::default());
        let err = svc.check_config().unwrap_err();
        assert!(err.to_string().contains("project_id"), "{err}");

        // 目标为空同样在拨号之前拦下
        let svc = Fcm::new(
            false,
            FcmConfig {
                project_id: "p".into(),
                client_email: "e".into(),
                private_key: "k".into(),
                ..Default::default()
            },
        );
        let err = svc.send(&Message::new("", "t")).unwrap_err();
        assert!(err.to_string().contains("device token is empty"), "{err}");
    }

    /// token_uri 缺省走 Google 官方,配置可覆盖(测试注入)。
    #[test]
    fn test_token_uri_override() {
        let svc = Fcm::new(false, FcmConfig::default());
        assert_eq!(svc.token_uri(), FCM_DEFAULT_TOKEN_URI);
        let svc = Fcm::new(
            false,
            FcmConfig {
                token_uri: "http://127.0.0.1:1/token".into(),
                ..Default::default()
            },
        );
        assert_eq!(svc.token_uri(), "http://127.0.0.1:1/token");
        assert_eq!(Service::name(&svc), "fcm");
    }

    /// OAuth2 scope 钉死:token 换发按它申请,漂移会直接被 Google 拒。
    #[test]
    fn test_fcm_scope_constant() {
        assert_eq!(
            FCM_SCOPE,
            "https://www.googleapis.com/auth/firebase.messaging"
        );
    }
}
