//! Apple APNs 推送渠道(Token 鉴权:.p8 + KeyID + TeamID)。对齐上游 `push/apns.go`。
//!
//! # ⚠️ HTTP/2 限制(必读)
//!
//! **APNs 强制 HTTP/2,而本 crate 内置的出站客户端(ureq)只支持 HTTP/1.1,
//! 因此 [`Apns::send`] 一律返回 [`NotifyError::NotConfigured`]("apns requires
//! http/2 which the built-in client does not support")。**
//!
//! 本模块仍完整实现并公开可离线测试的纯函数:
//! - [`mint_apns_token`]:ES256 provider token(官方有效期 1 小时);
//! - [`build_payload`] / [`build_headers`] / [`endpoint`]:payload、`apns-*` 头
//!   与请求 URL;
//! - [`parse_answer`]:应答归类(410 / reason=Unregistered|BadDeviceToken 归
//!   令牌失效)。
//!
//! 需要真发 APNs 的部署:外接任意 HTTP/2 客户端(如 hyper h2),用上述纯函数
//! 组装请求,再按 [`parse_answer`] 归类应答,即可与全 crate 的错误语义对齐。
//!
//! # 协议要点
//!
//! - 给 `Message::target`(APNs device token,hex 串)推一条提醒:`title`/`content`
//!   进 `aps.alert`,`params` 作为自定义键展开进顶层 payload(客户端本地渲染路由
//!   按需取),成功回执带 `apns-id`;
//! - APNs 要求 provider 复用连接(HTTP/2 多路复用),频繁建连会被视作 DoS——
//!   因此一个配置一个实例、实例内复用 provider token,多配置另起实例;
//! - .p8 私钥在构造期解析:私钥配错当场暴露,不等第一次投递。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

use crate::notify::{Message, NotifyError, Receipt, Service};

/// 生产网关。
pub const APNS_PRODUCTION_URL: &str = "https://api.push.apple.com";
/// 沙箱网关(开发构建的设备令牌只认沙箱)。
pub const APNS_SANDBOX_URL: &str = "https://api.sandbox.push.apple.com";

/// provider token 的官方有效期 1 小时;提前 10 分钟换新。
const APNS_TOKEN_TTL: Duration = Duration::from_secs(50 * 60);

/// Apple APNs 配置(Token 鉴权)。
#[derive(Debug, Clone, Default)]
pub struct ApnsConfig {
    /// TeamID / KeyID:开发者账号与 .p8 密钥标识。
    pub team_id: String,
    /// .p8 密钥标识。
    pub key_id: String,
    /// 推送主题(`apns-topic` 头,通常为 bundle id)。
    pub bundle_id: String,
    /// .p8 私钥的 PEM 内容(PKCS#8 ECDSA)。
    pub private_key: String,
    /// 走沙箱网关(开发构建的设备令牌只认沙箱)。
    pub sandbox: bool,
    /// 网关基地址,留空按 `sandbox` 切默认;测试可覆盖。
    pub api_base: String,
}

/// Apple APNs 推送渠道。
///
/// **受限实现**:`send` 不出网(HTTP/2 限制,见模块文档),签名与请求构造以
/// 纯函数形式完整公开。
/// [`Apns::build_request`] 的产物:请求端点、头键值对列表、payload 正文。
pub type ApnsRequestParts = (String, Vec<(String, String)>, String);

pub struct Apns {
    cfg: ApnsConfig,
    api_base: String,
    /// .p8 在构造期解析成编码密钥。
    key: EncodingKey,
    /// provider token 缓存:一小时内复用同一枚。
    token: Mutex<CachedToken>,
}

impl std::fmt::Debug for Apns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 密钥与缓存 token 不进 Debug 输出:日志里不该见到私钥材料。
        f.debug_struct("Apns")
            .field("cfg", &self.cfg)
            .field("api_base", &self.api_base)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct CachedToken {
    token: String,
    issued_at: Option<Instant>,
}

impl Apns {
    /// 构造 APNs 渠道。.p8 解析在构造期完成——私钥配错当场暴露,不等第一次投递。
    pub fn new(cfg: ApnsConfig) -> Result<Self, NotifyError> {
        if cfg.private_key.is_empty() {
            return Err(NotifyError::NotConfigured(
                "apns config incomplete: private_key required".into(),
            ));
        }
        let key = EncodingKey::from_ec_pem(cfg.private_key.as_bytes())
            .map_err(|e| NotifyError::NotConfigured(format!("apns private_key parse failed: {e}")))?;
        let api_base = if cfg.api_base.is_empty() {
            if cfg.sandbox {
                APNS_SANDBOX_URL.to_string()
            } else {
                APNS_PRODUCTION_URL.to_string()
            }
        } else {
            cfg.api_base.clone()
        };
        Ok(Apns { cfg, api_base, key, token: Mutex::new(CachedToken::default()) })
    }

    /// 取(缓存的)provider token:ES256 JWT,官方有效期 1 小时。
    fn provider_token(&self) -> Result<String, NotifyError> {
        {
            let cached = self.token.lock().expect("token 锁");
            if let Some(issued_at) = cached.issued_at {
                if !cached.token.is_empty() && issued_at.elapsed() < APNS_TOKEN_TTL {
                    return Ok(cached.token.clone());
                }
            }
        }
        let tok = mint_apns_token(&self.key, &self.cfg.key_id, &self.cfg.team_id, now_unix())?;
        let mut cached = self.token.lock().expect("token 锁");
        cached.token = tok.clone();
        cached.issued_at = Some(Instant::now());
        Ok(tok)
    }

    /// 构造一次推送的完整请求(URL、头、payload),供外接 HTTP/2 客户端复用。
    ///
    /// 返回 [`ApnsRequestParts`]`(endpoint, headers, body)`;provider token 按实例缓存。
    pub fn build_request(&self, msg: &Message) -> Result<ApnsRequestParts, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("apns device token is empty".into()));
        }
        if self.cfg.team_id.is_empty() || self.cfg.key_id.is_empty() || self.cfg.bundle_id.is_empty()
        {
            return Err(NotifyError::NotConfigured(
                "apns config incomplete: team_id/key_id/bundle_id required".into(),
            ));
        }
        let jwt = self.provider_token()?;
        let headers = build_headers(&jwt, &self.cfg.bundle_id);
        let endpoint = endpoint(&self.api_base, &msg.target);
        let payload = build_payload(&msg.title, &msg.content, &msg.params);
        Ok((endpoint, headers, payload))
    }
}

impl Service for Apns {
    fn name(&self) -> &str {
        "apns"
    }

    /// **不可用**:APNs 强制 HTTP/2,内置客户端只讲 HTTP/1.1,详见模块文档。
    ///
    /// 拨号之前拦下,归 [`NotifyError::NotConfigured`];真实投递请用
    /// [`Apns::build_request`] + 外接 HTTP/2 客户端 + [`parse_answer`]。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("apns device token is empty".into()));
        }
        if self.cfg.team_id.is_empty() || self.cfg.key_id.is_empty() || self.cfg.bundle_id.is_empty()
        {
            return Err(NotifyError::NotConfigured(
                "apns config incomplete: team_id/key_id/bundle_id required".into(),
            ));
        }
        Err(NotifyError::NotConfigured(
            "apns requires http/2 which the built-in client does not support".into(),
        ))
    }
}

/// 当前秒级 Unix 时间。
fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// 签一枚 APNs provider token(ES256 JWT):
/// header `{"alg":"ES256","kid":key_id}`(不带 typ,与上游逐字对应),
/// claims `{"iss":team_id,"iat":now}`,签名为 P-256 ECDSA——与 Apple 官方文档对应。
///
/// `iat` 由调用方注入以便离线测试;生产用 `now_unix`。
pub fn mint_apns_token(
    key: &EncodingKey,
    key_id: &str,
    team_id: &str,
    iat: i64,
) -> Result<String, NotifyError> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id.to_string());
    header.typ = None; // 上游手拼的 header 只有 alg/kid
    let claims = Claims { iss: team_id.to_string(), iat };
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| NotifyError::NotConfigured(format!("mint apns provider token failed: {e}")))
}

/// provider token 的 claims:`iss` 是 TeamID(APNs 按它找账号),`iat` 是签发时刻。
#[derive(Serialize)]
struct Claims {
    iss: String,
    iat: i64,
}

/// 构造推送 payload,可独立测试的纯函数:
/// `title`/`content` 进 `aps.alert`,`params` 作为自定义键展开进顶层 payload。
pub fn build_payload(title: &str, content: &str, params: &HashMap<String, String>) -> String {
    let mut payload = serde_json::Map::new();
    payload.insert(
        "aps".to_string(),
        serde_json::json!({
            "alert": {"title": title, "body": content},
            "sound": "default",
        }),
    );
    for (k, v) in params {
        payload.insert(k.clone(), serde_json::Value::from(v.as_str()));
    }
    serde_json::Value::Object(payload).to_string()
}

/// 构造请求头,可独立测试的纯函数:provider token 走 `bearer` 头,
/// `apns-*` 头逐条对齐上游(alert 型、最高优先级、立即过期)。
pub fn build_headers(jwt: &str, bundle_id: &str) -> Vec<(String, String)> {
    vec![
        ("Authorization".to_string(), format!("bearer {jwt}")),
        ("apns-topic".to_string(), bundle_id.to_string()),
        ("apns-push-type".to_string(), "alert".to_string()),
        ("apns-priority".to_string(), "10".to_string()),
        ("apns-expiration".to_string(), "0".to_string()),
    ]
}

/// 构造请求端点:`<api_base>/3/device/<token>`。
pub fn endpoint(api_base: &str, device_token: &str) -> String {
    format!("{api_base}/3/device/{device_token}")
}

/// 应答归类,可独立测试的纯函数。
///
/// 200 成功(`apns_id` 进回执);410 或 `apns-error-reason` 为
/// `Unregistered`/`BadDeviceToken` 归令牌失效(应用卸载/系统重置,调用方删行自
/// 清理,不算投递失败重试);其余按投递失败。
pub fn parse_answer(
    status: u16,
    reason: Option<&str>,
    apns_id: Option<&str>,
    body: &str,
) -> Result<Option<String>, NotifyError> {
    let invalid_reason = matches!(reason, Some("Unregistered") | Some("BadDeviceToken"));
    if status == 200 {
        return Ok(apns_id.map(|s| s.to_string()));
    }
    if status == 410 || invalid_reason {
        return Err(NotifyError::InvalidToken(format!("http {status}")));
    }
    Err(NotifyError::Delivery(format!(
        "apns push rejected: status={status} reason={}: {}",
        reason.unwrap_or(""),
        super::err_snippet(body)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试专用 P-256 .p8 私钥(进程内生成的固定测试密钥,绝非生产凭据)。
    const TEST_P8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgucIGqWOX4+m8RinG
AZlu+856/c7sp7Xyph5PYfw20DuhRANCAASnb0pAzyMV6BkIbruyEUz7OigGvXFc
JovJXTlKl+9S8eeXRM8cqE4Da6/zwyHcpasroUk1mTOsTclJBZToCyfP
-----END PRIVATE KEY-----
";

    fn config() -> ApnsConfig {
        ApnsConfig {
            team_id: "TEAM".into(),
            key_id: "KEY-1".into(),
            bundle_id: "com.example.app".into(),
            private_key: TEST_P8_PEM.into(),
            ..Default::default()
        }
    }

    /// base64url(无填充)解码 JWT 段。
    fn jwt_segment(token: &str, idx: usize) -> Vec<u8> {
        use base64_seg::*;
        decode(token.split('.').nth(idx).expect("JWT 三段式"))
    }

    // 极简 base64url 解码(仅测试用)。
    mod base64_seg {
        pub fn decode(seg: &str) -> Vec<u8> {
            let mut vals = Vec::with_capacity(seg.len());
            for c in seg.bytes() {
                let v = match c {
                    b'A'..=b'Z' => (c - b'A') as u32,
                    b'a'..=b'z' => (c - b'a' + 26) as u32,
                    b'0'..=b'9' => (c - b'0' + 52) as u32,
                    b'-' => 62,
                    b'_' => 63,
                    _ => panic!("非 base64url 字符: {c}"),
                };
                vals.push(v);
            }
            let mut out = Vec::new();
            for chunk in vals.chunks(4) {
                // 6 位组左对齐到 32 位字顶部,再取前 (组长度-1) 个整字节
                // (无填充段:余组不足 4 字符,低位补零后整字节即原文)。
                let n = chunk.iter().fold(0u32, |acc, &v| (acc << 6) | v)
                    << (32 - chunk.len() * 6);
                let bytes = n.to_be_bytes();
                let take = chunk.len() - 1;
                out.extend_from_slice(&bytes[..take]);
            }
            out
        }
    }

    /// 对齐上游 TestNewAPNsParsesP8Key:p8 在构造期解析,坏 PEM 归配置类;
    /// 默认生产网关,沙箱开关切沙箱网关。
    #[test]
    fn test_new_parses_p8_key() {
        let svc = Apns::new(config()).expect("合法 p8 应构造成功");
        assert_eq!(Service::name(&svc), "apns");
        assert_eq!(svc.api_base, APNS_PRODUCTION_URL, "默认生产网关");

        let sandbox = Apns::new(ApnsConfig { sandbox: true, ..config() }).unwrap();
        assert_eq!(sandbox.api_base, APNS_SANDBOX_URL, "沙箱开关切沙箱网关");

        let err = Apns::new(ApnsConfig {
            private_key: "not a pem".into(),
            ..ApnsConfig::default()
        })
        .unwrap_err();
        assert!(err.is_not_configured(), "坏 PEM 是配置问题: {err}");

        let err = Apns::new(ApnsConfig::default()).unwrap_err();
        assert!(err.to_string().contains("private_key required"));
    }

    /// 对齐上游 TestMintAPNsTokenStructure:三段式 JWT,header 带 alg/kid(无 typ,
    /// 与上游手拼形态逐字对应),claims 是 iss(TeamID)+iat。
    #[test]
    fn test_mint_apns_token_structure() {
        let key = EncodingKey::from_ec_pem(TEST_P8_PEM.as_bytes()).unwrap();
        let tok = mint_apns_token(&key, "KEY-1", "TEAM-9", 1_760_000_000).unwrap();

        let parts: Vec<&str> = tok.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT 三段式: {tok}");

        let header: serde_json::Value =
            serde_json::from_slice(&jwt_segment(&tok, 0)).expect("header 是 JSON");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY-1");
        assert!(header.get("typ").is_none(), "上游手拼 header 不含 typ");

        let claims: serde_json::Value =
            serde_json::from_slice(&jwt_segment(&tok, 1)).expect("claims 是 JSON");
        assert_eq!(claims["iss"], "TEAM-9", "iss 是 TeamID:APNs 按它找账号");
        assert_eq!(claims["iat"], 1_760_000_000, "iat 由调用方注入");
    }

    /// token 缓存:同一实例一小时内复用同一枚(签名输入一致)。
    #[test]
    fn test_provider_token_cached() {
        let svc = Apns::new(config()).unwrap();
        let t1 = svc.provider_token().unwrap();
        let t2 = svc.provider_token().unwrap();
        assert_eq!(t1, t2, "一小时窗口内应复用同一枚 provider token");
    }

    /// payload/头/端点构造对齐上游 Send 的请求形状。
    #[test]
    fn test_request_construction() {
        let mut params = HashMap::new();
        params.insert("msg_id".to_string(), "7".to_string());
        let payload = build_payload("重置验证码", "您的验证码是 123456", &params);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["aps"]["alert"]["title"], "重置验证码");
        assert_eq!(v["aps"]["alert"]["body"], "您的验证码是 123456");
        assert_eq!(v["aps"]["sound"], "default");
        assert_eq!(v["msg_id"], "7", "Params 展开为顶层自定义键,客户端本地路由按需取");

        let headers = build_headers("eyJ", "com.example.app");
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
                .unwrap()
        };
        assert_eq!(get("Authorization"), "bearer eyJ", "provider token 走 bearer 头");
        assert_eq!(get("apns-topic"), "com.example.app");
        assert_eq!(get("apns-push-type"), "alert");
        assert_eq!(get("apns-priority"), "10");
        assert_eq!(get("apns-expiration"), "0");

        assert_eq!(
            endpoint(APNS_PRODUCTION_URL, &"a".repeat(64)),
            format!("{}/3/device/{}", APNS_PRODUCTION_URL, "a".repeat(64))
        );
    }

    /// 对齐上游 TestAPNsInvalidToken:410 或 reason=Unregistered/BadDeviceToken
    /// 都归令牌失效——调用方删行自清理,不算投递失败重试。
    #[test]
    fn test_invalid_token_classification() {
        let cases = [
            (410, Some("Unregistered")),
            (400, Some("BadDeviceToken")),
            (400, Some("Unregistered")),
        ];
        for (status, reason) in cases {
            let err = parse_answer(status, reason, None, "{}").unwrap_err();
            assert!(
                err.is_invalid_token(),
                "http {status} reason {reason:?} 应归 InvalidToken,得到 {err}"
            );
        }
    }

    /// 对齐上游 TestAPNsPeerRejection:非失效类拒绝是投递失败,不是令牌失效。
    #[test]
    fn test_peer_rejection_classification() {
        let err = parse_answer(413, Some("PayloadTooLarge"), None, "payload too large").unwrap_err();
        assert!(!err.is_invalid_token(), "{err}");
        assert!(matches!(err, NotifyError::Delivery(_)));
        assert!(err.to_string().contains("PayloadTooLarge"));
        // 200 成功:apns-id 进回执
        let id = parse_answer(200, None, Some("apns-msg-1"), "{}").unwrap().unwrap();
        assert_eq!(id, "apns-msg-1");
    }

    /// send 受限:不出网,拨号之前返回 NotConfigured;目标/配置校验先行。
    #[test]
    fn test_send_is_gated_on_http2() {
        let svc = Apns::new(config()).unwrap();
        let err = svc.send(&Message::new("a".repeat(64), "t")).unwrap_err();
        assert!(err.is_not_configured());
        assert!(
            err.to_string().contains("http/2"),
            "错误文案要点名 HTTP/2 限制: {err}"
        );

        // 目标为空在限制检查之前拦下
        let err = svc.send(&Message::new("", "t")).unwrap_err();
        assert!(err.to_string().contains("device token is empty"), "{err}");

        // 配置不全同样先行
        let svc = Apns::new(ApnsConfig {
            team_id: String::new(),
            ..config()
        })
        .unwrap();
        let err = svc.send(&Message::new("tok", "t")).unwrap_err();
        assert!(err.to_string().contains("team_id/key_id/bundle_id"), "{err}");
    }

    /// build_request:外接 HTTP/2 客户端可拿齐 URL/头/payload 三件套。
    #[test]
    fn test_build_request_offline() {
        let mut cfg = config();
        cfg.api_base = "https://api.example.test".into();
        let svc = Apns::new(cfg).unwrap();
        let msg = Message::new("tok64", "t").with_content("c");
        let (endpoint, headers, payload) = svc.build_request(&msg).unwrap();
        assert_eq!(endpoint, "https://api.example.test/3/device/tok64");
        assert!(headers.iter().any(|(k, v)| k == "Authorization" && v.starts_with("bearer ey")));
        assert!(payload.contains(r#""aps""#));
    }
}
