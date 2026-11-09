//! 个推(GeTui)v2 REST API:sign 鉴权 + cid 单播,裸 HTTP,feature `notify`。
//! 对齐上游 `notify/getui/getui.go`。
//!
//! 两步协议:先拿鉴权 token(`POST /v2/{app_id}/auth`,`sign =
//! sha256(appkey + timestamp + mastersecret)` 小写 hex,毫秒时间戳),再推单播
//! (`POST /v2/{app_id}/push/single/cid`,token 走自定义 `token` 头)。token 按
//! 实例缓存,提前 60 秒刷新(厂商给了毫秒级过期时间);
//! `request_id` 随机生成防重(同 id 一小时内重复推送会被厂商去重丢弃)。
//!
//! 个推 v2 单播应答只回受理状态,回执无厂商消息 ID,留空。
//!
//! 与上游 Go 版的差异:`Config.Ref`(展示标识,只进错误文案)未移植;
//! `context.Context` 取消传播在本 crate 的阻塞式 API 里不存在。
//!
//! 测试离线进行:sign、鉴权体、payload 与应答解析拆成纯函数断言,不真实连网。

use std::sync::Mutex;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::notify::{check_target, map_ureq_error, new_client, Message, NotifyError, Receipt};

/// 个推 REST API 域。
pub const DEFAULT_API_BASE: &str = "https://restapi.getui.com";

/// 鉴权 token 提前刷新余量(毫秒):厂商给了毫秒级过期时间,卡着过期线走
/// 容易撞上两端时钟差。
const TOKEN_REFRESH_MARGIN_MS: i64 = 60_000;

/// 厂商过期时刻不可用(时钟未对齐,过期时刻已过)时的缓存时长兜底(毫秒)。
const AUTH_TTL_FALLBACK_MS: i64 = 3_600_000;

/// 进错误文案的响应片段上限:对端可能回一整页 HTML。
const SNIPPET_LIMIT: usize = 256;

/// 个推配置。cid 按消息传。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 应用三元组凭据:AppID。
    pub app_id: String,
    /// 应用三元组凭据:AppKey。
    pub app_key: String,
    /// 应用三元组凭据:MasterSecret。
    pub master_secret: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// 缓存的鉴权 token。
#[derive(Default)]
struct CachedToken {
    token: String,
    /// 过期时刻(本机时钟毫秒),已含提前刷新余量。
    expires_at_ms: i64,
}

/// 个推渠道。鉴权 token 按实例缓存(并发安全)。
pub struct Service {
    agent: ureq::Agent,
    cfg: Config,
    token: Mutex<CachedToken>,
}

/// 构造好的出站请求:纯数据,供离线测试断言。
struct Prepared {
    url: String,
    body: String,
    content_type: &'static str,
    headers: Vec<(&'static str, String)>,
}

impl Service {
    /// 构造个推渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
    pub fn new(cfg: Config) -> Self {
        let mut cfg = cfg;
        if cfg.api_base.is_empty() {
            cfg.api_base = DEFAULT_API_BASE.to_string();
        }
        Service {
            agent: new_client(crate::notify::allow_private_target()),
            cfg,
            token: Mutex::new(CachedToken::default()),
        }
    }

    /// 构造单播请求(纯函数):cid 进路径,token 走自定义请求头,
    /// payload 为通知栏消息 + 防重的 request_id。
    fn build_push_request(&self, token: &str, request_id: &str, msg: &Message) -> Prepared {
        Prepared {
            url: format!(
                "{}/v2/{}/push/single/cid",
                self.cfg.api_base, self.cfg.app_id
            ),
            body: build_push_payload(&msg.title, &msg.content, request_id).to_string(),
            content_type: "application/json; charset=utf-8",
            headers: vec![("token", token.to_string())],
        }
    }

    /// 取(缓存的)鉴权 token:`sign = sha256(appkey + timestamp + mastersecret)`。
    fn auth_token(&self) -> Result<String, NotifyError> {
        let now = utc_now_ms();
        {
            let cached = self.token.lock().unwrap_or_else(|e| e.into_inner());
            if !cached.token.is_empty() && now < cached.expires_at_ms {
                return Ok(cached.token.clone());
            }
        }

        let timestamp = utc_now_ms().to_string();
        let auth = Prepared {
            url: format!("{}/v2/{}/auth", self.cfg.api_base, self.cfg.app_id),
            body: build_auth_body(&self.cfg.app_key, &timestamp, &self.cfg.master_secret),
            content_type: "application/json; charset=utf-8",
            headers: Vec::new(),
        };
        let (status, body) = self.post(&auth)?;
        let (token, expire_time) = parse_auth_answer(status, &body)?;

        let mut cached = self.token.lock().unwrap_or_else(|e| e.into_inner());
        *cached = CachedToken {
            expires_at_ms: token_expires_at(utc_now_ms(), expire_time),
            token: token.clone(),
        };
        Ok(token)
    }

    /// POST 已构造好的请求(含 SSRF 预检),返回 (状态码, 应答文本)。
    /// 非 2xx 也返回应答文本,由各解析函数按厂商语义归类。
    fn post(&self, req: &Prepared) -> Result<(u16, String), NotifyError> {
        check_target(&req.url)?;
        let mut request = self
            .agent
            .post(&req.url)
            .set("Content-Type", req.content_type);
        for (name, value) in &req.headers {
            request = request.set(name, value);
        }
        match request.send_string(&req.body) {
            Ok(resp) => Ok((resp.status(), read_answer(resp)?)),
            Err(ureq::Error::Status(status, resp)) => Ok((status, read_answer(resp)?)),
            Err(err) => Err(map_ureq_error(err)),
        }
    }
}

impl crate::notify::Service for Service {
    fn name(&self) -> &str {
        "getui"
    }

    /// 给 Target(个推 cid)推一条通知栏消息:Title 为通知栏标题,Content 为
    /// 通知内容;个推 v2 单播应答只回受理状态,[`Receipt::provider_id`] 留空。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("getui cid is empty".into()));
        }
        if self.cfg.app_id.is_empty()
            || self.cfg.app_key.is_empty()
            || self.cfg.master_secret.is_empty()
        {
            return Err(NotifyError::NotConfigured(
                "getui config incomplete: app_id/app_key/master_secret required".into(),
            ));
        }
        let token = self.auth_token()?;
        let req = self.build_push_request(&token, &rand_text(), msg);
        let (status, body) = self.post(&req)?;
        parse_push_answer(status, &body)?;
        Ok(Receipt::default())
    }
}

// ---------------------------------------------------------------------------
// 可独立测试的纯函数
// ---------------------------------------------------------------------------

/// 鉴权 sign:`sha256(appkey + timestamp + mastersecret)` 小写 hex。
/// 签名细节漂移只改这里。
pub fn auth_sign(app_key: &str, timestamp: &str, master_secret: &str) -> String {
    sha256_hex(format!("{app_key}{timestamp}{master_secret}").as_bytes())
}

/// 构造鉴权请求体(`{"sign","timestamp","appkey"}`),可独立测试的纯函数。
pub fn build_auth_body(app_key: &str, timestamp: &str, master_secret: &str) -> String {
    json!({
        "sign": auth_sign(app_key, timestamp, master_secret),
        "timestamp": timestamp,
        "appkey": app_key,
    })
    .to_string()
}

/// 构造单播请求 payload,可独立测试的纯函数:
/// `push_message.notification` 为通知栏消息(`push_type: notify`);
/// `request_id` 要防重:同 id 一小时内重复推送会被厂商去重丢弃。
pub fn build_push_payload(title: &str, content: &str, request_id: &str) -> Value {
    json!({
        "request_id": request_id,
        "push_message": {
            "notification": {
                "title": title,
                "body": content,
                "push_type": "notify",
            },
        },
    })
}

/// 缓存过期时刻(本机时钟毫秒):厂商给的 `expire_time` 提前
/// 60 秒刷新;厂商时钟未对齐(过期时刻已过)时兜底一小时。
pub fn token_expires_at(now_ms: i64, expire_time: i64) -> i64 {
    let ttl = expire_time - now_ms;
    let ttl = if ttl <= 0 { AUTH_TTL_FALLBACK_MS } else { ttl };
    now_ms + ttl - TOKEN_REFRESH_MARGIN_MS
}

/// 解析鉴权应答,可独立测试的纯函数:2xx 且 `code == 0` 才算拿到 token,
/// 返回 `(token, expire_time 原始毫秒值)`。
fn parse_auth_answer(status: u16, body: &str) -> Result<(String, i64), NotifyError> {
    if !(200..300).contains(&status) {
        return Err(NotifyError::Delivery(format!(
            "auth endpoint answered {status}: {}",
            snippet(body)
        )));
    }
    #[derive(serde::Deserialize, Default)]
    struct AuthAnswer {
        #[serde(default)]
        code: i64,
        #[serde(default)]
        msg: String,
        #[serde(default)]
        data: AuthData,
    }
    #[derive(serde::Deserialize, Default)]
    struct AuthData {
        #[serde(default)]
        token: String,
        #[serde(default)]
        expire_time: i64,
    }
    let answer: AuthAnswer = serde_json::from_str(body).map_err(|_| {
        NotifyError::Delivery(format!("auth answer is not JSON: {}", snippet(body)))
    })?;
    if answer.code != 0 || answer.data.token.is_empty() {
        let msg = if answer.msg.is_empty() {
            "no message"
        } else {
            &answer.msg
        };
        return Err(NotifyError::Delivery(format!(
            "auth endpoint answered code={}: {msg}",
            answer.code
        )));
    }
    Ok((answer.data.token, answer.data.expire_time))
}

/// 解析单播应答,可独立测试的纯函数:2xx 且 `code == 0` 才是受理了。
fn parse_push_answer(status: u16, body: &str) -> Result<(), NotifyError> {
    if !(200..300).contains(&status) {
        return Err(NotifyError::Delivery(format!(
            "peer answered {status}: {}",
            snippet(body)
        )));
    }
    #[derive(serde::Deserialize, Default)]
    struct Answer {
        #[serde(default)]
        code: i64,
        #[serde(default)]
        msg: String,
    }
    let answer: Answer = serde_json::from_str(body).map_err(|_| {
        NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body)))
    })?;
    if answer.code != 0 {
        let msg = if answer.msg.is_empty() {
            "no message"
        } else {
            &answer.msg
        };
        return Err(NotifyError::Delivery(format!(
            "peer answered code={}: {msg}",
            answer.code
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/// SHA-256 小写 hex。
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut out = String::with_capacity(64);
    for b in hasher.finalize() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 本机时钟毫秒。
fn utc_now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// 随机 request_id(对齐 Go crypto/rand.Text:16 随机字节的 URL-safe base64,
/// 22 字符,无填充)。
fn rand_text() -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("系统随机源不可用时推送无从谈起");
    let mut out = String::with_capacity(22);
    for chunk in buf.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6 & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        }
    }
    out
}

/// 读对端应答文本。
fn read_answer(resp: ureq::Response) -> Result<String, NotifyError> {
    resp.into_string()
        .map_err(|e| NotifyError::Delivery(format!("read peer answer: {e}")))
}

/// 进错误文案的响应片段截断(按字节上限回退到字符边界)。
fn snippet(body: &str) -> String {
    if body.len() <= SNIPPET_LIMIT {
        return body.to_string();
    }
    let mut end = SNIPPET_LIMIT;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\u{2026}", &body[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::Service as _;

    fn full_cfg() -> Config {
        Config {
            app_id: "app-1".into(),
            app_key: "key-1".into(),
            master_secret: "ms-1".into(),
            ..Config::default()
        }
    }

    #[test]
    fn test_name() {
        assert_eq!(Service::new(full_cfg()).name(), "getui");
    }

    // 对齐上游 TestSendConfigIssue:缺 master_secret / 空 cid 在拨号之前拦下。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config {
            app_id: "a".into(),
            app_key: "k".into(),
            ..Config::default()
        })
        .send(&Message::new("cid", "t").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(
            err.to_string()
                .contains("app_id/app_key/master_secret required"),
            "{err}"
        );

        let err = Service::new(full_cfg())
            .send(&Message::new("", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("cid is empty"), "{err}");
    }

    // SSRF 预检:环回目标在鉴权一步就被拦(鉴权 URL 是本渠道拨的第一个地址)。
    #[test]
    fn test_blocked_target() {
        let cfg = Config {
            app_id: "a".into(),
            app_key: "k".into(),
            master_secret: "s".into(),
            api_base: "http://127.0.0.1:9".into(),
        };
        let err = Service::new(cfg)
            .send(&Message::new("cid", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // sign 纯函数:sha256(appkey+timestamp+mastersecret) 小写 hex,
    // 拼接顺序钉住(顺序错对端只会回 sign fail)。
    #[test]
    fn test_auth_sign() {
        let sign = auth_sign("key-1", "1760000000000", "ms-1");
        let mut hasher = Sha256::new();
        hasher.update(b"key-11760000000000ms-1");
        let want: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(sign, want);
        assert_eq!(sign.len(), 64, "sign 是 sha256 hex");
        assert!(
            sign.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "sign 是小写 hex: {sign}"
        );
    }

    // sha256_hex 对标准测试向量(签名的地基先钉死)。
    #[test]
    fn test_sha256_hex_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // 对齐上游 TestSendDeliversNotificationViaCID 的鉴权请求体断言:
    // appkey 进体、timestamp 非空、sign 是 64 位 sha256 hex。
    #[test]
    fn test_build_auth_body() {
        let body: Value =
            serde_json::from_str(&build_auth_body("key-1", "1760000000000", "ms-1")).unwrap();
        assert_eq!(body["appkey"], "key-1");
        assert_eq!(body["timestamp"], "1760000000000");
        assert_eq!(
            body["sign"].as_str().map(str::len),
            Some(64),
            "sign 是 sha256 hex"
        );
    }

    // 对齐上游 TestSendDeliversNotificationViaCID 的单播 payload 断言:
    // title/body/push_type 就位,request_id 防重必备。
    #[test]
    fn test_build_push_payload() {
        let payload = build_push_payload("重置验证码", "您的验证码是 123456", "req-abc");
        let notification = &payload["push_message"]["notification"];
        assert_eq!(notification["title"], "重置验证码");
        assert_eq!(notification["body"], "您的验证码是 123456");
        assert_eq!(notification["push_type"], "notify");
        assert_eq!(payload["request_id"], "req-abc");
    }

    // 单播请求:cid 进路径,token 走自定义 token 头。
    #[test]
    fn test_build_push_request() {
        let svc = Service::new(full_cfg());
        let req = svc.build_push_request(
            "gt-token",
            "req-abc",
            &Message::new("cid-1", "重置验证码").with_content("您的验证码是 123456"),
        );
        assert_eq!(
            req.url,
            "https://restapi.getui.com/v2/app-1/push/single/cid"
        );
        assert_eq!(req.content_type, "application/json; charset=utf-8");
        assert_eq!(
            req.headers[0],
            ("token", "gt-token".to_string()),
            "鉴权 token 走自定义 token 头"
        );
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["request_id"], "req-abc");
    }

    // token 缓存时刻:正常情况提前 60 秒;厂商时刻已过则兜底一小时(同样扣余量)。
    #[test]
    fn test_token_expires_at() {
        const MARGIN: i64 = 60_000;
        const FALLBACK: i64 = 3_600_000;
        assert_eq!(
            token_expires_at(1_000, 1_760_000_000_000),
            1_760_000_000_000 - MARGIN
        );
        assert_eq!(
            token_expires_at(1_000_000, 1_000),
            1_000_000 + FALLBACK - MARGIN
        );
    }

    // rand_text:22 字符 URL-safe 字母表,两次调用不重复。
    #[test]
    fn test_rand_text() {
        let text = rand_text();
        assert_eq!(text.len(), 22, "16 字节的 RawURL base64 是 22 字符: {text}");
        assert!(
            text.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{text}"
        );
        assert_ne!(rand_text(), text, "随机源不可复现");
    }

    // 鉴权应答解析:token/expire_time 就位;厂商码非 0 / token 缺失 / 非 JSON /
    // HTTP 层失败各自归类。
    #[test]
    fn test_parse_auth_answer() {
        let (token, expire_time) = parse_auth_answer(
            200,
            r#"{"code":0,"msg":"success","data":{"token":"gt-token","expire_time":1760000000000}}"#,
        )
        .unwrap();
        assert_eq!(token, "gt-token");
        assert_eq!(expire_time, 1760000000000);

        let err = parse_auth_answer(200, r#"{"code":10001,"msg":"token expired"}"#).unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("code=10001"), "{err}");

        // code=0 但 token 缺失:鉴权应答不完整,按失败带出厂商 msg。
        let err = parse_auth_answer(200, r#"{"code":0,"msg":"success"}"#).unwrap_err();
        assert!(err.to_string().contains("code=0"), "{err}");

        let err = parse_auth_answer(500, "boom").unwrap_err();
        assert!(
            err.to_string().contains("auth endpoint answered 500"),
            "{err}"
        );

        let err = parse_auth_answer(200, "<html>gateway</html>").unwrap_err();
        assert!(err.to_string().contains("not JSON"), "{err}");
    }

    // 单播应答解析:code=0 受理;厂商码非 0 归投递失败并带 code。
    #[test]
    fn test_parse_push_answer() {
        assert!(parse_push_answer(200, r#"{"code":0,"msg":"success"}"#).is_ok());

        let err = parse_push_answer(200, r#"{"code":10001,"msg":"token expired"}"#).unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("code=10001"), "{err}");

        let err = parse_push_answer(200, r#"{"code":3}"#).unwrap_err();
        assert!(err.to_string().contains("no message"), "{err}");

        let err = parse_push_answer(503, "unavailable").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");

        let err = parse_push_answer(200, "<html>gateway</html>").unwrap_err();
        assert!(err.to_string().contains("not JSON"), "{err}");
    }
}
