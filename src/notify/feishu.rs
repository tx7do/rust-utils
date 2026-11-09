//! 飞书应用消息渠道(im/v1/messages),零 SDK。
//!
//! 与群机器人(notify/webhook 的飞书风格)分工:机器人推群、凭签名 webhook;
//! 本渠道凭 app_id/app_secret 发**单聊/指定接收人**的应用消息。
//!
//! tenant_access_token 按实例缓存(过期前留余量);对端报 token 失效码
//! (99991663/99991661)时强刷一枚重试一次。测试离线进行:token/推送请求
//! 构造与应答解析拆成纯函数断言,不真实连网。

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::notify::{check_target, map_ureq_error, new_client, Message, NotifyError, Receipt};

/// 飞书开放平台域(国际版 Lark 用 [`Config::api_base`] 覆写为 <https://open.larksuite.com>)。
pub const DEFAULT_API_BASE: &str = "https://open.feishu.cn";

/// 默认接收人类型(open_id);支持 open_id/user_id/union_id/email/chat_id。
pub const RECEIVE_ID_TYPE_DEFAULT: &str = "open_id";

/// token 失效码:强刷一枚重试一次。
const ERR_CODE_TOKEN_INVALID: i64 = 99991663;
const ERR_CODE_TOKEN_EXPIRED: i64 = 99991661;

/// token 提前刷新余量。
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// 对端没给 expire 时的兜底有效期(飞书文档默认 7200s)。
const TOKEN_DEFAULT_TTL: i64 = 7200;

/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// 飞书应用消息配置。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 应用凭据 App ID。
    pub app_id: String,
    /// 应用凭据 App Secret。
    pub app_secret: String,
    /// 接收人 ID 类型,留空 open_id。
    pub receive_id_type: String,
    /// 域,留空用飞书;Lark 国际版可覆盖。
    pub api_base: String,
}

/// 飞书应用消息渠道。tenant_access_token 按实例缓存(并发安全)。
pub struct Service {
    agent: ureq::Agent,
    cfg: Config,
    token: Mutex<TokenState>,
}

/// 缓存的 tenant_access_token 与到期时刻(单调钟)。
#[derive(Default)]
struct TokenState {
    token: String,
    expires_at: Option<Instant>,
}

/// 构造好的出站请求:纯数据,供离线测试断言。
struct Prepared {
    url: String,
    body: String,
    content_type: &'static str,
    headers: Vec<(&'static str, String)>,
}

impl Service {
    /// 构造飞书应用消息渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
    pub fn new(cfg: Config) -> Self {
        let mut cfg = cfg;
        if cfg.api_base.is_empty() {
            cfg.api_base = DEFAULT_API_BASE.to_string();
        }
        if cfg.receive_id_type.is_empty() {
            cfg.receive_id_type = RECEIVE_ID_TYPE_DEFAULT.to_string();
        }
        Service {
            agent: new_client(crate::notify::allow_private_target()),
            cfg,
            token: Mutex::new(TokenState::default()),
        }
    }

    /// 构造取 token 请求(纯函数):凭据进 JSON body。
    fn build_token_request(cfg: &Config) -> Prepared {
        Prepared {
            url: format!(
                "{}/open-apis/auth/v3/tenant_access_token/internal",
                cfg.api_base.trim_end_matches('/')
            ),
            body: json!({
                "app_id": cfg.app_id,
                "app_secret": cfg.app_secret,
            })
            .to_string(),
            content_type: "application/json; charset=utf-8",
            headers: Vec::new(),
        }
    }

    /// 解析 token 应答(纯函数):返回 (tenant_access_token, 有效期秒数)。
    fn parse_token_answer(status: u16, body: &str) -> Result<(String, i64), NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "token endpoint answered {status}: {}",
                snippet(body)
            )));
        }
        let answer: Value = serde_json::from_str(body).map_err(|_| {
            NotifyError::Delivery(format!("token answer is not JSON: {}", snippet(body)))
        })?;
        let code = answer.get("code").and_then(Value::as_i64).unwrap_or(0);
        let token = answer
            .get("tenant_access_token")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let expire = answer.get("expire").and_then(Value::as_i64).unwrap_or(0);
        if code != 0 || token.is_empty() {
            let msg = answer
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            return Err(NotifyError::Delivery(format!(
                "token endpoint answered code={code}: {msg}"
            )));
        }
        Ok((token, expire))
    }

    /// 构造推送请求(纯函数):Bearer 令牌进鉴权头,receive_id_type 进 query;
    /// 飞书的 content 字段是"JSON 字符串套 JSON"——内层对象先序列化成串再嵌进去。
    fn build_push_request(&self, token: &str, msg: &Message) -> Result<Prepared, NotifyError> {
        let content = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };
        let inner = json!({ "text": content }).to_string();
        let payload = json!({
            "receive_id": msg.target,
            "msg_type": "text",
            "content": inner,
        });
        Ok(Prepared {
            url: format!(
                "{}/open-apis/im/v1/messages?receive_id_type={}",
                self.cfg.api_base.trim_end_matches('/'),
                query_escape(&self.cfg.receive_id_type),
            ),
            body: payload.to_string(),
            content_type: "application/json; charset=utf-8",
            headers: vec![("Authorization", format!("Bearer {token}"))],
        })
    }

    /// 解析推送应答(纯函数):code==0 即受理,message_id 进回执。
    fn parse_push_answer(status: u16, body: &str) -> Result<Receipt, NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "peer answered {status}: {}",
                snippet(body)
            )));
        }
        let answer: Value = serde_json::from_str(body).map_err(|_| {
            NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body)))
        })?;
        let code = answer.get("code").and_then(Value::as_i64).unwrap_or(0);
        if code != 0 {
            let msg = answer
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            return Err(NotifyError::Delivery(format!(
                "peer answered code={code}: {msg}"
            )));
        }
        let provider_id = answer
            .pointer("/data/message_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok(Receipt { provider_id })
    }

    /// 判定是否 token 失效错误(只认投递错误凭失效码识别;配置类失败
    /// 不该触发强刷):失效则丢弃缓存、强刷一枚重试一次。
    fn is_token_err(err: &NotifyError) -> bool {
        let NotifyError::Delivery(msg) = err else {
            return false;
        };
        msg.contains(&format!("code={ERR_CODE_TOKEN_INVALID}"))
            || msg.contains(&format!("code={ERR_CODE_TOKEN_EXPIRED}"))
    }

    /// 取(缓存的)tenant_access_token:过期前留余量,到点才换新。
    fn access_token(&self) -> Result<String, NotifyError> {
        {
            let st = self.lock_token();
            if !st.token.is_empty() && st.expires_at.is_some_and(|t| Instant::now() < t) {
                return Ok(st.token.clone());
            }
        }
        let req = Self::build_token_request(&self.cfg);
        check_target(&req.url)?;
        let (status, body) = self.post(&req)?;
        let (token, expire) = Self::parse_token_answer(status, &body)?;
        let ttl = if expire <= 0 {
            TOKEN_DEFAULT_TTL as u64
        } else {
            expire as u64
        };
        let mut st = self.lock_token();
        st.token = token.clone();
        st.expires_at = Some(
            Instant::now()
                + Duration::from_secs(ttl.saturating_sub(TOKEN_REFRESH_MARGIN.as_secs())),
        );
        Ok(token)
    }

    /// 丢弃缓存的 token:对端报失效码时强刷用。
    fn invalidate_token(&self) {
        let mut st = self.lock_token();
        st.token = String::new();
        st.expires_at = None;
    }

    fn lock_token(&self) -> MutexGuard<'_, TokenState> {
        self.token.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// POST 已构造好的请求,返回 (状态码, 应答文本)。
    fn post(&self, req: &Prepared) -> Result<(u16, String), NotifyError> {
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
        "feishu"
    }

    /// 给 Target(按 receive_id_type 解释:open_id/user_id/union_id/email/chat_id)
    /// 发一条文本消息。[`Receipt::provider_id`] 带回飞书的 message_id。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "feishu receive_id is empty".to_string(),
            ));
        }
        if self.cfg.app_id.is_empty() || self.cfg.app_secret.is_empty() {
            return Err(NotifyError::NotConfigured(
                "feishu config incomplete: app_id/app_secret required".to_string(),
            ));
        }
        // 先序列化好载荷:token 失效重试发的是同一份。
        let req = self.build_push_request("", msg)?;
        let token = self.access_token()?;
        let req = Prepared {
            headers: vec![("Authorization", format!("Bearer {token}"))],
            ..req
        };
        check_target(&req.url)?;
        match self.post(&req) {
            Ok((status, body)) => Self::parse_push_answer(status, &body),
            Err(err) if Self::is_token_err(&err) => {
                // token 在缓存窗口内被飞书侧作废是常态外的事:强刷一枚再试一次。
                self.invalidate_token();
                let token = self.access_token()?;
                let req = Prepared {
                    headers: vec![("Authorization", format!("Bearer {token}"))],
                    ..req
                };
                check_target(&req.url)?;
                let (status, body) = self.post(&req)?;
                Self::parse_push_answer(status, &body)
            }
            Err(err) => Err(err),
        }
    }
}

/// 读对端应答文本。
fn read_answer(resp: ureq::Response) -> Result<String, NotifyError> {
    resp.into_string()
        .map_err(|e| NotifyError::Delivery(format!("read peer answer: {e}")))
}

/// query 组件编码:保留字符(A-Z a-z 0-9 - _ . ~)原样,空格转 +,
/// 其余字节按 %XX(大写十六进制)。对齐 Go 的 url.QueryEscape。
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
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

    fn svc() -> Service {
        Service::new(Config {
            app_id: "app-1".into(),
            app_secret: "secret-1".into(),
            api_base: "https://open.example.test".into(),
            ..Config::default()
        })
    }

    #[test]
    fn test_name_and_default_receive_id_type() {
        let svc = Service::new(Config::default());
        assert_eq!(svc.name(), "feishu");
        assert_eq!(svc.cfg.receive_id_type, RECEIVE_ID_TYPE_DEFAULT);
    }

    // 配置缺失/目标缺失在拨号之前就拦下,归 NotConfigured。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config {
            app_id: "a".into(),
            ..Config::default()
        })
        .send(&Message::new("ou_x", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("app_id/app_secret"));

        let err = svc()
            .send(&Message::new("", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("receive_id is empty"));
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget(token 端点先于推送端点)。
    #[test]
    fn test_blocked_target() {
        let svc = Service::new(Config {
            app_id: "a".into(),
            app_secret: "s".into(),
            api_base: "http://127.0.0.1:9".into(),
            ..Config::default()
        });
        let err = svc
            .send(&Message::new("ou_x", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 取 token 请求构造(纯函数):凭据进 JSON body。
    #[test]
    fn test_build_token_request() {
        let req = Service::build_token_request(&Config {
            app_id: "app-1".into(),
            app_secret: "secret-1".into(),
            ..Config::default()
        });
        assert!(req
            .url
            .ends_with("/open-apis/auth/v3/tenant_access_token/internal"));
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["app_id"], "app-1");
        assert_eq!(payload["app_secret"], "secret-1");
    }

    // token 应答解析:取 token 与有效期;错误码归投递失败。
    #[test]
    fn test_parse_token_answer() {
        let (token, expire) = Service::parse_token_answer(
            200,
            r#"{"code":0,"msg":"ok","tenant_access_token":"t-1","expire":7200}"#,
        )
        .unwrap();
        assert_eq!(token, "t-1");
        assert_eq!(expire, 7200);

        let err = Service::parse_token_answer(200, r#"{"code":10003,"msg":"invalid app_id"}"#)
            .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("code=10003"));

        let err = Service::parse_token_answer(500, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
    }

    // 推送请求构造(纯函数):Bearer 鉴权头、receive_id_type 默认 open_id 进 query、
    // msg_type=text、content 是"JSON 字符串套 JSON"(内层先序列化成串)。
    #[test]
    fn test_build_push_request() {
        let svc = svc();
        let req = svc
            .build_push_request(
                "t-1",
                &Message::new("ou_user1", "审批提醒").with_content("您有一张单据待审批"),
            )
            .unwrap();
        assert_eq!(
            req.url, "https://open.example.test/open-apis/im/v1/messages?receive_id_type=open_id",
            "接收人类型默认 open_id"
        );
        assert_eq!(req.headers[0], ("Authorization", "Bearer t-1".to_string()));
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["receive_id"], "ou_user1");
        assert_eq!(payload["msg_type"], "text");
        // content 是"JSON 字符串套 JSON":内层先序列化成串再嵌进去。
        let inner: Value = serde_json::from_str(payload["content"].as_str().unwrap()).unwrap();
        assert_eq!(inner["text"], "审批提醒\n您有一张单据待审批");
    }

    // 推送应答解析:message_id 进回执;code 非零归投递失败。
    #[test]
    fn test_parse_push_answer() {
        let receipt = Service::parse_push_answer(
            200,
            r#"{"code":0,"msg":"success","data":{"message_id":"om_abc123"}}"#,
        )
        .unwrap();
        assert_eq!(
            receipt.provider_id, "om_abc123",
            "飞书的 message_id 要进回执"
        );

        let err = Service::parse_push_answer(200, r#"{"code":230001,"msg":"invalid receive_id"}"#)
            .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("code=230001"));

        let err = Service::parse_push_answer(500, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
    }

    // token 失效码判定:强刷重试只认飞书的两个失效码;普通业务错误不算。
    #[test]
    fn test_is_token_err() {
        let invalid = NotifyError::Delivery(format!(
            "peer answered code={ERR_CODE_TOKEN_INVALID}: invalid access token"
        ));
        assert!(Service::is_token_err(&invalid));

        let expired = NotifyError::Delivery(format!(
            "peer answered code={ERR_CODE_TOKEN_EXPIRED}: access token expired"
        ));
        assert!(Service::is_token_err(&expired));

        let other =
            NotifyError::Delivery("peer answered code=230001: invalid receive_id".to_string());
        assert!(!Service::is_token_err(&other));

        let not_configured = NotifyError::NotConfigured(format!("code={ERR_CODE_TOKEN_INVALID}"));
        assert!(!Service::is_token_err(&not_configured), "只认投递错误");
    }
}
