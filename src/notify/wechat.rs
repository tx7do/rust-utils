//! 微信公众号模板消息渠道:access_token 流程 + template/send。
//!
//! 走裸 HTTP,零 SDK。两条协议事实钉在实现里:
//!   - 模板消息必须有已备案的 template_id,正文形状是 data 字段里的键值对
//!     (每个键渲染成 {value}),没有自由文本通道;
//!   - access_token 有每日获取配额与 2 小时有效期,所以按过期前余量缓存、
//!     失效(40001/42001)时强刷重试一次,而不是每条消息都去要一枚新 token。
//!
//! 测试离线进行:token/推送请求构造与应答解析拆成纯函数断言,不真实连网。

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::notify::{check_target, map_ureq_error, new_client, Message, NotifyError, Receipt};

/// 微信公众号官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://api.weixin.qq.com";

/// token 失效码:强刷一次再试。
const ERR_CODE_TOKEN_INVALID: i64 = 40001;
const ERR_CODE_TOKEN_EXPIRED: i64 = 42001;

/// token 提前刷新余量:免得边界上用过期 token。
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// 对端没给 expires_in 时的兜底有效期(微信文档默认 7200s)。
const TOKEN_DEFAULT_TTL: i64 = 7200;

/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 512;

/// 微信公众号渠道配置。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 公众号凭据 AppID。
    pub app_id: String,
    /// 公众号凭据 AppSecret。
    pub app_secret: String,
    /// 已备案的模板消息 ID。模板消息没有它发不出去。
    pub template_id: String,
    /// 服务端基地址,留空用官方 API;测试与自建网关可覆盖。
    pub api_base: String,
}

/// 微信公众号渠道。access_token 按 Service 实例缓存(并发安全);
/// 一个实例对应一份凭据,凭据轮换时另起新实例。
pub struct Service {
    agent: ureq::Agent,
    cfg: Config,
    token: Mutex<TokenState>,
}

/// 缓存的 access_token 与到期时刻(单调钟)。
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
    /// 构造微信公众号渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
    pub fn new(cfg: Config) -> Self {
        let mut cfg = cfg;
        if cfg.api_base.is_empty() {
            cfg.api_base = DEFAULT_API_BASE.to_string();
        }
        Service {
            agent: new_client(crate::notify::allow_private_target()),
            cfg,
            token: Mutex::new(TokenState::default()),
        }
    }

    /// 构造取 token 请求(纯函数):凭据进 query。
    fn build_token_request(cfg: &Config) -> Prepared {
        Prepared {
            url: format!(
                "{}/cgi-bin/token?grant_type=client_credential&appid={}&secret={}",
                cfg.api_base.trim_end_matches('/'),
                query_escape(&cfg.app_id),
                query_escape(&cfg.app_secret),
            ),
            body: String::new(),
            content_type: "application/json",
            headers: Vec::new(),
        }
    }

    /// 解析 token 应答(纯函数):返回 (access_token, 有效期秒数)。
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
        let err_code = answer.get("errcode").and_then(Value::as_i64).unwrap_or(0);
        let token = answer
            .get("access_token")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let expires_in = answer
            .get("expires_in")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if err_code != 0 || token.is_empty() {
            let err_msg = answer
                .get("errmsg")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            return Err(NotifyError::Delivery(format!(
                "token endpoint answered errcode={err_code}: {err_msg}"
            )));
        }
        Ok((token, expires_in))
    }

    /// 构造模板消息载荷(纯函数):Params 的每个键渲染成模板的 {KEY} 占位值
    /// ({"value": v} 形状);Params 为空且 Content 非空时,整段正文落 "content"
    /// 键(对应模板里唯一一个 {{content.data}})。Title 不进模板消息——
    /// 公众号模板的形状全在 data 里,没有标题位。
    fn build_payload(&self, msg: &Message) -> String {
        let mut data = serde_json::Map::new();
        for (key, value) in &msg.params {
            data.insert(key.clone(), json!({ "value": value }));
        }
        if data.is_empty() && !msg.content.is_empty() {
            data.insert("content".to_string(), json!({ "value": msg.content }));
        }
        json!({
            "touser": msg.target,
            "template_id": self.cfg.template_id,
            "data": Value::Object(data),
        })
        .to_string()
    }

    /// 构造推送请求(纯函数):access_token 进 query。
    fn build_push_request(&self, token: &str, payload: &str) -> Prepared {
        Prepared {
            url: format!(
                "{}/cgi-bin/message/template/send?access_token={}",
                self.cfg.api_base.trim_end_matches('/'),
                query_escape(token),
            ),
            body: payload.to_string(),
            content_type: "application/json",
            headers: Vec::new(),
        }
    }

    /// 解析推送应答(纯函数):errcode==0 即受理,msgid 进回执。
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
        let err_code = answer.get("errcode").and_then(Value::as_i64).unwrap_or(0);
        if err_code != 0 {
            let err_msg = answer
                .get("errmsg")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            return Err(NotifyError::Delivery(format!(
                "peer answered errcode={err_code}: {err_msg}"
            )));
        }
        let msg_id = answer.get("msgid").and_then(Value::as_i64).unwrap_or(0);
        let provider_id = if msg_id != 0 {
            msg_id.to_string()
        } else {
            String::new()
        };
        Ok(Receipt { provider_id })
    }

    /// 判定是否 token 失效错误(只认投递错误凭失效码识别;配置类失败
    /// 不该触发强刷):失效则丢弃缓存、强刷一枚重试一次。
    fn is_token_err(err: &NotifyError) -> bool {
        let NotifyError::Delivery(msg) = err else {
            return false;
        };
        msg.contains(&format!("errcode={ERR_CODE_TOKEN_INVALID}"))
            || msg.contains(&format!("errcode={ERR_CODE_TOKEN_EXPIRED}"))
    }

    /// 取一枚可用的 access_token:缓存未到期直接用,否则向微信换取。
    fn access_token(&self) -> Result<String, NotifyError> {
        {
            let st = self.lock_token();
            if !st.token.is_empty() && st.expires_at.is_some_and(|t| Instant::now() < t) {
                return Ok(st.token.clone());
            }
        }
        let req = Self::build_token_request(&self.cfg);
        check_target(&req.url)?;
        let (status, body) = self.get(&req.url)?;
        let (token, expires_in) = Self::parse_token_answer(status, &body)?;
        let ttl = if expires_in <= 0 {
            TOKEN_DEFAULT_TTL as u64
        } else {
            expires_in as u64
        };
        let mut st = self.lock_token();
        st.token = token.clone();
        st.expires_at = Some(
            Instant::now()
                + Duration::from_secs(ttl.saturating_sub(TOKEN_REFRESH_MARGIN.as_secs())),
        );
        Ok(token)
    }

    /// 丢弃缓存的 access_token:对端报失效码时强刷用。
    fn invalidate_token(&self) {
        let mut st = self.lock_token();
        st.token = String::new();
        st.expires_at = None;
    }

    fn lock_token(&self) -> MutexGuard<'_, TokenState> {
        self.token.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// GET 请求,返回 (状态码, 应答文本)。
    fn get(&self, url: &str) -> Result<(u16, String), NotifyError> {
        match self.agent.get(url).call() {
            Ok(resp) => Ok((resp.status(), read_answer(resp)?)),
            Err(ureq::Error::Status(status, resp)) => Ok((status, read_answer(resp)?)),
            Err(err) => Err(map_ureq_error(err)),
        }
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
        "wechat"
    }

    /// 给 Target(openid)发一条模板消息。token 在缓存窗口内被微信侧作废
    /// (重置密钥/后台刷新)时强刷一枚再试一次;[`Receipt::provider_id`]
    /// 带回微信的 msgid。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "wechat openid is empty".to_string(),
            ));
        }
        if self.cfg.app_id.is_empty() || self.cfg.app_secret.is_empty() {
            return Err(NotifyError::NotConfigured(
                "wechat config missing app_id/app_secret".to_string(),
            ));
        }
        if self.cfg.template_id.is_empty() {
            return Err(NotifyError::NotConfigured(
                "wechat config missing template_id: template messages require a provider-side approved template"
                    .to_string(),
            ));
        }
        let payload = self.build_payload(msg);
        let token = self.access_token()?;
        let req = self.build_push_request(&token, &payload);
        check_target(&req.url)?;
        match self.post(&req) {
            Ok((status, body)) => Self::parse_push_answer(status, &body),
            Err(err) if Self::is_token_err(&err) => {
                // token 在缓存窗口内被微信侧作废:强刷一枚再试一次,仍失败才交出去。
                self.invalidate_token();
                let token = self.access_token()?;
                let req = self.build_push_request(&token, &payload);
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
    use std::collections::HashMap;

    fn svc() -> Service {
        Service::new(Config {
            app_id: "appid-1".into(),
            app_secret: "secret-1".into(),
            template_id: "TMPL-1".into(),
            api_base: "https://api.example.test".into(),
        })
    }

    #[test]
    fn test_name() {
        assert_eq!(Service::new(Config::default()).name(), "wechat");
    }

    // 配置缺失在拨号之前就拦下,归 NotConfigured;模板消息没 template_id
    // 就是发不出去,错要说清楚;目标缺失不是配置问题,文案单独区分。
    #[test]
    fn test_config_issues() {
        let msg = Message::new("oX-1", "").with_param("code", "1");
        let err = Service::new(Config::default()).send(&msg).unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("app_id/app_secret"));

        let err = Service::new(Config {
            app_id: "a".into(),
            app_secret: "s".into(),
            ..Config::default()
        })
        .send(&msg)
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("template_id"));

        let err = svc()
            .send(&Message::new("", "").with_param("code", "1"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("openid is empty"));
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget(token 端点先于推送端点)。
    #[test]
    fn test_blocked_target() {
        let svc = Service::new(Config {
            app_id: "a".into(),
            app_secret: "s".into(),
            template_id: "t".into(),
            api_base: "http://127.0.0.1:9".into(),
        });
        let err = svc
            .send(&Message::new("oX-1", "").with_param("code", "1"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 取 token 请求构造(纯函数):grant_type 固定,appid/secret 进 query。
    #[test]
    fn test_build_token_request() {
        let req = Service::build_token_request(&Config {
            app_id: "appid-1".into(),
            app_secret: "secret-1".into(),
            ..Config::default()
        });
        assert!(
            req.url.ends_with(
                "/cgi-bin/token?grant_type=client_credential&appid=appid-1&secret=secret-1"
            ),
            "got: {}",
            req.url
        );
    }

    // token 应答解析:取 token 与有效期;token 端点报错归投递失败。
    #[test]
    fn test_parse_token_answer() {
        let (token, expires_in) =
            Service::parse_token_answer(200, r#"{"access_token":"token-1","expires_in":7200}"#)
                .unwrap();
        assert_eq!(token, "token-1");
        assert_eq!(expires_in, 7200);

        // 微信对取 token 失败的答法:200 + errcode/errmsg。
        let err =
            Service::parse_token_answer(200, r#"{"errcode":40125,"errmsg":"invalid appsecret"}"#)
                .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("40125"));

        let err = Service::parse_token_answer(500, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
    }

    // 推送请求构造(纯函数):token 进 query、touser/template_id 原样、
    // Params 每键渲染成 {value} 形状;Title 不进模板消息。
    #[test]
    fn test_build_push_request_and_payload() {
        let svc = svc();
        let payload = svc.build_payload(
            &Message::new("oX-openid-1", "")
                .with_param("code", "123456")
                .with_param("minute", "10"),
        );
        let req = svc.build_push_request("token-1", &payload);
        assert_eq!(
            req.url,
            "https://api.example.test/cgi-bin/message/template/send?access_token=token-1"
        );
        let p: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(p["touser"], "oX-openid-1");
        assert_eq!(p["template_id"], "TMPL-1");
        let data = &p["data"];
        assert_eq!(
            data["code"],
            json!({ "value": "123456" }),
            "每个参数键渲染成 {{value}} 形状"
        );
        assert_eq!(data["minute"], json!({ "value": "10" }));
        assert!(p.get("title").is_none(), "Title 不进模板消息");
    }

    // 没带参数时整段正文落 "content" 键(对应模板里唯一的 {{content.data}})。
    #[test]
    fn test_build_payload_content_fallback() {
        let svc = svc();
        let payload = svc.build_payload(&Message::new("oX-1", "").with_content("整段正文"));
        let p: Value = serde_json::from_str(&payload).unwrap();
        let data = p["data"].as_object().unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data["content"], json!({ "value": "整段正文" }));
    }

    // 推送应答解析:msgid 进回执;errcode 非零归投递失败;
    // token 失效码能被 is_token_err 识别,业务错误不算。
    #[test]
    fn test_parse_push_answer_and_token_err() {
        let receipt =
            Service::parse_push_answer(200, r#"{"errcode":0,"errmsg":"ok","msgid":9527}"#).unwrap();
        assert_eq!(
            receipt.provider_id, "9527",
            "微信的 msgid 要进回执,对账全靠它"
        );

        let receipt = Service::parse_push_answer(200, r#"{"errcode":0}"#).unwrap();
        assert_eq!(receipt.provider_id, "", "msgid 为 0 时不进回执");

        // 业务错误(如频率限制)不走 token 强刷路径。
        let err = Service::parse_push_answer(
            200,
            r#"{"errcode":45009,"errmsg":"reach max api daily quota limit"}"#,
        )
        .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(!Service::is_token_err(&err), "非 token 错误不许触发强刷");
        assert!(err.to_string().contains("45009"));

        let invalid =
            Service::parse_push_answer(200, r#"{"errcode":40001,"errmsg":"invalid credential"}"#)
                .unwrap_err();
        assert!(Service::is_token_err(&invalid), "{invalid}");

        let expired =
            Service::parse_push_answer(200, r#"{"errcode":42001,"errmsg":"access_token expired"}"#)
                .unwrap_err();
        assert!(Service::is_token_err(&expired), "{expired}");

        let err = Service::parse_push_answer(500, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
    }

    // query_escape 细节抽查。
    #[test]
    fn test_query_escape() {
        assert_eq!(query_escape("a&b c"), "a%26b+c");
    }

    // Params 为空且正文为空:data 为空对象(模板占位渲染成空)。
    #[test]
    fn test_build_payload_empty() {
        let svc = svc();
        let payload = svc.build_payload(&Message::new("oX-1", ""));
        let p: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(p["data"], Value::Object(serde_json::Map::new()));
    }

    // msg.params 的 HashMap 顺序不影响 data 的形状(键值对逐项断言)。
    #[test]
    fn test_build_payload_many_params() {
        let svc = svc();
        let mut params = HashMap::new();
        params.insert("first".to_string(), "1".to_string());
        params.insert("second".to_string(), "2".to_string());
        let msg = Message {
            target: "oX-1".into(),
            params,
            ..Message::default()
        };
        let payload = svc.build_payload(&msg);
        let p: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(p["data"]["first"], json!({ "value": "1" }));
        assert_eq!(p["data"]["second"], json!({ "value": "2" }));
    }
}
