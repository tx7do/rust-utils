//! 钉钉工作通知渠道(企业内部应用异步消息),零 SDK。
//!
//! 与群机器人(notify/webhook 的钉钉风格)分工:机器人推群、凭签名 webhook;
//! 本渠道推**工作通知到成员个人**(userid_list),凭 app_key/app_secret/agent_id。
//!
//! access_token 按实例缓存(过期前留余量),失效不重试——轮换凭据另起实例
//! (对齐上游口径)。测试离线进行:token/推送请求构造与应答解析拆成纯函数
//! 断言,不真实连网。

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::notify::{Message, NotifyError, Receipt, check_target, map_ureq_error, new_client};

/// 钉钉官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://oapi.dingtalk.com";

/// access_token 提前刷新余量。
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// 对端没给 expires_in 时的兜底有效期(钉钉文档默认 7200s)。
const TOKEN_DEFAULT_TTL: i64 = 7200;

/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// 钉钉工作通知配置。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 企业内部应用凭据 AppKey。
    pub app_key: String,
    /// 企业内部应用凭据 AppSecret。
    pub app_secret: String,
    /// 企业的应用 AgentId(应用消息必填)。
    pub agent_id: i64,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// 钉钉工作通知渠道。access_token 按实例缓存(并发安全)。
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
    /// 构造钉钉工作通知渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
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
                "{}/gettoken?appkey={}&appsecret={}",
                cfg.api_base.trim_end_matches('/'),
                query_escape(&cfg.app_key),
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
        let expires_in = answer.get("expires_in").and_then(Value::as_i64).unwrap_or(0);
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

    /// 构造推送请求(纯函数):access_token 进 query,body 为已序列化的
    /// 异步工作通知载荷(agent_id 按数字出站)。
    fn build_push_request(&self, token: &str, payload: &str) -> Prepared {
        Prepared {
            url: format!(
                "{}/topapi/message/corpconversation/asyncsend_v2?access_token={}",
                self.cfg.api_base.trim_end_matches('/'),
                query_escape(token),
            ),
            body: payload.to_string(),
            content_type: "application/json; charset=utf-8",
            headers: Vec::new(),
        }
    }

    /// 构造工作通知载荷(纯函数):Target 为 userid_list(成员 userid 以 |
    /// 相连);text 类型无独立标题位,有标题时以换行相连。
    fn build_payload(&self, msg: &Message) -> String {
        let content = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };
        json!({
            "agent_id": self.cfg.agent_id,
            "userid_list": msg.target,
            "msg": {
                "msgtype": "text",
                "text": { "content": content },
            },
        })
        .to_string()
    }

    /// 解析推送应答(纯函数):errcode==0 表示已受理(异步接口),
    /// task_id 进回执;到账结果靠回调查询,不在本渠道。
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
        let task_id = answer.get("task_id").and_then(Value::as_i64).unwrap_or(0);
        let provider_id = if task_id != 0 {
            task_id.to_string()
        } else {
            String::new()
        };
        Ok(Receipt { provider_id })
    }

    /// 取(缓存的)access_token:过期前留余量,到点才换新。
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
            Instant::now() + Duration::from_secs(ttl.saturating_sub(TOKEN_REFRESH_MARGIN.as_secs())),
        );
        Ok(token)
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
        "dingtalk"
    }

    /// 给 Target(userid_list,成员 userid 以 | 相连)发工作通知。
    /// [`Receipt::provider_id`] 带回异步受理的 task_id。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "dingtalk userid_list is empty".to_string(),
            ));
        }
        if self.cfg.app_key.is_empty()
            || self.cfg.app_secret.is_empty()
            || self.cfg.agent_id == 0
        {
            return Err(NotifyError::NotConfigured(
                "dingtalk config incomplete: app_key/app_secret/agent_id required".to_string(),
            ));
        }
        let payload = self.build_payload(msg);
        let token = self.access_token()?;
        let req = self.build_push_request(&token, &payload);
        check_target(&req.url)?;
        let (status, body) = self.post(&req)?;
        Self::parse_push_answer(status, &body)
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
            app_key: "key-1".into(),
            app_secret: "secret-1".into(),
            agent_id: 123,
            api_base: "https://oapi.example.test".into(),
        })
    }

    #[test]
    fn test_name() {
        assert_eq!(Service::new(Config::default()).name(), "dingtalk");
    }

    // 配置缺失(agent_id 为 0)/目标缺失在拨号之前就拦下,归 NotConfigured。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config {
            app_key: "k".into(),
            app_secret: "s".into(),
            ..Config::default()
        })
        .send(&Message::new("a", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("app_key/app_secret/agent_id"));

        let err = svc()
            .send(&Message::new("", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("userid_list is empty"));
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget(token 端点先于推送端点)。
    #[test]
    fn test_blocked_target() {
        let svc = Service::new(Config {
            app_key: "k".into(),
            app_secret: "s".into(),
            agent_id: 1,
            api_base: "http://127.0.0.1:9".into(),
        });
        let err = svc
            .send(&Message::new("a", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 取 token 请求构造(纯函数):凭据进 query,值按 QueryEscape 编码。
    #[test]
    fn test_build_token_request() {
        let cfg = Config {
            app_key: "key&1".into(),
            app_secret: "secret 1".into(),
            ..Config::default()
        };
        let req = Service::build_token_request(&cfg);
        assert!(req.url.ends_with("/gettoken?appkey=key%261&appsecret=secret+1"));
    }

    // token 应答解析:取 token 与有效期;错误码归投递失败。
    #[test]
    fn test_parse_token_answer() {
        let (token, expires_in) =
            Service::parse_token_answer(200, r#"{"errcode":0,"errmsg":"ok","access_token":"tk-1","expires_in":7200}"#)
                .unwrap();
        assert_eq!(token, "tk-1");
        assert_eq!(expires_in, 7200);

        let err = Service::parse_token_answer(200, r#"{"errcode":40001,"errmsg":"invalid appkey"}"#)
            .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("errcode=40001"));

        let err =
            Service::parse_token_answer(200, r#"{"errcode":0,"access_token":""}"#).unwrap_err();
        assert!(err.to_string().contains("token endpoint answered"));

        let err = Service::parse_token_answer(500, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");

        let err = Service::parse_token_answer(200, "not json").unwrap_err();
        assert!(err.to_string().contains("not JSON"));
    }

    // 推送请求构造(纯函数):token 进 query、agent_id 按数字出站、
    // userid_list 原样、text 无独立标题位(标题换行相连)。
    #[test]
    fn test_build_push_request_and_payload() {
        let svc = svc();
        let payload = svc.build_payload(&Message::new("zhangsan|lisi", "审批提醒").with_content(
            "您有一张单据待审批",
        ));
        let req = svc.build_push_request("tk-1", &payload);
        assert_eq!(
            req.url,
            "https://oapi.example.test/topapi/message/corpconversation/asyncsend_v2?access_token=tk-1"
        );
        assert_eq!(req.content_type, "application/json; charset=utf-8");

        let p: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(p["agent_id"], 123, "agent_id 按数字出站");
        assert_eq!(p["userid_list"], "zhangsan|lisi");
        assert_eq!(p["msg"]["msgtype"], "text");
        assert_eq!(
            p["msg"]["text"]["content"],
            "审批提醒\n您有一张单据待审批"
        );
    }

    // 推送应答解析:task_id 进回执;errcode 非零归投递失败。
    #[test]
    fn test_parse_push_answer() {
        let receipt = Service::parse_push_answer(200, r#"{"errcode":0,"errmsg":"ok","task_id":66779}"#)
            .unwrap();
        assert_eq!(receipt.provider_id, "66779", "异步受理的 task_id 要进回执");

        let err =
            Service::parse_push_answer(200, r#"{"errcode":40007,"errmsg":"invalid agent_id"}"#)
                .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("errcode=40007"));

        let err = Service::parse_push_answer(500, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
    }

    // query_escape 细节:保留字符原样、空格转 +、非 ASCII 按 UTF-8 %XX。
    #[test]
    fn test_query_escape() {
        assert_eq!(query_escape("aBc-_.~123"), "aBc-_.~123");
        assert_eq!(query_escape("a b"), "a+b");
        assert_eq!(query_escape("a&b=c"), "a%26b%3Dc");
    }
}
