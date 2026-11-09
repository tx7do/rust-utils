//! 企业微信应用消息渠道:access_token 流 + message/send,零依赖。
//!
//! 与群机器人 webhook 的分工:机器人(notify/webhook 的企微风格)推群、只凭
//! webhook 地址;本渠道推**应用消息到成员个人**(touser),凭
//! corp_id/corp_secret/agent_id。
//!
//! access_token 按实例缓存(过期前留余量);对端报 token 失效码(40014/42001)
//! 时强刷一枚重试一次——密钥重置/后台刷新是常态外的事,重试一次就够。
//! 企业微信对应用消息不回消息 ID,回执为空;无效成员列在 errcode 0 应答的
//! invaliduser 字段里,由调用方按需取,本渠道不因部分无效而判失败。
//! 测试离线进行:token/推送请求构造与应答解析拆成纯函数断言,不真实连网。

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::notify::{check_target, map_ureq_error, new_client, Message, NotifyError, Receipt};

/// 企业微信官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://qyapi.weixin.qq.com";

/// token 失效码:强刷一枚重试一次。
const ERR_CODE_TOKEN_INVALID: i64 = 40014;
const ERR_CODE_TOKEN_EXPIRED: i64 = 42001;

/// token 提前刷新余量。
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// 对端没给 expires_in 时的兜底有效期(企微文档默认 7200s)。
const TOKEN_DEFAULT_TTL: i64 = 7200;

/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// 企业微信应用消息配置。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 企业 ID。
    pub corp_id: String,
    /// 自建应用的 Secret。
    pub corp_secret: String,
    /// 自建应用的 AgentId(应用消息必填)。
    pub agent_id: i64,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// 企业微信应用消息渠道。access_token 按实例缓存(并发安全);
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
    /// 构造企业微信应用消息渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
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

    /// 构造取 token 请求(纯函数):corpid+corpsecret 进 query。
    fn build_token_request(cfg: &Config) -> Prepared {
        Prepared {
            url: format!(
                "{}/cgi-bin/gettoken?corpid={}&corpsecret={}",
                cfg.api_base.trim_end_matches('/'),
                query_escape(&cfg.corp_id),
                query_escape(&cfg.corp_secret),
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

    /// 构造应用消息载荷(纯函数):touser 语法——成员账号以 | 相连
    /// ("zhangsan|lisi"),"@all" 表示全员;agentid 按数字出站(企微要求);
    /// text 类型无独立标题位,有标题时以换行相连。
    fn build_payload(&self, msg: &Message) -> String {
        let content = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };
        json!({
            "touser": msg.target,
            "msgtype": "text",
            "agentid": self.cfg.agent_id,
            "text": { "content": content },
        })
        .to_string()
    }

    /// 构造推送请求(纯函数):access_token 进 query。
    fn build_push_request(&self, token: &str, payload: &str) -> Prepared {
        Prepared {
            url: format!(
                "{}/cgi-bin/message/send?access_token={}",
                self.cfg.api_base.trim_end_matches('/'),
                query_escape(token),
            ),
            body: payload.to_string(),
            content_type: "application/json; charset=utf-8",
            headers: Vec::new(),
        }
    }

    /// 解析推送应答(纯函数):errcode==0 即受理(无效成员在 invaliduser
    /// 字段,不影响受理);应用消息不回消息 ID,回执为空。
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
        Ok(Receipt::default())
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
        "wecom"
    }

    /// 给 Target 发应用消息(无效成员列在 errcode 0 应答的 invaliduser 字段里,
    /// 不影响受理):token 失效时强刷一枚重试一次。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "wecom touser is empty".to_string(),
            ));
        }
        if self.cfg.corp_id.is_empty() || self.cfg.corp_secret.is_empty() || self.cfg.agent_id == 0
        {
            return Err(NotifyError::NotConfigured(
                "wecom config incomplete: corp_id/corp_secret/agent_id required".to_string(),
            ));
        }
        let payload = self.build_payload(msg);
        let token = self.access_token()?;
        let req = self.build_push_request(&token, &payload);
        check_target(&req.url)?;
        match self.post(&req) {
            Ok((status, body)) => Self::parse_push_answer(status, &body),
            Err(err) if Self::is_token_err(&err) => {
                // token 在缓存窗口内被企微侧作废:强刷一枚再试一次。
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

    fn svc() -> Service {
        Service::new(Config {
            corp_id: "corp-1".into(),
            corp_secret: "secret-1".into(),
            agent_id: 1000002,
            api_base: "https://qyapi.example.test".into(),
        })
    }

    #[test]
    fn test_name() {
        assert_eq!(Service::new(Config::default()).name(), "wecom");
    }

    // 配置缺失(缺 agent_id)/目标缺失在拨号之前就拦下,归 NotConfigured。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config {
            corp_id: "c".into(),
            corp_secret: "s".into(),
            ..Config::default()
        })
        .send(&Message::new("a", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("corp_id/corp_secret/agent_id"));

        let err = svc()
            .send(&Message::new("", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("touser is empty"));
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget(token 端点先于推送端点)。
    #[test]
    fn test_blocked_target() {
        let svc = Service::new(Config {
            corp_id: "c".into(),
            corp_secret: "s".into(),
            agent_id: 1,
            api_base: "http://127.0.0.1:9".into(),
        });
        let err = svc
            .send(&Message::new("a", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 取 token 请求构造(纯函数):corpid/corpsecret 进 query,值按 QueryEscape。
    #[test]
    fn test_build_token_request() {
        let req = Service::build_token_request(&Config {
            corp_id: "corp&1".into(),
            corp_secret: "secret 1".into(),
            ..Config::default()
        });
        assert!(
            req.url
                .ends_with("/cgi-bin/gettoken?corpid=corp%261&corpsecret=secret+1"),
            "got: {}",
            req.url
        );
    }

    // token 应答解析:取 token 与有效期;错误码归投递失败。
    #[test]
    fn test_parse_token_answer() {
        let (token, expires_in) = Service::parse_token_answer(
            200,
            r#"{"errcode":0,"errmsg":"ok","access_token":"token-1","expires_in":7200}"#,
        )
        .unwrap();
        assert_eq!(token, "token-1");
        assert_eq!(expires_in, 7200);

        let err =
            Service::parse_token_answer(200, r#"{"errcode":40013,"errmsg":"invalid corpid"}"#)
                .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("errcode=40013"));

        let err = Service::parse_token_answer(500, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
    }

    // 推送请求构造(纯函数):token 进 query、agentid 按数字出站、
    // touser 原样、text 无独立标题位(标题换行相连)。
    #[test]
    fn test_build_push_request_and_payload() {
        let svc = svc();
        let payload =
            svc.build_payload(&Message::new("zhangsan", "工单提醒").with_content("您的工单已受理"));
        let req = svc.build_push_request("token-1", &payload);
        assert_eq!(
            req.url,
            "https://qyapi.example.test/cgi-bin/message/send?access_token=token-1"
        );
        assert_eq!(req.content_type, "application/json; charset=utf-8");

        let p: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(p["touser"], "zhangsan");
        assert_eq!(p["msgtype"], "text");
        assert_eq!(p["agentid"], 1000002, "agentid 要按数字出站(企微要求)");
        assert_eq!(p["text"]["content"], "工单提醒\n您的工单已受理");
    }

    // @all 全员语法原样透传。
    #[test]
    fn test_build_payload_at_all() {
        let svc = svc();
        let payload = svc.build_payload(&Message::new("@all", "").with_content("全员公告"));
        let p: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(p["touser"], "@all");
    }

    // 推送应答解析:errcode==0 即受理(应用消息不回消息 ID,回执为空);
    // errcode 非零归投递失败;token 失效码能被 is_token_err 识别。
    #[test]
    fn test_parse_push_answer_and_token_err() {
        let receipt =
            Service::parse_push_answer(200, r#"{"errcode":0,"errmsg":"ok","invaliduser":""}"#)
                .unwrap();
        assert_eq!(receipt.provider_id, "", "应用消息不回消息 ID,回执为空");

        let err = Service::parse_push_answer(200, r#"{"errcode":81013,"errmsg":"invalid user"}"#)
            .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("errcode=81013"));

        // token 失效码(40014/42001)能被识别,供强刷重试路径用。
        let invalid =
            Service::parse_push_answer(200, r#"{"errcode":40014,"errmsg":"invalid access_token"}"#)
                .unwrap_err();
        assert!(Service::is_token_err(&invalid), "{invalid}");

        let expired =
            Service::parse_push_answer(200, r#"{"errcode":42001,"errmsg":"access_token expired"}"#)
                .unwrap_err();
        assert!(Service::is_token_err(&expired), "{expired}");

        let other =
            Service::parse_push_answer(200, r#"{"errcode":81013,"errmsg":"x"}"#).unwrap_err();
        assert!(!Service::is_token_err(&other), "业务错误不走强刷路径");
    }
}
