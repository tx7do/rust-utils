//! Vonage(原 Nexmo)SMS 渠道:API Key/Secret 表单,零 SDK。
//!
//! 测试离线进行:请求构造与回执解析拆成纯函数断言,不真实连网。

use serde_json::Value;

use crate::notify::{Message, NotifyError, Receipt, check_target, map_ureq_error, new_client};

/// Vonage 官方 REST 域。
pub const DEFAULT_API_BASE: &str = "https://rest.nexmo.com";

/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Vonage 短信配置。Target(收件号 E.164,无 + 前缀)按消息传。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 账户 API Key。
    pub api_key: String,
    /// 账户 API Secret。
    pub api_secret: String,
    /// 发送方:已注册的发信 ID 或 Vonage 号码(E.164)。
    pub from: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// Vonage 短信渠道。无状态,可并发使用。
pub struct Service {
    agent: ureq::Agent,
    cfg: Config,
}

/// 构造好的出站请求:纯数据,供离线测试断言。
struct Prepared {
    url: String,
    body: String,
    content_type: &'static str,
    headers: Vec<(&'static str, String)>,
}

impl Service {
    /// 构造 Vonage 短信渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
    pub fn new(cfg: Config) -> Self {
        let mut cfg = cfg;
        if cfg.api_base.is_empty() {
            cfg.api_base = DEFAULT_API_BASE.to_string();
        }
        Service {
            agent: new_client(crate::notify::allow_private_target()),
            cfg,
        }
    }

    /// 构造请求(纯函数):凭据与消息全在表单里,
    /// 收件号剥掉 + 前缀(Vonage 要无 + 的 E.164),
    /// 正文 = Title 与 Content 以单换行相连。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "vonage destination is empty".to_string(),
            ));
        }
        if self.cfg.api_key.is_empty() || self.cfg.api_secret.is_empty() || self.cfg.from.is_empty()
        {
            return Err(NotifyError::NotConfigured(
                "vonage config incomplete: api_key/api_secret/from required".to_string(),
            ));
        }
        let body = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };
        let to = msg.target.strip_prefix('+').unwrap_or(&msg.target);
        let body = format!(
            "api_key={}&api_secret={}&to={}&from={}&text={}",
            form_urlencode(&self.cfg.api_key),
            form_urlencode(&self.cfg.api_secret),
            form_urlencode(to),
            form_urlencode(&self.cfg.from),
            form_urlencode(&body),
        );
        Ok(Prepared {
            url: format!(
                "{}/sms/json",
                self.cfg.api_base.trim_end_matches('/')
            ),
            body,
            content_type: "application/x-www-form-urlencoded",
            headers: Vec::new(),
        })
    }

    /// 解析回执(纯函数):HTTP 层 2xx 之后还要看 messages[0].status
    /// ——"0" 才算受理,message-id 进回执;status 非零是业务失败。
    fn parse_answer(status: u16, body: &str) -> Result<Receipt, NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "peer answered {status}: {}",
                snippet(body)
            )));
        }
        let answer: Value = serde_json::from_str(body).map_err(|_| {
            NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body)))
        })?;
        let messages = answer.get("messages").and_then(Value::as_array);
        let Some(m) = messages.and_then(|msgs| msgs.first()) else {
            return Err(NotifyError::Delivery(format!(
                "peer answered without messages: {}",
                snippet(body)
            )));
        };
        let m_status = m.get("status").and_then(Value::as_str).unwrap_or("");
        if m_status != "0" {
            let error_text = m
                .get("error-text")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            return Err(NotifyError::Delivery(format!(
                "peer answered status={m_status}: {error_text}"
            )));
        }
        let provider_id = m
            .get("message-id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok(Receipt { provider_id })
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
        "vonage"
    }

    /// 给 Target 发一条短信:[`Receipt::provider_id`] 带回 Vonage 的 message-id。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        let req = self.build_request(msg)?;
        check_target(&req.url)?;
        let (status, body) = self.post(&req)?;
        Self::parse_answer(status, &body)
    }
}

/// 读对端应答文本。
fn read_answer(resp: ureq::Response) -> Result<String, NotifyError> {
    resp.into_string()
        .map_err(|e| NotifyError::Delivery(format!("read peer answer: {e}")))
}

/// application/x-www-form-urlencoded 组件编码:保留字符(A-Z a-z 0-9 - _ . ~)
/// 原样,空格转 +,其余字节按 %XX(大写十六进制)。对齐 Go 的 url.QueryEscape。
fn form_urlencode(s: &str) -> String {
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

    #[test]
    fn test_name() {
        assert_eq!(Service::new(Config::default()).name(), "vonage");
    }

    // 配置缺失/目标缺失在拨号之前就拦下,归 NotConfigured。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config {
            api_key: "k".into(),
            ..Config::default()
        })
        .send(&Message::new("8613800138000", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("api_key/api_secret/from"));

        let err = Service::new(Config {
            api_key: "k".into(),
            api_secret: "s".into(),
            from: "F".into(),
            ..Config::default()
        })
        .send(&Message::new("", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("destination is empty"));
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget。
    #[test]
    fn test_blocked_target() {
        let err = Service::new(Config {
            api_key: "k".into(),
            api_secret: "s".into(),
            from: "F".into(),
            api_base: "http://127.0.0.1:9".into(),
        })
        .send(&Message::new("8613800138000", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 请求构造离线断言:路径 /sms/json、凭据与消息全在表单、
    // 收件号剥掉 + 前缀、正文 UTF-8 百分号编码。
    #[test]
    fn test_build_request() {
        let svc = Service::new(Config {
            api_key: "k1".into(),
            api_secret: "s1".into(),
            from: "Acme".into(),
            api_base: "https://rest.example.test".into(),
        });
        let req = svc
            .build_request(
                &Message::new("+8613800138000", "重置验证码").with_content("您的验证码是 123456"),
            )
            .unwrap();
        assert_eq!(req.url, "https://rest.example.test/sms/json");
        assert_eq!(req.content_type, "application/x-www-form-urlencoded");
        let form = &req.body;
        assert!(form.contains("api_key=k1"));
        assert!(form.contains("api_secret=s1"));
        assert!(form.contains("to=8613800138000"), "Vonage 收件号无 + 前缀");
        assert!(form.contains("from=Acme"));
        assert!(form.contains("text=%E9%87%8D%E7%BD%AE%E9%AA%8C%E8%AF%81%E7%A0%81"));
    }

    // 回执解析:message-id 进回执;status 非零判投递失败,文案带对端说明。
    #[test]
    fn test_parse_answer() {
        let receipt = Service::parse_answer(
            200,
            r#"{"message-count":"1","messages":[{"status":"0","message-id":"0A00000012AB","to":"8613800138000"}]}"#,
        )
        .unwrap();
        assert_eq!(receipt.provider_id, "0A00000012AB", "message-id 要进回执");

        let err = Service::parse_answer(
            200,
            r#"{"message-count":"1","messages":[{"status":"9","error-text":"Invalid api key"}]}"#,
        )
        .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("status=9"));
        assert!(err.to_string().contains("Invalid api key"));

        let err = Service::parse_answer(200, r#"{"message-count":"0","messages":[]}"#).unwrap_err();
        assert!(err.to_string().contains("without messages"));

        let err = Service::parse_answer(200, "not json").unwrap_err();
        assert!(err.to_string().contains("not JSON"));

        let err = Service::parse_answer(500, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
    }
}
