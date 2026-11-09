//! SendGrid Mail Send v3:Bearer 令牌 + JSON 邮件,裸 HTTP,feature `notify`。
//! 对齐上游 `notify/sendgrid/sendgrid.go`。
//!
//! 受理(HTTP 202)即成功:SendGrid 的消息 ID 在响应头 `X-Message-Id` 里,
//! 进回执供对账——body 是空的,对账全靠这个头。
//!
//! 与上游 Go 版的差异:`Config.Ref`(展示标识,只进错误文案)未移植;
//! `context.Context` 取消传播在本 crate 的阻塞式 API 里不存在。
//!
//! 测试离线进行:请求构造(payload 形态)与回执解析拆成纯函数断言,不真实连网。

use serde_json::{json, Value};

use crate::notify::{check_target, map_ureq_error, new_client, Message, NotifyError, Receipt};

/// SendGrid 官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://api.sendgrid.com";

/// Mail Send v3 端点路径。
const SEND_PATH: &str = "/v3/mail/send";

/// 进错误文案的响应片段上限:对端可能回一整页 HTML。
const SNIPPET_LIMIT: usize = 256;

/// SendGrid 渠道配置。收件邮箱按消息传。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 发信 API Key。
    pub api_key: String,
    /// 发件人地址。
    pub from: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// SendGrid 渠道。无状态,可并发使用。
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
    /// 构造 SendGrid 渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
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

    /// 构造请求(纯函数):Bearer 令牌进鉴权头,payload 按 v3 形态组装。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "sendgrid recipient is empty".into(),
            ));
        }
        if self.cfg.api_key.is_empty() || self.cfg.from.is_empty() {
            return Err(NotifyError::NotConfigured(
                "sendgrid config incomplete: api_key/from required".into(),
            ));
        }
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured(
                "sendgrid message body is empty".into(),
            ));
        }
        Ok(Prepared {
            url: format!("{}{SEND_PATH}", self.cfg.api_base),
            body: build_payload(&msg.target, &self.cfg.from, &msg.title, &msg.content).to_string(),
            content_type: "application/json",
            headers: vec![("Authorization", format!("Bearer {}", self.cfg.api_key))],
        })
    }

    /// 解析回执(纯函数):受理(2xx)即成功,消息 ID 从响应头
    /// `X-Message-Id` 取(拿不到留空)。
    fn parse_answer(
        status: u16,
        body: &str,
        message_id: Option<&str>,
    ) -> Result<Receipt, NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "peer answered {status}: {}",
                snippet(body)
            )));
        }
        Ok(Receipt {
            provider_id: message_id.unwrap_or_default().to_string(),
        })
    }

    /// POST 已构造好的请求,返回 (状态码, X-Message-Id 响应头, 应答文本)。
    /// 非 2xx 也返回应答文本,由 [`Self::parse_answer`] 统一归类。
    fn post(&self, req: &Prepared) -> Result<(u16, Option<String>, String), NotifyError> {
        let mut request = self
            .agent
            .post(&req.url)
            .set("Content-Type", req.content_type);
        for (name, value) in &req.headers {
            request = request.set(name, value);
        }
        let resp = match request.send_string(&req.body) {
            Ok(resp) => resp,
            Err(ureq::Error::Status(_, resp)) => resp,
            Err(err) => return Err(map_ureq_error(err)),
        };
        let status = resp.status();
        let message_id = resp.header("X-Message-Id").map(str::to_string);
        let body = read_answer(resp)?;
        Ok((status, message_id, body))
    }
}

impl crate::notify::Service for Service {
    fn name(&self) -> &str {
        "sendgrid"
    }

    /// 给 Target(收件邮箱)发一封纯文本邮件:受理(202)即成功,
    /// [`Receipt::provider_id`] 带回响应头 `X-Message-Id` 里的消息 ID。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        let req = self.build_request(msg)?;
        check_target(&req.url)?;
        let (status, message_id, body) = self.post(&req)?;
        Self::parse_answer(status, &body, message_id.as_deref())
    }
}

// ---------------------------------------------------------------------------
// 可独立测试的纯函数
// ---------------------------------------------------------------------------

/// 构造 v3 请求 payload,可独立测试的纯函数:
/// `personalizations[0].to[0].email` 是收件人,`from.email` 是发件人,
/// 纯文本正文走 `content[0]`(`type: text/plain`)。
pub fn build_payload(target: &str, from: &str, subject: &str, content: &str) -> Value {
    json!({
        "personalizations": [
            {"to": [{"email": target}]},
        ],
        "from": {"email": from},
        "subject": subject,
        "content": [
            {"type": "text/plain", "value": content},
        ],
    })
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

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
            api_key: "SG.key".into(),
            from: "noreply@example.com".into(),
            ..Config::default()
        }
    }

    #[test]
    fn test_name() {
        assert_eq!(Service::new(full_cfg()).name(), "sendgrid");
    }

    // 对齐上游 TestSendDeliversV3Shape 的离线部分:路径、Bearer 头、
    // payload 的 personalizations/from/subject/content 逐字段核对。
    #[test]
    fn test_build_request() {
        let svc = Service::new(full_cfg());
        let req = svc
            .build_request(
                &Message::new("alice@example.com", "重置验证码")
                    .with_content("您的验证码是 123456"),
            )
            .unwrap();
        assert_eq!(req.url, "https://api.sendgrid.com/v3/mail/send");
        assert_eq!(req.content_type, "application/json");
        assert_eq!(
            req.headers[0],
            ("Authorization", "Bearer SG.key".to_string()),
            "Bearer 令牌进鉴权头"
        );

        let payload: Value = serde_json::from_str(&req.body).unwrap();
        let to = &payload["personalizations"][0]["to"][0];
        assert_eq!(
            to["email"], "alice@example.com",
            "收件人进 personalizations"
        );
        assert_eq!(payload["from"]["email"], "noreply@example.com");
        assert_eq!(payload["subject"], "重置验证码");
        assert_eq!(payload["content"][0]["type"], "text/plain");
        assert_eq!(payload["content"][0]["value"], "您的验证码是 123456");
    }

    // 对齐上游 TestSendConfigIssues:配置缺失 / 空收件人 / 空正文在拨号之前拦下。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config::default())
            .send(&Message::new("a@b.c", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("api_key/from required"), "{err}");

        let svc = Service::new(full_cfg());
        let err = svc
            .send(&Message::new("", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("recipient is empty"), "{err}");

        let err = svc.send(&Message::new("a@b.c", "t")).unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("message body is empty"), "{err}");
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget。
    #[test]
    fn test_blocked_target() {
        let cfg = Config {
            api_key: "SG.key".into(),
            from: "noreply@example.com".into(),
            api_base: "http://127.0.0.1:9".into(),
        };
        let err = Service::new(cfg)
            .send(&Message::new("a@b.c", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // build_payload 纯函数:与上游测试的 JSON 形态逐字段对齐。
    #[test]
    fn test_build_payload() {
        let payload = build_payload(
            "alice@example.com",
            "noreply@example.com",
            "重置验证码",
            "您的验证码是 123456",
        );
        assert_eq!(
            payload,
            json!({
                "personalizations": [{"to": [{"email": "alice@example.com"}]}],
                "from": {"email": "noreply@example.com"},
                "subject": "重置验证码",
                "content": [{"type": "text/plain", "value": "您的验证码是 123456"}],
            })
        );
    }

    // 回执解析:受理即成功,X-Message-Id 响应头进回执(没有就留空);非 2xx 归投递失败。
    #[test]
    fn test_parse_answer() {
        let receipt = Service::parse_answer(202, "", Some("sg-msg-1")).unwrap();
        assert_eq!(
            receipt.provider_id, "sg-msg-1",
            "X-Message-Id 响应头要进回执"
        );

        let receipt = Service::parse_answer(202, "", None).unwrap();
        assert_eq!(receipt.provider_id, "");

        let err = Service::parse_answer(400, r#"{"errors":[{"message":"Bad Request"}]}"#, None)
            .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("400"), "{err}");

        let err = Service::parse_answer(503, "<html>gateway</html>", None).unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
    }
}
