//! Postmark 邮件 API:服务令牌头 + JSON 邮件,裸 HTTP,feature `notify`。
//! 对齐上游 `notify/postmark/postmark.go`。
//!
//! 鉴权是自定义请求头 `X-Postmark-Server-Token`(服务级令牌)。
//! Postmark 的业务错误也是 HTTP 200 + `ErrorCode != 0`,只看状态码会假成功:
//! body 的 `ErrorCode` 必须一并核对。
//!
//! 与上游 Go 版的差异:`Config.Ref`(展示标识,只进错误文案)未移植;
//! `context.Context` 取消传播在本 crate 的阻塞式 API 里不存在。
//!
//! 测试离线进行:请求构造与回执解析拆成纯函数断言,不真实连网。

use serde_json::{Value, json};

use crate::notify::{Message, NotifyError, Receipt, check_target, map_ureq_error, new_client};

/// Postmark 官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://api.postmarkapp.com";

/// Email 端点路径。
const SEND_PATH: &str = "/email";

/// 进错误文案的响应片段上限:对端可能回一整页 HTML。
const SNIPPET_LIMIT: usize = 256;

/// Postmark 配置。收件邮箱按消息传。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 服务级令牌(请求头 X-Postmark-Server-Token)。
    pub server_token: String,
    /// 发件人地址(或 `"Name <addr>"` 形态)。
    pub from: String,
    /// 可选的消息流 Tag(默认 outbound,不传该字段)。
    pub message_stream: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// Postmark 渠道。无状态,可并发使用。
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
    /// 构造 Postmark 渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
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

    /// 构造请求(纯函数):服务令牌进自定义头,payload 按 Postmark 形态组装
    /// (配了消息流才带 MessageStream 字段)。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("postmark recipient is empty".into()));
        }
        if self.cfg.server_token.is_empty() || self.cfg.from.is_empty() {
            return Err(NotifyError::NotConfigured(
                "postmark config incomplete: server_token/from required".into(),
            ));
        }
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured("postmark message body is empty".into()));
        }
        let stream = if self.cfg.message_stream.is_empty() {
            None
        } else {
            Some(self.cfg.message_stream.as_str())
        };
        Ok(Prepared {
            url: format!("{}{SEND_PATH}", self.cfg.api_base),
            body: build_payload(
                &self.cfg.from,
                &msg.target,
                &msg.title,
                &msg.content,
                stream,
            )
            .to_string(),
            content_type: "application/json",
            headers: vec![
                ("X-Postmark-Server-Token", self.cfg.server_token.clone()),
                ("Accept", "application/json".to_string()),
            ],
        })
    }

    /// 解析回执(纯函数):2xx 之后还要看 body 的 ErrorCode(0 为成功)——
    /// Postmark 的业务错误也是 HTTP 200,只看状态码会假成功;
    /// 成功时数字 MessageID 进回执。
    fn parse_answer(status: u16, body: &str) -> Result<Receipt, NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "peer answered {status}: {}",
                snippet(body)
            )));
        }
        #[derive(serde::Deserialize, Default)]
        struct Answer {
            #[serde(rename = "MessageID", default)]
            message_id: String,
            #[serde(rename = "ErrorCode", default)]
            error_code: i64,
            #[serde(rename = "Message", default)]
            message: String,
        }
        let answer: Answer = serde_json::from_str(body).map_err(|_| {
            NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body)))
        })?;
        if answer.error_code != 0 {
            let message = if answer.message.is_empty() { "no message" } else { &answer.message };
            return Err(NotifyError::Delivery(format!(
                "peer answered error_code={}: {message}",
                answer.error_code
            )));
        }
        Ok(Receipt { provider_id: answer.message_id })
    }

    /// POST 已构造好的请求,返回 (状态码, 应答文本)。
    /// 非 2xx 也返回应答文本,由 [`Self::parse_answer`] 统一归类。
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
        "postmark"
    }

    /// 给 Target(收件邮箱)发一封纯文本邮件。
    /// [`Receipt::provider_id`] 带回 Postmark 的数字 MessageID。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        let req = self.build_request(msg)?;
        check_target(&req.url)?;
        let (status, body) = self.post(&req)?;
        Self::parse_answer(status, &body)
    }
}

// ---------------------------------------------------------------------------
// 可独立测试的纯函数
// ---------------------------------------------------------------------------

/// 构造 email 请求 payload,可独立测试的纯函数;
/// `message_stream` 非空才带 MessageStream 字段(不传对端走默认 outbound)。
pub fn build_payload(
    from: &str,
    to: &str,
    subject: &str,
    text_body: &str,
    message_stream: Option<&str>,
) -> Value {
    let mut payload = json!({
        "From": from,
        "To": to,
        "Subject": subject,
        "TextBody": text_body,
    });
    if let Some(stream) = message_stream {
        payload["MessageStream"] = json!(stream);
    }
    payload
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
            server_token: "st-1".into(),
            from: "noreply@example.com".into(),
            ..Config::default()
        }
    }

    #[test]
    fn test_name() {
        assert_eq!(Service::new(full_cfg()).name(), "postmark");
    }

    // 对齐上游 TestSendDeliversTokenHeaderAndShape 的离线部分:路径、令牌头、
    // payload 的 From/To/Subject/TextBody 逐字段核对。
    #[test]
    fn test_build_request() {
        let svc = Service::new(full_cfg());
        let req = svc
            .build_request(
                &Message::new("alice@example.com", "重置验证码").with_content("您的验证码是 123456"),
            )
            .unwrap();
        assert_eq!(req.url, "https://api.postmarkapp.com/email");
        assert_eq!(req.content_type, "application/json");
        assert!(req.headers.contains(&("Accept", "application/json".to_string())));
        assert_eq!(
            req.headers[0],
            ("X-Postmark-Server-Token", "st-1".to_string()),
            "服务令牌进自定义请求头"
        );

        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["From"], "noreply@example.com");
        assert_eq!(payload["To"], "alice@example.com");
        assert_eq!(payload["Subject"], "重置验证码");
        assert_eq!(payload["TextBody"], "您的验证码是 123456");
        assert!(
            payload.get("MessageStream").is_none(),
            "没配消息流就不传该字段:对端走默认 outbound"
        );
    }

    // 配了消息流就带 MessageStream 字段。
    #[test]
    fn test_build_request_message_stream() {
        let cfg = Config {
            server_token: "st-1".into(),
            from: "noreply@example.com".into(),
            message_stream: "broadcast".into(),
            ..Config::default()
        };
        let svc = Service::new(cfg);
        let req = svc
            .build_request(&Message::new("a@b.c", "t").with_content("c"))
            .unwrap();
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["MessageStream"], "broadcast");
    }

    // 对齐上游 TestSendConfigIssue:配置缺失 / 空收件人 / 空正文在拨号之前拦下。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config::default())
            .send(&Message::new("a@b.c", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("server_token/from required"), "{err}");

        let svc = Service::new(full_cfg());
        let err = svc.send(&Message::new("", "t").with_content("c")).unwrap_err();
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
            server_token: "st-1".into(),
            from: "noreply@example.com".into(),
            api_base: "http://127.0.0.1:9".into(),
            ..Config::default()
        };
        let err = Service::new(cfg)
            .send(&Message::new("a@b.c", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // build_payload 纯函数:MessageStream 只有配了才出现。
    #[test]
    fn test_build_payload() {
        let base = build_payload("noreply@example.com", "alice@example.com", "重置验证码", "您的验证码是 123456", None);
        assert_eq!(
            base,
            json!({
                "From": "noreply@example.com",
                "To": "alice@example.com",
                "Subject": "重置验证码",
                "TextBody": "您的验证码是 123456",
            })
        );

        let with_stream = build_payload("f@e.c", "a@b.c", "t", "c", Some("outbound"));
        assert_eq!(with_stream["MessageStream"], "outbound");
    }

    // 对齐上游 TestSendPostmarkErrorInside200:HTTP 200 + ErrorCode!=0 是业务失败,
    // 只看状态码会假成功;成功时 MessageID 进回执。
    #[test]
    fn test_parse_answer() {
        let receipt = Service::parse_answer(
            200,
            r#"{"To":"alice@example.com","SubmittedAt":"2026-10-15","MessageID":"1234567","ErrorCode":0,"Message":"OK"}"#,
        )
        .unwrap();
        assert_eq!(receipt.provider_id, "1234567", "Postmark 的 MessageID 要进回执");

        let err = Service::parse_answer(200, r#"{"ErrorCode":401,"Message":"Invalid API Request"}"#).unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("error_code=401"), "{err}");

        let err = Service::parse_answer(200, r#"{"ErrorCode":10}"#).unwrap_err();
        assert!(err.to_string().contains("no message"), "{err}");

        let err = Service::parse_answer(422, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");

        let err = Service::parse_answer(200, "<html>gateway</html>").unwrap_err();
        assert!(err.to_string().contains("not JSON"), "{err}");
    }
}
