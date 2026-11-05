//! Slack Incoming Webhook:裸 HTTP POST,零依赖。
//!
//! 渠道约定:
//! - `Config::webhook_url` 是完整的 incoming webhook 地址(`https://hooks.slack.com/services/...`,
//!   App 管理页创建,创建时绑定到具体频道),即收件身份——`Message.target` 无意义;
//! - 发一条 mrkdwn 文本消息:Title 以粗体行起头(`*text*`,Slack 无独立标题位);
//! - 对端回 200 "ok" 即成功;Incoming Webhook 不回消息 ID,[`Receipt`] 为空。

use std::io::Read;

use serde_json::{json, Map, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// 应答读取上限。
const ANSWER_LIMIT: usize = 4 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Slack 渠道配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 完整的 incoming webhook 地址(<https://hooks.slack.com/services/...>)。
    pub webhook_url: String,
}

/// Slack 渠道。无状态,可并发使用。
pub struct Service {
    client: ureq::Agent,
    allow_private: bool,
    cfg: Config,
}

/// 一切就绪、只待发送的出站请求。
#[derive(Debug)]
struct Outbound {
    method: &'static str,
    url: String,
    body: String,
    headers: Vec<(&'static str, String)>,
}

impl Service {
    /// 构造 Slack 渠道。
    ///
    /// `allow_private = true`(本机联调)时整条 SSRF 防线关闭;生产部署必须传 `false`。
    pub fn new(allow_private: bool, cfg: Config) -> Self {
        Service {
            client: new_client(allow_private),
            allow_private,
            cfg,
        }
    }

    /// 渠道名。
    pub fn name(&self) -> &str {
        "slack"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.webhook_url.is_empty() {
            return Err(NotifyError::NotConfigured(
                "slack config incomplete: webhook_url required".into(),
            ));
        }

        // Title 以 mrkdwn 粗体行起头(Slack 无独立标题位)。
        let text = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("*{}*\n{}", msg.title, msg.content)
        };

        let mut payload = Map::new();
        payload.insert("text".into(), json!(text));

        Ok(Outbound {
            method: "POST",
            url: self.cfg.webhook_url.clone(),
            body: Value::Object(payload).to_string(),
            headers: vec![("Content-Type", "application/json; charset=utf-8".to_string())],
        })
    }

    /// 对端 2xx 即成功,无 body 判据。
    fn parse_response(&self, _body: &str) -> Result<Receipt, NotifyError> {
        Ok(Receipt::default())
    }

    /// 处理一个已拿到的响应:状态码判门。
    fn finish(&self, resp: ureq::Response) -> Result<Receipt, NotifyError> {
        let status = resp.status();
        let body = read_body_limited(resp, ANSWER_LIMIT);
        if !(200..=299).contains(&status) {
            return Err(status_error(status, &body));
        }
        self.parse_response(&body)
    }
}

impl NotifyService for Service {
    fn name(&self) -> &str {
        Service::name(self)
    }

    /// 发一条 mrkdwn 文本消息。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured("slack message body is empty".into()));
        }

        let out = self.build_request(msg)?;

        if !self.allow_private {
            check_target(&out.url)?;
        }

        let mut req = self.client.request(out.method, &out.url);
        for (k, v) in &out.headers {
            req = req.set(k, v);
        }
        match req.send_string(&out.body) {
            Ok(resp) => self.finish(resp),
            Err(ureq::Error::Status(status, resp)) => {
                Err(status_error(status, &read_body_limited(resp, ANSWER_LIMIT)))
            }
            Err(err) => Err(map_ureq_error(err)),
        }
    }
}

/// 把对端应答读进来并限长。
fn read_body_limited(resp: ureq::Response, limit: usize) -> String {
    let mut buf = Vec::new();
    let _ = resp.into_reader().take(limit as u64).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// 应答片段截断(退到字符边界,不劈开 UTF-8 字符)。
fn snippet(body: &str) -> String {
    if body.len() <= SNIPPET_LIMIT {
        return body.to_string();
    }
    let mut end = SNIPPET_LIMIT;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &body[..end])
}

/// 非 2xx 状态的错误:带状态码与响应片段。
fn status_error(status: u16, body: &str) -> NotifyError {
    NotifyError::Delivery(format!("peer answered {status}: {}", snippet(body)))
}

// ---------------------------------------------------------------------------
// 测试(纯离线:构造;不发 HTTP)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Service {
        Service::new(true, Config { ref_: "7".into(), webhook_url: "https://hooks.example/services/x".into() })
    }

    #[test]
    fn test_missing_webhook_url_is_not_configured() {
        let svc = Service::new(true, Config::default());
        assert_eq!(svc.name(), "slack");
        let err = svc.build_request(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_content_is_not_configured() {
        let err = service().send(&Message::new("", "t")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_mrkdwn_text() {
        let svc = service();
        let out = svc
            .build_request(&Message::new("", "重置验证码").with_content("您的验证码是 123456"))
            .unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "https://hooks.example/services/x");
        assert_eq!(out.headers[0].1, "application/json; charset=utf-8");

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["text"], "*重置验证码*\n您的验证码是 123456", "Title 以 mrkdwn 粗体行起头");
    }

    #[test]
    fn test_plain_when_no_title() {
        let svc = service();
        let out = svc.build_request(&Message::new("", "").with_content("只有正文")).unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["text"], "只有正文");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(false, Config { webhook_url: "http://127.0.0.1:1/hook".into(), ..Config::default() });
        let err = svc.send(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_status_error_is_delivery() {
        let err = status_error(400, "invalid_payload");
        assert!(err.to_string().contains("400"), "{err}");
        assert!(err.to_string().contains("invalid_payload"));
        assert!(!err.is_not_configured(), "拨过号被拒 = 投递失败");
    }
}
