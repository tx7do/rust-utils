//! Microsoft Teams 工作流 Webhook:Adaptive Card 形态,零依赖。
//!
//! 渠道约定:
//! - `Config::webhook_url` 是 Power Automate「发布到 Web 时」工作流生成的入站地址
//!   (`https://*.webhook.office.com/...` 或 logic.azure.com;O365 组连接器已于 2024 退役),
//!   即收件身份——`Message.target` 无意义;
//! - 发一张 Adaptive Card:Title 为加粗大字块(`weight=Bolder`、`size=Medium`),
//!   Content 为正文块(`wrap=true`);
//! - 工作流 Webhook 只回 200(无消息 ID),[`Receipt`] 为空。

use std::io::Read;

use serde_json::json;

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// 应答读取上限。
const ANSWER_LIMIT: usize = 8 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Teams 渠道配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// Power Automate 工作流的入站地址(https://*.webhook.office.com/... 或 logic.azure.com)。
    pub webhook_url: String,
}

/// Teams 渠道。无状态,可并发使用。
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
    /// 构造 Teams 渠道。
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
        "teams"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.webhook_url.is_empty() {
            return Err(NotifyError::NotConfigured(
                "teams config incomplete: webhook_url required".into(),
            ));
        }

        // Title 为加粗大字块(Content 正文块在前,Title 块插到最前)。
        let mut card_body = vec![json!({
            "type": "TextBlock",
            "text": msg.content,
            "wrap": true,
        })];
        if !msg.title.is_empty() {
            card_body.insert(
                0,
                json!({
                    "type": "TextBlock",
                    "text": msg.title,
                    "weight": "Bolder",
                    "size": "Medium",
                    "wrap": true,
                }),
            );
        }

        let payload = json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": card_body,
                },
            }],
        });

        Ok(Outbound {
            method: "POST",
            url: self.cfg.webhook_url.clone(),
            body: payload.to_string(),
            headers: vec![("Content-Type", "application/json".to_string())],
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

    /// 发一张 Adaptive Card。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured("teams message body is empty".into()));
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
    use serde_json::Value;

    fn service() -> Service {
        Service::new(true, Config { ref_: "7".into(), webhook_url: "https://webhook.office.com/workflow/1".into() })
    }

    #[test]
    fn test_missing_webhook_url_is_not_configured() {
        let svc = Service::new(true, Config::default());
        assert_eq!(svc.name(), "teams");
        let err = svc.build_request(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_content_is_not_configured() {
        let err = service().send(&Message::new("", "t")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_adaptive_card() {
        let svc = service();
        let out = svc
            .build_request(&Message::new("", "重置验证码").with_content("您的验证码是 123456"))
            .unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "https://webhook.office.com/workflow/1");

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["type"], "message");

        let attachments = payload["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0]["contentType"], "application/vnd.microsoft.card.adaptive");

        let content = &attachments[0]["content"];
        assert_eq!(content["type"], "AdaptiveCard");
        let blocks = content["body"].as_array().unwrap();
        assert_eq!(blocks.len(), 2, "Title 加粗大字块 + Content 正文块");
        assert_eq!(blocks[0]["type"], "TextBlock");
        assert_eq!(blocks[0]["weight"], "Bolder");
        assert_eq!(blocks[0]["text"], "重置验证码");
        assert_eq!(blocks[1]["text"], "您的验证码是 123456");
        assert_eq!(blocks[1]["wrap"], true);
    }

    #[test]
    fn test_plain_body_when_no_title() {
        let svc = service();
        let out = svc.build_request(&Message::new("", "").with_content("只有正文")).unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        let blocks = payload["attachments"][0]["content"]["body"].as_array().unwrap();
        assert_eq!(blocks.len(), 1, "无 Title 只有一个正文块");
        assert_eq!(blocks[0]["text"], "只有正文");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(false, Config { webhook_url: "http://127.0.0.1:1/hook".into(), ..Config::default() });
        let err = svc.send(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_status_error() {
        let err = status_error(400, "bad request");
        assert!(err.to_string().contains("400") && err.to_string().contains("bad request"));
    }
}
