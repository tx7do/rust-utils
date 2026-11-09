//! Discord Webhook:裸 HTTP POST,零依赖。
//!
//! 渠道约定:
//! - `Config::webhook_url` 是完整的 webhook 地址(`https://discord.com/api/webhooks/...`,
//!   创建时绑定频道),即收件身份——`Message.target` 无意义;
//! - 请求追加 `?wait=true`:让 Discord 回完整消息对象,message id 全靠它进
//!   [`Receipt::provider_id`] 供对账;
//! - 带 Title 时走 embed(标题 + 描述的卡片形态),否则纯文本;
//! - 429(限流)等非 2xx 一律 [`NotifyError::Delivery`]。

use std::io::Read;

use serde_json::{json, Map, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt,
    Service as NotifyService,
};

/// 应答读取上限。
const ANSWER_LIMIT: usize = 8 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Discord 渠道配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 完整的 webhook 地址(<https://discord.com/api/webhooks/...>)。
    pub webhook_url: String,
}

/// Discord 渠道。无状态,可并发使用。
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
    /// 构造 Discord 渠道。
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
        "discord"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.webhook_url.is_empty() {
            return Err(NotifyError::NotConfigured(
                "discord config incomplete: webhook_url required".into(),
            ));
        }

        // 带 Title 走 embed(标题 + 描述),否则纯文本;embed 形态下不发重复的 content。
        let mut payload = Map::new();
        if !msg.title.is_empty() {
            payload.insert(
                "embeds".into(),
                json!([{ "title": msg.title, "description": msg.content }]),
            );
        } else {
            payload.insert("content".into(), json!(msg.content));
        }

        Ok(Outbound {
            method: "POST",
            // wait=true 才回消息对象,message id 全靠它。
            url: format!("{}?wait=true", self.cfg.webhook_url),
            body: Value::Object(payload).to_string(),
            headers: vec![(
                "Content-Type",
                "application/json; charset=utf-8".to_string(),
            )],
        })
    }

    /// 解析 2xx 应答:Discord 的 message id 进回执(解析不出就留空)。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let mut receipt = Receipt::default();
        if let Some(id) = answer.get("id").and_then(Value::as_str) {
            receipt.provider_id = id.to_string();
        }
        Ok(receipt)
    }

    /// 处理一个已拿到的响应:状态码判门,2xx 之后才轮到 body 说话。
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

    /// 发一条消息。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured(
                "discord message body is empty".into(),
            ));
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
// 测试(纯离线:构造与应答解析;不发 HTTP)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Service {
        Service::new(
            true,
            Config {
                ref_: "7".into(),
                webhook_url: "https://discord.example/api/webhooks/1/2".into(),
            },
        )
    }

    #[test]
    fn test_missing_webhook_url_is_not_configured() {
        let svc = Service::new(true, Config::default());
        assert_eq!(svc.name(), "discord");
        let err = svc
            .build_request(&Message::new("", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_content_is_not_configured() {
        let err = service().send(&Message::new("", "t")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_embed_with_title() {
        let svc = service();
        let out = svc
            .build_request(&Message::new("", "重置验证码").with_content("您的验证码是 123456"))
            .unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(
            out.url, "https://discord.example/api/webhooks/1/2?wait=true",
            "wait=true 才回消息对象"
        );

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        let embeds = payload["embeds"].as_array().unwrap();
        assert_eq!(embeds.len(), 1);
        assert_eq!(embeds[0]["title"], "重置验证码");
        assert_eq!(embeds[0]["description"], "您的验证码是 123456");
        assert!(
            payload.get("content").is_none(),
            "embed 形态下不该再发重复的 content"
        );
        assert_eq!(out.headers[0].1, "application/json; charset=utf-8");
    }

    #[test]
    fn test_build_request_plain_when_no_title() {
        let svc = service();
        let out = svc
            .build_request(&Message::new("", "").with_content("只有正文"))
            .unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["content"], "只有正文");
        assert!(payload.get("embeds").is_none());
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(
            false,
            Config {
                webhook_url: "http://127.0.0.1:1/hook".into(),
                ..Config::default()
            },
        );
        let err = svc
            .send(&Message::new("", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_parse_response_message_id() {
        let svc = service();
        let receipt = svc.parse_response(r#"{"id":"119900211"}"#).unwrap();
        assert_eq!(receipt.provider_id, "119900211", "message id 要进回执");
        assert_eq!(svc.parse_response("{}").unwrap().provider_id, "");
    }

    #[test]
    fn test_rate_limited_is_delivery() {
        // 429(限流)走状态码分支:限流报文进错误文案。
        let err = status_error(
            429,
            r#"{"message":"You are being rate limited.","code":200029}"#,
        );
        assert!(err.to_string().contains("429"), "{err}");
        assert!(err.to_string().contains("rate limited"));
        assert!(!err.is_not_configured(), "拨过号被拒 = 投递失败");
    }
}
