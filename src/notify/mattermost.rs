//! Mattermost 入站 Webhook:Slack 兼容形态,零 SDK。
//!
//! 渠道约定:
//! - `Config::webhook_url` 是完整的入站地址(`https://host/hooks/<key>`,集成页创建),
//!   即收件身份——`Message.target` 无意义;
//! - 发一条 markdown 文本:Title 以粗体行起头(Mattermost 的 `**text**` 即粗体);
//! - `Config::channel` 可选:覆盖 webhook 默认频道(`@user` 私聊或 `#channel`);
//! - 对端 2xx 即成功(应答无消息 ID),[`Receipt`] 为空。

use std::io::Read;

use serde_json::{json, Map, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// 应答读取上限。
const ANSWER_LIMIT: usize = 4 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Mattermost 渠道配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 完整的入站地址(`<https://host/hooks/…>`)。
    pub webhook_url: String,
    /// 可选:覆盖 webhook 默认频道(@user 私聊或 #channel)。
    pub channel: String,
}

/// Mattermost 渠道。无状态,可并发使用。
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
    /// 构造 Mattermost 渠道。
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
        "mattermost"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.webhook_url.is_empty() {
            return Err(NotifyError::NotConfigured(
                "mattermost config incomplete: webhook_url required".into(),
            ));
        }

        // Title 以粗体行起头(Mattermost 的 **text** 即粗体)。
        let text = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("**{}**\n{}", msg.title, msg.content)
        };

        let mut payload = Map::new();
        payload.insert("text".into(), json!(text));
        if !self.cfg.channel.is_empty() {
            payload.insert("channel".into(), json!(self.cfg.channel));
        }

        Ok(Outbound {
            method: "POST",
            url: self.cfg.webhook_url.clone(),
            body: Value::Object(payload).to_string(),
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

    /// 发一条 markdown 文本。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured("mattermost message body is empty".into()));
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
        Service::new(
            true,
            Config {
                ref_: "7".into(),
                webhook_url: "https://mm.example/hooks/key-1".into(),
                channel: "#ops".into(),
            },
        )
    }

    #[test]
    fn test_missing_webhook_url_is_not_configured() {
        let svc = Service::new(true, Config::default());
        let err = svc.build_request(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_content_is_not_configured() {
        let err = service().send(&Message::new("", "t")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_markdown_text() {
        let svc = service();
        let out = svc.build_request(&Message::new("", "磁盘告警").with_content("用量 92%")).unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "https://mm.example/hooks/key-1");

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["text"], "**磁盘告警**\n用量 92%", "Mattermost 的粗体是 **text**");
        assert_eq!(payload["channel"], "#ops", "Channel 覆盖 webhook 默认频道");
    }

    #[test]
    fn test_plain_text_when_no_title_and_no_channel() {
        let svc = Service::new(true, Config { webhook_url: "https://mm.example/hooks/k".into(), ..Config::default() });
        let out = svc.build_request(&Message::new("", "").with_content("只有正文")).unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["text"], "只有正文");
        assert!(payload.get("channel").is_none(), "未配 channel 不占字段");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(false, Config { webhook_url: "http://127.0.0.1:1/hooks/k".into(), ..Config::default() });
        let err = svc.send(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_status_error() {
        let err = status_error(500, "boom");
        assert!(err.to_string().contains("500") && err.to_string().contains("boom"));
    }
}
