//! LINE Messaging API(push 消息):裸 HTTP POST `/v2/bot/message/push`,零 SDK。
//!
//! 渠道约定:
//! - `Message.target` 是收件目标(userId / groupId / roomId),进 body 的 `to`;
//! - `Config::channel_access_token` 是频道的长时访问令牌(开发者控制台签发,必填,
//!   缺了在拨号之前拦下),走 `Authorization: Bearer` 头;
//! - LINE 文本消息无独立标题位:正文 = Title + Content(有标题时换行相连);
//! - 服务基地址默认官方 [`DEFAULT_API_BASE`],测试可覆盖;
//! - 对端 2xx 即成功(不回消息 ID),[`Receipt`] 为空。

use std::io::Read;

use serde_json::json;

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// LINE 官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://api.line.me";

/// 应答读取上限。
const ANSWER_LIMIT: usize = 8 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// LINE 渠道配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 频道的长时访问令牌(开发者控制台签发)。
    pub channel_access_token: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// LINE 渠道。无状态,可并发使用。
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
    /// 构造 LINE 渠道。
    ///
    /// `allow_private = true`(本机联调)时整条 SSRF 防线关闭;生产部署必须传 `false`。
    pub fn new(allow_private: bool, cfg: Config) -> Self {
        let api_base = if cfg.api_base.is_empty() {
            DEFAULT_API_BASE.to_string()
        } else {
            cfg.api_base
        };
        Service {
            client: new_client(allow_private),
            allow_private,
            cfg: Config { api_base, ..cfg },
        }
    }

    /// 渠道名。
    pub fn name(&self) -> &str {
        "line"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.channel_access_token.is_empty() {
            return Err(NotifyError::NotConfigured(
                "line config incomplete: channel_access_token required".into(),
            ));
        }

        // LINE 文本消息无独立标题位:正文 = Title + Content(有标题时换行相连)。
        let text = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };

        let payload = json!({
            "to": msg.target,
            "messages": [{ "type": "text", "text": text }],
        });

        Ok(Outbound {
            method: "POST",
            url: format!("{}/v2/bot/message/push", self.cfg.api_base),
            body: payload.to_string(),
            headers: vec![
                ("Authorization", format!("Bearer {}", self.cfg.channel_access_token)),
                ("Content-Type", "application/json".to_string()),
            ],
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

    /// 给 Target 推一条文本消息。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("line destination is empty".into()));
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
        Service::new(
            true,
            Config { ref_: "7".into(), channel_access_token: "cat-1".into(), api_base: "https://line.example".into() },
        )
    }

    #[test]
    fn test_missing_token_is_not_configured() {
        let svc = Service::new(true, Config::default());
        let err = svc.build_request(&Message::new("U1", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_destination_is_not_configured() {
        let err = service().send(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_push_message() {
        let svc = service();
        let out = svc
            .build_request(&Message::new("U1234", "重置验证码").with_content("您的验证码是 123456"))
            .unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "https://line.example/v2/bot/message/push");

        let header = |name: &str| {
            out.headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(header("Authorization"), "Bearer cat-1");

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["to"], "U1234");
        let messages = payload["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["type"], "text");
        assert_eq!(messages[0]["text"], "重置验证码\n您的验证码是 123456");
    }

    #[test]
    fn test_plain_when_no_title() {
        let svc = service();
        let out = svc.build_request(&Message::new("U1", "").with_content("只有正文")).unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["messages"][0]["text"], "只有正文");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(false, Config { channel_access_token: "t".into(), api_base: "http://127.0.0.1:1".into(), ..Config::default() });
        let err = svc.send(&Message::new("U1", "").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_status_error() {
        let err = status_error(400, "invalid");
        assert!(err.to_string().contains("400") && err.to_string().contains("invalid"));
    }
}
