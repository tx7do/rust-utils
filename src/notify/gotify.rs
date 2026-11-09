//! 自建推送服务(Gotify Server):application token + `/message`,零 SDK。
//!
//! 渠道约定:
//! - Gotify 的 application token 即收件身份,所以 `Message.target` 在本渠道无意义——
//!   一个 Service 对应一个应用;
//! - Gotify 没有官方公有域,`Config::server_url` 必填;
//! - token 走 URL query(Gotify 的惯例):`/message?token=<app_token>`;
//! - `Config::priority` 是默认优先级(0~10),`Message.params["priority"]` 可按条覆盖;
//! - 应答 body 的 `id`(消息 ID)进 [`Receipt::provider_id`] 供对账。

use std::io::Read;

use serde_json::{json, Map, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt,
    Service as NotifyService,
};

/// 应答读取上限。
const ANSWER_LIMIT: usize = 4 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Gotify 渠道配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 自建 Gotify 服务基地址(必填——Gotify 没有官方公有域)。
    pub server_url: String,
    /// Gotify 应用的 application token。
    pub app_token: String,
    /// 默认优先级(0~10,各家客户端对高优先级的呈现不同);
    /// `Message.params["priority"]` 可按条覆盖。
    pub priority: i32,
}

/// Gotify 渠道。无状态,可并发使用。
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
    /// 构造 Gotify 渠道。
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
        "gotify"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.server_url.is_empty() || self.cfg.app_token.is_empty() {
            return Err(NotifyError::NotConfigured(
                "gotify config incomplete: server_url/app_token required".into(),
            ));
        }

        let mut payload = Map::new();
        payload.insert("title".into(), json!(msg.title));
        payload.insert("message".into(), json!(msg.content));

        let mut priority = self.cfg.priority;
        if let Some(p) = msg.params.get("priority") {
            priority = p.parse::<i32>().map_err(|_| {
                NotifyError::NotConfigured(format!("params[priority] {p:?} is not a number"))
            })?;
        }
        if priority != 0 {
            payload.insert("priority".into(), json!(priority));
        }

        Ok(Outbound {
            method: "POST",
            // application token 走 query(Gotify 的惯例)。
            url: format!(
                "{}/message?token={}",
                self.cfg.server_url,
                query_escape(&self.cfg.app_token)
            ),
            body: Value::Object(payload).to_string(),
            headers: vec![("Content-Type", "application/json".to_string())],
        })
    }

    /// 解析 2xx 应答:Gotify 回的消息 id 进回执(解析不出就留空,不影响成功判定)。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let mut receipt = Receipt::default();
        if let Some(id) = answer.get("id").and_then(Value::as_i64) {
            if id != 0 {
                receipt.provider_id = id.to_string();
            }
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

    /// 发一条消息(Target 忽略——收件身份是 AppToken)。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured(
                "gotify message body is empty".into(),
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

/// URL 查询成分编码(按字节:ASCII 字母数字与 `-_.~` 直通,空格作 `+`,其余 `%XX`)。
fn query_escape(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
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
                server_url: "https://gotify.example".into(),
                app_token: "Atoken".into(),
                priority: 0,
            },
        )
    }

    #[test]
    fn test_missing_config_is_not_configured() {
        let svc = Service::new(
            true,
            Config {
                server_url: "https://example.com".into(),
                ..Config::default()
            },
        );
        assert_eq!(svc.name(), "gotify");
        let err = svc
            .build_request(&Message::new("", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "缺 app_token 在拨号之前就该拦下");
    }

    #[test]
    fn test_empty_content_is_not_configured() {
        let err = service().send(&Message::new("", "t")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_token_and_shape() {
        let svc = service();
        let msg = Message::new("", "重置验证码")
            .with_content("您的验证码是 123456")
            .with_param("priority", "4");
        let out = svc.build_request(&msg).unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(
            out.url, "https://gotify.example/message?token=Atoken",
            "application token 走 query(Gotify 的惯例)"
        );

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["title"], "重置验证码");
        assert_eq!(payload["message"], "您的验证码是 123456");
        assert_eq!(payload["priority"], 4, "Params[priority] 按条覆盖默认档位");
    }

    #[test]
    fn test_priority_default_and_zero_omitted() {
        // 配置默认优先级生效。
        let svc = Service::new(
            true,
            Config {
                server_url: "https://g.example".into(),
                app_token: "t".into(),
                priority: 7,
                ..Config::default()
            },
        );
        let out = svc
            .build_request(&Message::new("", "t").with_content("c"))
            .unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["priority"], 7);

        // 0 不占字段(对端按默认档位处理)。
        let out = service()
            .build_request(&Message::new("", "t").with_content("c"))
            .unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert!(payload.get("priority").is_none(), "priority=0 不占字段");

        // 垃圾优先级在拨号之前拦下。
        let err = service()
            .build_request(
                &Message::new("", "t")
                    .with_content("c")
                    .with_param("priority", "high"),
            )
            .unwrap_err();
        assert!(err.is_not_configured(), "优先级要数字档位");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(
            false,
            Config {
                server_url: "http://127.0.0.1:1".into(),
                app_token: "t".into(),
                ..Config::default()
            },
        );
        let err = svc
            .send(&Message::new("", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_parse_response_returns_message_id() {
        let svc = service();
        let receipt = svc
            .parse_response(r#"{"id":42,"appid":1,"message":"m","title":"t","priority":4}"#)
            .unwrap();
        assert_eq!(receipt.provider_id, "42", "Gotify 的消息 ID 要进回执");

        // 解析不出 id 就留空,不影响成功判定。
        assert_eq!(svc.parse_response("not json").unwrap().provider_id, "");
        assert_eq!(svc.parse_response(r#"{"id":0}"#).unwrap().provider_id, "");
    }

    #[test]
    fn test_status_error() {
        let err = status_error(500, "boom");
        assert!(err.to_string().contains("500") && err.to_string().contains("boom"));
    }
}
