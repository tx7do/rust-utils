//! Zulip 消息(stream 形态):Basic Auth 机器人,零 SDK。
//!
//! 渠道约定:
//! - `Message.target` 是 stream 频道名,进表单的 `to`;
//! - `Config::server_url`/`bot_email`/`bot_api_key` 三者必填(缺了在拨号之前拦下);
//!   机器人凭据走 Basic Auth(用户名/密码);
//! - stream 消息必须有 topic:`Config::topic` 是默认,`Message.params["topic"]` 可按条覆盖,
//!   两处都没有在拨号之前拦下(不是投递失败);
//! - 正文 = Title + Content(有标题时换行相连);
//! - 应答 body 的 `result`("success" 才算)、原因放 `msg`;消息 `id`
//!   进 [`Receipt::provider_id`] 供对账。

use std::io::Read;

use serde_json::Value;

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt,
    Service as NotifyService,
};

/// 应答读取上限。
const ANSWER_LIMIT: usize = 8 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Zulip 渠道配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 服务基地址(必填——Zulip 都是自建/云租户域)。
    pub server_url: String,
    /// 机器人邮箱(Basic Auth 的用户名)。
    pub bot_email: String,
    /// 机器人 API Key(Basic Auth 的密码)。
    pub bot_api_key: String,
    /// stream 消息必须有 topic;`Message.params["topic"]` 可按条覆盖。
    pub topic: String,
}

/// Zulip 渠道。无状态,可并发使用。
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
    /// 构造 Zulip 渠道。
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
        "zulip"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.server_url.is_empty()
            || self.cfg.bot_email.is_empty()
            || self.cfg.bot_api_key.is_empty()
        {
            return Err(NotifyError::NotConfigured(
                "zulip config incomplete: server_url/bot_email/bot_api_key required".into(),
            ));
        }

        // topic 按条覆盖默认;两处都没有就拦下——stream 消息没 topic 发不出去。
        let topic = msg
            .params
            .get("topic")
            .cloned()
            .unwrap_or_else(|| self.cfg.topic.clone());
        if topic.is_empty() {
            return Err(NotifyError::NotConfigured(
                "zulip requires a topic: set Config.Topic or params[\"topic\"]".into(),
            ));
        }

        // 正文 = Title + Content(有标题时换行相连)。
        let content = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };

        let pairs: Vec<(String, String)> = vec![
            ("type".to_string(), "stream".to_string()),
            ("to".to_string(), msg.target.clone()),
            ("topic".to_string(), topic),
            ("content".to_string(), content),
        ];

        Ok(Outbound {
            method: "POST",
            url: format!(
                "{}/api/v1/messages",
                self.cfg.server_url.trim_end_matches('/')
            ),
            body: form_encode(&pairs),
            headers: vec![
                (
                    "Authorization",
                    format!(
                        "Basic {}",
                        base64_standard(
                            format!("{}:{}", self.cfg.bot_email, self.cfg.bot_api_key).as_bytes()
                        )
                    ),
                ),
                (
                    "Content-Type",
                    "application/x-www-form-urlencoded".to_string(),
                ),
            ],
        })
    }

    /// 解析 2xx 应答:Zulip 的结论在 body 的 result("success")。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body).map_err(|_| {
            NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body)))
        })?;
        let result = answer.get("result").and_then(Value::as_str).unwrap_or("");
        if result != "success" {
            let mut message = answer.get("msg").and_then(Value::as_str).unwrap_or("");
            if message.is_empty() {
                message = "no message";
            }
            return Err(NotifyError::Delivery(format!(
                "peer answered result={result}: {message}"
            )));
        }
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

    /// 给 Target(stream 频道名)发一条消息。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("zulip stream is empty".into()));
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

/// 标准 base64(带 `=` 填充),用于 Basic 认证头。
fn base64_standard(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// URL 查询/表单成分编码(按字节:ASCII 字母数字与 `-_.~` 直通,空格作 `+`,其余 `%XX`)。
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

/// 参数对的有序表单编码(按键名排序,键与值均经 `query_escape` 编码,对齐 Go url.Values.Encode)。
fn form_encode(pairs: &[(String, String)]) -> String {
    let mut pairs = pairs.to_vec();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
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
                server_url: "https://zulip.example/".into(),
                bot_email: "bot@example.com".into(),
                bot_api_key: "key-1".into(),
                topic: "告警".into(),
            },
        )
    }

    #[test]
    fn test_missing_config_is_not_configured() {
        // 只配 topic:缺 server/bot 凭据。
        let svc = Service::new(
            true,
            Config {
                topic: "t".into(),
                ..Config::default()
            },
        );
        let err = svc
            .build_request(&Message::new("ops", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_stream_is_not_configured() {
        let err = service()
            .send(&Message::new("", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_missing_topic_is_not_configured() {
        // stream 消息没 topic 发不出去,拨号之前拦下。
        let svc = Service::new(
            true,
            Config {
                ref_: "9".into(),
                server_url: "https://z.example".into(),
                bot_email: "b@e".into(),
                bot_api_key: "k".into(),
                ..Config::default()
            },
        );
        let err = svc
            .build_request(&Message::new("ops", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_stream_message() {
        let svc = service();
        let out = svc
            .build_request(&Message::new("ops", "磁盘告警").with_content("用量 92%"))
            .unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(
            out.url, "https://zulip.example/api/v1/messages",
            "基地址尾部斜杠剥掉"
        );

        let header = |name: &str| {
            out.headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(
            header("Authorization"),
            format!("Basic {}", base64_standard(b"bot@example.com:key-1"))
        );

        // 表单按键名排序(content、to、topic、type)。
        assert!(out.body.contains("type=stream"));
        assert!(out.body.contains("to=ops"));
        assert!(
            out.body.contains("topic=%E5%91%8A%E8%AD%A6"),
            "stream 消息必须有 topic(Config 默认): {}",
            out.body
        );
        assert!(out
            .body
            .contains("content=%E7%A3%81%E7%9B%98%E5%91%8A%E8%AD%A6"));
    }

    #[test]
    fn test_topic_param_overrides() {
        let svc = Service::new(
            true,
            Config {
                ref_: "9".into(),
                server_url: "https://z.example".into(),
                bot_email: "b@e".into(),
                bot_api_key: "k".into(),
                topic: "default".into(),
            },
        );
        let msg = Message::new("ops", "")
            .with_content("c")
            .with_param("topic", "deploy");
        let out = svc.build_request(&msg).unwrap();
        assert!(
            out.body.contains("topic=deploy"),
            "Params[topic] 按条覆盖: {}",
            out.body
        );
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(
            false,
            Config {
                server_url: "http://127.0.0.1:1".into(),
                bot_email: "b@e".into(),
                bot_api_key: "k".into(),
                topic: "t".into(),
                ..Config::default()
            },
        );
        let err = svc
            .send(&Message::new("ops", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_parse_response_result() {
        let svc = service();

        // 成功:消息 ID 进回执。
        let receipt = svc
            .parse_response(r#"{"result":"success","msg":"","id":3159981}"#)
            .unwrap();
        assert_eq!(receipt.provider_id, "3159981", "Zulip 的消息 ID 要进回执");

        let err = svc
            .parse_response(r#"{"result":"error","msg":"stream does not exist"}"#)
            .unwrap_err();
        assert!(err.to_string().contains("result=error"), "{err}");
        assert!(err.to_string().contains("stream does not exist"));
        assert!(!err.is_not_configured(), "拨过号被拒 = 投递失败");

        // id=0 不进回执。
        assert_eq!(
            svc.parse_response(r#"{"result":"success","id":0}"#)
                .unwrap()
                .provider_id,
            ""
        );

        // 缺 msg 兜底"no message"。
        let err = svc.parse_response(r#"{"result":"error"}"#).unwrap_err();
        assert!(err.to_string().contains("no message"));

        // 非 JSON 应答照实报。
        let err = svc.parse_response("<html>boom</html>").unwrap_err();
        assert!(err.to_string().contains("peer answer is not JSON"));
    }

    #[test]
    fn test_status_error() {
        let err = status_error(401, "denied");
        assert!(err.to_string().contains("401") && err.to_string().contains("denied"));
    }
}
