//! Rocket.Chat `chat.postMessage`:用户头鉴权,零 SDK。
//!
//! 渠道约定:
//! - `Message.target` 是频道名(`@user` 或 `#channel`),进 body 的 `channel`;
//! - `Config::server_url`/`user_id`/`auth_token` 三者必填(缺了在拨号之前拦下);
//!   鉴权走 `X-Auth-Token` / `X-User-Id` 两个请求头;
//! - 正文 = Title + Content(有标题时换行相连);
//! - 应答 body 的 `success`(true 为成功)、原因放 `error`;成功时消息 `_id`
//!   进 [`Receipt::provider_id`] 供对账。

use std::io::Read;

use serde_json::{json, Map, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// 应答读取上限。
const ANSWER_LIMIT: usize = 8 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Rocket.Chat 渠道配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 服务基地址(必填——Rocket.Chat 都是自建/私有化部署)。
    pub server_url: String,
    /// 个人访问令牌的用户 ID(账户页创建)。
    pub user_id: String,
    /// 个人访问令牌(账户页创建)。
    pub auth_token: String,
}

/// Rocket.Chat 渠道。无状态,可并发使用。
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
    /// 构造 Rocket.Chat 渠道。
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
        "rocketchat"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.server_url.is_empty() || self.cfg.user_id.is_empty() || self.cfg.auth_token.is_empty() {
            return Err(NotifyError::NotConfigured(
                "rocketchat config incomplete: server_url/user_id/auth_token required".into(),
            ));
        }

        // 正文 = Title + Content(有标题时换行相连)。
        let text = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };

        let mut payload = Map::new();
        payload.insert("channel".into(), json!(msg.target));
        payload.insert("text".into(), json!(text));

        Ok(Outbound {
            method: "POST",
            url: format!("{}/api/v1/chat.postMessage", self.cfg.server_url.trim_end_matches('/')),
            body: Value::Object(payload).to_string(),
            headers: vec![
                ("X-Auth-Token", self.cfg.auth_token.clone()),
                ("X-User-Id", self.cfg.user_id.clone()),
                ("Content-Type", "application/json".to_string()),
            ],
        })
    }

    /// 解析 2xx 应答:业务结论在 body 的 success。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body)
            .map_err(|_| NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body))))?;
        let success = answer.get("success").and_then(Value::as_bool).unwrap_or(false);
        if !success {
            let mut error = answer.get("error").and_then(Value::as_str).unwrap_or("");
            if error.is_empty() {
                error = "no message";
            }
            return Err(NotifyError::Delivery(format!("peer answered success=false: {error}")));
        }
        let mut receipt = Receipt::default();
        if let Some(id) = answer.get("message").and_then(|m| m.get("_id")).and_then(Value::as_str) {
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

    /// 给 Target 发一条消息。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("rocketchat channel is empty".into()));
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
                server_url: "https://rc.example/".into(),
                user_id: "uid-1".into(),
                auth_token: "tok-1".into(),
            },
        )
    }

    #[test]
    fn test_missing_config_is_not_configured() {
        // 只配 server_url:缺 user_id/auth_token。
        let svc = Service::new(true, Config { server_url: "https://example.com".into(), ..Config::default() });
        let err = svc.build_request(&Message::new("#ops", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_channel_is_not_configured() {
        let err = service().send(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_user_headers() {
        let svc = service();
        let out = svc
            .build_request(&Message::new("#ops", "部署完成").with_content("v1.2.0 已上线"))
            .unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "https://rc.example/api/v1/chat.postMessage", "基地址尾部斜杠剥掉");

        let header = |name: &str| {
            out.headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(header("X-User-Id"), "uid-1");
        assert_eq!(header("X-Auth-Token"), "tok-1");

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["channel"], "#ops");
        assert_eq!(payload["text"], "部署完成\nv1.2.0 已上线");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(
            false,
            Config { server_url: "http://127.0.0.1:1".into(), user_id: "u".into(), auth_token: "t".into(), ..Config::default() },
        );
        let err = svc.send(&Message::new("#ops", "").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_parse_response_success_false() {
        let svc = service();

        // 成功:消息 _id 进回执。
        let receipt = svc.parse_response(r#"{"success":true,"message":{"_id":"msg-9"}}"#).unwrap();
        assert_eq!(receipt.provider_id, "msg-9", "消息 _id 要进回执");

        let err = svc.parse_response(r#"{"success":false,"error":"invalid-channel"}"#).unwrap_err();
        assert!(err.to_string().contains("success=false"), "{err}");
        assert!(err.to_string().contains("invalid-channel"));
        assert!(!err.is_not_configured(), "拨过号被拒 = 投递失败");

        // 缺 error 兜底"no message"。
        let err = svc.parse_response(r#"{"success":false}"#).unwrap_err();
        assert!(err.to_string().contains("no message"));

        // 非 JSON 应答照实报。
        let err = svc.parse_response("<html>boom</html>").unwrap_err();
        assert!(err.to_string().contains("peer answer is not JSON"));
    }

    #[test]
    fn test_status_error() {
        let err = status_error(401, "unauthorized");
        assert!(err.to_string().contains("401") && err.to_string().contains("unauthorized"));
    }
}
