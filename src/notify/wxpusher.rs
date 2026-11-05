//! 微信个人推送(WxPusher):裸 HTTP POST `/api/send/message`,零 SDK。
//!
//! 渠道约定:
//! - 收件身份是 `Message.target` 携带的 UID(形如 UID_xxx),进 body 的 `uids` 数组;
//! - `Config::app_token` 是应用的 APP_TOKEN(必填,缺了在拨号之前拦下);
//! - `summary` 是微信通知栏预览:Title 兜 Content 前缀;
//! - `Config::content_type` 选正文形态(1 文本 / 2 HTML / 3 Markdown),缺省按文本;
//! - WxPusher 的成功码是 `1000` 不是 0——钉住,别被顺手"统一"成 0;
//! - 成功时 `data[0].messageId` 进 [`Receipt::provider_id`] 供对账。

use std::io::Read;

use serde_json::{json, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// WxPusher 官方域。
pub const DEFAULT_API_BASE: &str = "https://wxpusher.zjiecode.com";

/// contentType 取值:文本。
pub const CONTENT_TEXT: i32 = 1;
/// contentType 取值:HTML。
pub const CONTENT_HTML: i32 = 2;
/// contentType 取值:Markdown。
pub const CONTENT_MARKDOWN: i32 = 3;

/// 应答读取上限。
const ANSWER_LIMIT: usize = 8 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// WxPusher 配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// WxPusher 应用的 APP_TOKEN。
    pub app_token: String,
    /// 正文形态:1 文本 / 2 HTML / 3 Markdown,留空按文本。
    pub content_type: i32,
    /// 服务基地址,留空用官方。
    pub api_base: String,
}

/// WxPusher 渠道。无状态,可并发使用。
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
    /// 构造 WxPusher 渠道。
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
        "wxpusher"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.app_token.is_empty() {
            return Err(NotifyError::NotConfigured(
                "wxpusher config incomplete: app_token required".into(),
            ));
        }

        // summary 是微信通知栏预览:Title 兜 Content 前缀(20 字节,退到字符边界)。
        let mut summary = msg.title.clone();
        if summary.is_empty() {
            summary = summary_prefix(&msg.content, 20);
        }

        let mut content_type = self.cfg.content_type;
        if content_type == 0 {
            content_type = CONTENT_TEXT;
        }

        let payload = json!({
            "appToken": self.cfg.app_token,
            "content": msg.content,
            "summary": summary,
            "contentType": content_type,
            "uids": [msg.target],
        });

        Ok(Outbound {
            method: "POST",
            url: format!("{}/api/send/message", self.cfg.api_base),
            body: payload.to_string(),
            headers: vec![("Content-Type", "application/json".to_string())],
        })
    }

    /// 解析 2xx 应答:WxPusher 的成功码是 1000。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body)
            .map_err(|_| NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body))))?;
        let code = answer.get("code").and_then(Value::as_i64).unwrap_or(0);
        if code != 1000 {
            let mut message = answer.get("msg").and_then(Value::as_str).unwrap_or("");
            if message.is_empty() {
                message = "no message";
            }
            return Err(NotifyError::Delivery(format!("peer answered code={code}: {message}")));
        }

        let mut receipt = Receipt::default();
        let message_id = answer
            .get("data")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|d| d.get("messageId"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if message_id != 0 {
            receipt.provider_id = message_id.to_string();
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

    /// 给 Target(UID)推一条消息。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("wxpusher uid is empty".into()));
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

/// 取前 `limit` 字节但退到字符边界(Go 按字节硬切会产生乱码)。
fn summary_prefix(content: &str, limit: usize) -> String {
    if content.len() <= limit {
        return content.to_string();
    }
    let mut end = limit;
    while end > 0 && !content.is_char_boundary(end) {
        end -= 1;
    }
    content[..end].to_string()
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
            Config { ref_: "7".into(), app_token: "AT_x".into(), api_base: "https://wx.example".into(), content_type: 0 },
        )
    }

    #[test]
    fn test_missing_app_token_is_not_configured() {
        let svc = Service::new(true, Config::default());
        assert_eq!(svc.name(), "wxpusher");
        let err = svc.build_request(&Message::new("UID_x", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_uid_is_not_configured() {
        let err = service().send(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_uid_message() {
        let svc = service();
        let out = svc
            .build_request(&Message::new("UID_x", "重置验证码").with_content("您的验证码是 123456"))
            .unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "https://wx.example/api/send/message");

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["appToken"], "AT_x");
        assert_eq!(payload["uids"], json!(["UID_x"]));
        assert_eq!(payload["content"], "您的验证码是 123456");
        assert_eq!(payload["contentType"], 1, "默认文本形态");
        assert_eq!(payload["summary"], "重置验证码", "summary 是通知栏预览(Title 兜底)");
    }

    #[test]
    fn test_summary_falls_back_to_content_prefix() {
        let svc = service();
        // 无 Title:取 Content 前 20 字节(ASCII 正好 20 个)。
        let out = svc
            .build_request(&Message::new("UID_x", "").with_content("012345678901234567890123456789"))
            .unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["summary"], "01234567890123456789");

        // 中文不在字节中间劈开:每个汉字 3 字节,6 个汉字 18 字节 <= 20,
        // 第 7 个会把总量推到 21 字节,退回 6 个汉字。
        let msg = Message::new("UID_x", "").with_content("汉".repeat(10));
        let out = svc.build_request(&msg).unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["summary"], "汉汉汉汉汉汉", "summary 按 20 字节退字符边界截取");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(false, Config { app_token: "t".into(), api_base: "http://127.0.0.1:1".into(), ..Config::default() });
        let err = svc.send(&Message::new("UID_x", "").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_success_code_is_1000() {
        let svc = service();

        // 成功码是 1000 不是 0——钉住,别被顺手"统一"成 0。
        let receipt = svc
            .parse_response(r#"{"code":1000,"msg":"处理成功","data":[{"uid":"UID_x","messageId":731}]}"#)
            .unwrap();
        assert_eq!(receipt.provider_id, "731", "WxPusher 的 messageId 要进回执");

        // code=0(缺省)也不算成功。
        let err = svc.parse_response(r#"{"code":0}"#).unwrap_err();
        assert!(err.to_string().contains("code=0"), "{err}");

        let err = svc.parse_response(r#"{"code":1001,"msg":"appToken无效"}"#).unwrap_err();
        assert!(err.to_string().contains("code=1001"), "{err}");
        assert!(!err.is_not_configured(), "拨过号被拒 = 投递失败");

        // 缺 msg 兜底"no message"。
        let err = svc.parse_response(r#"{"code":1002}"#).unwrap_err();
        assert!(err.to_string().contains("no message"));

        // 非 JSON 应答照实报。
        let err = svc.parse_response("<html>boom</html>").unwrap_err();
        assert!(err.to_string().contains("peer answer is not JSON"));
    }

    #[test]
    fn test_status_error() {
        let err = status_error(500, "boom");
        assert!(err.to_string().contains("500") && err.to_string().contains("boom"));
    }

    #[test]
    fn test_content_type_constants() {
        // 正文形态档位:1 文本 / 2 HTML / 3 Markdown(对齐上游 ContentText/ContentHTML/ContentMarkdown)。
        assert_eq!(CONTENT_TEXT, 1);
        assert_eq!(CONTENT_HTML, 2);
        assert_eq!(CONTENT_MARKDOWN, 3);
    }
}
