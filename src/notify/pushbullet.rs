//! Pushbullet 推送(note):裸 HTTP POST `/v2/pushes`,零 SDK。
//!
//! 渠道约定:
//! - 鉴权头是 `Access-Token`(账户 Access Token)——不是 Bearer;
//! - `Message.target` 为目标设备 device_iden(可选,留空推到账号的所有设备);
//! - 服务基地址默认官方 [`DEFAULT_API_BASE`],测试可覆盖;
//! - 应答 body 的 `iden`(推送标识)进 [`Receipt::provider_id`] 供对账。

use std::io::Read;

use serde_json::{json, Map, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// Pushbullet 官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://api.pushbullet.com";

/// 应答读取上限。
const ANSWER_LIMIT: usize = 8 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Pushbullet 配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 账户 Access Token。
    pub api_key: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// Pushbullet 渠道。无状态,可并发使用。
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
    /// 构造 Pushbullet 渠道。
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
        "pushbullet"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.api_key.is_empty() {
            return Err(NotifyError::NotConfigured(
                "pushbullet config incomplete: api_key required".into(),
            ));
        }

        let mut payload = Map::new();
        payload.insert("type".into(), json!("note"));
        payload.insert("title".into(), json!(msg.title));
        payload.insert("body".into(), json!(msg.content));
        // 无 Target 不带 device_iden:推全部设备。
        if !msg.target.is_empty() {
            payload.insert("device_iden".into(), json!(msg.target));
        }

        Ok(Outbound {
            method: "POST",
            url: format!("{}/v2/pushes", self.cfg.api_base),
            body: Value::Object(payload).to_string(),
            headers: vec![
                ("Access-Token", self.cfg.api_key.clone()),
                ("Content-Type", "application/json".to_string()),
            ],
        })
    }

    /// 解析 2xx 应答:Pushbullet 的 iden 进回执(解析不出就留空)。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let mut receipt = Receipt::default();
        if let Some(iden) = answer.get("iden").and_then(Value::as_str) {
            receipt.provider_id = iden.to_string();
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

    /// 推一条 note。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured("pushbullet message body is empty".into()));
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
            Config { ref_: "7".into(), api_key: "o.token-1".into(), api_base: "https://pb.example".into() },
        )
    }

    #[test]
    fn test_missing_api_key_is_not_configured() {
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
    fn test_build_request_delivers_note() {
        let svc = service();
        let out = svc
            .build_request(&Message::new("device-iden-9", "下载完成").with_content("报告已生成"))
            .unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "https://pb.example/v2/pushes");

        let header = |name: &str| {
            out.headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(header("Access-Token"), "o.token-1", "Pushbullet 的鉴权头是 Access-Token 不是 Bearer");

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["type"], "note");
        assert_eq!(payload["title"], "下载完成");
        assert_eq!(payload["body"], "报告已生成");
        assert_eq!(payload["device_iden"], "device-iden-9", "Target 作为目标设备");
    }

    #[test]
    fn test_without_target_pushes_all_devices() {
        let svc = Service::new(true, Config { api_key: "k".into(), api_base: "https://pb.example".into(), ..Config::default() });
        let out = svc.build_request(&Message::new("", "t").with_content("c")).unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert!(payload.get("device_iden").is_none(), "无 Target 推全部设备");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(false, Config { api_key: "k".into(), api_base: "http://127.0.0.1:1".into(), ..Config::default() });
        let err = svc.send(&Message::new("", "t").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_parse_response_returns_iden() {
        let svc = service();
        let receipt = svc
            .parse_response(r#"{"type":"note","iden":"ujzX123","title":"t","body":"c"}"#)
            .unwrap();
        assert_eq!(receipt.provider_id, "ujzX123", "Pushbullet 的 iden 要进回执");
        assert_eq!(svc.parse_response("{}").unwrap().provider_id, "");
    }

    #[test]
    fn test_status_error() {
        let err = status_error(401, "invalid token");
        assert!(err.to_string().contains("401") && err.to_string().contains("invalid token"));
    }
}
