//! IFTTT Maker Webhooks(自动化触发):裸 HTTP POST,零 SDK。
//!
//! 渠道约定:
//! - `Message.target` 是 event 事件名,进请求路径:`<api_base>/trigger/<event>/json?key=<key>`;
//! - `Config::api_key` 是账户的 Webhooks Key(必填,缺了在拨号之前拦下);
//! - 值槽映射:`value1` = Title、`value2` = Content、`value3` = `Message.params["value3"]`;
//! - IFTTT 只回 200 "Congratulations!",无消息 ID,[`Receipt`] 为空。

use std::io::Read;

use serde_json::{json, Map, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// IFTTT Maker Webhooks 官方域。
pub const DEFAULT_API_BASE: &str = "https://maker.ifttt.com";

/// 应答读取上限。
const ANSWER_LIMIT: usize = 4 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// IFTTT 配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 账户的 Webhooks Key。
    pub api_key: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// IFTTT 渠道。无状态,可并发使用。
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
    /// 构造 IFTTT 渠道。
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
        "ifttt"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.api_key.is_empty() {
            return Err(NotifyError::NotConfigured(
                "ifttt config incomplete: api_key required".into(),
            ));
        }

        let mut payload = Map::new();
        payload.insert("value1".into(), json!(msg.title));
        payload.insert("value2".into(), json!(msg.content));
        if let Some(v3) = msg.params.get("value3") {
            payload.insert("value3".into(), json!(v3));
        }

        Ok(Outbound {
            method: "POST",
            // 事件名与 key 直拼进 URL(与上游 fmt.Sprintf 一致,不做转义)。
            url: format!("{}/trigger/{}/json?key={}", self.cfg.api_base, msg.target, self.cfg.api_key),
            body: Value::Object(payload).to_string(),
            headers: vec![("Content-Type", "application/json".to_string())],
        })
    }

    /// IFTTT 只回 200 文本,无 body 判据:2xx 即成功。
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

    /// 触发一次 Target 事件。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("ifttt event is empty".into()));
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
        Service::new(true, Config { ref_: "7".into(), api_key: "k-1".into(), api_base: "https://ifttt.example".into() })
    }

    #[test]
    fn test_missing_api_key_is_not_configured() {
        let svc = Service::new(true, Config::default());
        assert_eq!(svc.name(), "ifttt");
        let err = svc.build_request(&Message::new("evt", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_event_is_not_configured() {
        let err = service().send(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_triggers_event() {
        let svc = service();
        let msg = Message::new("build_done", "构建完成")
            .with_content("产物已就绪")
            .with_param("value3", "v1.2.0");
        let out = svc.build_request(&msg).unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "https://ifttt.example/trigger/build_done/json?key=k-1", "事件名进路径,key 进 query");

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["value1"], "构建完成");
        assert_eq!(payload["value2"], "产物已就绪");
        assert_eq!(payload["value3"], "v1.2.0", "value3 从 Params 取");

        // 没配 value3 就不发这个键。
        let out = svc.build_request(&Message::new("e", "").with_content("c")).unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert!(payload.get("value3").is_none());
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(false, Config { api_key: "k".into(), api_base: "http://127.0.0.1:1".into(), ..Config::default() });
        let err = svc.send(&Message::new("evt", "").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_status_error_is_delivery() {
        // IFTTT 的鉴权失败回 401 + errors JSON:走状态码分支,片段进错误文案。
        let err = status_error(401, r#"{"errors":[{"message":"Authentication failed"}]}"#);
        assert!(err.to_string().contains("401"), "{err}");
        assert!(err.to_string().contains("Authentication failed"));
        assert!(!err.is_not_configured(), "拨过号被拒 = 投递失败");
    }

    #[test]
    fn test_parse_response_is_always_ok() {
        assert_eq!(service().parse_response("Congratulations!").unwrap(), Receipt::default());
    }
}
