//! Home Assistant 通知服务(REST API):零 SDK。
//!
//! 渠道约定:
//! - 个人/家庭推送:`Message.target` 无意义(Service 决定通知面);
//! - `Config::server_url` 是 HA 实例基地址(必填,如 `http://homeassistant.local:8123`;
//!   兼容字段 `api_base` 与其等价,二选一配置均可);`token` 是长期访问令牌(必填);
//! - `Config::service` 是 notify 服务名(`notify.persistent_notification` /
//!   `notify.mobile_app_xxx`),进请求路径 `/api/services/notify/<service>`,
//!   缺省走 `SERVICE_DEFAULT`(persistent_notification);
//! - `Message.target` 若填了进 `data.target`(按平台解释);`Message.params` 原样进
//!   `data`(各家 notify 平台的自定义字段,如 markdown 的 title 或推送渠道);
//! - 鉴权走 `Authorization: Bearer <token>`;对端 2xx 即成功,[`Receipt`] 为空。

use std::io::Read;

use serde_json::{json, Map, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// 默认 notify 服务(手机伴侣 App 的通知平台)。
pub const SERVICE_DEFAULT: &str = "persistent_notification";

/// 应答读取上限。
const ANSWER_LIMIT: usize = 8 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Home Assistant 配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// HA 实例基地址(必填,如 <http://homeassistant.local:8123>)。
    pub server_url: String,
    /// 长期访问令牌(Long-Lived Access Token)。
    pub token: String,
    /// notify 服务名(notify.persistent_notification / notify.mobile_app_xxx)。
    pub service: String,
    /// 兼容字段:与 server_url 等价(二选一配置均可)。
    pub api_base: String,
}

/// HA 通知渠道。无状态,可并发使用。
pub struct HASService {
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

impl HASService {
    /// 构造 Home Assistant 通知渠道。
    ///
    /// `allow_private = true`(本机联调)时整条 SSRF 防线关闭;生产部署必须传 `false`。
    pub fn new(allow_private: bool, cfg: Config) -> Self {
        let mut cfg = cfg;
        if cfg.server_url.is_empty() {
            cfg.server_url = std::mem::take(&mut cfg.api_base);
        }
        if cfg.service.is_empty() {
            cfg.service = SERVICE_DEFAULT.to_string();
        }
        HASService {
            client: new_client(allow_private),
            allow_private,
            cfg,
        }
    }

    /// 渠道名。
    pub fn name(&self) -> &str {
        "homeassistant"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.server_url.is_empty() || self.cfg.token.is_empty() {
            return Err(NotifyError::NotConfigured(
                "homeassistant config incomplete: server_url/token required".into(),
            ));
        }

        // data:Params 原样进(各家 notify 平台的自定义字段),Target 落 data.target 由平台解释。
        let mut data = Map::new();
        for (k, v) in &msg.params {
            data.insert(k.clone(), json!(v));
        }
        if !msg.target.is_empty() {
            data.insert("target".into(), json!(msg.target));
        }

        let mut payload = Map::new();
        payload.insert("message".into(), json!(msg.content));
        if !msg.title.is_empty() {
            payload.insert("title".into(), json!(msg.title));
        }
        if !data.is_empty() {
            payload.insert("data".into(), Value::Object(data));
        }

        Ok(Outbound {
            method: "POST",
            // 服务名进路径;真实服务名是字母数字下划线,不做路径转义(与上游 fmt.Sprintf 一致)。
            url: format!("{}/api/services/notify/{}", self.cfg.server_url.trim_end_matches('/'), self.cfg.service),
            body: Value::Object(payload).to_string(),
            headers: vec![
                ("Authorization", format!("Bearer {}", self.cfg.token)),
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

impl NotifyService for HASService {
    fn name(&self) -> &str {
        HASService::name(self)
    }

    /// 调一次 notify 服务。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured("homeassistant message body is empty".into()));
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

    fn service() -> HASService {
        HASService::new(
            true,
            Config {
                ref_: "7".into(),
                server_url: "http://ha.example:8123/".into(),
                token: "llat-1".into(),
                service: "mobile_app_phone".into(),
                ..Config::default()
            },
        )
    }

    #[test]
    fn test_missing_config_is_not_configured() {
        // 只配 server:缺 token。
        let svc = HASService::new(true, Config { server_url: "http://ha:8123".into(), ..Config::default() });
        let err = svc.build_request(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_content_is_not_configured() {
        let err = service().send(&Message::new("", "t")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_api_base_fallback_and_default_service() {
        // api_base 与 server_url 等价(二选一);service 缺省走持久通知。
        let svc = HASService::new(
            true,
            Config { api_base: "http://ha2.example:8123".into(), token: "t".into(), ..Config::default() },
        );
        let out = svc.build_request(&Message::new("", "").with_content("c")).unwrap();
        assert_eq!(out.url, "http://ha2.example:8123/api/services/notify/persistent_notification",
            "缺省走持久通知服务,api_base 兜底基地址");
    }

    #[test]
    fn test_build_request_calls_notify_service() {
        let svc = service();
        let msg = Message::new("entity.kitchen_display", "门铃")
            .with_content("有人在门口")
            .with_param("channel", "critical");
        let out = svc.build_request(&msg).unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "http://ha.example:8123/api/services/notify/mobile_app_phone", "服务名进路径");

        let header = |name: &str| {
            out.headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(header("Authorization"), "Bearer llat-1");

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["message"], "有人在门口");
        assert_eq!(payload["title"], "门铃");
        assert_eq!(payload["data"]["target"], "entity.kitchen_display", "Target 落 data.target 由平台解释");
        assert_eq!(payload["data"]["channel"], "critical", "Params 原样进 data");
    }

    #[test]
    fn test_no_data_when_no_target_and_params() {
        let svc = service();
        let out = svc.build_request(&Message::new("", "t").with_content("c")).unwrap();
        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert!(payload.get("data").is_none(), "无 target 无 params 不占 data 字段");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = HASService::new(false, Config { server_url: "http://127.0.0.1:1".into(), token: "t".into(), ..Config::default() });
        let err = svc.send(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_status_error() {
        let err = status_error(401, "unauthorized");
        assert!(err.to_string().contains("401") && err.to_string().contains("unauthorized"));
    }
}
