//! Opsgenie Alerts v2 渠道(创建告警),零 SDK。
//!
//! 测试离线进行:请求构造与回执解析拆成纯函数断言,不真实连网。

use serde_json::{Value, json};

use crate::notify::{Message, NotifyError, Receipt, check_target, map_ureq_error, new_client};

/// Opsgenie 官方 API 域(欧盟租户用 [`Config::api_base`] 覆写为 api.eu.opsgenie.com)。
pub const DEFAULT_API_BASE: &str = "https://api.opsgenie.com";

/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Opsgenie 渠道配置。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 集成的 API Key(请求头 GenieKey)。
    pub api_key: String,
    /// 服务基地址,留空用官方;欧盟租户与测试可覆盖。
    pub api_base: String,
}

/// Opsgenie 渠道。无状态,可并发使用。
pub struct Service {
    agent: ureq::Agent,
    cfg: Config,
}

/// 构造好的出站请求:纯数据,供离线测试断言。
struct Prepared {
    url: String,
    body: String,
    content_type: &'static str,
    headers: Vec<(&'static str, String)>,
}

impl Service {
    /// 构造 Opsgenie 渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
    pub fn new(cfg: Config) -> Self {
        let mut cfg = cfg;
        if cfg.api_base.is_empty() {
            cfg.api_base = DEFAULT_API_BASE.to_string();
        }
        Service {
            agent: new_client(crate::notify::allow_private_target()),
            cfg,
        }
    }

    /// 构造请求(纯函数):message 必填(Title 优先、Content 兜底),
    /// Content 全文进 description,Target 作为 alias 供告警去重/关联。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured(
                "opsgenie message is empty".to_string(),
            ));
        }
        if self.cfg.api_key.is_empty() {
            return Err(NotifyError::NotConfigured(
                "opsgenie config incomplete: api_key required".to_string(),
            ));
        }
        let message = if msg.title.is_empty() {
            &msg.content
        } else {
            &msg.title
        };
        let mut payload = json!({
            "message": message,
            "description": msg.content,
        });
        if !msg.target.is_empty() {
            payload["alias"] = json!(msg.target);
        }
        Ok(Prepared {
            url: format!("{}/v2/alerts", self.cfg.api_base.trim_end_matches('/')),
            body: payload.to_string(),
            content_type: "application/json",
            headers: vec![("Authorization", format!("GenieKey {}", self.cfg.api_key))],
        })
    }

    /// 解析回执(纯函数):2xx 即受理,requestId 进回执;
    /// 应答不是 JSON 时按上游口径不判失败(requestId 留空)。
    fn parse_answer(status: u16, body: &str) -> Result<Receipt, NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "peer answered {status}: {}",
                snippet(body)
            )));
        }
        let answer: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let provider_id = answer
            .get("requestId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok(Receipt { provider_id })
    }

    /// POST 已构造好的请求,返回 (状态码, 应答文本)。
    fn post(&self, req: &Prepared) -> Result<(u16, String), NotifyError> {
        let mut request = self
            .agent
            .post(&req.url)
            .set("Content-Type", req.content_type);
        for (name, value) in &req.headers {
            request = request.set(name, value);
        }
        match request.send_string(&req.body) {
            Ok(resp) => Ok((resp.status(), read_answer(resp)?)),
            Err(ureq::Error::Status(status, resp)) => Ok((status, read_answer(resp)?)),
            Err(err) => Err(map_ureq_error(err)),
        }
    }
}

impl crate::notify::Service for Service {
    fn name(&self) -> &str {
        "opsgenie"
    }

    /// 创建一条告警:[`Receipt::provider_id`] 带回 requestId。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        let req = self.build_request(msg)?;
        check_target(&req.url)?;
        let (status, body) = self.post(&req)?;
        Self::parse_answer(status, &body)
    }
}

/// 读对端应答文本。
fn read_answer(resp: ureq::Response) -> Result<String, NotifyError> {
    resp.into_string()
        .map_err(|e| NotifyError::Delivery(format!("read peer answer: {e}")))
}

/// 进错误文案的响应片段截断(按字节上限回退到字符边界)。
fn snippet(body: &str) -> String {
    if body.len() <= SNIPPET_LIMIT {
        return body.to_string();
    }
    let mut end = SNIPPET_LIMIT;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\u{2026}", &body[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::Service as _;

    #[test]
    fn test_name() {
        assert_eq!(Service::new(Config::default()).name(), "opsgenie");
    }

    // 配置缺失/正文缺失在拨号之前就拦下,归 NotConfigured。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config::default())
            .send(&Message::new("", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("api_key"));

        let err = Service::new(Config {
            api_key: "gk".into(),
            ..Config::default()
        })
        .send(&Message::new("", ""))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("message is empty"));
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget。
    #[test]
    fn test_blocked_target() {
        let err = Service::new(Config {
            api_key: "gk".into(),
            api_base: "http://127.0.0.1:9".into(),
        })
        .send(&Message::new("", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 请求构造离线断言:路径、GenieKey 鉴权头、Title 顶 message 位、
    // Content 全文进 description、Target 进 alias。
    #[test]
    fn test_build_request() {
        let svc = Service::new(Config {
            api_key: "gk-1".into(),
            ..Config::default()
        });
        let req = svc
            .build_request(
                &Message::new("disk-alert-1", "磁盘告警").with_content("root 分区用量 92%"),
            )
            .unwrap();
        assert_eq!(req.url, "https://api.opsgenie.com/v2/alerts");
        assert_eq!(req.headers[0], ("Authorization", "GenieKey gk-1".to_string()));
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["message"], "磁盘告警", "message 必填位由 Title 顶上");
        assert_eq!(
            payload["description"], "root 分区用量 92%",
            "Content 全文进 description"
        );
        assert_eq!(payload["alias"], "disk-alert-1", "alias 即去重关联键");
    }

    // 无 Title 时 message 由 Content 兜底;无 Target 时不传 alias。
    #[test]
    fn test_build_request_title_fallback() {
        let svc = Service::new(Config {
            api_key: "gk".into(),
            ..Config::default()
        });
        let req = svc
            .build_request(&Message::new("", "").with_content("没有标题的告警"))
            .unwrap();
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["message"], "没有标题的告警");
        assert!(payload.get("alias").is_none());
    }

    // 回执解析:requestId 进回执;应答非 JSON 不判失败。
    #[test]
    fn test_parse_answer() {
        let receipt = Service::parse_answer(
            202,
            r#"{"result":"Request will be processed","took":1,"requestId":"rq-1"}"#,
        )
        .unwrap();
        assert_eq!(receipt.provider_id, "rq-1", "requestId 要进回执");

        let receipt = Service::parse_answer(200, "not json").unwrap();
        assert_eq!(receipt.provider_id, "");

        let err = Service::parse_answer(401, "denied").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("401"));
    }
}
