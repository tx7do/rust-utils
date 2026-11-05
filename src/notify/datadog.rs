//! Datadog Events API 渠道(事件/告警发布),零 SDK。
//!
//! 测试离线进行:请求构造与回执解析拆成纯函数断言,不真实连网。

use serde_json::{Value, json};

use crate::notify::{Message, NotifyError, Receipt, check_target, map_ureq_error, new_client};

/// Datadog US 站点域;欧盟 us3/us5 站点用 [`Config::api_base`] 覆写。
pub const DEFAULT_API_BASE: &str = "https://api.datadoghq.com";

/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Datadog 配置。个人/站点点对点:Target 无意义(API Key 即租户身份)。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 组织的 API Key。
    pub api_key: String,
    /// 事件优先级:"normal" / "low",留空 normal。
    pub priority: String,
    /// 事件标签(可选)。
    pub tags: Vec<String>,
    /// 站点域,留空用 US;eu/us3/us5/ddog-gov 各站点按需覆盖。
    pub api_base: String,
}

/// Datadog 渠道。无状态,可并发使用。
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
    /// 构造 Datadog 渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
    /// priority 留空 normal。
    pub fn new(cfg: Config) -> Self {
        let mut cfg = cfg;
        if cfg.api_base.is_empty() {
            cfg.api_base = DEFAULT_API_BASE.to_string();
        }
        if cfg.priority.is_empty() {
            cfg.priority = "normal".to_string();
        }
        Service {
            agent: new_client(crate::notify::allow_private_target()),
            cfg,
        }
    }

    /// 构造请求(纯函数):Target(可选)落事件的 host 字段——事件归属到哪台主机。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured(
                "datadog event text is empty".to_string(),
            ));
        }
        if self.cfg.api_key.is_empty() {
            return Err(NotifyError::NotConfigured(
                "datadog config incomplete: api_key required".to_string(),
            ));
        }
        let mut payload = json!({
            "title": msg.title,
            "text": msg.content,
            "priority": self.cfg.priority,
        });
        if !msg.target.is_empty() {
            payload["host"] = json!(msg.target);
        }
        if !self.cfg.tags.is_empty() {
            payload["tags"] = json!(self.cfg.tags);
        }
        Ok(Prepared {
            url: format!(
                "{}/api/v1/events",
                self.cfg.api_base.trim_end_matches('/')
            ),
            body: payload.to_string(),
            content_type: "application/json",
            headers: vec![("DD-API-KEY", self.cfg.api_key.clone())],
        })
    }

    /// 解析回执(纯函数):body 的 status 必须是 ok,事件 ID 进回执。
    fn parse_answer(status: u16, body: &str) -> Result<Receipt, NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "peer answered {status}: {}",
                snippet(body)
            )));
        }
        let answer: Value = serde_json::from_str(body).map_err(|_| {
            NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body)))
        })?;
        let answer_status = answer.get("status").and_then(Value::as_str).unwrap_or("");
        if answer_status != "ok" {
            let message = answer
                .get("errors")
                .and_then(Value::as_array)
                .and_then(|errors| errors.first())
                .and_then(Value::as_str)
                .unwrap_or("no message");
            return Err(NotifyError::Delivery(format!(
                "peer answered status={answer_status}: {message}"
            )));
        }
        let event_id = answer
            .pointer("/event/id")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let provider_id = if event_id != 0 {
            event_id.to_string()
        } else {
            String::new()
        };
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
        "datadog"
    }

    /// 发布一条事件:[`Receipt::provider_id`] 带回 Datadog 的事件 ID。
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
    fn test_name_and_default_priority() {
        let svc = Service::new(Config {
            api_key: "k".into(),
            ..Config::default()
        });
        assert_eq!(svc.name(), "datadog");
        assert_eq!(svc.cfg.priority, "normal", "priority 留空 normal");
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
            api_key: "k".into(),
            ..Config::default()
        })
        .send(&Message::new("", ""))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("event text is empty"));
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget。
    #[test]
    fn test_blocked_target() {
        let err = Service::new(Config {
            api_key: "k".into(),
            api_base: "http://127.0.0.1:9".into(),
            ..Config::default()
        })
        .send(&Message::new("", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 请求构造离线断言:路径、DD-API-KEY 鉴权头、title/text/priority、
    // tags 数组、Target 落 host 字段。
    #[test]
    fn test_build_request() {
        let svc = Service::new(Config {
            api_key: "dd-key".into(),
            priority: "low".into(),
            tags: vec!["env:prod".into(), "team:infra".into()],
            api_base: "https://api.example.test".into(),
        });
        let req = svc
            .build_request(&Message::new("worker-7", "磁盘告警").with_content("用量 92%"))
            .unwrap();
        assert_eq!(req.url, "https://api.example.test/api/v1/events");
        assert_eq!(
            req.headers[0],
            ("DD-API-KEY", "dd-key".to_string()),
            "Datadog 的鉴权头是 DD-API-KEY"
        );
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["title"], "磁盘告警");
        assert_eq!(payload["text"], "用量 92%");
        assert_eq!(payload["priority"], "low");
        assert_eq!(payload["tags"][0], "env:prod");
        assert_eq!(payload["tags"][1], "team:infra");
        assert_eq!(payload["host"], "worker-7", "Target 落 host 字段");
    }

    // 无 Target 时不传 host;无 tags 时不传 tags。
    #[test]
    fn test_build_request_optional_fields() {
        let svc = Service::new(Config {
            api_key: "k".into(),
            ..Config::default()
        });
        let req = svc
            .build_request(&Message::new("", "").with_content("c"))
            .unwrap();
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert!(payload.get("host").is_none());
        assert!(payload.get("tags").is_none());
    }

    // 回执解析:事件 ID 进回执;status != ok 判投递失败,文案带首条错误。
    #[test]
    fn test_parse_answer() {
        let receipt = Service::parse_answer(
            200,
            r#"{"status":"ok","event":{"id":1728312,"title":"磁盘告警","text":"用量 92%","tags":[]}}"#,
        )
        .unwrap();
        assert_eq!(receipt.provider_id, "1728312", "事件 ID 要进回执");

        // 上游用 403 压测:对端拒收是投递失败,文案带对端说明。
        let err = Service::parse_answer(
            403,
            r#"{"status":"error","errors":["API key invalid"]}"#,
        )
        .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("API key invalid"));

        let err = Service::parse_answer(200, "not json").unwrap_err();
        assert!(err.to_string().contains("not JSON"));

        let receipt = Service::parse_answer(200, r#"{"status":"ok"}"#).unwrap();
        assert_eq!(receipt.provider_id, "", "事件 ID 为 0 时不进回执");
    }
}
