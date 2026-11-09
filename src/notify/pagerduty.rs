//! PagerDuty Events API v2 渠道(trigger 告警),零 SDK。
//!
//! 测试离线进行:请求构造与回执解析拆成纯函数断言,不真实连网。

use serde_json::{json, Value};

use crate::notify::{check_target, map_ureq_error, new_client, Message, NotifyError, Receipt};

/// Events API 官方域。
pub const DEFAULT_API_BASE: &str = "https://events.pagerduty.com";

/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// PagerDuty 渠道配置。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 集成的 Routing Key(Events API v2)。
    pub routing_key: String,
    /// 告警级别:critical / error / warning / info,留空 info。
    pub severity: String,
    /// 事件来源描述,留空 "notify"。
    pub source: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// PagerDuty 渠道。无状态,可并发使用。
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
    /// 构造 PagerDuty 渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
    /// severity 留空 info,source 留空 "notify"。
    pub fn new(cfg: Config) -> Self {
        let mut cfg = cfg;
        if cfg.api_base.is_empty() {
            cfg.api_base = DEFAULT_API_BASE.to_string();
        }
        if cfg.severity.is_empty() {
            cfg.severity = "info".to_string();
        }
        if cfg.source.is_empty() {
            cfg.source = "notify".to_string();
        }
        Service {
            agent: new_client(crate::notify::allow_private_target()),
            cfg,
        }
    }

    /// 构造请求(纯函数):Content 为 summary(必填),Target 为 dedup key——
    /// 同 key 的事件被 PagerDuty 关联为同一告警的重现;Title 落 custom_details。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured(
                "pagerduty summary is empty".to_string(),
            ));
        }
        if self.cfg.routing_key.is_empty() {
            return Err(NotifyError::NotConfigured(
                "pagerduty config incomplete: routing_key required".to_string(),
            ));
        }
        let mut payload = json!({
            "routing_key": self.cfg.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": msg.content,
                "source": self.cfg.source,
                "severity": self.cfg.severity,
                "timestamp": chrono_now_rfc3339(),
            },
        });
        if !msg.title.is_empty() {
            payload["payload"]["custom_details"] = json!({"title": msg.title});
        }
        if !msg.target.is_empty() {
            payload["dedup_key"] = json!(msg.target);
        }
        Ok(Prepared {
            url: format!("{}/v2/enqueue", self.cfg.api_base.trim_end_matches('/')),
            body: payload.to_string(),
            content_type: "application/json",
            headers: Vec::new(),
        })
    }

    /// 解析回执(纯函数):body 的 status 必须是 success,
    /// 确认后的 dedup key 进回执。
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
        if answer_status != "success" {
            let message = answer
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            return Err(NotifyError::Delivery(format!(
                "peer answered status={answer_status}: {message}"
            )));
        }
        let provider_id = answer
            .get("dedup_key")
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
        "pagerduty"
    }

    /// 触发一条告警:[`Receipt::provider_id`] 带回确认后的 dedup key。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        let req = self.build_request(msg)?;
        check_target(&req.url)?;
        let (status, body) = self.post(&req)?;
        Self::parse_answer(status, &body)
    }
}

/// 当前时刻的 RFC 3339 时间串(事件时间戳)。
fn chrono_now_rfc3339() -> String {
    // notify feature 依赖 chrono(clock);依赖缺失时留空,对端可自行补时间。
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
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
    fn test_name_and_defaults() {
        let svc = Service::new(Config {
            routing_key: "rk".into(),
            ..Config::default()
        });
        assert_eq!(svc.name(), "pagerduty");
        assert_eq!(svc.cfg.severity, "info", "severity 留空 info");
        assert_eq!(svc.cfg.source, "notify", "source 留空 notify");
    }

    // 配置缺失/正文缺失在拨号之前就拦下,归 NotConfigured。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config::default())
            .send(&Message::new("", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("routing_key"));

        let err = Service::new(Config {
            routing_key: "rk".into(),
            ..Config::default()
        })
        .send(&Message::new("", ""))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("summary is empty"));
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget。
    #[test]
    fn test_blocked_target() {
        let err = Service::new(Config {
            routing_key: "rk".into(),
            api_base: "http://127.0.0.1:9".into(),
            ..Config::default()
        })
        .send(&Message::new("", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 请求构造离线断言:路径、routing_key、event_action、dedup_key、
    // payload 的 summary/severity/source、Title 落 custom_details。
    #[test]
    fn test_build_request() {
        let svc = Service::new(Config {
            routing_key: "rk-1".into(),
            severity: "error".into(),
            source: "go-wind".into(),
            api_base: "https://events.example.test".into(),
        });
        let req = svc
            .build_request(
                &Message::new("disk-alert-1", "磁盘告警").with_content("root 分区用量 92%"),
            )
            .unwrap();
        assert_eq!(req.url, "https://events.example.test/v2/enqueue");
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["routing_key"], "rk-1");
        assert_eq!(payload["event_action"], "trigger");
        assert_eq!(payload["dedup_key"], "disk-alert-1", "Target 作为去重键");
        let pl = &payload["payload"];
        assert_eq!(pl["summary"], "root 分区用量 92%");
        assert_eq!(pl["severity"], "error");
        assert_eq!(pl["source"], "go-wind");
        assert_eq!(
            pl["custom_details"]["title"], "磁盘告警",
            "Title 落 custom_details"
        );
        assert!(
            pl.get("timestamp").and_then(Value::as_str).is_some(),
            "事件要带时间戳"
        );
    }

    // 无 Title 时不传 custom_details;无 Target 时不传 dedup_key。
    #[test]
    fn test_build_request_optional_fields() {
        let svc = Service::new(Config {
            routing_key: "rk".into(),
            ..Config::default()
        });
        let req = svc
            .build_request(&Message::new("", "").with_content("c"))
            .unwrap();
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert!(payload.get("dedup_key").is_none());
        assert!(payload["payload"].get("custom_details").is_none());
    }

    // 回执解析:确认后的 dedup_key 进回执;status != success 判投递失败。
    #[test]
    fn test_parse_answer() {
        let receipt = Service::parse_answer(
            202,
            r#"{"status":"success","message":"Event processed","dedup_key":"disk-alert-1"}"#,
        )
        .unwrap();
        assert_eq!(
            receipt.provider_id, "disk-alert-1",
            "确认后的 dedup key 要进回执"
        );

        // 上游用 400 压测:对端拒收是投递失败,文案带对端说明。
        let err = Service::parse_answer(
            400,
            r#"{"status":"invalid_event","message":"Summary is required"}"#,
        )
        .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("invalid_event"));

        let err = Service::parse_answer(200, "not json").unwrap_err();
        assert!(err.to_string().contains("not JSON"));

        let err = Service::parse_answer(200, r#"{"status":"","message":""}"#).unwrap_err();
        assert!(err.to_string().contains("status="));
    }
}
