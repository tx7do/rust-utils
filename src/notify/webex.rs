//! Cisco Webex 消息渠道(Bot),零 SDK。
//!
//! 测试离线进行:请求构造与回执解析拆成纯函数断言,不真实连网。

use serde_json::{json, Value};

use crate::notify::{check_target, map_ureq_error, new_client, Message, NotifyError, Receipt};

/// Webex 官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://webexapis.com";

/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Webex 配置。Target(roomId 或人员邮箱)按消息传。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 机器人的 Bearer 令牌。
    pub bot_token: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// Webex 渠道。无状态,可并发使用。
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
    /// 构造 Webex 渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
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

    /// 构造请求(纯函数):含 "@" 按 toPersonEmail(私聊人员),否则按
    /// roomId(空间)。正文 = Title 与 Content 以单换行相连。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "webex destination is empty".to_string(),
            ));
        }
        if self.cfg.bot_token.is_empty() {
            return Err(NotifyError::NotConfigured(
                "webex config incomplete: bot_token required".to_string(),
            ));
        }
        let text = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };
        let mut payload = json!({ "text": text });
        if msg.target.contains('@') {
            payload["toPersonEmail"] = json!(msg.target);
        } else {
            payload["roomId"] = json!(msg.target);
        }
        Ok(Prepared {
            url: format!("{}/v1/messages", self.cfg.api_base.trim_end_matches('/')),
            body: payload.to_string(),
            content_type: "application/json",
            headers: vec![("Authorization", format!("Bearer {}", self.cfg.bot_token))],
        })
    }

    /// 解析回执(纯函数):2xx 即受理,消息 id 进回执;
    /// 应答不是 JSON 时按上游口径不判失败(id 留空)。
    fn parse_answer(status: u16, body: &str) -> Result<Receipt, NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "peer answered {status}: {}",
                snippet(body)
            )));
        }
        let answer: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let provider_id = answer
            .get("id")
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
        "webex"
    }

    /// 给 Target 发一条消息:[`Receipt::provider_id`] 带回 Webex 的消息 id。
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
        assert_eq!(Service::new(Config::default()).name(), "webex");
    }

    // 配置缺失/目标缺失在拨号之前就拦下,归 NotConfigured。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config::default())
            .send(&Message::new("ROOM1", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("bot_token"));

        let err = Service::new(Config {
            bot_token: "bt".into(),
            ..Config::default()
        })
        .send(&Message::new("", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("destination is empty"));
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget。
    #[test]
    fn test_blocked_target() {
        let err = Service::new(Config {
            bot_token: "bt".into(),
            api_base: "http://127.0.0.1:9".into(),
        })
        .send(&Message::new("ROOM1", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 请求构造离线断言:路径、Bearer 鉴权头、无 @ 的 Target 按空间投递、
    // 标题与正文以单换行相连。
    #[test]
    fn test_build_request_room() {
        let svc = Service::new(Config {
            bot_token: "bt-1".into(),
            api_base: "https://webex.example.test".into(),
        });
        let req = svc
            .build_request(&Message::new("ROOM1", "部署完成").with_content("v1.2.0 已上线"))
            .unwrap();
        assert_eq!(req.url, "https://webex.example.test/v1/messages");
        assert_eq!(req.headers[0], ("Authorization", "Bearer bt-1".to_string()));
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["roomId"], "ROOM1");
        assert!(
            payload.get("toPersonEmail").is_none(),
            "无 @ 的 Target 按空间投递"
        );
        assert_eq!(payload["text"], "部署完成\nv1.2.0 已上线");
    }

    // 含 @ 按 1v1 私聊投递,不再带 roomId。
    #[test]
    fn test_build_request_person_email() {
        let svc = Service::new(Config {
            bot_token: "bt".into(),
            ..Config::default()
        });
        let req = svc
            .build_request(&Message::new("alice@example.com", "").with_content("c"))
            .unwrap();
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["toPersonEmail"], "alice@example.com");
        assert!(payload.get("roomId").is_none());
    }

    // 回执解析:消息 id 进回执;应答非 JSON 不判失败;非 2xx 归投递失败。
    #[test]
    fn test_parse_answer() {
        let receipt =
            Service::parse_answer(200, r#"{"id":"msg-1","roomId":"ROOM1","text":"x"}"#).unwrap();
        assert_eq!(receipt.provider_id, "msg-1");

        let receipt = Service::parse_answer(200, "not json").unwrap();
        assert_eq!(receipt.provider_id, "");

        let err = Service::parse_answer(401, r#"{"message":"Invalid token"}"#).unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("401"));
    }
}
