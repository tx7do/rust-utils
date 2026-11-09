//! WhatsApp Business Cloud API(Meta Graph)渠道:单条文本,零 SDK。
//!
//! 收件人须先与业务号码开启会话(24h 窗口或模板消息);本渠道只管 text 形态直发。
//! 测试离线进行:请求构造与回执解析拆成纯函数断言,不真实连网。

use serde_json::{json, Value};

use crate::notify::{check_target, map_ureq_error, new_client, Message, NotifyError, Receipt};

/// Meta Graph API 域。
pub const DEFAULT_API_BASE: &str = "https://graph.facebook.com";

/// Graph API 默认版本(路径段)。
pub const DEFAULT_API_VERSION: &str = "v21.0";

/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// WhatsApp 渠道配置。Target(收件号 E.164 无 + 号,如 8613800138000)按消息传。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 业务电话号码 ID(Meta 后台的 Phone number ID)。
    pub phone_number_id: String,
    /// 永久系统用户令牌。
    pub access_token: String,
    /// Graph API 版本段,留空用默认。
    pub api_version: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// WhatsApp 渠道。无状态,可并发使用。
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
    /// 构造 WhatsApp 渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
    pub fn new(cfg: Config) -> Self {
        let mut cfg = cfg;
        if cfg.api_base.is_empty() {
            cfg.api_base = DEFAULT_API_BASE.to_string();
        }
        if cfg.api_version.is_empty() {
            cfg.api_version = DEFAULT_API_VERSION.to_string();
        }
        Service {
            agent: new_client(crate::notify::allow_private_target()),
            cfg,
        }
    }

    /// 构造请求(纯函数):版本段与号码 ID 进路径,Bearer 令牌进鉴权头,
    /// 正文 = Title 与 Content 以单换行相连。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "whatsapp destination is empty".to_string(),
            ));
        }
        if self.cfg.phone_number_id.is_empty() || self.cfg.access_token.is_empty() {
            return Err(NotifyError::NotConfigured(
                "whatsapp config incomplete: phone_number_id/access_token required".to_string(),
            ));
        }
        let body = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };
        let payload = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": msg.target,
            "type": "text",
            "text": { "preview_url": false, "body": body },
        });
        Ok(Prepared {
            url: format!(
                "{}/{}/{}/messages",
                self.cfg.api_base.trim_end_matches('/'),
                self.cfg.api_version,
                self.cfg.phone_number_id
            ),
            body: payload.to_string(),
            content_type: "application/json",
            headers: vec![("Authorization", format!("Bearer {}", self.cfg.access_token))],
        })
    }

    /// 解析回执(纯函数):2xx 即受理,wamid 进回执;
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
            .pointer("/messages/0/id")
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
        "whatsapp"
    }

    /// 给 Target 发一条文本消息:[`Receipt::provider_id`] 带回 wamid 消息 ID。
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
    fn test_name_and_default_version() {
        let svc = Service::new(Config {
            phone_number_id: "1".into(),
            access_token: "t".into(),
            ..Config::default()
        });
        assert_eq!(svc.name(), "whatsapp");
        assert_eq!(svc.cfg.api_version, DEFAULT_API_VERSION);
    }

    // 配置缺失/目标缺失在拨号之前就拦下,归 NotConfigured。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config {
            phone_number_id: "1".into(),
            ..Config::default()
        })
        .send(&Message::new("8613800138000", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("phone_number_id/access_token"));

        let err = Service::new(Config {
            phone_number_id: "1".into(),
            access_token: "t".into(),
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
            phone_number_id: "1".into(),
            access_token: "t".into(),
            api_base: "http://127.0.0.1:9".into(),
            ..Config::default()
        })
        .send(&Message::new("8613800138000", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 请求构造离线断言:Cloud API 形状——版本段与号码 ID 进路径、
    // Bearer 鉴权头、messaging_product/recipient_type/to/text.body。
    #[test]
    fn test_build_request() {
        let svc = Service::new(Config {
            phone_number_id: "1065403".into(),
            access_token: "eaag".into(),
            api_version: "v21.0".into(),
            api_base: "https://graph.example.test".into(),
        });
        let req = svc
            .build_request(
                &Message::new("8613800138000", "重置验证码").with_content("您的验证码是 123456"),
            )
            .unwrap();
        assert_eq!(
            req.url, "https://graph.example.test/v21.0/1065403/messages",
            "版本段与号码 ID 进路径"
        );
        assert_eq!(req.headers[0], ("Authorization", "Bearer eaag".to_string()));
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["messaging_product"], "whatsapp");
        assert_eq!(payload["recipient_type"], "individual");
        assert_eq!(payload["to"], "8613800138000");
        assert_eq!(payload["type"], "text");
        assert_eq!(payload["text"]["preview_url"], false);
        assert_eq!(payload["text"]["body"], "重置验证码\n您的验证码是 123456");
    }

    // 回执解析:wamid 进回执;非 2xx 归投递失败。
    #[test]
    fn test_parse_answer() {
        let receipt = Service::parse_answer(
            200,
            r#"{"messaging_product":"whatsapp","contacts":[],"messages":[{"id":"wamid.XXX"}]}"#,
        )
        .unwrap();
        assert_eq!(receipt.provider_id, "wamid.XXX", "wamid 要进回执");

        let receipt = Service::parse_answer(200, r#"{"messaging_product":"whatsapp"}"#).unwrap();
        assert_eq!(receipt.provider_id, "");

        // 上游口径:非 2xx 的 Graph API 错误是投递失败。
        let err = Service::parse_answer(
            400,
            r#"{"error":{"type":"OAuthException","message":"Invalid OAuth access token"}}"#,
        )
        .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("400"));

        let err = Service::parse_answer(200, "not json").unwrap();
        assert_eq!(err.provider_id, "", "应答非 JSON 不判失败");
    }
}
