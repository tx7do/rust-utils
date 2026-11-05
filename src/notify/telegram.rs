//! Telegram Bot API 渠道:把通知正文用 `sendMessage` 发到指定 chat。
//!
//! 走裸 HTTP,零 SDK。移植上游时钉在实现里的一个坑:Telegram 会用 HTTP 200
//! 返回 `{"ok":false,...}`(代理/网关场景尤其常见),只看状态码会把"对方没收"
//! 记成发送成功——所以 2xx 之后还要看 body 的 `ok` 字段。
//!
//! 与上游 Go 版的归类差异:厂商明确判定收件目标失效的应答
//! (`error_code=403` 机器人被目标拉黑 / 描述含 `chat not found`)归
//! [`NotifyError::InvalidToken`]——这类目标重试没有意义,调用方应清理;
//! 上游 Go 把它们当普通投递失败返回。
//!
//! 测试离线进行:请求构造与回执解析拆成纯函数断言,不真实连网。

use serde_json::{Value, json};

use crate::notify::{Message, NotifyError, Receipt, check_target, map_ureq_error, new_client};

/// Telegram 官方 API 域;测试与自建网关可用 [`Config::api_base`] 覆写。
pub const DEFAULT_API_BASE: &str = "https://api.telegram.org";

/// 进错误文案的响应片段上限:对端可能回一整页 HTML。
const SNIPPET_LIMIT: usize = 512;

/// Telegram 渠道配置。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 机器人令牌(BotFather 签发)。
    pub bot_token: String,
    /// 服务端基地址,留空用官方 API;测试与自建网关可覆盖。
    pub api_base: String,
    /// 可选解析模式:MarkdownV2 / HTML / 空串(纯文本)。
    /// 配了之后 Message.title/content 里的标记按该模式解析,转义是调用方的事。
    pub parse_mode: String,
}

/// Telegram 渠道。无状态:配置在构造时注入,可并发使用。
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
    /// 构造 Telegram 渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
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

    /// 构造请求(纯函数):token 在路径上——放进 query 等于把它泄进访问日志。
    /// 正文 = Title 与 Content 以空行相连;配置了 parse_mode 才传该字段。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "telegram chat_id is empty".to_string(),
            ));
        }
        if self.cfg.bot_token.is_empty() {
            return Err(NotifyError::NotConfigured(
                "telegram config missing bot_token".to_string(),
            ));
        }
        let text = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n\n{}", msg.title, msg.content)
        };
        let mut payload = json!({
            "chat_id": msg.target,
            "text": text,
        });
        if !self.cfg.parse_mode.is_empty() {
            payload["parse_mode"] = json!(self.cfg.parse_mode);
        }
        Ok(Prepared {
            url: format!(
                "{}/bot{}/sendMessage",
                self.cfg.api_base.trim_end_matches('/'),
                self.cfg.bot_token
            ),
            body: payload.to_string(),
            content_type: "application/json",
            headers: Vec::new(),
        })
    }

    /// 解析回执(纯函数):HTTP 200 不代表发送成功,还要看 body 的 ok 字段。
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
        if answer.get("ok").and_then(Value::as_bool) != Some(true) {
            let code = answer
                .get("error_code")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let desc = answer
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("no description");
            // 厂商明确判定收件目标失效:目标 chat 不存在,或机器人被目标拉黑。
            // 这类失败重试没有意义,归 InvalidToken 供调用方清理(见模块文档)。
            if code == 403 || desc.contains("chat not found") {
                return Err(NotifyError::InvalidToken(format!(
                    "peer answered ok=false code={code}: {desc}"
                )));
            }
            return Err(NotifyError::Delivery(format!(
                "peer answered ok=false code={code}: {desc}"
            )));
        }
        let message_id = answer
            .pointer("/result/message_id")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let provider_id = if message_id != 0 {
            message_id.to_string()
        } else {
            String::new()
        };
        Ok(Receipt { provider_id })
    }

    /// POST 已构造好的请求,返回 (状态码, 应答文本)。
    /// 非 2xx 也返回应答文本,由 [`Self::parse_answer`] 统一归类——对端的
    /// 错误说明在 body 里,丢了对账就没依据了。
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
        "telegram"
    }

    /// 投递一条消息:target 为 chat_id(数字或 @频道名)。
    /// [`Receipt::provider_id`] 带回 Telegram 的 message_id。
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

    fn svc(cfg: Config) -> Service {
        Service::new(cfg)
    }

    #[test]
    fn test_name() {
        assert_eq!(svc(Config::default()).name(), "telegram");
    }

    // 配置缺失/目标缺失在拨号之前就拦下,归 NotConfigured。
    #[test]
    fn test_config_issues() {
        let msg = Message::new("123456", "t").with_content("c");
        let err = svc(Config::default()).send(&msg).unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("bot_token"));

        let err = svc(Config {
            bot_token: "t".into(),
            ..Config::default()
        })
        .send(&Message::new("", "t").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("chat_id is empty"));
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget。
    #[test]
    fn test_blocked_target() {
        let cfg = Config {
            bot_token: "t".into(),
            api_base: "http://127.0.0.1:9".into(),
            ..Config::default()
        };
        let err = svc(cfg)
            .send(&Message::new("1", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 请求构造离线断言:token 在路径上、标题与正文空行相连、
    // 没配 parse_mode 就不传该字段。
    #[test]
    fn test_build_request() {
        let svc = svc(Config {
            bot_token: "TOKEN".into(),
            ..Config::default()
        });
        let req = svc
            .build_request(&Message::new("123456", "重置验证码").with_content("您的验证码是 123456"))
            .unwrap();
        assert_eq!(req.url, "https://api.telegram.org/botTOKEN/sendMessage");
        assert_eq!(req.content_type, "application/json");
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["chat_id"], "123456");
        assert_eq!(payload["text"], "重置验证码\n\n您的验证码是 123456");
        assert!(
            payload.get("parse_mode").is_none(),
            "没配解析模式就不传:对端按纯文本处理"
        );
    }

    // 配置了 parse_mode 就透传。
    #[test]
    fn test_build_request_parse_mode() {
        let svc = svc(Config {
            bot_token: "t".into(),
            parse_mode: "HTML".into(),
            ..Config::default()
        });
        let req = svc
            .build_request(&Message::new("1", "").with_content("<b>hi</b>"))
            .unwrap();
        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["parse_mode"], "HTML");
    }

    // 回执解析:message_id 进回执。
    #[test]
    fn test_parse_answer_ok() {
        let receipt = Service::parse_answer(
            200,
            r#"{"ok":true,"result":{"message_id":42,"chat_id":123}}"#,
        )
        .unwrap();
        assert_eq!(receipt.provider_id, "42", "message_id 要进回执,对账全靠它");
    }

    // HTTP 200 + ok=false 是业务失败;403/虚拟"chat not found"归 InvalidToken,
    // 其余归 Delivery。错误文案带上对端的说明。
    #[test]
    fn test_parse_answer_ok_false() {
        let err = Service::parse_answer(
            200,
            r#"{"ok":false,"error_code":403,"description":"bot was blocked by the user"}"#,
        )
        .unwrap_err();
        assert!(err.is_invalid_token(), "{err}");
        assert!(err.to_string().contains("ok=false"));
        assert!(err.to_string().contains("bot was blocked by the user"));

        let err = Service::parse_answer(
            200,
            r#"{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}"#,
        )
        .unwrap_err();
        assert!(err.is_invalid_token(), "{err}");

        // 429 限流等:对端拒收是投递失败,不是配置问题。
        let err = Service::parse_answer(
            200,
            r#"{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 5"}"#,
        )
        .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("code=429"));
        assert!(!err.is_not_configured());
    }

    // 非 2xx 状态按对端语义归类为投递失败,文案带状态码与片段。
    #[test]
    fn test_parse_answer_http_error() {
        let err = Service::parse_answer(
            429,
            r#"{"ok":false,"error_code":429,"description":"Too Many Requests"}"#,
        )
        .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("429"));

        let err = Service::parse_answer(502, "<html>gateway</html>").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");

        let err = Service::parse_answer(200, "not json").unwrap_err();
        assert!(err.to_string().contains("not JSON"));
    }
}
