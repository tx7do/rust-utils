//! 极光推送(JPush)v3/push:Basic Auth + registration_id 单播,裸 HTTP,
//! feature `notify`。对齐上游 `notify/jpush/jpush.go`。
//!
//! 平台是 `all`(安卓 + iOS 一单两投):安卓有独立通知栏标题位;iOS 10+ 的
//! alert 支持标题子段,有标题时 iOS 走 `{"title","body"}` 对象,没有时 alert
//! 就是正文串,两者都带 `sound: default`。
//!
//! 错误在 `{"error":{"code","message"}}` 里:[`parse_error`] 把厂商明确判定的
//! 令牌失效码 1011(registration_id 无效,应用卸载/实例删除)归
//! [`NotifyError::InvalidToken`]——失效令牌重试没有意义,调用方应删行自清理。
//!
//! 与上游 Go 版的差异:`Config.Ref`(展示标识,只进错误文案)未移植;
//! `context.Context` 取消传播在本 crate 的阻塞式 API 里不存在。
//!
//! 测试离线进行:请求构造、Basic Auth 与错误归类拆成纯函数断言,不真实连网。

use serde_json::{Value, json};

use crate::notify::{Message, NotifyError, Receipt, check_target, map_ureq_error, new_client};

/// JPush 官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://api.jpush.cn";

/// JPush 错误码:registration_id 无效(应用卸载/实例删除),归令牌失效。
pub const ERR_INVALID_REGISTRATION_ID: i64 = 1011;

/// push 端点路径。
const SEND_PATH: &str = "/v3/push";

/// 进错误文案的响应片段上限:对端可能回一整页 HTML。
const SNIPPET_LIMIT: usize = 256;

/// 极光推送配置。registration_id 按消息传。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 应用凭据(Basic Auth 的用户名)。
    pub app_key: String,
    /// 应用凭据(Basic Auth 的密码)。
    pub master_secret: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// 极光推送渠道。无状态,可并发使用。
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
    /// 构造极光推送渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
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

    /// 构造请求(纯函数):Basic auth(app_key:master_secret) 进鉴权头,
    /// payload 为 platform=all + registration_id 单播 + 双平台通知。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "jpush registration_id is empty".into(),
            ));
        }
        if self.cfg.app_key.is_empty() || self.cfg.master_secret.is_empty() {
            return Err(NotifyError::NotConfigured(
                "jpush config incomplete: app_key/master_secret required".into(),
            ));
        }
        Ok(Prepared {
            url: format!("{}{SEND_PATH}", self.cfg.api_base),
            body: build_payload(&msg.target, &msg.title, &msg.content).to_string(),
            content_type: "application/json; charset=utf-8",
            headers: vec![(
                "Authorization",
                basic_auth(&self.cfg.app_key, &self.cfg.master_secret),
            )],
        })
    }

    /// POST 已构造好的请求,返回 (状态码, 应答文本)。
    /// 非 2xx 也返回应答文本,由 [`Self::parse_answer`] 统一归类。
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
        "jpush"
    }

    /// 给 Target(registration_id)推一条通知。
    /// Title 进安卓通知栏标题;iOS 无独立标题(进 alert 的 title 子段,iOS 10+ 支持)。
    /// [`Receipt::provider_id`] 带回 JPush 的 msg_id。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        let req = self.build_request(msg)?;
        check_target(&req.url)?;
        let (status, body) = self.post(&req)?;
        if !(200..300).contains(&status) {
            return Err(parse_error(status, &body));
        }
        Ok(Receipt { provider_id: parse_msg_id(&body) })
    }
}

// ---------------------------------------------------------------------------
// 可独立测试的纯函数
// ---------------------------------------------------------------------------

/// HTTP Basic 鉴权头值:`Basic base64(app_key:master_secret)`。
pub fn basic_auth(app_key: &str, master_secret: &str) -> String {
    format!("Basic {}", base64_encode(format!("{app_key}:{master_secret}").as_bytes()))
}

/// 构造 v3/push payload,可独立测试的纯函数:
/// platform=all;audience 为 registration_id 单播;通知双平台——安卓有标题就走
/// title 字段,iOS 的 alert 在有标题时是 `{"title","body"}` 对象(iOS 10+),
/// 没有标题时就是正文串,两者都带 `sound: default`。
pub fn build_payload(target: &str, title: &str, content: &str) -> Value {
    let mut notification = json!({ "alert": content });
    let mut android = json!({ "alert": content });
    if title.is_empty() {
        notification["ios"] = json!({ "alert": content, "sound": "default" });
    } else {
        android["title"] = json!(title);
        notification["ios"] = json!({
            "alert": {"title": title, "body": content},
            "sound": "default",
        });
    }
    notification["android"] = android;
    json!({
        "platform": "all",
        "audience": {"registration_id": [target]},
        "notification": notification,
    })
}

/// 解析成功应答的 msg_id,可独立测试的纯函数;
/// 缺失/为 0 时留空(对齐上游:解析错误被忽略)。
pub fn parse_msg_id(body: &str) -> String {
    #[derive(serde::Deserialize, Default)]
    struct Answer {
        #[serde(default)]
        msg_id: i64,
    }
    let answer: Answer = serde_json::from_str(body).unwrap_or_default();
    if answer.msg_id != 0 {
        answer.msg_id.to_string()
    } else {
        String::new()
    }
}

/// 非 2xx 应答归类,可独立测试的纯函数。
/// 错误在 `{"error":{"code","message"}}` 里:1011 是令牌失效(registration_id
/// 无效),其余按投递失败带出状态码与原文。
pub fn parse_error(status: u16, body: &str) -> NotifyError {
    #[derive(serde::Deserialize, Default)]
    struct Answer {
        #[serde(default)]
        error: ErrorBody,
    }
    #[derive(serde::Deserialize, Default)]
    struct ErrorBody {
        #[serde(default)]
        code: i64,
        #[serde(default)]
        message: String,
    }
    let answer: Answer = serde_json::from_str(body).unwrap_or_default();
    if answer.error.code == 0 {
        return NotifyError::Delivery(format!("peer answered {status}: {}", snippet(body)));
    }
    if answer.error.code == ERR_INVALID_REGISTRATION_ID {
        return NotifyError::InvalidToken(format!(
            "code {}: {}",
            answer.error.code, answer.error.message
        ));
    }
    let message = if answer.error.message.is_empty() {
        "no message"
    } else {
        &answer.error.message
    };
    NotifyError::Delivery(format!("peer answered error code={}: {message}", answer.error.code))
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/// 标准 base64(带填充)。Basic auth 需要它的 app_key:master_secret 串;
/// crate 的 base64 工具在 notify feature 下不可用(被 captcha/crypto 等门控),
/// 这份实现就地兜住(标准字母表 + '=',对齐 RFC 4648)。
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
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

    fn full_cfg() -> Config {
        Config {
            app_key: "key-1".into(),
            master_secret: "secret-1".into(),
            ..Config::default()
        }
    }

    #[test]
    fn test_name() {
        assert_eq!(Service::new(full_cfg()).name(), "jpush");
    }

    // 对齐上游 TestSendDeliversBasicAuthAndAudience 的离线部分:路径、
    // Basic auth(app_key:master_secret)、单播 audience 与双平台通知形态。
    #[test]
    fn test_build_request() {
        let svc = Service::new(full_cfg());
        let req = svc
            .build_request(
                &Message::new("reg-token-1", "重置验证码").with_content("您的验证码是 123456"),
            )
            .unwrap();
        assert_eq!(req.url, "https://api.jpush.cn/v3/push");
        assert_eq!(req.content_type, "application/json; charset=utf-8");
        assert_eq!(
            req.headers[0],
            ("Authorization", "Basic a2V5LTE6c2VjcmV0LTE=".to_string()),
            "Basic auth(app_key:master_secret)"
        );

        let payload: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(payload["platform"], "all");
        assert_eq!(
            payload["audience"]["registration_id"],
            json!(["reg-token-1"]),
            "单播 audience"
        );
        let notification = &payload["notification"];
        assert_eq!(notification["alert"], "您的验证码是 123456", "顶层 alert 是正文");
        assert_eq!(
            notification["android"]["title"], "重置验证码",
            "安卓有独立通知栏标题位"
        );
        assert_eq!(
            notification["ios"]["alert"],
            json!({"title": "重置验证码", "body": "您的验证码是 123456"}),
            "iOS 10+ 的 alert 支持标题子段"
        );
        assert_eq!(notification["ios"]["sound"], "default");
    }

    // 没有标题:iOS 的 alert 就是正文串,安卓不带 title 字段。
    #[test]
    fn test_build_payload_without_title() {
        let payload = build_payload("r", "", "c");
        assert!(payload["notification"]["android"].get("title").is_none());
        assert_eq!(payload["notification"]["ios"]["alert"], "c");
        assert_eq!(payload["notification"]["ios"]["sound"], "default");
    }

    // 对齐上游 TestSendConfigIssue:缺 master_secret / 空 registration_id 在拨号之前拦下。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config {
            app_key: "k".into(),
            ..Config::default()
        })
        .send(&Message::new("r", "t").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("app_key/master_secret required"), "{err}");

        let err = Service::new(full_cfg())
            .send(&Message::new("", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("registration_id is empty"), "{err}");
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget。
    #[test]
    fn test_blocked_target() {
        let cfg = Config {
            app_key: "k".into(),
            master_secret: "s".into(),
            api_base: "http://127.0.0.1:9".into(),
        };
        let err = Service::new(cfg)
            .send(&Message::new("r", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // basic_auth 纯函数钉值。
    #[test]
    fn test_basic_auth() {
        assert_eq!(basic_auth("key-1", "secret-1"), "Basic a2V5LTE6c2VjcmV0LTE=");
        assert_eq!(basic_auth("a", "b"), "Basic YTpi");
    }

    // 对齐上游 TestSendInvalidRegistrationID:1011 = registration_id 失效,
    // 归 InvalidToken,调用方要删行自清理。
    #[test]
    fn test_parse_error_invalid_token() {
        let err = parse_error(
            400,
            r#"{"error":{"code":1011,"message":"cannot find user by this audience","request_id":"req-1"}}"#,
        );
        assert!(err.is_invalid_token(), "1011 = registration_id 失效,得到 {err}");
        assert!(err.to_string().contains("1011"), "{err}");
    }

    // 对齐上游 TestSendPeerError:其余厂商码按投递失败带出,不是令牌失效。
    #[test]
    fn test_parse_error_delivery() {
        let err = parse_error(401, r#"{"error":{"code":1003,"message":"appkey not exist"}}"#);
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(!err.is_invalid_token(), "{err}");
        assert!(err.to_string().contains("1003"), "{err}");
        assert!(err.to_string().contains("appkey not exist"), "{err}");

        let err = parse_error(500, r#"{"error":{"code":50}}"#);
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("no message"), "{err}");
    }

    // 错误体不是 JSON / error.code 为 0:按投递失败带出状态码与原文。
    #[test]
    fn test_parse_error_unparsable() {
        let err = parse_error(502, "<html>gateway</html>");
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("502"), "{err}");

        let err = parse_error(400, r#"{"error":{}}"#);
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("400"), "{err}");
    }

    // msg_id 解析:进回执;缺失/为 0 留空。
    #[test]
    fn test_parse_msg_id() {
        assert_eq!(parse_msg_id(r#"{"sendno":"0","msg_id":1828256768}"#), "1828256768");
        assert_eq!(parse_msg_id(r#"{"sendno":"0"}"#), "");
        assert_eq!(parse_msg_id("not json"), "");
    }
}
