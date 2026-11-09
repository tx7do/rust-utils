//! Twilio SMS 渠道:裸 HTTP 调 Messages API(Basic Auth),零依赖。
//!
//! 测试离线进行:请求构造与回执解析拆成纯函数断言,不真实连网。

use serde_json::Value;

use crate::notify::{check_target, map_ureq_error, new_client, Message, NotifyError, Receipt};

/// Twilio 官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://api.twilio.com";

/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Twilio 渠道配置。Target(收件号 E.164)按消息传。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 账号 SID。
    pub account_sid: String,
    /// Auth Token。
    pub auth_token: String,
    /// 发送方:Twilio 号码(E.164)或已验证的 Sender ID / Messaging Service SID(MG 开头)。
    pub from: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// Twilio 渠道。无状态,可并发使用。
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
    /// 构造 Twilio 渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
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

    /// 构造请求(纯函数):SID 进路径,Basic auth(sid:token) 进鉴权头,
    /// 表单字段 To/From/Body,正文 = Title 与 Content 以单换行相连。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "twilio destination is empty".to_string(),
            ));
        }
        if self.cfg.account_sid.is_empty()
            || self.cfg.auth_token.is_empty()
            || self.cfg.from.is_empty()
        {
            return Err(NotifyError::NotConfigured(
                "twilio config incomplete: account_sid/auth_token/from required".to_string(),
            ));
        }
        let body = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };
        let body = format!(
            "To={}&From={}&Body={}",
            form_urlencode(&msg.target),
            form_urlencode(&self.cfg.from),
            form_urlencode(&body),
        );
        Ok(Prepared {
            url: format!(
                "{}/2010-04-01/Accounts/{}/Messages.json",
                self.cfg.api_base.trim_end_matches('/'),
                self.cfg.account_sid
            ),
            body,
            content_type: "application/x-www-form-urlencoded",
            headers: vec![(
                "Authorization",
                format!(
                    "Basic {}",
                    base64_encode(
                        format!("{}:{}", self.cfg.account_sid, self.cfg.auth_token).as_bytes()
                    )
                ),
            )],
        })
    }

    /// 解析回执(纯函数):2xx 即受理(创建成功通常是 201,对端语义已由
    /// 状态码分类兜住),消息 SID 进回执;应答不是 JSON 时不判失败(SID 留空)。
    fn parse_answer(status: u16, body: &str) -> Result<Receipt, NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "peer answered {status}: {}",
                snippet(body)
            )));
        }
        let answer: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let provider_id = answer
            .get("sid")
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
        "twilio"
    }

    /// 给 Target(收件手机号,E.164,如 +8613800138000)发一条短信:
    /// [`Receipt::provider_id`] 带回 Twilio 的消息 SID。
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

/// 标准 base64(带填充)。Basic auth 需要 SID:token 的 base64;
/// crate 的 base64util 在 notify feature 下不可用(被 captcha/crypto 等门控),
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

/// application/x-www-form-urlencoded 组件编码:保留字符(A-Z a-z 0-9 - _ . ~)
/// 原样,空格转 +,其余字节按 %XX(大写十六进制)。对齐 Go 的 url.QueryEscape。
fn form_urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
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
        assert_eq!(Service::new(Config::default()).name(), "twilio");
    }

    // 配置缺失/目标缺失在拨号之前就拦下,归 NotConfigured。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config {
            account_sid: "AC".into(),
            ..Config::default()
        })
        .send(&Message::new("+8613800138000", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("account_sid/auth_token/from"));

        let err = Service::new(Config {
            account_sid: "AC".into(),
            auth_token: "t".into(),
            from: "F".into(),
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
            account_sid: "AC".into(),
            auth_token: "t".into(),
            from: "F".into(),
            api_base: "http://127.0.0.1:9".into(),
        })
        .send(&Message::new("+8613800138000", "").with_content("c"))
        .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // 请求构造离线断言:SID 进路径、Basic auth(sid:token)、
    // 表单字段 To/From/Body、标题与正文以单换行相连。
    #[test]
    fn test_build_request() {
        let svc = Service::new(Config {
            account_sid: "AC123".into(),
            auth_token: "tok".into(),
            from: "+15550001111".into(),
            api_base: "https://api.example.test".into(),
        });
        let req = svc
            .build_request(
                &Message::new("+8613800138000", "重置验证码").with_content("您的验证码是 123456"),
            )
            .unwrap();
        assert_eq!(
            req.url, "https://api.example.test/2010-04-01/Accounts/AC123/Messages.json",
            "SID 要进路径"
        );
        assert_eq!(
            req.headers[0],
            ("Authorization", "Basic QUMxMjM6dG9r".to_string()),
            "Basic auth(sid:token)"
        );
        assert_eq!(req.content_type, "application/x-www-form-urlencoded");
        let form = &req.body;
        let mut pairs = form.split('&').collect::<Vec<_>>();
        pairs.sort_unstable();
        assert_eq!(pairs, ["Body=%E9%87%8D%E7%BD%AE%E9%AA%8C%E8%AF%81%E7%A0%81%0A%E6%82%A8%E7%9A%84%E9%AA%8C%E8%AF%81%E7%A0%81%E6%98%AF+123456", "From=%2B15550001111", "To=%2B8613800138000"]);
    }

    // 表单编码细节:保留字符原样、空格转 +、非 ASCII 按 UTF-8 %XX。
    #[test]
    fn test_form_urlencode() {
        assert_eq!(form_urlencode("aBc-_.~123"), "aBc-_.~123");
        assert_eq!(form_urlencode("a b"), "a+b");
        assert_eq!(form_urlencode("a&b=c"), "a%26b%3Dc");
        assert_eq!(form_urlencode("验证"), "%E9%AA%8C%E8%AF%81");
    }

    // 回执解析:消息 SID 进回执;对端 400(如号码非法)归投递失败。
    #[test]
    fn test_parse_answer() {
        let receipt = Service::parse_answer(
            201,
            r#"{"sid":"SM8f","status":"queued","to":"+8613800138000"}"#,
        )
        .unwrap();
        assert_eq!(receipt.provider_id, "SM8f", "Twilio 的消息 SID 要进回执");

        let receipt = Service::parse_answer(201, "not json").unwrap();
        assert_eq!(receipt.provider_id, "");

        let err = Service::parse_answer(
            400,
            r#"{"code":21211,"message":"The 'To' number is not a valid phone number"}"#,
        )
        .unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("21211"));
    }
}
