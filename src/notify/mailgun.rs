//! Mailgun Messages API:Basic Auth + 表单邮件,裸 HTTP,feature `notify`。
//! 对齐上游 `notify/mailgun/mailgun.go`。
//!
//! 鉴权是 HTTP Basic(用户名固定 `"api"`,密码为域 API Key);发信域名进路径
//! (`/v3/{domain}/messages`)。欧盟租户用 [`Config::api_base`] 覆写为
//! `https://api.eu.mailgun.net`。
//!
//! 与上游 Go 版的差异:`Config.Ref`(展示标识,只进错误文案)未移植;
//! `context.Context` 取消传播在本 crate 的阻塞式 API 里不存在。
//!
//! 测试离线进行:请求构造、Basic Auth 与回执解析拆成纯函数断言,不真实连网。

use crate::notify::{Message, NotifyError, Receipt, check_target, map_ureq_error, new_client};

/// Mailgun 官方 API 域(欧盟租户覆写 `https://api.eu.mailgun.net`)。
pub const DEFAULT_API_BASE: &str = "https://api.mailgun.net";

/// Basic Auth 的固定用户名。
const AUTH_USERNAME: &str = "api";

/// 进错误文案的响应片段上限:对端可能回一整页 HTML。
const SNIPPET_LIMIT: usize = 256;

/// Mailgun 渠道配置。收件邮箱按消息传。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 已验证的发信域名(v3 路径段)。
    pub domain: String,
    /// 发件人地址。
    pub from: String,
    /// 域 API 密钥(Basic Auth 的密码)。
    pub api_key: String,
    /// 服务基地址,留空用官方;欧盟租户与测试可覆盖。
    pub api_base: String,
}

/// Mailgun 渠道。无状态,可并发使用。
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
    /// 构造 Mailgun 渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
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

    /// 构造请求(纯函数):域名进路径,Basic auth(api:key) 进鉴权头,
    /// 表单字段 from/to/subject/text。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("mailgun recipient is empty".into()));
        }
        if self.cfg.domain.is_empty() || self.cfg.api_key.is_empty() {
            return Err(NotifyError::NotConfigured(
                "mailgun config incomplete: domain/api_key required".into(),
            ));
        }
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured("mailgun message body is empty".into()));
        }
        Ok(Prepared {
            url: format!(
                "{}/v3/{}/messages",
                self.cfg.api_base,
                path_escape(&self.cfg.domain)
            ),
            body: form_encode(&[
                ("from".to_string(), self.cfg.from.clone()),
                ("to".to_string(), msg.target.clone()),
                ("subject".to_string(), msg.title.clone()),
                ("text".to_string(), msg.content.clone()),
            ]),
            content_type: "application/x-www-form-urlencoded",
            headers: vec![("Authorization", basic_auth(AUTH_USERNAME, &self.cfg.api_key))],
        })
    }

    /// 解析回执(纯函数):2xx 即受理,消息 id(形如 `<2026...@domain>`)进回执;
    /// 应答不是 JSON 时不判失败,id 留空(对齐上游:解析错误被忽略)。
    fn parse_answer(status: u16, body: &str) -> Result<Receipt, NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "peer answered {status}: {}",
                snippet(body)
            )));
        }
        #[derive(serde::Deserialize, Default)]
        struct Answer {
            #[serde(default)]
            id: String,
        }
        let answer: Answer = serde_json::from_str(body).unwrap_or_default();
        Ok(Receipt { provider_id: answer.id })
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
        "mailgun"
    }

    /// 给 Target(收件邮箱)发一封纯文本邮件。
    /// [`Receipt::provider_id`] 带回 Mailgun 的消息 id(形如 `<2026...@domain>`)。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        let req = self.build_request(msg)?;
        check_target(&req.url)?;
        let (status, body) = self.post(&req)?;
        Self::parse_answer(status, &body)
    }
}

// ---------------------------------------------------------------------------
// 可独立测试的纯函数
// ---------------------------------------------------------------------------

/// HTTP Basic 鉴权头值:`Basic base64(user:password)`。
pub fn basic_auth(user: &str, password: &str) -> String {
    format!("Basic {}", base64_encode(format!("{user}:{password}").as_bytes()))
}

/// messages 端点:基地址去尾部斜杠后拼 `/v3/{domain}/messages`,
/// 域名经路径段转义(Go `url.PathEscape` 语义)。
pub fn endpoint(api_base: &str, domain: &str) -> String {
    format!("{}/v3/{}/messages", api_base.trim_end_matches('/'), path_escape(domain))
}

/// 构造 messages 表单体,可独立测试的纯函数。
pub fn build_form(from: &str, to: &str, subject: &str, text: &str) -> String {
    form_encode(&[
        ("from".to_string(), from.to_string()),
        ("to".to_string(), to.to_string()),
        ("subject".to_string(), subject.to_string()),
        ("text".to_string(), text.to_string()),
    ])
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/// 标准 base64(带填充)。Basic auth 需要它的用户名:密码串;
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

/// 路径段转义(Go `url.PathEscape` 语义):字母数字、`-_.~` 与子分隔符
/// `$&+,;=:@` 直通,其余(含 `/` 与空格)按 %XX 大写十六进制。
fn path_escape(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~'
            | b'$' | b'&' | b'+' | b',' | b';' | b'=' | b':' | b'@' => out.push(b as char),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// application/x-www-form-urlencoded 组件编码:保留字符(A-Z a-z 0-9 - _ . ~)
/// 原样,空格转 +,其余字节按 %XX(大写十六进制)。对齐 Go 的 url.QueryEscape。
fn form_urlencode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// 参数对的有序表单编码(Go `url.Values.Encode()` 语义):按键名排序。
fn form_encode(pairs: &[(String, String)]) -> String {
    let mut pairs = pairs.to_vec();
    pairs.sort();
    let mut out = String::new();
    for (k, v) in &pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&form_urlencode(k));
        out.push('=');
        out.push_str(&form_urlencode(v));
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
            domain: "mg.example.com".into(),
            api_key: "key-1".into(),
            from: "noreply@mg.example.com".into(),
            ..Config::default()
        }
    }

    #[test]
    fn test_name() {
        assert_eq!(Service::new(full_cfg()).name(), "mailgun");
    }

    // 对齐上游 TestSendDeliversBasicAuthForm 的离线部分:Basic auth(api:key)、
    // 域名进路径、表单四个字段全部就位。
    #[test]
    fn test_build_request() {
        let svc = Service::new(full_cfg());
        let req = svc
            .build_request(
                &Message::new("alice@example.com", "重置验证码").with_content("您的验证码是 123456"),
            )
            .unwrap();
        assert_eq!(req.url, "https://api.mailgun.net/v3/mg.example.com/messages", "域名进路径");
        assert_eq!(
            req.headers[0],
            ("Authorization", "Basic YXBpOmtleS0x".to_string()),
            "Basic auth(api:key),用户名固定 api"
        );
        assert_eq!(req.content_type, "application/x-www-form-urlencoded");
        assert!(req.body.contains("from=noreply%40mg.example.com"), "{}", req.body);
        assert!(req.body.contains("to=alice%40example.com"), "{}", req.body);
        assert!(
            req.body.contains("subject=%E9%87%8D%E7%BD%AE%E9%AA%8C%E8%AF%81%E7%A0%81"),
            "{}",
            req.body
        );
        assert!(
            req.body.contains("text=%E6%82%A8%E7%9A%84%E9%AA%8C%E8%AF%81%E7%A0%81%E6%98%AF+123456"),
            "空格转 +: {}",
            req.body
        );
    }

    // 对齐上游 TestSendConfigIssue:配置缺失 / 空收件人 / 空正文在拨号之前拦下。
    #[test]
    fn test_config_issues() {
        let err = Service::new(Config::default())
            .send(&Message::new("a@b.c", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("domain/api_key required"), "{err}");

        let svc = Service::new(full_cfg());
        let err = svc.send(&Message::new("", "t").with_content("c")).unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("recipient is empty"), "{err}");

        let err = svc.send(&Message::new("a@b.c", "t")).unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("message body is empty"), "{err}");
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget。
    #[test]
    fn test_blocked_target() {
        let cfg = Config {
            domain: "mg.example.com".into(),
            api_key: "k".into(),
            from: "f@mg.example.com".into(),
            api_base: "http://127.0.0.1:9".into(),
        };
        let err = Service::new(cfg)
            .send(&Message::new("a@b.c", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // Basic auth 与端点纯函数钉值。
    #[test]
    fn test_basic_auth_and_endpoint() {
        assert_eq!(basic_auth("api", "key-1"), "Basic YXBpOmtleS0x");
        assert_eq!(endpoint("https://api.mailgun.net", "mg.example.com"), "https://api.mailgun.net/v3/mg.example.com/messages");
        assert_eq!(endpoint("https://api.eu.mailgun.net/", "mg.example.com"), "https://api.eu.mailgun.net/v3/mg.example.com/messages", "尾部斜杠剥掉");
    }

    // 路径段转义(Go url.PathEscape 语义):子分隔符直通,斜杠与空格转义。
    #[test]
    fn test_path_escape() {
        assert_eq!(path_escape("mg.example.com"), "mg.example.com");
        assert_eq!(path_escape("a/b"), "a%2Fb", "路径段里的斜杠要转义");
        assert_eq!(path_escape("a b"), "a%20b", "路径里的空格是 %20 不是 +");
        assert_eq!(path_escape("a$b&c+d,e;f=g:h@i~j_k-l.m"), "a$b&c+d,e;f=g:h@i~j_k-l.m", "子分隔符直通");
        assert_eq!(path_escape("100%"), "100%25");
    }

    // build_form 纯函数:表单键有序、值经 QueryEscape。
    #[test]
    fn test_build_form() {
        let body = build_form("noreply@mg.example.com", "alice@example.com", "标题", "正文 123");
        let keys: Vec<&str> = body.split('&').map(|kv| kv.split('=').next().unwrap()).collect();
        assert_eq!(keys, ["from", "subject", "text", "to"], "表单键按字母序出站");
    }

    // 回执解析:消息 id 进回执;应答不是 JSON 不判失败(id 留空);非 2xx 归投递失败。
    #[test]
    fn test_parse_answer() {
        let receipt = Service::parse_answer(
            200,
            r#"{"id":"<20261015.0@mg.example.com>","message":"Queued. Thank you."}"#,
        )
        .unwrap();
        assert_eq!(
            receipt.provider_id, "<20261015.0@mg.example.com>",
            "Mailgun 的消息 id 要进回执"
        );

        let receipt = Service::parse_answer(200, "not json").unwrap();
        assert_eq!(receipt.provider_id, "");

        let err = Service::parse_answer(400, "domain not found").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("400"), "{err}");
    }

    // 表单编码细节:保留字符原样、空格转 +、@ 按 %XX。
    #[test]
    fn test_form_urlencode() {
        assert_eq!(form_urlencode("aBc-_.~123"), "aBc-_.~123");
        assert_eq!(form_urlencode("a b"), "a+b");
        assert_eq!(form_urlencode("a@b.c"), "a%40b.c");
        assert_eq!(form_urlencode("a/b"), "a%2Fb");
    }
}
