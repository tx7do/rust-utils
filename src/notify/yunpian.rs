//! 云片短信(single_send 自由文本形态),裸 HTTP,feature `notify`。
//! 对齐上游 `notify/yunpian/yunpian.go`。
//!
//! 与模板短信(阿里云/腾讯云)的分工:模板短信的正文出自审核过的模板,只传
//! 占位值;云片的 single_send 收**整段自由文本**(含签名,如
//! "【GoWind】您的验证码是 123456"),签名合规是调用方的事。
//! 正文按 67 字符计费的通道不替调用方注水,`Message::title` 忽略。
//!
//! 业务结论在 HTTP 200 的 body 里(`code == 0` 才是发出去了),只看状态码会把
//! "对方没收"记成发送成功。
//!
//! 与上游 Go 版的差异:`Config.Ref`(展示标识,只进错误文案)未移植;
//! `context.Context` 取消传播在本 crate 的阻塞式 API 里不存在。
//!
//! 测试离线进行:请求构造与回执解析拆成纯函数断言,不真实连网。

use crate::notify::sms::normalize_phone_number;
use crate::notify::{check_target, map_ureq_error, new_client, Message, NotifyError, Receipt};

/// 云片官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://sms.yunpian.com";

/// single_send 端点路径。
const SEND_PATH: &str = "/v2/sms/single_send.json";

/// 进错误文案的响应片段上限:对端可能回一整页 HTML。
const SNIPPET_LIMIT: usize = 256;

/// 云片短信配置。手机号与正文按消息传。
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// 云片账户的 API Key。
    pub api_key: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// 云片短信渠道。无状态,可并发使用。
pub struct Service {
    agent: ureq::Agent,
    cfg: Config,
}

/// 构造好的出站请求:纯数据,供离线测试断言。
struct Prepared {
    url: String,
    body: String,
    content_type: &'static str,
}

impl Service {
    /// 构造云片短信渠道:出站走 SSRF 守卫客户端(内网目标在拨号前被拦)。
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

    /// 构造请求(纯函数):手机号归一为 CN 裸号,正文整段自由文本原样出站。
    fn build_request(&self, msg: &Message) -> Result<Prepared, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured(
                "yunpian sms text is empty".into(),
            ));
        }
        if self.cfg.api_key.is_empty() {
            return Err(NotifyError::NotConfigured(
                "yunpian config incomplete: api_key required".into(),
            ));
        }
        // 目标归一在出站前裁决:号码不合法一次都不碰对端,归配置/目标类。
        let (national, _) =
            normalize_phone_number(&msg.target).map_err(NotifyError::NotConfigured)?;
        Ok(Prepared {
            url: format!("{}{SEND_PATH}", self.cfg.api_base),
            body: form_encode(&[
                ("apikey".to_string(), self.cfg.api_key.clone()),
                ("mobile".to_string(), national),
                ("text".to_string(), msg.content.clone()),
            ]),
            content_type: "application/x-www-form-urlencoded",
        })
    }

    /// 解析回执(纯函数):业务结论在 body 的 code(0 为成功);成功时 sid 进回执。
    fn parse_answer(status: u16, body: &str) -> Result<String, NotifyError> {
        if !(200..300).contains(&status) {
            return Err(NotifyError::Delivery(format!(
                "peer answered {status}: {}",
                snippet(body)
            )));
        }
        #[derive(serde::Deserialize, Default)]
        struct Answer {
            #[serde(default)]
            code: i64,
            #[serde(default)]
            msg: String,
            #[serde(default)]
            sid: i64,
        }
        let answer: Answer = serde_json::from_str(body).map_err(|_| {
            NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body)))
        })?;
        if answer.code != 0 {
            let msg = if answer.msg.is_empty() {
                "no message"
            } else {
                &answer.msg
            };
            return Err(NotifyError::Delivery(format!(
                "peer answered code={}: {msg}",
                answer.code
            )));
        }
        if answer.sid != 0 {
            Ok(answer.sid.to_string())
        } else {
            Ok(String::new())
        }
    }

    /// POST 已构造好的请求,返回 (状态码, 应答文本)。
    /// 非 2xx 也返回应答文本,由 [`Self::parse_answer`] 统一归类。
    fn post(&self, req: &Prepared) -> Result<(u16, String), NotifyError> {
        match self
            .agent
            .post(&req.url)
            .set("Content-Type", req.content_type)
            .send_string(&req.body)
        {
            Ok(resp) => Ok((resp.status(), read_answer(resp)?)),
            Err(ureq::Error::Status(status, resp)) => Ok((status, read_answer(resp)?)),
            Err(err) => Err(map_ureq_error(err)),
        }
    }
}

impl crate::notify::Service for Service {
    fn name(&self) -> &str {
        "yunpian"
    }

    /// 给 Target(手机号,CN 裸号或 E.164)发一条自由文本短信:
    /// 正文 = `Message::content` 原样出站(须含已报备的签名【XX】,否则对端拒);
    /// `Message::title` 忽略——按 67 字符计费的通道不替调用方注水。
    /// [`Receipt::provider_id`] 带回云片的 sid。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        let req = self.build_request(msg)?;
        check_target(&req.url)?;
        let (status, body) = self.post(&req)?;
        let provider_id = Self::parse_answer(status, &body)?;
        Ok(Receipt { provider_id })
    }
}

/// 构造 single_send 的完整表单体,可独立测试的纯函数。
pub fn build_form(api_key: &str, mobile: &str, text: &str) -> String {
    form_encode(&[
        ("apikey".to_string(), api_key.to_string()),
        ("mobile".to_string(), mobile.to_string()),
        ("text".to_string(), text.to_string()),
    ])
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
            api_key: "apikey-1".into(),
            ..Config::default()
        }
    }

    #[test]
    fn test_name() {
        assert_eq!(Service::new(full_cfg()).name(), "yunpian");
    }

    // 对齐上游 TestSendDeliversFormShape 的离线部分:路径、表单关键字段
    // (apikey / CN 裸号 / 正文整段自由文本含签名)。
    #[test]
    fn test_build_request() {
        let svc = Service::new(full_cfg());
        let req = svc
            .build_request(
                &Message::new("13800138000", "标题被忽略")
                    .with_content("【GoWind】您的验证码是 123456"),
            )
            .unwrap();
        assert_eq!(req.url, "https://sms.yunpian.com/v2/sms/single_send.json");
        assert_eq!(req.content_type, "application/x-www-form-urlencoded");
        assert!(req.body.contains("apikey=apikey-1"), "{}", req.body);
        assert!(
            req.body.contains("mobile=13800138000"),
            "CN 裸号出站(NormalizePhoneNumber 归一): {}",
            req.body
        );
        assert!(
            req.body.contains("text=%E3%80%90GoWind%E3%80%91"),
            "正文整段自由文本(含签名)原样出站: {}",
            req.body
        );
    }

    // 对齐上游 TestSendE164Normalized:+86 前缀剥掉。
    #[test]
    fn test_e164_normalized() {
        let svc = Service::new(full_cfg());
        let req = svc
            .build_request(&Message::new("+8613800138000", "").with_content("【G】x"))
            .unwrap();
        assert!(
            req.body.contains("mobile=13800138000"),
            "+86 前缀剥掉: {}",
            req.body
        );
    }

    // 对齐上游 TestSendBadMobileIsConfigClass / TestSendConfigIssue:
    // 号码不合法、缺 api_key、正文为空,全部在拨号之前拦下,归 NotConfigured。
    #[test]
    fn test_config_and_target_issues() {
        let svc = Service::new(full_cfg());
        let err = svc
            .send(&Message::new("not-a-phone", "").with_content("【G】x"))
            .unwrap_err();
        assert!(err.is_not_configured(), "号码不合法一次都不碰对端: {err}");

        let err = Service::new(Config::default())
            .send(&Message::new("13800138000", "").with_content("【G】x"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("api_key required"), "{err}");

        let err = Service::new(full_cfg())
            .send(&Message::new("13800138000", ""))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("sms text is empty"), "{err}");
    }

    // SSRF 预检:环回目标在拨号之前归 BlockedTarget。
    #[test]
    fn test_blocked_target() {
        let cfg = Config {
            api_key: "k".into(),
            api_base: "http://127.0.0.1:9".into(),
        };
        let err = Service::new(cfg)
            .send(&Message::new("13800138000", "").with_content("【G】x"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    // build_form 纯函数:表单键有序、值经 QueryEscape。
    #[test]
    fn test_build_form() {
        let body = build_form("apikey-1", "13800138000", "【GoWind】您的验证码是 123456");
        let keys: Vec<&str> = body
            .split('&')
            .map(|kv| kv.split('=').next().unwrap())
            .collect();
        assert_eq!(keys, ["apikey", "mobile", "text"], "表单键按字母序出站");
        assert!(body.contains("apikey=apikey-1"));
        assert!(body.contains("text=%E3%80%90GoWind%E3%80%91"));
    }

    // 对齐上游 TestSendPeerErrorCode:厂商码非 0 归投递失败,文案带 code。
    #[test]
    fn test_parse_answer() {
        let provider_id = Service::parse_answer(
            200,
            r#"{"code":0,"msg":"OK","count":1,"fee":1,"unit":"RMB","mobile":"13800138000","sid":1690001}"#,
        )
        .unwrap();
        assert_eq!(provider_id, "1690001", "云片的 sid 要进回执");

        // 成功但 sid 为 0:回执留空。
        let provider_id = Service::parse_answer(200, r#"{"code":0,"msg":"OK"}"#).unwrap();
        assert_eq!(provider_id, "");

        let err =
            Service::parse_answer(200, r#"{"code":-4,"msg":"apikey 不存在或被禁用"}"#).unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");
        assert!(err.to_string().contains("code=-4"), "{err}");

        let err = Service::parse_answer(200, r#"{"code":13}"#).unwrap_err();
        assert!(err.to_string().contains("no message"), "{err}");

        let err = Service::parse_answer(500, "boom").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)), "{err}");

        let err = Service::parse_answer(200, "<html>gateway</html>").unwrap_err();
        assert!(err.to_string().contains("not JSON"), "{err}");
    }

    // 表单编码细节:保留字符原样、空格转 +、非 ASCII 按 UTF-8 %XX。
    #[test]
    fn test_form_urlencode() {
        assert_eq!(form_urlencode("aBc-_.~123"), "aBc-_.~123");
        assert_eq!(form_urlencode("a b"), "a+b");
        assert_eq!(form_urlencode("a&b=c"), "a%26b%3Dc");
        assert_eq!(
            form_urlencode("【签名】"),
            "%E3%80%90%E7%AD%BE%E5%90%8D%E3%80%91"
        );
    }
}
