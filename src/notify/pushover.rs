//! Pushover 推送:裸 HTTP 表单 API `/1/messages.json`,零依赖。
//!
//! 渠道约定:
//! - 收件身份是 `Message.target` 携带的用户 key(30 字母)——一个应用可以推给多个用户;
//! - `Config::app_token` 是应用的 API Token(必填,缺了在拨号之前拦下);
//! - `Message.params` 原生字段直传表单(priority/sound/device/url/url_title/retry/expire 等,
//!   字符串值即可)——priority=-1~2 的重试语义是应用的事,本包不越权校验;
//! - 应答 body 的 `status`(1 才是发出去)是业务结论,失败时 `errors` 数组点名原因;
//!   成功时 `request` ID 进 [`Receipt::provider_id`] 供对账。

use std::io::Read;

use serde_json::Value;

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// Pushover 官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://api.pushover.net";

/// 应答读取上限。
const ANSWER_LIMIT: usize = 4 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Pushover 渠道配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 应用的 API Token。
    pub app_token: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// Pushover 渠道。无状态,可并发使用。
pub struct Service {
    client: ureq::Agent,
    allow_private: bool,
    cfg: Config,
}

/// 一切就绪、只待发送的出站请求。
#[derive(Debug)]
struct Outbound {
    method: &'static str,
    url: String,
    body: String,
    headers: Vec<(&'static str, String)>,
}

impl Service {
    /// 构造 Pushover 渠道。
    ///
    /// `allow_private = true`(本机联调)时整条 SSRF 防线关闭;生产部署必须传 `false`。
    pub fn new(allow_private: bool, cfg: Config) -> Self {
        let api_base = if cfg.api_base.is_empty() {
            DEFAULT_API_BASE.to_string()
        } else {
            cfg.api_base
        };
        Service {
            client: new_client(allow_private),
            allow_private,
            cfg: Config { api_base, ..cfg },
        }
    }

    /// 渠道名。
    pub fn name(&self) -> &str {
        "pushover"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.app_token.is_empty() {
            return Err(NotifyError::NotConfigured(
                "pushover config incomplete: app_token required".into(),
            ));
        }

        let mut pairs: Vec<(String, String)> = vec![
            ("token".to_string(), self.cfg.app_token.clone()),
            ("user".to_string(), msg.target.clone()),
            ("message".to_string(), msg.content.clone()),
        ];
        if !msg.title.is_empty() {
            pairs.push(("title".to_string(), msg.title.clone()));
        }
        // Params 原生字段直传表单(可覆盖基础字段)。
        for (k, v) in &msg.params {
            pairs.push((k.clone(), v.clone()));
        }

        Ok(Outbound {
            method: "POST",
            url: format!("{}/1/messages.json", self.cfg.api_base),
            body: form_encode(&pairs),
            headers: vec![("Content-Type", "application/x-www-form-urlencoded".to_string())],
        })
    }

    /// 解析 2xx 应答:status==1 才是发出去了;失败时 errors 数组点名原因。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body)
            .map_err(|_| NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body))))?;
        let status = answer.get("status").and_then(Value::as_i64).unwrap_or(0);
        if status != 1 {
            let errors: Vec<String> = answer
                .get("errors")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let joined = if errors.is_empty() { "no message".to_string() } else { errors.join("; ") };
            return Err(NotifyError::Delivery(format!("peer answered status=0: {joined}")));
        }
        let mut receipt = Receipt::default();
        if let Some(request) = answer.get("request").and_then(Value::as_str) {
            receipt.provider_id = request.to_string();
        }
        Ok(receipt)
    }

    /// 处理一个已拿到的响应:状态码判门,2xx 之后才轮到 body 说话。
    fn finish(&self, resp: ureq::Response) -> Result<Receipt, NotifyError> {
        let status = resp.status();
        let body = read_body_limited(resp, ANSWER_LIMIT);
        if !(200..=299).contains(&status) {
            return Err(status_error(status, &body));
        }
        self.parse_response(&body)
    }
}

impl NotifyService for Service {
    fn name(&self) -> &str {
        Service::name(self)
    }

    /// 给 Target(Pushover 用户 key)推一条通知。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("pushover user key is empty".into()));
        }

        let out = self.build_request(msg)?;

        if !self.allow_private {
            check_target(&out.url)?;
        }

        let mut req = self.client.request(out.method, &out.url);
        for (k, v) in &out.headers {
            req = req.set(k, v);
        }
        match req.send_string(&out.body) {
            Ok(resp) => self.finish(resp),
            Err(ureq::Error::Status(status, resp)) => {
                Err(status_error(status, &read_body_limited(resp, ANSWER_LIMIT)))
            }
            Err(err) => Err(map_ureq_error(err)),
        }
    }
}

/// 把对端应答读进来并限长。
fn read_body_limited(resp: ureq::Response, limit: usize) -> String {
    let mut buf = Vec::new();
    let _ = resp.into_reader().take(limit as u64).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// 应答片段截断(退到字符边界,不劈开 UTF-8 字符)。
fn snippet(body: &str) -> String {
    if body.len() <= SNIPPET_LIMIT {
        return body.to_string();
    }
    let mut end = SNIPPET_LIMIT;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &body[..end])
}

/// 非 2xx 状态的错误:带状态码与响应片段。
fn status_error(status: u16, body: &str) -> NotifyError {
    NotifyError::Delivery(format!("peer answered {status}: {}", snippet(body)))
}

/// URL 查询/表单成分编码(按字节:ASCII 字母数字与 `-_.~` 直通,空格作 `+`,其余 `%XX`)。
fn query_escape(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
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

/// 参数对的有序表单编码(按键名排序,键与值均经 `query_escape` 编码,对齐 Go url.Values.Encode)。
fn form_encode(pairs: &[(String, String)]) -> String {
    let mut pairs = pairs.to_vec();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// ---------------------------------------------------------------------------
// 测试(纯离线:构造与应答解析;不发 HTTP)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Service {
        Service::new(
            true,
            Config { ref_: "7".into(), app_token: "app-token".into(), api_base: "https://po.example".into() },
        )
    }

    #[test]
    fn test_config_issues() {
        // 缺 app_token 在拨号之前就该拦下。
        let svc = Service::new(true, Config::default());
        let err = svc.build_request(&Message::new("user-key", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());

        // user key 为空同样在联系对端之前拦下。
        let err = service().send(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_form_shape() {
        let svc = service();
        let msg = Message::new("user-key-30chars", "重置验证码")
            .with_content("您的验证码是 123456")
            .with_param("priority", "2")
            .with_param("sound", "siren");
        let out = svc.build_request(&msg).unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "https://po.example/1/messages.json");
        assert_eq!(out.headers[0].1, "application/x-www-form-urlencoded");

        assert!(out.body.contains("token=app-token"));
        assert!(out.body.contains("user=user-key-30chars"));
        assert!(out.body.contains("title=%E9%87%8D%E7%BD%AE%E9%AA%8C%E8%AF%81%E7%A0%81"));
        assert!(out.body.contains("priority=2"), "Params 原生字段直传表单");
        assert!(out.body.contains("sound=siren"));
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(false, Config { app_token: "t".into(), api_base: "http://127.0.0.1:1".into(), ..Config::default() });
        let err = svc.send(&Message::new("user", "").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_parse_response_status_zero_means_rejected() {
        let svc = service();

        // 成功:request ID 进回执。
        let receipt = svc.parse_response(r#"{"status":1,"request":"e4e3a4"}"#).unwrap();
        assert_eq!(receipt.provider_id, "e4e3a4", "Pushover 的 request ID 要进回执");

        // status=0:HTTP 200 也算失败,errors 数组点名原因。
        let err = svc
            .parse_response(
                r#"{"status":0,"request":"x","errors":["user identifier is not a valid user, group, or subscribed user key"]}"#,
            )
            .unwrap_err();
        assert!(err.to_string().contains("status=0"), "{err}");
        assert!(err.to_string().contains("user identifier is not a valid user"));
        assert!(!err.is_not_configured(), "拨过号被拒 = 投递失败");

        // 缺 errors 兜底"no message"。
        let err = svc.parse_response(r#"{"status":0}"#).unwrap_err();
        assert!(err.to_string().contains("no message"));

        // 非 JSON 应答照实报。
        let err = svc.parse_response("oops").unwrap_err();
        assert!(err.to_string().contains("peer answer is not JSON"));
    }

    #[test]
    fn test_status_error() {
        let err = status_error(429, "slow down");
        assert!(err.to_string().contains("429") && err.to_string().contains("slow down"));
    }
}
