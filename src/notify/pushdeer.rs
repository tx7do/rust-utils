//! PushDeer(自建微信推送):裸 HTTP 表单调 `/message/push`,零 SDK。
//!
//! 渠道约定:
//! - 个人推送:`Message.target` 无意义(PushKey 即收件绑定);
//! - 表单字段:`pushkey` 为设备 PushKey,`text` 进通知预览(Title),`desp` 为 Markdown 正文(Content);
//! - 服务基地址默认官方 `DEFAULT_SERVER_URL`(api2.pushdeer.com),自建部署用
//!   [`Config::server_url`] 覆盖;
//! - PushDeer 把业务结论放应答 body 的 `code`(0 为成功)、原因放 `error`;
//!   只看 HTTP 状态码会把"没收"记成"送达"。

use std::io::Read;

use serde_json::Value;

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// PushDeer 官方服务域(自建部署常见,server_url 覆写)。
pub const DEFAULT_SERVER_URL: &str = "https://api2.pushdeer.com";

/// 应答读取上限。
const ANSWER_LIMIT: usize = 8 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// PushDeer 配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 设备的 PushKey。
    pub push_key: String,
    /// 服务基地址,留空用官方;自建部署覆盖。
    pub server_url: String,
}

/// PushDeer 渠道。无状态,可并发使用。
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
    /// 构造 PushDeer 渠道。
    ///
    /// `allow_private = true`(本机联调)时整条 SSRF 防线关闭;生产部署必须传 `false`。
    pub fn new(allow_private: bool, cfg: Config) -> Self {
        let server_url = if cfg.server_url.is_empty() {
            DEFAULT_SERVER_URL.to_string()
        } else {
            cfg.server_url
        };
        Service {
            client: new_client(allow_private),
            allow_private,
            cfg: Config { server_url, ..cfg },
        }
    }

    /// 渠道名。
    pub fn name(&self) -> &str {
        "pushdeer"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.push_key.is_empty() {
            return Err(NotifyError::NotConfigured(
                "pushdeer config incomplete: push_key required".into(),
            ));
        }

        let form = form_encode(&[
            ("pushkey", &self.cfg.push_key),
            ("text", &msg.title),
            ("desp", &msg.content),
        ]);

        Ok(Outbound {
            method: "POST",
            url: format!("{}/message/push", self.cfg.server_url.trim_end_matches('/')),
            body: form,
            headers: vec![("Content-Type", "application/x-www-form-urlencoded".to_string())],
        })
    }

    /// 解析 2xx 应答:业务结论在 body 的 code(0 为成功)。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body)
            .map_err(|_| NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body))))?;
        let code = answer.get("code").and_then(Value::as_i64).unwrap_or(0);
        if code != 0 {
            let mut error = answer.get("error").and_then(Value::as_str).unwrap_or("");
            if error.is_empty() {
                error = "no message";
            }
            return Err(NotifyError::Delivery(format!("peer answered code={code}: {error}")));
        }
        Ok(Receipt::default())
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

    /// 推一条消息。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured("pushdeer message body is empty".into()));
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
fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> =
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
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
            Config { ref_: "7".into(), push_key: "PK123".into(), server_url: "https://deer.example/".into() },
        )
    }

    #[test]
    fn test_missing_push_key_is_not_configured() {
        let svc = Service::new(true, Config::default());
        assert_eq!(svc.name(), "pushdeer");
        let err = svc.build_request(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_content_is_not_configured() {
        let err = service().send(&Message::new("", "t")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_delivers_form() {
        let svc = service();
        let out = svc.build_request(&Message::new("", "下载完成").with_content("**报告已生成**")).unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "https://deer.example/message/push", "基地址尾部斜杠剥掉");
        assert_eq!(out.headers[0].1, "application/x-www-form-urlencoded");

        // 表单按键名排序(des、pushkey、text),中文按 UTF-8 字节转义。
        assert!(out.body.contains("pushkey=PK123"));
        assert!(out.body.contains("text=%E4%B8%8B%E8%BD%BD%E5%AE%8C%E6%88%90"), "text 是通知预览: {}", out.body);
        assert!(out.body.contains("desp=%2A%2A%E6%8A%A5%E5%91%8A%E5%B7%B2%E7%94%9F%E6%88%90%2A%2A"), "desp 是 Markdown 正文");
        assert!(out.body.starts_with("desp="), "表单按键名排序");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(false, Config { push_key: "k".into(), server_url: "http://127.0.0.1:1".into(), ..Config::default() });
        let err = svc.send(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_parse_response_business_code() {
        let svc = service();
        assert!(svc.parse_response(r#"{"code":0,"content":{"result":[{"token":"ok"}]}}"#).is_ok());

        let err = svc.parse_response(r#"{"code":1000,"error":"wrong key"}"#).unwrap_err();
        assert!(err.to_string().contains("code=1000"), "{err}");
        assert!(err.to_string().contains("wrong key"));
        assert!(!err.is_not_configured(), "拨过号被拒 = 投递失败");

        // 缺 error 兜底"no message"。
        let err = svc.parse_response(r#"{"code":9}"#).unwrap_err();
        assert!(err.to_string().contains("no message"));

        // 非 JSON 应答照实报。
        let err = svc.parse_response("<html>boom</html>").unwrap_err();
        assert!(err.to_string().contains("peer answer is not JSON"));
    }

    #[test]
    fn test_status_error() {
        let err = status_error(500, "boom");
        assert!(err.to_string().contains("500") && err.to_string().contains("boom"));
    }
}
