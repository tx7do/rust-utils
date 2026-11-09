//! Join by joaoapps(设备推送):裸 HTTP 表单调 `/_ah/api/messaging/v1/sendPush`,零 SDK。
//!
//! 渠道约定:
//! - `Message.target` 是设备 ID,多台以逗号相连,进表单的 `deviceIds`;留空推全部设备;
//! - `Config::api_key` 是账户 API Key(必填,缺了在拨号之前拦下);
//! - Join 的 `text` 参数 = 标题行 + `\n` + 正文;`title` 单独进表单;
//! - 应答 body 的 `success`(true 为成功)、原因放 `errorMessage`;
//!   只看 HTTP 状态码会把"没收"记成"送达"。

use std::io::Read;

use serde_json::Value;

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt,
    Service as NotifyService,
};

/// Join 官方 API 域。
pub const DEFAULT_API_BASE: &str = "https://joinjoaomgcd.appspot.com";

/// 应答读取上限。
const ANSWER_LIMIT: usize = 8 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Join 配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 账户 API Key(Join 官网个人页获取)。
    pub api_key: String,
    /// 服务基地址,留空用官方;测试可覆盖。
    pub api_base: String,
}

/// Join 渠道。无状态,可并发使用。
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
    /// 构造 Join 渠道。
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
        "join"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.api_key.is_empty() {
            return Err(NotifyError::NotConfigured(
                "join config incomplete: api_key required".into(),
            ));
        }

        // Join 的 text 参数 = 标题行 + \n + 正文。
        let text = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };

        let mut pairs: Vec<(String, String)> = vec![
            ("apikey".to_string(), self.cfg.api_key.clone()),
            ("title".to_string(), msg.title.clone()),
            ("text".to_string(), text),
        ];
        if !msg.target.is_empty() {
            pairs.push(("deviceIds".to_string(), msg.target.clone()));
        }

        Ok(Outbound {
            method: "POST",
            url: format!("{}/_ah/api/messaging/v1/sendPush", self.cfg.api_base),
            body: form_encode(&pairs),
            headers: vec![(
                "Content-Type",
                "application/x-www-form-urlencoded".to_string(),
            )],
        })
    }

    /// 解析 2xx 应答:业务结论在 body 的 success。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body).map_err(|_| {
            NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body)))
        })?;
        let success = answer
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !success {
            let mut error = answer
                .get("errorMessage")
                .and_then(Value::as_str)
                .unwrap_or("");
            if error.is_empty() {
                error = "no message";
            }
            return Err(NotifyError::Delivery(format!(
                "peer answered success=false: {error}"
            )));
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

    /// 推一条通知到 Target 设备。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.content.is_empty() {
            return Err(NotifyError::NotConfigured(
                "join message body is empty".into(),
            ));
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
            Config {
                ref_: "7".into(),
                api_key: "key-1".into(),
                api_base: "https://join.example".into(),
            },
        )
    }

    #[test]
    fn test_missing_api_key_is_not_configured() {
        let svc = Service::new(true, Config::default());
        assert_eq!(svc.name(), "join");
        let err = svc
            .build_request(&Message::new("", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_content_is_not_configured() {
        let err = service().send(&Message::new("", "t")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_delivers_to_device_ids() {
        let svc = service();
        let out = svc
            .build_request(&Message::new("dev1,dev2", "构建完成").with_content("产物已就绪"))
            .unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(
            out.url,
            "https://join.example/_ah/api/messaging/v1/sendPush"
        );
        assert_eq!(out.headers[0].1, "application/x-www-form-urlencoded");

        // 表单按键名排序(apikey、deviceIds、text、title)。
        assert!(out.body.contains("apikey=key-1"));
        assert!(
            out.body.contains("deviceIds=dev1%2Cdev2"),
            "多设备逗号相连走 deviceIds"
        );
        assert!(out.body.contains("text=%E6%9E%84%E5%BB%BA%E5%AE%8C%E6%88%90%0A%E4%BA%A7%E7%89%A9%E5%B7%B2%E5%B0%B1%E7%BB%AA"),
            "text = 标题行 + 换行 + 正文");
        assert!(out
            .body
            .contains("title=%E6%9E%84%E5%BB%BA%E5%AE%8C%E6%88%90"));
    }

    #[test]
    fn test_without_target_pushes_all_devices() {
        let svc = Service::new(
            true,
            Config {
                api_key: "k".into(),
                api_base: "https://j.example".into(),
                ..Config::default()
            },
        );
        let out = svc
            .build_request(&Message::new("", "").with_content("c"))
            .unwrap();
        assert!(
            !out.body.contains("deviceIds"),
            "无 Target 不带 deviceIds,推全部设备"
        );
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(
            false,
            Config {
                api_key: "k".into(),
                api_base: "http://127.0.0.1:1".into(),
                ..Config::default()
            },
        );
        let err = svc
            .send(&Message::new("", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_parse_response_failure_answer() {
        let svc = service();
        assert!(svc
            .parse_response(r#"{"success":true,"userAccountId":"acc"}"#)
            .is_ok());

        let err = svc
            .parse_response(r#"{"success":false,"errorMessage":"API key not valid"}"#)
            .unwrap_err();
        assert!(err.to_string().contains("success=false"), "{err}");
        assert!(err.to_string().contains("API key not valid"));
        assert!(!err.is_not_configured(), "拨过号被拒 = 投递失败");

        // 缺 errorMessage 兜底"no message"。
        let err = svc.parse_response(r#"{"success":false}"#).unwrap_err();
        assert!(err.to_string().contains("no message"));

        // 非 JSON 应答照实报。
        let err = svc.parse_response("<html>boom</html>").unwrap_err();
        assert!(err.to_string().contains("peer answer is not JSON"));
    }

    #[test]
    fn test_status_error() {
        let err = status_error(503, "unavailable");
        assert!(err.to_string().contains("503") && err.to_string().contains("unavailable"));
    }
}
