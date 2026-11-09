//! Bark iOS 推送:裸 HTTP 调 `/push` 接口,零 SDK。
//!
//! 渠道约定:
//! - 收件身份是 `Message.target` 携带的设备 device_key——一个 Service 可服务多台设备;
//! - 服务基地址默认官方 [`DEFAULT_SERVER_URL`](api.day.app),自建服务用 [`Config::server_url`] 覆盖;
//! - `Message.params` 的键值原样并进出站 JSON(Bark 的 level/badge/sound/group/url/icon 等
//!   原生字段,字符串值直传,拼错的字段名由对端忽略——Bark 对未知字段宽容);
//! - Bark 把业务结论放应答 body 的 `code` 字段(HTTP 恒 200 时代的行为,仍旧兼容判断),
//!   `code != 200` 即失败——只看状态码会把"没收"记成"送达"。

use std::io::Read;

use serde_json::{Map, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt,
    Service as NotifyService,
};

/// Bark 官方服务域。
pub const DEFAULT_SERVER_URL: &str = "https://api.day.app";

/// 应答读取上限:判业务结论要看的 body 是一个几百字节的小 JSON。
const ANSWER_LIMIT: usize = 4 * 1024;
/// 进错误文案的响应片段上限:只用于排障,别把一整页 HTML 塞进去。
const SNIPPET_LIMIT: usize = 256;

/// Bark 渠道配置。Target(设备密钥)按消息传,不进配置——一个 Service 可以服务多台设备。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 服务基地址,留空用官方 api.day.app;自建服务可覆盖。
    pub server_url: String,
}

/// Bark 渠道。无状态,可并发使用。
pub struct Service {
    client: ureq::Agent,
    allow_private: bool,
    server_url: String,
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
    /// 构造 Bark 渠道。
    ///
    /// `allow_private = true`(本机联调)时整条 SSRF 防线关闭(连环回都能发);
    /// 生产部署必须传 `false`(出站既过 [`check_target`] 预检,也过客户端守卫解析器)。
    pub fn new(allow_private: bool, cfg: Config) -> Self {
        let server_url = if cfg.server_url.is_empty() {
            DEFAULT_SERVER_URL.to_string()
        } else {
            cfg.server_url
        };
        Service {
            client: new_client(allow_private),
            allow_private,
            server_url,
        }
    }

    /// 渠道名。
    pub fn name(&self) -> &str {
        "bark"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        let mut payload = Map::new();
        payload.insert("device_key".into(), Value::String(msg.target.clone()));
        payload.insert("title".into(), Value::String(msg.title.clone()));
        payload.insert("body".into(), Value::String(msg.content.clone()));
        // Params 原生字段直传 JSON(可覆盖基础字段)。
        for (k, v) in &msg.params {
            payload.insert(k.clone(), Value::String(v.clone()));
        }

        Ok(Outbound {
            method: "POST",
            url: format!("{}/push", self.server_url),
            body: Value::Object(payload).to_string(),
            headers: vec![(
                "Content-Type",
                "application/json; charset=utf-8".to_string(),
            )],
        })
    }

    /// 解析 2xx 应答:Bark 把业务结论放 body 的 code 里。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body).map_err(|_| {
            NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body)))
        })?;
        let code = answer.get("code").and_then(Value::as_i64).unwrap_or(0);
        if code != 200 {
            let mut message = answer.get("message").and_then(Value::as_str).unwrap_or("");
            if message.is_empty() {
                message = "no message";
            }
            return Err(NotifyError::Delivery(format!(
                "peer answered code={code}: {message}"
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

    /// 给 Target(Bark App 的 device_key)推一条通知。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured(
                "bark device_key is empty".into(),
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

/// 应答片段截断:进错误文案就够排障了(Go 按字节硬切会产生乱码,这里退到字符边界)。
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

// ---------------------------------------------------------------------------
// 测试(纯离线:构造与应答解析;不发 HTTP)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Service {
        Service::new(true, Config::default())
    }

    #[test]
    fn test_build_request_payload_shape() {
        let svc = service();
        let msg = Message::new("device-key-1", "重置验证码")
            .with_content("您的验证码是 123456")
            .with_param("group", "auth")
            .with_param("sound", "minuet");
        let out = svc.build_request(&msg).unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, format!("{DEFAULT_SERVER_URL}/push"));

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["device_key"], "device-key-1");
        assert_eq!(payload["title"], "重置验证码");
        assert_eq!(payload["body"], "您的验证码是 123456");
        assert_eq!(payload["group"], "auth", "Params 原生字段直传 JSON");
        assert_eq!(payload["sound"], "minuet");

        assert_eq!(out.headers[0].0, "Content-Type");
        assert_eq!(out.headers[0].1, "application/json; charset=utf-8");
    }

    #[test]
    fn test_server_url_override_and_default() {
        // 默认官方域;自建服务可覆盖。
        let plain = service();
        let url = plain.build_request(&Message::new("k", "t")).unwrap().url;
        assert!(url.starts_with(DEFAULT_SERVER_URL));

        let custom = Service::new(
            true,
            Config {
                server_url: "https://bark.self-hosted.example".into(),
                ..Config::default()
            },
        );
        assert_eq!(
            custom.build_request(&Message::new("k", "t")).unwrap().url,
            "https://bark.self-hosted.example/push"
        );
    }

    #[test]
    fn test_send_empty_target_is_not_configured() {
        assert_eq!(service().name(), "bark");
        let err = service()
            .send(&Message::new("", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "一次都没联系对端,按\"没尝试\"归类");
    }

    #[test]
    fn test_send_blocked_target() {
        // SSRF 防线:生产默认下环回地址一次都拨不出去,归 BlockedTarget。
        let svc = Service::new(
            false,
            Config {
                server_url: "http://127.0.0.1:1".into(),
                ..Config::default()
            },
        );
        let err = svc
            .send(&Message::new("device-key", "t").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_parse_response_business_code() {
        let svc = service();

        // 成功:code=200。
        assert!(svc
            .parse_response(r#"{"code":200,"message":"success","timestamp":1760000000}"#)
            .is_ok());

        // 业务码非 200:HTTP 200 也算失败,错误带业务码与原因。
        let err = svc
            .parse_response(r#"{"code":400,"message":"key not found"}"#)
            .unwrap_err();
        assert!(err.to_string().contains("code=400"), "{err}");
        assert!(err.to_string().contains("key not found"));
        assert!(!err.is_not_configured(), "拨过号被拒 = 投递失败");

        // 无 message 兜底"no message"。
        let err = svc.parse_response(r#"{"code":500}"#).unwrap_err();
        assert!(err.to_string().contains("no message"));

        // 缺 code 字段按 0 处理(Go 零值语义):!= 200 即失败。
        assert!(svc.parse_response(r#"{"message":"weird"}"#).is_err());

        // 非 JSON 应答:对端已用 2xx 表态,但结论读不出就照实报。
        let err = svc.parse_response("<html>boom</html>").unwrap_err();
        assert!(err.to_string().contains("peer answer is not JSON"), "{err}");
    }

    #[test]
    fn test_status_error_includes_status_and_snippet() {
        let err = status_error(502, "<html>Bad Gateway</html>");
        assert!(err.to_string().contains("502"));
        assert!(err.to_string().contains("Bad Gateway"));
        assert!(matches!(err, NotifyError::Delivery(_)));
    }

    #[test]
    fn test_snippet_truncates() {
        assert_eq!(snippet("short"), "short");
        let long = "字".repeat(200); // 每字 3 字节,共 600 字节
        let got = snippet(&long);
        assert!(got.len() <= SNIPPET_LIMIT + "…".len());
        assert!(got.ends_with('…'));
    }
}
