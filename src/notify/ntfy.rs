//! 主题推送(ntfy.sh 及自建服务):JSON publish,零 SDK。
//!
//! 渠道约定:
//! - 收件身份是 `Message.target` 携带的主题名(topic);
//! - JSON publish 走服务根路径——主题名/标题/正文都在 body 里,绕开表单转义与头注入两类坑;
//! - 服务基地址默认官方 [`DEFAULT_SERVER_URL`](ntfy.sh),自建服务用 [`Config::server_url`] 覆盖;
//! - 认证三选:`Config::access_token`(tk_ 开头)优先,其次 `Config::user`/`password` 基础认证;
//! - `Config::priority` 默认优先级(1~5,0 默认),`Message.params["priority"]` 可按条覆盖;
//! - `Config::tags` 默认标签(emoji shortcode 或文本);
//! - 应答 body 的 `id`(消息 ID)进 [`Receipt::provider_id`] 供对账。

use std::io::Read;

use serde_json::{json, Map, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt, Service as NotifyService,
};

/// ntfy 官方服务域。
pub const DEFAULT_SERVER_URL: &str = "https://ntfy.sh";

/// 优先级档位(1 最低 ~ 5 最高;0 默认)。
pub const PRIORITY_MIN: i32 = 1;
pub const PRIORITY_DEFAULT: i32 = 0;
pub const PRIORITY_HIGH: i32 = 4;
pub const PRIORITY_MAX: i32 = 5;

/// 应答读取上限。
const ANSWER_LIMIT: usize = 4 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// ntfy 渠道配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// 服务基地址,留空用官方 ntfy.sh;自建服务可覆盖。
    pub server_url: String,
    /// 默认优先级(1~5,0 默认);`Message.params["priority"]` 可按条覆盖。
    pub priority: i32,
    /// 基础认证用户名(自建服务常见);与 access_token 二选一。
    pub user: String,
    /// 基础认证密码。
    pub password: String,
    /// 访问令牌(ntfy access tokens,tk_ 开头);优先于 user/password。
    pub access_token: String,
    /// 默认标签(emoji shortcode 或文本)。
    pub tags: Vec<String>,
}

/// ntfy 渠道。无状态,可并发使用。
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
    /// 构造 ntfy 渠道。
    ///
    /// `allow_private = true`(本机联调)时整条 SSRF 防线关闭;生产部署必须传 `false`。
    pub fn new(allow_private: bool, cfg: Config) -> Self {
        Service {
            client: new_client(allow_private),
            allow_private,
            cfg,
        }
    }

    /// 渠道名。
    pub fn name(&self) -> &str {
        "ntfy"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        let mut payload = Map::new();
        payload.insert("topic".into(), json!(msg.target));
        payload.insert("title".into(), json!(msg.title));
        payload.insert("message".into(), json!(msg.content));
        if !self.cfg.tags.is_empty() {
            payload.insert("tags".into(), json!(self.cfg.tags));
        }

        let mut priority = self.cfg.priority;
        if let Some(p) = msg.params.get("priority") {
            priority = p.parse::<i32>().map_err(|_| {
                NotifyError::NotConfigured(format!("params[priority] {p:?} is not a number 0-5"))
            })?;
        }
        if priority != 0 {
            payload.insert("priority".into(), json!(priority));
        }

        // 认证:令牌优先于基础认证。
        let mut headers = vec![("Content-Type", "application/json".to_string())];
        if !self.cfg.access_token.is_empty() {
            headers.push(("Authorization", format!("Bearer {}", self.cfg.access_token)));
        } else if !self.cfg.user.is_empty() {
            headers.push(("Authorization", format!("Basic {}", base64_standard(format!("{}:{}", self.cfg.user, self.cfg.password).as_bytes()))));
        }

        Ok(Outbound {
            method: "POST",
            url: self.cfg.server_url.clone(),
            body: Value::Object(payload).to_string(),
            headers,
        })
    }

    /// 解析 2xx 应答:ntfy 回的消息 id 进回执。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let mut receipt = Receipt::default();
        if let Some(id) = answer.get("id").and_then(Value::as_str) {
            receipt.provider_id = id.to_string();
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

    /// 给 Target(ntfy 主题名)发一条消息。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("ntfy topic is empty".into()));
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

/// 标准 base64(带 `=` 填充),用于 Basic 认证头。
fn base64_standard(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TABLE[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[n as usize & 63] as char } else { '=' });
    }
    out
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
                server_url: "https://ntfy.example".into(),
                user: "u".into(),
                password: "p".into(),
                tags: vec!["warning".into()],
                ..Config::default()
            },
        )
    }

    #[test]
    fn test_build_request_json_publish_shape() {
        let svc = service();
        let msg = Message::new("alerts", "磁盘告警")
            .with_content("用量 92%")
            .with_param("priority", "4");
        let out = svc.build_request(&msg).unwrap();

        assert_eq!(out.method, "POST");
        assert_eq!(out.url, "https://ntfy.example", "JSON publish 走根路径:主题在 body 里,绕开头注入");

        let header = |name: &str| {
            out.headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(header("Authorization"), "Basic dTpw", "基础认证 user:pass");
        assert_eq!(header("Content-Type"), "application/json");

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["topic"], "alerts");
        assert_eq!(payload["title"], "磁盘告警");
        assert_eq!(payload["message"], "用量 92%");
        assert_eq!(payload["priority"], 4, "Params[priority] 按条覆盖默认档位");
        assert_eq!(payload["tags"], json!(["warning"]));
    }

    #[test]
    fn test_token_auth_overrides_basic() {
        let svc = Service::new(
            true,
            Config {
                server_url: "https://n.example".into(),
                user: "u".into(),
                password: "p".into(),
                access_token: "tk_x".into(),
                ..Config::default()
            },
        );
        let out = svc.build_request(&Message::new("t", "").with_content("c")).unwrap();
        let auth = out
            .headers
            .iter()
            .find(|(k, _)| *k == "Authorization")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        assert_eq!(auth, "Bearer tk_x", "令牌认证优先于基础认证");
    }

    #[test]
    fn test_empty_topic_is_not_configured() {
        let err = service().send(&Message::new("", "").with_content("c")).unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_bad_priority_param_rejected() {
        let err = service()
            .build_request(&Message::new("t", "").with_content("c").with_param("priority", "high"))
            .unwrap_err();
        assert!(err.is_not_configured(), "优先级要数字档位,垃圾值在拨号之前拦下");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(false, Config { server_url: "http://127.0.0.1:1".into(), ..Config::default() });
        let err = svc.send(&Message::new("t", "").with_content("c")).unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_parse_response_returns_id() {
        let svc = service();
        let receipt = svc
            .parse_response(r#"{"id":"sP8vG0","time":1760000000,"topic":"alerts"}"#)
            .unwrap();
        assert_eq!(receipt.provider_id, "sP8vG0", "ntfy 的消息 ID 要进回执");
        assert_eq!(svc.parse_response("{}").unwrap().provider_id, "");
    }

    #[test]
    fn test_status_error() {
        let err = status_error(403, "unauthorized");
        assert!(err.to_string().contains("403") && err.to_string().contains("unauthorized"));
    }
}
