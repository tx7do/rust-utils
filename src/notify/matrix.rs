//! Matrix 客户端-服务端 API(房间文本消息):零 SDK。
//!
//! 渠道约定:
//! - `Message.target` 是房间 ID(如 `!abc:example.org`),按 Matrix 规范显式转义进路径
//!   (`!` → `%21`、`:` → `%3A`、`%` → `%25`);
//! - 事务发送是 PUT(事务 ID 会话内唯一,客户端重复发送时对端据此去重),路径段
//!   `/send/m.text/<txnId>`,`access_token` 走 query;
//! - 正文 = Title + Content(有标题时换行相连),`msgtype` 固定 `m.text`;
//! - 应答 body 的 `event_id` 进 [`Receipt::provider_id`] 供对账;缺 `event_id` 即失败
//!   (错误带 `errcode`/`error`)。

use std::io::Read;

use serde_json::{json, Value};

use crate::notify::{
    check_target, map_ureq_error, new_client, Message, NotifyError, Receipt,
    Service as NotifyService,
};

/// 应答读取上限。
const ANSWER_LIMIT: usize = 8 * 1024;
/// 进错误文案的响应片段上限。
const SNIPPET_LIMIT: usize = 256;

/// Matrix 渠道配置。
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// 渠道配置的展示标识(ID、名字均可):只进错误文案。
    pub ref_: String,
    /// homeserver 基地址(必填——Matrix 都是自建/托管域)。
    pub server_url: String,
    /// 用户 access token(登录或注册应用服务获得)。
    pub access_token: String,
}

/// Matrix 渠道。无状态,可并发使用。
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
    /// 构造 Matrix 渠道。
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
        "matrix"
    }

    /// 构造出站请求(纯函数,离线可测)。
    fn build_request(&self, msg: &Message) -> Result<Outbound, NotifyError> {
        if self.cfg.server_url.is_empty() || self.cfg.access_token.is_empty() {
            return Err(NotifyError::NotConfigured(
                "matrix config incomplete: server_url/access_token required".into(),
            ));
        }

        // 正文 = Title + Content(有标题时换行相连)。
        let body = if msg.title.is_empty() {
            msg.content.clone()
        } else {
            format!("{}\n{}", msg.title, msg.content)
        };
        let payload = json!({
            "msgtype": "m.text",
            "body": body,
        });

        // 事务 ID 只需会话内唯一:客户端重复发送时对端据此去重。
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.text/{}?access_token={}",
            self.cfg.server_url.trim_end_matches('/'),
            room_id_path(&msg.target),
            txn_id(),
            query_escape(&self.cfg.access_token),
        );

        Ok(Outbound {
            method: "PUT",
            url,
            body: payload.to_string(),
            headers: vec![("Content-Type", "application/json".to_string())],
        })
    }

    /// 解析 2xx 应答:event_id 缺失即失败(Matrix 也会在 2xx 里回 MatrixError 的情况少见,
    /// 但按上游口径:非 JSON 照实报,缺 event_id 带 errcode 报)。
    fn parse_response(&self, body: &str) -> Result<Receipt, NotifyError> {
        let answer: Value = serde_json::from_str(body).map_err(|_| {
            NotifyError::Delivery(format!("peer answer is not JSON: {}", snippet(body)))
        })?;
        let event_id = answer.get("event_id").and_then(Value::as_str).unwrap_or("");
        if event_id.is_empty() {
            let errcode = answer.get("errcode").and_then(Value::as_str).unwrap_or("");
            let mut error = answer.get("error").and_then(Value::as_str).unwrap_or("");
            if error.is_empty() {
                error = "no event_id";
            }
            return Err(NotifyError::Delivery(format!(
                "peer answered errcode={errcode}: {error}"
            )));
        }
        Ok(Receipt {
            provider_id: event_id.to_string(),
        })
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

    /// 给 Target(房间 ID)发一条 m.text 消息。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("matrix room id is empty".into()));
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

/// 房间 ID 进 URL 路径段:`!` 与 `:` 是路径合法字符,通用转义不会动它们,
/// 而 Matrix 规范要求显式转义(`%21` / `%3A`);`%` 先转义避免二次解释。
fn room_id_path(room_id: &str) -> String {
    room_id
        .replace('%', "%25")
        .replace('!', "%21")
        .replace(':', "%3A")
}

/// 会话内唯一的事务 ID(16 随机字节的 URL 安全 base64,无填充)。
fn txn_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("getrandom 生成随机字节失败");
    base64_url_nopad(&buf)
}

/// URL 安全 base64(不带填充)。
fn base64_url_nopad(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[n as usize & 63] as char);
        }
    }
    out
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

/// URL 查询成分编码(按字节:ASCII 字母数字与 `-_.~` 直通,空格作 `+`,其余 `%XX`)。
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
                server_url: "https://matrix.example/".into(),
                access_token: "syt-1".into(),
            },
        )
    }

    #[test]
    fn test_missing_config_is_not_configured() {
        let svc = Service::new(
            true,
            Config {
                server_url: "https://example.org".into(),
                ..Config::default()
            },
        );
        assert_eq!(svc.name(), "matrix");
        let err = svc
            .build_request(&Message::new("!r:s.org", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_empty_room_is_not_configured() {
        let err = service()
            .send(&Message::new("", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured());
    }

    #[test]
    fn test_build_request_event_put() {
        let svc = service();
        let out = svc
            .build_request(
                &Message::new("!room:example.org", "部署完成").with_content("v1.2.0 已上线"),
            )
            .unwrap();

        assert_eq!(out.method, "PUT", "事务发送是 PUT(txnId 幂等)");
        assert!(
            out.url.starts_with(
                "https://matrix.example/_matrix/client/v3/rooms/%21room%3Aexample.org/send/m.text/"
            ),
            "房间 ID 要 URL 转义进路径(! 和 : 是保留字): {}",
            out.url
        );
        assert!(out.url.contains("access_token=syt-1"), "token 走 query");
        // 事务 ID 段是 22 字符的 URL 安全 base64。
        let txn = out
            .url
            .split("/send/m.text/")
            .nth(1)
            .and_then(|s| s.split('?').next())
            .unwrap();
        assert_eq!(txn.len(), 22, "16 字节 → 22 字符无填充: {txn}");

        let payload: Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(payload["msgtype"], "m.text");
        assert_eq!(payload["body"], "部署完成\nv1.2.0 已上线");
    }

    #[test]
    fn test_txn_id_differs_per_send() {
        let svc = service();
        let a = svc
            .build_request(&Message::new("!r:s.org", "").with_content("c"))
            .unwrap();
        let b = svc
            .build_request(&Message::new("!r:s.org", "").with_content("c"))
            .unwrap();
        assert_ne!(a.url, b.url, "每次发送换事务 ID,重复发送靠它去重");
    }

    #[test]
    fn test_send_blocked_target() {
        let svc = Service::new(
            false,
            Config {
                server_url: "http://127.0.0.1:1".into(),
                access_token: "t".into(),
                ..Config::default()
            },
        );
        let err = svc
            .send(&Message::new("!r:s.org", "").with_content("c"))
            .unwrap_err();
        assert!(err.is_blocked_target(), "{err}");
    }

    #[test]
    fn test_parse_response_event_id() {
        let svc = service();
        let receipt = svc
            .parse_response(r#"{"event_id":"$abc123:example.org"}"#)
            .unwrap();
        assert_eq!(
            receipt.provider_id, "$abc123:example.org",
            "event_id 要进回执"
        );

        // 缺 event_id 即失败,带 errcode。
        let err = svc
            .parse_response(r#"{"errcode":"M_UNKNOWN","error":"boom"}"#)
            .unwrap_err();
        assert!(err.to_string().contains("errcode=M_UNKNOWN"), "{err}");

        // 全缺兜底"no event_id"。
        let err = svc.parse_response(r#"{}"#).unwrap_err();
        assert!(err.to_string().contains("no event_id"));

        // 非 JSON 应答照实报。
        let err = svc.parse_response("<html>boom</html>").unwrap_err();
        assert!(err.to_string().contains("peer answer is not JSON"));
    }

    #[test]
    fn test_matrix_error_body_in_status_error() {
        // 403 + M_FORBIDDEN:走状态码分支,JSON 片段进错误文案(上游口径)。
        let err = status_error(
            403,
            r#"{"errcode":"M_FORBIDDEN","error":"You are not in the room"}"#,
        );
        assert!(err.to_string().contains("403"), "{err}");
        assert!(err.to_string().contains("M_FORBIDDEN"));
        assert!(!err.is_not_configured(), "拨过号被拒 = 投递失败");
    }

    #[test]
    fn test_room_id_path() {
        assert_eq!(room_id_path("!a:b"), "%21a%3Ab");
        assert_eq!(room_id_path("100%"), "100%25");
    }
}
