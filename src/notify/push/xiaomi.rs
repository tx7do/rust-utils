//! 小米推送(MiPush)通知栏消息,feature `notify`。对齐上游 `push/xiaomi.go`。
//!
//! 通知栏形态(非透传):`title`/`content` 进通知面板,`params` 以 `extra.{key}`
//! 表单键透传——通知栏消息点击经 `extra.uri` 深链回端内。静态 `Authorization:
//! Key=` 头鉴权;响应码 20201/20202 归 [`NotifyError::InvalidToken`]。

use crate::notify::{Message, NotifyError, Receipt, Service};

/// MiPush 通知栏消息端点。
pub const XIAOMI_SEND_URL: &str = "https://api.xmpush.xiaomi.com/v2/message/regid";

/// MiPush 响应码中"目标 regId 无效"类(厂商码漂移只改这里的表)。
const INVALID_CODES: [i64; 2] = [20_201, 20_202];

/// 小米推送配置。
#[derive(Debug, Clone, Default)]
pub struct XiaomiConfig {
    /// MiPush 的应用 Secret(请求头 `Authorization: Key=<app_secret>`)。
    pub app_secret: String,
    /// 端点,留空用官方;测试可覆盖。
    pub send_url: String,
}

/// 小米推送渠道。无状态,可并发使用。
pub struct Xiaomi {
    agent: ureq::Agent,
    send_url: String,
    cfg: XiaomiConfig,
}

impl Xiaomi {
    /// 构造小米推送渠道;`allow_private` 仅供本机联调时关闭 SSRF 防线。
    pub fn new(allow_private: bool, cfg: XiaomiConfig) -> Self {
        let send_url = if cfg.send_url.is_empty() {
            XIAOMI_SEND_URL.to_string()
        } else {
            cfg.send_url.clone()
        };
        Xiaomi { agent: crate::notify::new_client(allow_private), send_url, cfg }
    }
}

impl Service for Xiaomi {
    fn name(&self) -> &str {
        "xiaomi"
    }

    /// 给 Target(MiPush regId)推一条通知栏消息。
    /// Title/Content 进通知面板(title/description),Params 以 `extra.{key}`
    /// 表单键透传——通知栏消息点击经 `extra.uri` 深链回端内。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("xiaomi regId is empty".into()));
        }
        if self.cfg.app_secret.is_empty() {
            return Err(NotifyError::NotConfigured(
                "xiaomi config incomplete: app_secret required".into(),
            ));
        }

        let form = build_form(&msg.target, &msg.title, &msg.content, &msg.params);
        let auth = format!("Key={}", self.cfg.app_secret);
        let (status, body) = super::post(
            &self.agent,
            &self.send_url,
            &[("Authorization", auth.as_str()), ("Content-Type", "application/x-www-form-urlencoded")],
            &form,
        )?;
        parse_answer(status, &body)?;
        Ok(Receipt::default())
    }
}

/// 构造表单体,可独立测试的纯函数:固定字段 + `extra.{key}` 透传,
/// 按键名排序出站(Go url.Values.Encode 语义)。
pub fn build_form(
    registration_id: &str,
    title: &str,
    description: &str,
    params: &std::collections::HashMap<String, String>,
) -> String {
    let mut pairs = vec![
        ("description".to_string(), description.to_string()),
        ("pass_through".to_string(), "0".to_string()),
        ("registration_id".to_string(), registration_id.to_string()),
        ("title".to_string(), title.to_string()),
    ];
    for (k, v) in params {
        pairs.push((format!("extra.{k}"), v.clone()));
    }
    super::form_encode(&pairs)
}

/// 应答归类,可独立测试的纯函数。
///
/// 2xx 且 `code == 0` 才是发出去了;20201/20202 归令牌失效;其余投递失败。
pub fn parse_answer(status: u16, body: &str) -> Result<(), NotifyError> {
    #[derive(serde::Deserialize, Default)]
    struct Answer {
        #[serde(default)]
        code: i64,
    }
    let answer: Answer = serde_json::from_str(body).map_err(|_| {
        NotifyError::Delivery(format!("xiaomi answer is not JSON: {}", super::err_snippet(body)))
    })?;
    if (200..300).contains(&status) && answer.code == 0 {
        return Ok(());
    }
    if INVALID_CODES.contains(&answer.code) {
        return Err(NotifyError::InvalidToken(format!("invalid regid (code {})", answer.code)));
    }
    Err(NotifyError::Delivery(format!(
        "xiaomi push failed: http {status} code {}: {}",
        answer.code,
        super::err_snippet(body)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 对齐上游 TestXiaomiSendDeliversNotificationForm:通知栏形态 + extra.* 透传。
    #[test]
    fn test_build_form_shape() {
        let mut params = std::collections::HashMap::new();
        params.insert("uri".to_string(), "app://chat/42".to_string());
        let form = build_form("reg-1", "重置验证码", "您的验证码是 123456", &params);

        // 表单键排序后逐项核对(键已编码,值需解码语义;这里用包含断言)
        let pairs: Vec<(String, String)> = form
            .split('&')
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            })
            .collect();
        let get = |key: &str| -> String {
            let idx = pairs.iter().position(|(k, _)| k == key).expect("键必在表单中");
            let raw = pairs[idx].1.as_bytes();
            // 全量 %XX 解码(QueryEscape 语义:空格编码为 +)。
            let mut out = Vec::with_capacity(raw.len());
            let mut i = 0;
            while i < raw.len() {
                if raw[i] == b'%' && i + 2 < raw.len() {
                    let hi = (raw[i + 1] as char).to_digit(16);
                    let lo = (raw[i + 2] as char).to_digit(16);
                    if let (Some(hi), Some(lo)) = (hi, lo) {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                        continue;
                    }
                }
                out.push(if raw[i] == b'+' { b' ' } else { raw[i] });
                i += 1;
            }
            String::from_utf8(out).expect("解码回 UTF-8")
        };
        assert_eq!(get("registration_id"), "reg-1");
        assert_eq!(get("title"), "重置验证码");
        assert_eq!(get("description"), "您的验证码是 123456");
        assert_eq!(get("pass_through"), "0", "通知栏形态,非透传");
        assert_eq!(get("extra.uri"), "app://chat/42", "Params 以 extra.键 表单键透传,点击深链靠它");
    }

    /// 对齐上游 TestXiaomiInvalidRegId:20201/20202 = regId 失效。
    #[test]
    fn test_invalid_regid_codes() {
        for code in [20_201_i64, 20_202] {
            let body = format!(r#"{{"result":"fail","code":{code}}}"#);
            let err = parse_answer(200, &body).unwrap_err();
            assert!(err.is_invalid_token(), "code {code} = regId 失效,得到 {err}");
            assert!(err.to_string().contains(&code.to_string()));
        }
    }

    /// 对齐上游 TestXiaomiPeerError:非失效码是投递失败,文案带厂商码。
    #[test]
    fn test_peer_error() {
        let err = parse_answer(200, r#"{"result":"fail","code":1001,"reason":"quota"}"#).unwrap_err();
        assert!(!err.is_invalid_token());
        assert!(matches!(err, NotifyError::Delivery(_)));
        assert!(err.to_string().contains("1001"));
        // HTTP 层失败 / 非JSON
        assert!(matches!(parse_answer(500, "boom").unwrap_err(), NotifyError::Delivery(_)));
        assert!(matches!(parse_answer(200, "<html/>").unwrap_err(), NotifyError::Delivery(_)));
    }

    /// 成功路径:2xx 且 code==0。
    #[test]
    fn test_success() {
        assert!(parse_answer(200, r#"{"result":"ok","code":0,"data":{"id":"msg-1"}}"#).is_ok());
    }

    /// 拨号前自检:缺 app_secret / 空 regId。
    #[test]
    fn test_pre_dial_checks() {
        let svc = Xiaomi::new(false, XiaomiConfig::default());
        let err = svc.send(&Message::new("reg", "t")).unwrap_err();
        assert!(err.is_not_configured());
        assert!(err.to_string().contains("app_secret"), "{err}");

        let svc = Xiaomi::new(false, XiaomiConfig { app_secret: "s".into(), ..Default::default() });
        let err = svc.send(&Message::new("", "t")).unwrap_err();
        assert!(err.to_string().contains("regId is empty"), "{err}");
        assert_eq!(Service::name(&svc), "xiaomi");
    }

    /// 官方 regId 单播端点钉死(对齐上游 XiaomiSendURL)。
    #[test]
    fn test_xiaomi_send_url_constant() {
        assert_eq!(XIAOMI_SEND_URL, "https://api.xmpush.xiaomi.com/v2/message/regid");
    }
}
