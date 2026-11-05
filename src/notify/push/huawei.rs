//! 华为 / 荣耀 Push Kit 推送(HMS / Honor Push Kit),feature `notify`。
//! 对齐上游 `push/huawei.go`。
//!
//! 两者协议同形,只差域名(默认生产域;`token_url`/`send_url` 可覆盖供测试):
//! OAuth2 `client_credentials` 换访问令牌(按凭证缓存——换凭据即失效重取),
//! 逐台设备 POST `messages:send`。
//!
//! 华为系响应码在 `0x80000000` 段;`0x80200xxx` 子段为令牌/目标无效类,归
//! [`NotifyError::InvalidToken`](厂商码漂移只改 `huawei_err_invalid_range`)。

use std::sync::Mutex;

use crate::notify::{Message, NotifyError, Receipt, Service};

/// 华为 Push Kit 令牌端点。
pub const HUAWEI_TOKEN_URL: &str = "https://oauth-login.cloud.huawei.com/oauth2/v3/token";
/// 华为 Push Kit 发送端点(含 `%s` app_id 占位)。
pub const HUAWEI_SEND_URL: &str = "https://push-api.cloud.huawei.com/v1/%s/messages:send";
/// 荣耀 Push Kit 令牌端点。
pub const HONOR_TOKEN_URL: &str = "https://oauth-login.hihonorcloud.com/oauth2/v3/token";
/// 荣耀 Push Kit 发送端点(含 `%s` app_id 占位)。
pub const HONOR_SEND_URL: &str = "https://push-drcn.hihonorcloud.com/v1/%s/messages:send";

/// 成功码(上游按十进制 80000000 判定;华为系响应码形如 8xxx xxxx)。
const HUAWEI_CODE_OK: i64 = 80_000_000;
/// 令牌/目标无效类响应码段(含两端,上游 0x80200xxx 段的十进制写法)。
const HUAWEI_ERR_INVALID_LO: i64 = 80_200_000;
const HUAWEI_ERR_INVALID_HI: i64 = 80_209_999;

/// 华为/荣耀推送配置。
#[derive(Debug, Clone, Default)]
pub struct HuaweiConfig {
    /// 推送服务凭据:client id。
    pub client_id: String,
    /// 推送服务凭据:client secret。
    pub client_secret: String,
    /// 令牌端点,留空按 honor 开关切华为/荣耀的默认生产域;测试可覆盖。
    pub token_url: String,
    /// 发送端点,含 `%s` app_id 占位;留空同上;测试可覆盖。
    pub send_url: String,
}

/// 判定华为系厂商码是否属于"令牌/目标无效"段。
fn huawei_err_invalid_range(code: i64) -> bool {
    (HUAWEI_ERR_INVALID_LO..=HUAWEI_ERR_INVALID_HI).contains(&code)
}

/// 缓存的访问令牌:与凭证绑定,换凭据即失效重取。
#[derive(Default)]
struct CachedToken {
    client_id: String,
    client_secret: String,
    expiry_unix: i64,
    token: String,
}

/// 华为/荣耀共用的发送内核:令牌缓存 + 端点。
struct HuaweiStyle {
    agent: ureq::Agent,
    token_url: String,
    send_url: String,
    cached: Mutex<Option<CachedToken>>,
}

impl HuaweiStyle {
    /// 取(按凭证缓存的)OAuth2 访问令牌。
    fn get_access_token(&self, client_id: &str, client_secret: &str) -> Result<String, NotifyError> {
        let now = chrono::Utc::now().timestamp();
        {
            let cached = self.cached.lock().expect("huawei token 锁");
            if let Some(c) = cached.as_ref() {
                if c.client_id == client_id
                    && c.client_secret == client_secret
                    && now < c.expiry_unix
                {
                    return Ok(c.token.clone());
                }
            }
        }

        // 表单按键名排序出站(Go url.Values.Encode 语义)。
        let form = super::form_encode(&[
            ("client_id".to_string(), client_id.to_string()),
            ("client_secret".to_string(), client_secret.to_string()),
            ("grant_type".to_string(), "client_credentials".to_string()),
        ]);
        let (status, body) = super::post(
            &self.agent,
            &self.token_url,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            &form,
        )?;
        if status != 200 {
            return Err(NotifyError::Delivery(format!(
                "oauth token failed: http {status}: {}",
                super::err_snippet(&body)
            )));
        }
        #[derive(serde::Deserialize)]
        struct TokenResp {
            #[serde(default)]
            access_token: String,
            #[serde(default)]
            expires_in: i64,
        }
        let tok: TokenResp = serde_json::from_str(&body)
            .map_err(|_| NotifyError::Delivery("oauth token response malformed".into()))?;
        if tok.access_token.is_empty() {
            return Err(NotifyError::Delivery("oauth token response malformed".into()));
        }

        let mut cached = self.cached.lock().expect("huawei token 锁");
        *cached = Some(CachedToken {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            expiry_unix: now + tok.expires_in,
            token: tok.access_token.clone(),
        });
        Ok(tok.access_token)
    }

    fn send(&self, cfg: &HuaweiConfig, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("device token is empty".into()));
        }
        if cfg.client_id.is_empty() || cfg.client_secret.is_empty() {
            return Err(NotifyError::NotConfigured(
                "config incomplete: client_id/client_secret required".into(),
            ));
        }

        let access_token = self.get_access_token(&cfg.client_id, &cfg.client_secret)?;
        let payload = build_send_payload(&msg.target, &msg.title, &msg.content, &msg.params);
        let endpoint = send_endpoint(&self.send_url, &cfg.client_id);
        let auth = format!("Bearer {access_token}");
        let (status, body) = super::post(
            &self.agent,
            &endpoint,
            &[("Authorization", auth.as_str()), ("Content-Type", "application/json; charset=UTF-8")],
            &payload,
        )?;
        let provider_id = parse_answer(status, &body)?;
        Ok(Receipt { provider_id })
    }
}

/// 华为推送渠道(HMS Push Kit)。
pub struct Huawei {
    inner: HuaweiStyle,
    cfg: HuaweiConfig,
}

impl Huawei {
    /// 构造华为推送渠道;`allow_private` 仅供本机联调时关闭 SSRF 防线。
    pub fn new(allow_private: bool, cfg: HuaweiConfig) -> Self {
        let token_url = if cfg.token_url.is_empty() { HUAWEI_TOKEN_URL } else { &cfg.token_url };
        let send_url = if cfg.send_url.is_empty() { HUAWEI_SEND_URL } else { &cfg.send_url };
        Huawei {
            inner: HuaweiStyle {
                agent: crate::notify::new_client(allow_private),
                token_url: token_url.to_string(),
                send_url: send_url.to_string(),
                cached: Mutex::new(None),
            },
            cfg,
        }
    }
}

impl Service for Huawei {
    fn name(&self) -> &str {
        "huawei"
    }

    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        self.inner.send(&self.cfg, msg)
    }
}

/// 荣耀推送渠道。协议与华为同形,只差域名。
pub struct Honor {
    inner: HuaweiStyle,
    cfg: HuaweiConfig,
}

impl Honor {
    /// 构造荣耀推送渠道。
    pub fn new(allow_private: bool, cfg: HuaweiConfig) -> Self {
        let token_url = if cfg.token_url.is_empty() { HONOR_TOKEN_URL } else { &cfg.token_url };
        let send_url = if cfg.send_url.is_empty() { HONOR_SEND_URL } else { &cfg.send_url };
        Honor {
            inner: HuaweiStyle {
                agent: crate::notify::new_client(allow_private),
                token_url: token_url.to_string(),
                send_url: send_url.to_string(),
                cached: Mutex::new(None),
            },
            cfg,
        }
    }
}

impl Service for Honor {
    fn name(&self) -> &str {
        "honor"
    }

    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        self.inner.send(&self.cfg, msg)
    }
}

/// 构造发送端点:模板里的 `%s` 以路径转义后的 app_id 填充。
pub fn send_endpoint(template: &str, client_id: &str) -> String {
    template.replace("%s", &path_escape(client_id))
}

/// 构造发送 payload,可独立测试的纯函数:
/// `token` 是设备 regId,`notification` 进通知面板,`data` 携带业务自定义键。
pub fn build_send_payload(
    token: &str,
    title: &str,
    body: &str,
    data: &std::collections::HashMap<String, String>,
) -> String {
    serde_json::json!({
        "message": {
            "token": token,
            "notification": {"title": title, "body": body},
            "data": data,
        }
    })
    .to_string()
}

/// 应答归类,可独立测试的纯函数。成功返回 `requestId`。
///
/// 2xx 且 `code == 0x80000000` 才是发出去了;`0x80200xxx` 段归令牌失效;
/// 其余(含非 2xx 与非失效厂商码)按投递失败。
pub fn parse_answer(status: u16, body: &str) -> Result<String, NotifyError> {
    #[derive(serde::Deserialize, Default)]
    #[allow(non_snake_case)]
    struct Answer {
        #[serde(default)]
        code: i64,
        #[serde(default, rename = "requestId")]
        request_id: String,
    }
    let answer: Answer = serde_json::from_str(body).unwrap_or_default();
    if (200..300).contains(&status) && answer.code == HUAWEI_CODE_OK {
        return Ok(answer.request_id);
    }
    if huawei_err_invalid_range(answer.code) {
        return Err(NotifyError::InvalidToken(format!(
            "invalid push token (code {})",
            answer.code
        )));
    }
    Err(NotifyError::Delivery(format!(
        "push send failed: http {status} code {}: {}",
        answer.code,
        super::err_snippet(body)
    )))
}

/// Go `url.PathEscape` 语义:字母数字与 `-_.~!$&'()*+,;=:@` 直通,其余按字节转义。
fn path_escape(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(b as char),
            b'-' | b'_' | b'.' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+'
            | b',' | b';' | b'=' | b':' | b'@' => out.push(b as char),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 默认域切换:华为与荣耀各用各的生产域;配置可整体覆盖(测试注入)。
    #[test]
    fn test_default_endpoints() {
        let hw = Huawei::new(false, HuaweiConfig::default());
        assert_eq!(hw.inner.token_url, HUAWEI_TOKEN_URL);
        assert_eq!(hw.inner.send_url, HUAWEI_SEND_URL);
        assert_eq!(Service::name(&hw), "huawei");

        let honor = Honor::new(false, HuaweiConfig::default());
        assert_eq!(honor.inner.token_url, HONOR_TOKEN_URL);
        assert_eq!(honor.inner.send_url, HONOR_SEND_URL);
        assert_eq!(Service::name(&honor), "honor");

        // 端点被 Config 覆写后两者等价(荣耀/华为协议同形)
        let cfg = HuaweiConfig {
            token_url: "http://127.0.0.1:1/token".into(),
            send_url: "http://127.0.0.1:1/v1/app-%s/messages:send".into(),
            ..Default::default()
        };
        let hw = Huawei::new(false, cfg);
        assert_eq!(hw.inner.token_url, "http://127.0.0.1:1/token");
    }

    /// 端点模板填充:app_id 进路径并经路径转义。
    #[test]
    fn test_send_endpoint_escapes_app_id() {
        assert_eq!(
            send_endpoint(HUAWEI_SEND_URL, "app-1"),
            "https://push-api.cloud.huawei.com/v1/app-1/messages:send"
        );
        assert_eq!(
            send_endpoint("https://x/v1/%s/messages:send", "a/b c"),
            "https://x/v1/a%2Fb%20c/messages:send"
        );
    }

    /// 消息形状对齐上游:token/notification/data。
    #[test]
    fn test_send_payload_shape() {
        let mut data = std::collections::HashMap::new();
        data.insert("msg_id".to_string(), "7".to_string());
        let payload = build_send_payload("hw-reg-1", "重置验证码", "您的验证码是 123456", &data);
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["message"]["token"], "hw-reg-1");
        assert_eq!(v["message"]["notification"]["title"], "重置验证码");
        assert_eq!(v["message"]["notification"]["body"], "您的验证码是 123456");
        assert_eq!(v["message"]["data"]["msg_id"], "7");
    }

    /// 对齐上游 TestHuaweiInvalidTokenCode:0x80200xxx 段是令牌无效类。
    #[test]
    fn test_invalid_token_code() {
        let err = parse_answer(200, r#"{"code":80200007,"msg":"answer","requestId":"req-1"}"#)
            .unwrap_err();
        assert!(err.is_invalid_token(), "80200xxx 段 = 令牌失效,得到 {err}");
        assert!(err.to_string().contains("80200007"));
        // 段两端同样在册
        assert!(parse_answer(200, r#"{"code":80200000}"#).unwrap_err().is_invalid_token());
        assert!(parse_answer(200, r#"{"code":80209999}"#).unwrap_err().is_invalid_token());
    }

    /// 对齐上游 TestHuaweiNonOKCodeIsTransportError:非失效段厂商码是投递失败。
    #[test]
    fn test_non_ok_code_is_delivery() {
        let err = parse_answer(200, r#"{"code":80000001,"msg":"answer","requestId":"req-42"}"#)
            .unwrap_err();
        assert!(!err.is_invalid_token(), "{err}");
        assert!(matches!(err, NotifyError::Delivery(_)));
        assert!(err.to_string().contains("80000001"));
        // 非 2xx 同样投递失败
        let err = parse_answer(500, r#"{"code":80000000}"#).unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)));
        // 非 JSON 应答按 code=0 处理 → 投递失败(与上游 json.Unmarshal 忽略错误一致)
        let err = parse_answer(502, "<html/>").unwrap_err();
        assert!(matches!(err, NotifyError::Delivery(_)));
    }

    /// 成功路径:requestId 进回执;成功码就是 0x80000000(80000000)。
    #[test]
    fn test_success_parses_request_id() {
        let id = parse_answer(200, r#"{"code":80000000,"msg":"answer","requestId":"req-42"}"#).unwrap();
        assert_eq!(id, "req-42");
    }

    /// 拨号前自检:缺凭据拦下;目标为空拦下。
    #[test]
    fn test_pre_dial_checks() {
        let hw = Huawei::new(false, HuaweiConfig::default());
        let err = hw.send(&Message::new("reg", "t")).unwrap_err();
        assert!(err.is_not_configured(), "缺凭据在拨号之前就该拦下: {err}");
        assert!(err.to_string().contains("client_id/client_secret"));

        let hw = Huawei::new(
            false,
            HuaweiConfig { client_id: "c".into(), client_secret: "s".into(), ..Default::default() },
        );
        let err = hw.send(&Message::new("", "t")).unwrap_err();
        assert!(err.to_string().contains("device token is empty"), "{err}");
    }
}
