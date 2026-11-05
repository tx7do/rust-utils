//! OPPO 推送(key/secret 两段式鉴权),feature `notify`。对齐上游 `push/oppo.go`。
//!
//! 通知栏形态没有数据面——`Message::params` 被忽略,业务数据请自行并进 `content`。
//! 通知标题按 28 runes 截断(厂商上限 32 字符,超了直接 400);响应码 2008 归
//! [`NotifyError::InvalidToken`]。auth token 按实例缓存至到期。

use std::sync::Mutex;

use crate::notify::{Message, NotifyError, Receipt, Service};

/// OPPO Push 鉴权端点。
pub const OPPO_AUTH_URL: &str = "https://push.oppomobile.com/server/v1/message/auth/aliyun";
/// OPPO Push 单播通知端点。
pub const OPPO_SEND_URL: &str =
    "https://push.oppomobile.com/server/v1/message/notification/unicast";

/// "registration_id 无效"响应码(厂商码漂移只改这里)。
const OPPO_INVALID_CODE: i64 = 2008;

/// OPPO 通知标题上限 32 字符,按 28 runes 截断防 400。
pub const OPPO_TITLE_MAX: usize = 28;

/// OPPO 推送配置。
#[derive(Debug, Clone, Default)]
pub struct OppoConfig {
    /// OPPO 推送凭据:app key。
    pub app_key: String,
    /// OPPO 推送凭据:app secret。
    pub app_secret: String,
    /// 鉴权端点,留空用官方;测试可覆盖。
    pub auth_url: String,
    /// 发送端点,留空用官方;测试可覆盖。
    pub send_url: String,
}

/// 缓存的 auth token:到期即重取。
#[derive(Default)]
struct CachedToken {
    token: String,
    expiry_unix: i64,
}

/// OPPO 推送渠道。auth token 按实例缓存,并发安全。
pub struct Oppo {
    agent: ureq::Agent,
    cfg: OppoConfig,
    auth_url: String,
    send_url: String,
    cached: Mutex<Option<CachedToken>>,
}

impl Oppo {
    /// 构造 OPPO 推送渠道;`allow_private` 仅供本机联调时关闭 SSRF 防线。
    pub fn new(allow_private: bool, cfg: OppoConfig) -> Self {
        let auth_url =
            if cfg.auth_url.is_empty() { OPPO_AUTH_URL.to_string() } else { cfg.auth_url.clone() };
        let send_url =
            if cfg.send_url.is_empty() { OPPO_SEND_URL.to_string() } else { cfg.send_url.clone() };
        Oppo {
            agent: crate::notify::new_client(allow_private),
            cfg,
            auth_url,
            send_url,
            cached: Mutex::new(None),
        }
    }

    /// 取(缓存至到期的)auth token:两段式鉴权第一阶段。
    fn get_auth_token(&self) -> Result<String, NotifyError> {
        let now = chrono::Utc::now().timestamp();
        {
            let cached = self.cached.lock().expect("oppo token 锁");
            if let Some(c) = cached.as_ref() {
                if !c.token.is_empty() && now < c.expiry_unix {
                    return Ok(c.token.clone());
                }
            }
        }

        // 表单按键名排序出站(Go url.Values.Encode 语义)。
        let form = super::form_encode(&[
            ("key".to_string(), self.cfg.app_key.clone()),
            ("secret".to_string(), self.cfg.app_secret.clone()),
        ]);
        let (status, body) = super::post(
            &self.agent,
            &self.auth_url,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            &form,
        )?;
        if status != 200 {
            return Err(NotifyError::Delivery(format!(
                "oppo auth failed: http {status}: {}",
                super::err_snippet(&body)
            )));
        }
        #[derive(serde::Deserialize, Default)]
        struct AuthResp {
            #[serde(default)]
            code: i64,
            #[serde(default)]
            data: AuthData,
        }
        #[derive(serde::Deserialize, Default)]
        #[allow(non_snake_case)]
        struct AuthData {
            #[serde(default, rename = "authToken")]
            auth_token: String,
            #[serde(default, rename = "expiresIn")]
            expires_in: i64,
        }
        let answer: AuthResp = serde_json::from_str(&body)
            .map_err(|_| NotifyError::Delivery("oppo auth response malformed".into()))?;
        if answer.code != 0 || answer.data.auth_token.is_empty() {
            return Err(NotifyError::Delivery("oppo auth response malformed".into()));
        }

        let mut cached = self.cached.lock().expect("oppo token 锁");
        *cached = Some(CachedToken {
            token: answer.data.auth_token.clone(),
            expiry_unix: now + answer.data.expires_in,
        });
        Ok(answer.data.auth_token)
    }
}

impl Service for Oppo {
    fn name(&self) -> &str {
        "oppo"
    }

    /// 给 Target(OPPO registration_id)推一条通知栏消息。
    /// Title 按 28 runes 截断(厂商上限 32 字符,超了 400)。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("oppo registration_id is empty".into()));
        }
        if self.cfg.app_key.is_empty() || self.cfg.app_secret.is_empty() {
            return Err(NotifyError::NotConfigured(
                "oppo config incomplete: app_key/app_secret required".into(),
            ));
        }

        let auth_token = self.get_auth_token()?;
        let form = super::form_encode(&[
            ("auth_token".to_string(), auth_token),
            ("click_action_type".to_string(), "0".to_string()),
            ("content".to_string(), msg.content.clone()),
            ("registration_id".to_string(), msg.target.clone()),
            ("title".to_string(), super::truncate_runes(&msg.title, OPPO_TITLE_MAX)),
        ]);
        let (status, body) = super::post(
            &self.agent,
            &self.send_url,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            &form,
        )?;
        parse_answer(status, &body)?;
        Ok(Receipt::default())
    }
}

/// 应答归类,可独立测试的纯函数。
///
/// 2xx 且 `code == 0` 才是发出去了;2008 归令牌失效;其余投递失败。
pub fn parse_answer(status: u16, body: &str) -> Result<(), NotifyError> {
    #[derive(serde::Deserialize, Default)]
    struct Answer {
        #[serde(default)]
        code: i64,
    }
    let answer: Answer = serde_json::from_str(body).unwrap_or_default();
    if (200..300).contains(&status) && answer.code == 0 {
        return Ok(());
    }
    if answer.code == OPPO_INVALID_CODE {
        return Err(NotifyError::InvalidToken(format!(
            "invalid registration_id (code {OPPO_INVALID_CODE})"
        )));
    }
    Err(NotifyError::Delivery(format!(
        "oppo push failed: http {status} code {}: {}",
        answer.code,
        super::err_snippet(body)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 对齐上游 TestOppoTitleTruncatedTo28Runes:标题按 rune 截到 28 个,前缀截断。
    #[test]
    fn test_title_truncated_to_28_runes() {
        let long = "重".repeat(40);
        let truncated = super::super::truncate_runes(&long, OPPO_TITLE_MAX);
        assert_eq!(truncated.chars().count(), OPPO_TITLE_MAX, "标题按 rune 截到 28 个");
        assert_eq!(truncated.chars().next().unwrap(), '重', "截断是前缀截断");

        // 发送表单里的 title 也是截断后的
        let form = super::super::form_encode(&[
            ("auth_token".to_string(), "t".to_string()),
            ("click_action_type".to_string(), "0".to_string()),
            ("content".to_string(), "c".to_string()),
            ("registration_id".to_string(), "reg-1".to_string()),
            ("title".to_string(), truncated),
        ]);
        assert!(form.contains("click_action_type=0"), "点击打开应用");
        assert!(form.contains("registration_id=reg-1"));
        assert!(form.contains("auth_token=t"));
    }

    /// 对齐上游 TestOppoInvalidRegistrationID:2008 = registration_id 失效。
    #[test]
    fn test_invalid_registration_id() {
        let err = parse_answer(200, r#"{"code":2008,"message":"registration_id invalid"}"#).unwrap_err();
        assert!(err.is_invalid_token(), "2008 = registration_id 失效,得到 {err}");
    }

    /// 非失效码 / HTTP 层失败归投递失败。
    #[test]
    fn test_peer_error() {
        let err = parse_answer(200, r#"{"code":13,"message":"system error"}"#).unwrap_err();
        assert!(!err.is_invalid_token());
        assert!(matches!(err, NotifyError::Delivery(_)));
        assert!(parse_answer(500, "boom").is_err());
        // 非 JSON 按 code=0 处理:非 2xx 才失败
        assert!(parse_answer(200, "<html/>").is_ok());
        assert!(parse_answer(502, "<html/>").is_err());
    }

    /// 成功路径。
    #[test]
    fn test_success() {
        assert!(parse_answer(200, r#"{"code":0,"message":"ok"}"#).is_ok());
    }

    /// 拨号前自检:缺 app_key/app_secret;空 registration_id。
    #[test]
    fn test_pre_dial_checks() {
        let svc = Oppo::new(false, OppoConfig::default());
        let err = svc.send(&Message::new("reg", "t")).unwrap_err();
        assert!(err.is_not_configured());
        assert!(!err.is_invalid_token());
        assert!(err.to_string().contains("app_key/app_secret"), "{err}");

        let svc = Oppo::new(
            false,
            OppoConfig { app_key: "k".into(), app_secret: "s".into(), ..Default::default() },
        );
        let err = svc.send(&Message::new("", "t")).unwrap_err();
        assert!(err.to_string().contains("registration_id is empty"), "{err}");
        assert_eq!(Service::name(&svc), "oppo");
    }

    /// 官方端点钉死:key/secret 鉴权与单播通知两段,对齐上游 OppoAuthURL/OppoSendURL。
    #[test]
    fn test_oppo_endpoint_constants() {
        assert_eq!(OPPO_AUTH_URL, "https://push.oppomobile.com/server/v1/message/auth/aliyun");
        assert_eq!(OPPO_SEND_URL, "https://push.oppomobile.com/server/v1/message/notification/unicast");
    }
}
