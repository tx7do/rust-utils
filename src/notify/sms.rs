//! 短信渠道:阿里云 Dysmsapi 与腾讯云 SMS 的裸 HTTP 实现(零 SDK)。
//! 对齐上游 `sms` 包(`sms.go` + `phone.go` + `aliyun.go` + `tencent.go`)。
//!
//! 协议差异一览:
//! - 阿里云是 RPC 风格:全部参数排序拼接做 HMAC-SHA1 签名,请求是一张普通表单
//!   (见 [`aliyun`]);
//! - 腾讯云是 TC3-HMAC-SHA256:签名不只盖参数,还盖整个 JSON 请求体,手机号只认
//!   E.164(见 [`tencent`])。
//!
//! 两家都把业务结论放在 HTTP 200 的 body 里(阿里云 `Code=="OK"`、腾讯云无
//! `Error` 且 `SendStatusSet[0].Code=="Ok"`),只看状态码会把"对方没收"记成发送成功。
//!
//! 手机号形态见 [`normalize_phone_number`];构造期即拒认不出的服务商
//! ([`SmsService::new`]),配置自检见 [`SmsService::precheck`]。

pub mod aliyun;
pub mod phone;
pub mod tencent;

pub use phone::normalize_phone_number;

use std::collections::HashMap;

use crate::notify::{Message, NotifyError, Receipt, Service};

/// 服务商标识。存储里这一列的值域与这里的常量逐字相同(按名字配对)。
pub const PROVIDER_ALIYUN: &str = "ALIYUN";
/// 服务商标识:腾讯云。
pub const PROVIDER_TENCENT: &str = "TENCENT";

/// 短信渠道配置。`provider` 决定哪些字段必填(见 [`SmsService::precheck`])。
#[derive(Debug, Clone, Default)]
pub struct SmsConfig {
    /// 服务商:`ALIYUN` / `TENCENT`。
    pub provider: String,
    /// 服务商访问密钥 ID。
    pub access_key_id: String,
    /// 服务商访问密钥。
    pub access_secret: String,
    /// 服务商侧已备案的短信签名。
    pub sign_name: String,
    /// 短信模板 ID(阿里云正文含 `${code}`,腾讯云正文含 `{1}`)。
    pub template_code: String,
    /// 腾讯云 SmsSdkAppId(必填);阿里云留空。
    pub app_id: String,
    /// 地域:腾讯云必填(空兜默认 ap-guangzhou);阿里云留空兜 cn-hangzhou。
    pub region: String,
}

/// 短信渠道。无状态:配置在构造时注入,可并发使用。
#[derive(Debug)]
pub struct SmsService {
    agent: ureq::Agent,
    cfg: SmsConfig,
}

impl SmsService {
    /// 构造短信渠道。`provider` 认不出当场报错——拼错的服务商名不该等到第一次
    /// 投递才暴露;`allow_private` 为 `true` 时关闭 SSRF 防线,仅供本机联调。
    pub fn new(allow_private: bool, cfg: SmsConfig) -> Result<Self, NotifyError> {
        match cfg.provider.as_str() {
            PROVIDER_ALIYUN | PROVIDER_TENCENT => {}
            other => {
                return Err(NotifyError::NotConfigured(format!(
                    "unknown sms provider {other:?} (expected ALIYUN / TENCENT)"
                )))
            }
        }
        Ok(SmsService { agent: crate::notify::new_client(allow_private), cfg })
    }

    /// 配置自检:按服务商核对必填项,不拨号。
    ///
    /// 错误文案直接点名缺哪个字段(以上游的配置键名);按序核对,缺多项时报第一个。
    pub fn precheck(&self) -> Result<(), NotifyError> {
        let required: &[(&str, &str)] = match self.cfg.provider.as_str() {
            PROVIDER_ALIYUN => &[
                ("sms_access_key_id", self.cfg.access_key_id.as_str()),
                ("sms_access_secret", self.cfg.access_secret.as_str()),
                ("sms_sign_name", self.cfg.sign_name.as_str()),
                ("sms_template_code", self.cfg.template_code.as_str()),
            ],
            PROVIDER_TENCENT => &[
                ("sms_access_key_id", self.cfg.access_key_id.as_str()),
                ("sms_access_secret", self.cfg.access_secret.as_str()),
                ("sms_sign_name", self.cfg.sign_name.as_str()),
                ("sms_template_code", self.cfg.template_code.as_str()),
                ("sms_app_id", self.cfg.app_id.as_str()),
                ("sms_region", self.cfg.region.as_str()),
            ],
            other => {
                return Err(NotifyError::NotConfigured(format!(
                    "unknown sms provider {other:?} (expected ALIYUN / TENCENT)"
                )))
            }
        };
        for (name, value) in required {
            if value.is_empty() {
                return Err(NotifyError::NotConfigured(format!(
                    "{name} is required for provider {}",
                    self.cfg.provider
                )));
            }
        }
        Ok(())
    }
}

/// 腾讯云的位置参数:按参数名排序取值。
///
/// 单参数(验证码 code)无感;多参数时模板 `{1}{2}` 的对应关系由这个排序决定。
pub fn template_params_ordered(params: &HashMap<String, String>) -> Vec<String> {
    let mut keys: Vec<&String> = params.keys().collect();
    keys.sort();
    keys.into_iter().map(|k| params[k].clone()).collect()
}

impl Service for SmsService {
    fn name(&self) -> &str {
        "sms"
    }

    /// 投递一条短信:`Message::target` 为手机号(见 [`normalize_phone_number`]),
    /// `Message::params` 为模板参数——阿里云按参数名整表传 JSON(模板写 `${name}`),
    /// 腾讯云按参数名排序取值传位置参数(模板写 `{1}{2}…`,单参数无感,多参数请
    /// 核对模板占位顺序)。
    ///
    /// `params` 为空直接拒绝:短信没有自由文本通道,正文出自服务商侧审核过的模板。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        let receipt = Receipt::default();
        if msg.target.is_empty() {
            return Err(NotifyError::NotConfigured("sms target is empty".into()));
        }
        if msg.params.is_empty() {
            return Err(NotifyError::NotConfigured(
                "sms template params are empty: SMS has no free-text channel, \
                 the body comes from a provider-side approved template"
                    .into(),
            ));
        }

        // 目标错了没有"发到别家去"的软失败,也没碰过对端:归配置/目标类。
        let (national, e164) = normalize_phone_number(&msg.target)
            .map_err(NotifyError::NotConfigured)?;

        match self.cfg.provider.as_str() {
            PROVIDER_ALIYUN => {
                aliyun::send(&self.agent, &self.cfg, &national, &msg.params)?;
            }
            PROVIDER_TENCENT => {
                tencent::send(&self.agent, &self.cfg, &e164, &template_params_ordered(&msg.params))?;
            }
            other => {
                return Err(NotifyError::NotConfigured(format!(
                    "unknown sms provider {other:?} (expected ALIYUN / TENCENT)"
                )))
            }
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_cfg() -> SmsConfig {
        SmsConfig {
            provider: PROVIDER_ALIYUN.into(),
            access_key_id: "k".into(),
            access_secret: "s".into(),
            sign_name: "sig".into(),
            template_code: "SMS_1".into(),
            app_id: "140000".into(),
            region: "ap-guangzhou".into(),
        }
    }

    /// 对齐上游 TestPrecheck:缺哪项报哪项,未知厂商直接拒绝。
    #[test]
    fn test_precheck() {
        // 阿里云全量通过;不需要 app_id/region
        let svc = SmsService::new(false, full_cfg()).unwrap();
        assert!(svc.precheck().is_ok());
        let mut aliyun = full_cfg();
        aliyun.app_id = String::new();
        aliyun.region = String::new();
        assert!(SmsService::new(false, aliyun).unwrap().precheck().is_ok());

        // 腾讯云缺 app_id / region,文案点名配置键
        let mut tencent = full_cfg();
        tencent.provider = PROVIDER_TENCENT.into();
        tencent.app_id = String::new();
        let err = SmsService::new(false, tencent.clone()).unwrap().precheck().unwrap_err();
        assert!(err.to_string().contains("sms_app_id"), "{err}");
        assert!(err.is_not_configured());
        tencent.app_id = "140000".into();
        tencent.region = String::new();
        let err = SmsService::new(false, tencent).unwrap().precheck().unwrap_err();
        assert!(err.to_string().contains("sms_region"), "{err}");
    }

    /// 对齐上游 TestNewRejectsUnknownProvider:服务商名拼错在构造期就报。
    #[test]
    fn test_new_rejects_unknown_provider() {
        let err = SmsService::new(false, SmsConfig { provider: "SMSC".into(), ..Default::default() })
            .unwrap_err();
        assert!(err.is_not_configured());
        assert!(err.to_string().contains("unknown sms provider"));

        let svc = SmsService::new(false, SmsConfig { provider: PROVIDER_ALIYUN.into(), ..Default::default() }).unwrap();
        assert_eq!(Service::name(&svc), "sms");
    }

    /// 对齐上游 TestSendRequiresParams:没带模板参数的投递直接拒绝,
    /// 短信没有自由文本通道;目标为空同样在拨号之前拦下。
    #[test]
    fn test_send_rejects_before_dial() {
        let svc = SmsService::new(false, SmsConfig { provider: PROVIDER_ALIYUN.into(), ..Default::default() })
            .unwrap();

        let err = svc.send(&Message::new("13800138000", "t")).unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("template params are empty"));

        let err = svc
            .send(&Message::new("", "t").with_param("code", "1"))
            .unwrap_err();
        assert!(err.is_not_configured());
        assert!(err.to_string().contains("target is empty"));
    }

    /// 号码不合法一次都不碰对端:归配置/目标类,与上游语义一致。
    #[test]
    fn test_send_bad_phone_is_config_class() {
        let svc = SmsService::new(false, SmsConfig { provider: PROVIDER_ALIYUN.into(), ..Default::default() })
            .unwrap();
        let err = svc
            .send(&Message::new("not-a-phone", "t").with_param("code", "1"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("not-a-phone"));
    }

    /// 腾讯云位置参数:按参数名排序取值。
    #[test]
    fn test_template_params_ordered() {
        let mut params = HashMap::new();
        params.insert("b".to_string(), "2".to_string());
        params.insert("a".to_string(), "1".to_string());
        params.insert("c".to_string(), "3".to_string());
        assert_eq!(template_params_ordered(&params), vec!["1", "2", "3"]);
    }
}
