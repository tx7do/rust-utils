//! SMTP 邮件渠道:把 [`Message`] 映射到同 crate [`crate::mailer`] 的一次投递。
//!
//! 传输层的行为(TLS 模式、会话错误分支)由 [`crate::mailer`] 钉死,本渠道
//! 只钉映射本身与入口校验:Target 为收件地址,Title 为 Subject,Content 为
//! 纯文本正文;多个收件人的场景由调用方直接用 [`crate::mailer::send_mail`]。
//!
//! 错误归类(对齐核心包"联系对端之前一律 NotConfigured"的准则):
//! [`crate::mailer::send_mail`] 在拨号之前的本地校验(host/port 未配、收件人
//! 为空/非法、TLS 模式不认识、发件人地址非法)归 [`NotifyError::NotConfigured`];
//! 只有 `send mail failed: ...`(连接/认证/投递,已拨过号)归 [`NotifyError::Delivery`]。
//! 邮件走 SMTP,不经 HTTP,所以不做 SSRF 预检(对齐上游)。

use crate::mailer::{self, SmtpConfig};
use crate::notify::{Message, NotifyError, Receipt};

/// SMTP 连接配置:直接复用 mailer 的配置类型(对齐上游 `type Config = mailer.SmtpConfig`)。
pub type Config = SmtpConfig;

/// 邮件渠道。无状态:配置在构造时注入,可并发使用。
pub struct Service {
    cfg: Config,
}

impl Service {
    /// 构造邮件渠道。
    pub fn new(cfg: Config) -> Self {
        Service { cfg }
    }
}

impl crate::notify::Service for Service {
    fn name(&self) -> &str {
        "email"
    }

    /// 投递一封邮件:Target 为收件地址(为空在拨号之前拒绝),
    /// Title 为 Subject,Content 为纯文本正文。SMTP 投递没有服务商消息 ID,
    /// 回执为空(对齐上游)。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError> {
        let (to, subject, body) = build_mail(msg)?;
        mailer::send_mail(&self.cfg, &[to.as_str()], &subject, &body)
            .map_err(|e| classify_mailer_error(&e))?;
        Ok(Receipt::default())
    }
}

/// 把消息映射成一封邮件(纯函数):返回 (收件地址, Subject, 正文)。
fn build_mail(msg: &Message) -> Result<(String, String, String), NotifyError> {
    if msg.target.is_empty() {
        return Err(NotifyError::NotConfigured(
            "email target is empty".to_string(),
        ));
    }
    Ok((msg.target.clone(), msg.title.clone(), msg.content.clone()))
}

/// 把 [`crate::mailer::send_mail`] 的错误归为通知错误(纯函数)。
///
/// mailer 的错误文案语义(见其文档):拨号之前的本地校验(配置/组包)与
/// `send mail failed: ...`(已拨过号的连接/认证/投递失败)可凭前缀区分。
fn classify_mailer_error(err: &str) -> NotifyError {
    if err.starts_with("send mail failed") {
        NotifyError::Delivery(err.to_string())
    } else {
        NotifyError::NotConfigured(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::Service as _;

    fn svc() -> Service {
        Service::new(SmtpConfig::new(
            "smtp.example.com",
            465,
            "u",
            "p",
            "noreply@example.com",
            "SSL",
        ))
    }

    #[test]
    fn test_name() {
        assert_eq!(svc().name(), "email");
    }

    // 没有收件人的投递在拨号之前就拒绝(对齐上游入口校验)。
    #[test]
    fn test_empty_target() {
        let err = svc().send(&Message::new("", "t")).unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("email target is empty"));
    }

    // 映射语义:Target 为收件地址、Title 为 Subject、Content 为正文。
    #[test]
    fn test_build_mail_mapping() {
        let (to, subject, body) = build_mail(
            &Message::new("user@example.com", "注册验证码").with_content("您的验证码是 123456"),
        )
        .unwrap();
        assert_eq!(to, "user@example.com");
        assert_eq!(subject, "注册验证码");
        assert_eq!(body, "您的验证码是 123456");

        // 标题/正文为空也原样映射(上游对空 Subject/正文不做兜底)。
        let (to, subject, body) = build_mail(&Message::new("u@example.com", "")).unwrap();
        assert_eq!(to, "u@example.com");
        assert_eq!(subject, "");
        assert_eq!(body, "");
    }

    // mailer 错误归类:拨号前的本地校验归 NotConfigured,
    // 已拨过号的 send mail failed 归 Delivery。
    #[test]
    fn test_classify_mailer_error() {
        for msg in [
            "smtp host/port is not configured",
            "recipient is empty",
            "unsupported tls mode: QUANTUM",
            "invalid recipient address \"not-an-address\": x",
            "sender address is empty",
            "build message failed: x",
        ] {
            let err = classify_mailer_error(msg);
            assert!(err.is_not_configured(), "{msg:?} 应归 NotConfigured,得到 {err}");
        }
        let err = classify_mailer_error("send mail failed: connection refused");
        assert!(
            matches!(err, NotifyError::Delivery(_)),
            "会话阶段错误应归 Delivery,得到 {err}"
        );
    }

    // 配置缺失走完整 send 路径(不连网):host/port 未配,mailer 在拨号前拒绝。
    #[test]
    fn test_send_not_configured() {
        let err = Service::new(SmtpConfig::default())
            .send(&Message::new("user@example.com", "s").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("smtp host/port is not configured"));

        let err = Service::new(SmtpConfig::new("127.0.0.1", 0, "", "", "", "NONE"))
            .send(&Message::new("user@example.com", "s").with_content("c"))
            .unwrap_err();
        assert!(err.is_not_configured(), "{err}");

        // TLS 模式不认识:配置值不认识是配置问题,不该和 SMTP 服务端报错混淆。
        let err = Service::new(SmtpConfig::new(
            "smtp.example.com",
            465,
            "",
            "",
            "noreply@example.com",
            "QUANTUM",
        ))
        .send(&Message::new("user@example.com", "s").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("unsupported tls mode"));
    }

    // 收件地址非法:组包阶段(拨号之前)判出,归 NotConfigured。
    #[test]
    fn test_send_invalid_recipient() {
        let err = Service::new(SmtpConfig::new(
            "smtp.example.com",
            465,
            "u",
            "p",
            "noreply@example.com",
            "SSL",
        ))
        .send(&Message::new("not-an-address", "s").with_content("c"))
        .unwrap_err();
        assert!(err.is_not_configured(), "{err}");
        assert!(err.to_string().contains("invalid recipient address"));
    }
}
