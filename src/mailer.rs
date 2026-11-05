//! SMTP 邮件发送:STARTTLS / 隐式 SSL,发件人显示名。
//!
//! 移植自 go-utils 的 `mailer` 包(`smtp.go` + `smtp_test.go`):给定
//! [`SmtpConfig`] 与收件人列表,组装一封 UTF-8 纯文本邮件并经 SMTP 投递,
//! 常用于登录链路里的验证码邮件。
//!
//! 与 Go 版逐式对应:
//!
//! | Go                        | Rust                                  | 说明 |
//! |---------------------------|---------------------------------------|------|
//! | `SendMail(ctx, cfg, ...)` | [`send_mail`]                         | 同步阻塞 API;Rust 无 context,lettre 自带 60s 命令超时兜底 |
//! | `SmtpConfig`              | [`SmtpConfig`]                        | 字段一一对应(`Port` 收窄为 `u16`,SMTP 端口值域本就如此) |
//! | `IsSupportedTlsMode`      | [`is_supported_tls_mode`]             | 判定逻辑逐字对齐 |
//! | `buildMessage`            | [`build_message`]                     | 组包语义一致,字节差异见下 |
//!
//! TLS 三模式(`TlsMode` 字符串值,大小写不敏感)到 lettre 的映射:
//!
//! * `""` / `"NONE"` / `"START_TLS"` → [`Tls::Opportunistic`]:明文建连,
//!   服务器广告 STARTTLS 则升级、否则按明文继续——与 Go 版 `dialStartTLS`
//!   的"支持则升级、不支持就明文走"逐句对应(lettre 0.11 没有
//!   `Tls::Starttls` 枚举值,`Opportunistic` 正是这一语义)。
//! * `"SSL"` → [`Tls::Wrapper`]:全程 TLS,通常配 465 端口。
//! * 其余值(如 `"SSL_TLS"`)→ 投递前直接报错,不拨号。
//!
//! 已知与 Go 版的行为差异(均不破坏 SMTP 语义):
//!
//! * **组包**:Go 手拼头部;Rust 用 lettre builder。lettre 会额外带
//!   `Date` 与 `Content-Transfer-Encoding` 头,charset 写作小写
//!   `utf-8`,正文末尾不再多补一个 CRLF(终止点由 SMTP 客户端负责)。
//! * **Subject 编码**:Go 把非 ASCII 主题原样裸写(依赖服务端容忍);
//!   lettre 按 RFC 2047 编码为 `=?utf-8?b?...?=`,各客户端都能正确显示,
//!   更规范。发件人显示名的引号/RFC 2047 行为两边一致。
//! * **认证**:Go 只用 PLAIN(lettre 对齐为
//!   [`Credentials`],机制按服务器广告在 PLAIN/LOGIN 中协商;Go 的
//!   "仅回环地址才允许明文 PLAIN" 保护,lettre 无此限制,请在
//!   `TlsMode=SSL` 或真实 STARTTLS 环境下传凭据)。
//! * **错误文案**:本地校验(`host/port` 未配、收件人为空、模式不认识)
//!   与 Go 逐字一致;连接后的会话阶段错误,lettre 不暴露 MAIL/RCPT/DATA
//!   阶段归属,统一包装为 `send mail failed: ...`。
//! * **空发件人**:Go 允许 `From` 与 `Username` 全空、发出空 `From:` 头;
//!   lettre 要求合法地址,此场景返回 `sender address is empty`。
//!
//! 上游测试中的 mock SMTP(脚本化假服务器)在 Rust 侧没有等价物,离线
//! 可测的语义(模式解析、组包、本地校验、transport 装配)已全部转为
//! 单元测试;真实拨号与会话拒绝分支不在测试范围。
//!
//! ```
//! use rust_utils::mailer::{build_message, is_supported_tls_mode, SmtpConfig};
//!
//! let cfg = SmtpConfig::new("smtp.example.com", 465, "noreply@example.com", "auth-token",
//!         "noreply@example.com", "SSL")
//!     // 发件人显示名(可选):From 头为 `名称 <地址>`,非 ASCII 名称按 RFC 2047 编码
//!     .with_from_name("风行商店");
//!
//! assert!(is_supported_tls_mode(&cfg.tls_mode));
//! assert!(!is_supported_tls_mode("SSL_TLS")); // 枚举外的库值要提前判出来
//!
//! // 组包是纯内存操作:From / To / Subject / MIME 头齐备,可离线断言
//! let message = build_message(&cfg, &["user@example.com"], "注册验证码", "123456").unwrap();
//! let formatted = String::from_utf8(message.formatted()).unwrap();
//! assert!(formatted.starts_with("From: =?utf-8?"));
//! assert!(formatted.contains("To: user@example.com\r\n"));
//! assert!(formatted.contains("Subject: =?utf-8?"));
//! ```

use lettre::message::header::{ContentType, MIME_VERSION_1_0};
use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::{SmtpTransport, SmtpTransportBuilder};
use lettre::{Address, Transport};

// ---------------------------------------------------------------------------
// TLS 模式解析
// ---------------------------------------------------------------------------

/// `TlsMode` 字符串的判定结果(内部值)。
///
/// 加密方式在配置里是可空字符串列,而值域只有三个(见 [`SmtpConfig::tls_mode`]):
/// 演示数据/手工改库都能写出 `"SSL_TLS"` 这类枚举外的串。拨号前把它判出来
/// 比拨号失败更有用——"配置值不认识"是配置问题,不该和"SMTP 服务端报错"
/// 混成同一种失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TlsModeKind {
    /// `NONE` / `START_TLS` / 空串:明文建连,服务端支持则升级 STARTTLS
    Plaintext,
    /// `SSL`:全程 TLS(通常 465)
    Implicit,
    /// 枚举外的值,拨号前直接拒绝
    Unrecognized,
}

/// 把配置里的 `TlsMode` 字符串归为三值(大小写不敏感)。
fn parse_tls_mode(mode: &str) -> TlsModeKind {
    match mode.to_ascii_uppercase().as_str() {
        "SSL" => TlsModeKind::Implicit,
        "NONE" | "START_TLS" | "" => TlsModeKind::Plaintext,
        _ => TlsModeKind::Unrecognized,
    }
}

/// 报告 `mode` 是否为 [`send_mail`] 能识别的加密方式。
///
/// 渠道配置在投递前用它自检,免得枚举外的值一路走到拨号才失败。
/// 识别:`""`、`"NONE"`、`"START_TLS"`、`"SSL"`(大小写不敏感);
/// 不识别:`"SSL_TLS"`、`"TLS"`、`"STARTTLS"`(注意:Go 版只认带下划线的
/// `START_TLS`)等。
///
/// ```
/// use rust_utils::mailer::is_supported_tls_mode;
///
/// assert!(is_supported_tls_mode("SSL"));
/// assert!(is_supported_tls_mode("start_tls"));
/// assert!(is_supported_tls_mode(""));
/// assert!(!is_supported_tls_mode("QUANTUM"));
/// ```
pub fn is_supported_tls_mode(mode: &str) -> bool {
    parse_tls_mode(mode) != TlsModeKind::Unrecognized
}

// ---------------------------------------------------------------------------
// SmtpConfig
// ---------------------------------------------------------------------------

/// SMTP 连接配置,与 Go 版 `SmtpConfig` 字段一一对应。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmtpConfig {
    /// 服务器地址(如 `smtp.example.com`)
    pub host: String,
    /// 端口(SSL 通常 465,STARTTLS/明文通常 587/25;0 视为未配置)
    pub port: u16,
    /// 用户名(空则不做认证)
    pub username: String,
    /// 密码/授权码
    pub password: String,
    /// 发件人地址(空则回退为 [`SmtpConfig::username`])
    pub from: String,
    /// 发件人显示名(可选)。非空时 `From` 头为 `名称 <地址>`,非 ASCII 名称
    /// 按 RFC 2047 编码——收件客户端直接显示这个名,而不是裸地址。
    pub from_name: String,
    /// TLS 模式:`""` / `NONE` / `START_TLS` / `SSL`(大小写不敏感)
    pub tls_mode: String,
}

impl SmtpConfig {
    /// 创建一份配置(`from_name` 留空,需要时用 [`SmtpConfig::with_from_name`] 补)。
    ///
    /// ```
    /// use rust_utils::mailer::SmtpConfig;
    ///
    /// let cfg = SmtpConfig::new("smtp.example.com", 587, "user", "token",
    ///     "noreply@example.com", "START_TLS");
    /// assert_eq!(cfg.port, 587);
    /// assert_eq!(cfg.from_name, "");
    /// ```
    pub fn new(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
        from: impl Into<String>,
        tls_mode: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
            password: password.into(),
            from: from.into(),
            from_name: String::new(),
            tls_mode: tls_mode.into(),
        }
    }

    /// 设置发件人显示名(上游 98aa69a5 新加的可选字段,必须保留)。
    ///
    /// ```
    /// use rust_utils::mailer::SmtpConfig;
    ///
    /// let cfg = SmtpConfig::new("smtp.example.com", 465, "user", "token",
    ///     "noreply@example.com", "SSL").with_from_name("GoWind Shop");
    /// assert_eq!(cfg.from_name, "GoWind Shop");
    /// ```
    pub fn with_from_name(mut self, from_name: impl Into<String>) -> Self {
        self.from_name = from_name.into();
        self
    }

    /// 解析发件人邮箱(对应 Go 版 `SendMail` 开头的 from 回退 + 显示名包装):
    ///
    /// * `from` 为空时回退为 `username`(两边都做 trim);
    /// * 两者皆空时返回错误(lettre 要求合法地址;Go 版此场景会发出空
    ///   `From:` 头,属上游的宽容边界,Rust 收紧为显式报错);
    /// * `from_name` 非空时包成带显示名的 [`Mailbox`]。
    fn sender_mailbox(&self) -> Result<Mailbox, String> {
        let from = self.from.trim();
        let address = if from.is_empty() { self.username.trim() } else { from };
        if address.is_empty() {
            return Err("sender address is empty".to_owned());
        }
        let address: Address = address
            .parse()
            .map_err(|e| format!("invalid sender address {address:?}: {e}"))?;
        let name = if self.from_name.is_empty() {
            None
        } else {
            Some(self.from_name.clone())
        };
        Ok(Mailbox::new(name, address))
    }
}

// ---------------------------------------------------------------------------
// 组包
// ---------------------------------------------------------------------------

/// 按 Go 版 `buildMessage` 的语义组装一封 UTF-8 纯文本邮件。
///
/// 头部齐备:From(带可选显示名)、To(多收件人并成一个头,逗号分隔)、
/// Subject(非 ASCII 自动 RFC 2047 编码)、`MIME-Version: 1.0`、
/// `Content-Type: text/plain; charset=utf-8`。正文原样作为纯文本,
/// 含非 ASCII 时 lettre 自动选合适的 `Content-Transfer-Encoding`。
///
/// ```
/// use rust_utils::mailer::{build_message, SmtpConfig};
///
/// let cfg = SmtpConfig::new("smtp.example.com", 587, "", "",
///     "sender@example.test", "NONE");
/// let message = build_message(&cfg, &["rcpt1@example.test", "rcpt2@example.test"],
///     "plain subject", "plain body").unwrap();
/// let formatted = String::from_utf8(message.formatted()).unwrap();
/// assert!(formatted.contains("From: sender@example.test\r\n"));
/// assert!(formatted.contains("To: rcpt1@example.test, rcpt2@example.test\r\n"));
/// assert!(formatted.contains("Subject: plain subject\r\n"));
/// ```
pub fn build_message(cfg: &SmtpConfig, to: &[&str], subject: &str, body: &str) -> Result<Message, String> {
    let from = cfg.sender_mailbox()?;

    let mut builder = Message::builder().from(from);
    for rcpt in to {
        let address: Address = rcpt
            .parse()
            .map_err(|e| format!("invalid recipient address {:?}: {e}", rcpt))?;
        builder = builder.to(Mailbox::new(None, address));
    }

    builder
        .subject(subject.to_owned())
        .header(MIME_VERSION_1_0)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_owned())
        .map_err(|e| format!("build message failed: {e}"))
}

// ---------------------------------------------------------------------------
// transport 装配与发送
// ---------------------------------------------------------------------------

/// 按配置装配一个同步 SMTP transport(不拨号,纯配置)。
///
/// * `SSL` → [`Tls::Wrapper`]:连接即握手,配 465;
/// * `""`/`NONE`/`START_TLS` → [`Tls::Opportunistic`]:明文建连,广告
///   STARTTLS 则升级,否则明文继续(内网调试常见);
/// * 其余值 → 返回 `unsupported tls mode: <值>`,不产生任何连接。
///
/// 用户名非空时挂上 [`Credentials`],机制由 lettre 按服务器广告在
/// PLAIN/LOGIN 中协商(对应 Go 版 `Username != ""` 才 `smtp.PlainAuth`)。
pub fn build_transport(cfg: &SmtpConfig) -> Result<SmtpTransport, String> {
    let tls_kind = parse_tls_mode(&cfg.tls_mode);

    let builder: SmtpTransportBuilder =
        SmtpTransport::builder_dangerous(cfg.host.clone()).port(cfg.port);
    let builder = match tls_kind {
        TlsModeKind::Implicit => {
            let tls_parameters = TlsParameters::new(cfg.host.clone())
                .map_err(|e| format!("build tls parameters failed: {e}"))?;
            builder.tls(Tls::Wrapper(tls_parameters))
        }
        TlsModeKind::Plaintext => {
            let tls_parameters = TlsParameters::new(cfg.host.clone())
                .map_err(|e| format!("build tls parameters failed: {e}"))?;
            builder.tls(Tls::Opportunistic(tls_parameters))
        }
        TlsModeKind::Unrecognized => {
            return Err(format!("unsupported tls mode: {}", cfg.tls_mode));
        }
    };

    let builder = if cfg.username.is_empty() {
        builder
    } else {
        builder.credentials(Credentials::new(cfg.username.clone(), cfg.password.clone()))
    };
    Ok(builder.build())
}

/// 通过 SMTP 发送一封纯文本邮件,`to` 可为多个收件人。
///
/// 错误语义与 Go 版对齐:
///
/// * `host` 未配或 `port` 为 0 → `"smtp host/port is not configured"`;
/// * 收件人列表为空 → `"recipient is empty"`;
/// * `TlsMode` 不认识 → `"unsupported tls mode: <值>"`;
/// * 发件人地址非法/为空 → 以 `invalid sender address` / `sender address is empty` 报错。
///
/// 以上全部在拨号前返回;之后的连接、认证、投递失败统一包装为
/// `send mail failed: <lettre 错误>`(lettre 不区分会话阶段)。
///
/// 本函数是同步阻塞调用,Rust 无 context 形参;lettre 对每条 SMTP 命令
/// 自带 60 秒超时,不会无限期挂死。真实发送示例(需要可达的 SMTP 服务端,
/// 文档中不实际执行):
///
/// ```no_run
/// use rust_utils::mailer::{send_mail, SmtpConfig};
///
/// let cfg = SmtpConfig::new("smtp.example.com", 465, "noreply@example.com", "auth-token",
///         "noreply@example.com", "SSL")
///     .with_from_name("风行商店");
/// send_mail(&cfg, &["user@example.com"], "注册验证码", "您的验证码是 123456")?;
/// # Ok::<(), String>(())
/// ```
pub fn send_mail(cfg: &SmtpConfig, to: &[&str], subject: &str, body: &str) -> Result<(), String> {
    if cfg.host.is_empty() || cfg.port == 0 {
        return Err("smtp host/port is not configured".to_owned());
    }
    if to.is_empty() {
        return Err("recipient is empty".to_owned());
    }

    let message = build_message(cfg, to, subject, body)?;
    let transport = build_transport(cfg)?;

    transport
        .send(&message)
        .map(|_| ())
        .map_err(|e| format!("send mail failed: {e}"))
}

// ---------------------------------------------------------------------------
// 测试:全部离线,不连网(上游 mock SMTP 会话不可移植,见模块头)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 格式化整封邮件并剔除自动生成的 `Date` 行,得到与时间无关的
    /// 可精确比对的字节序列。
    fn formatted_without_date(message: &Message) -> String {
        let formatted = String::from_utf8(message.formatted()).unwrap();
        let mut out = String::new();
        for line in formatted.split_inclusive("\r\n") {
            if !line.starts_with("Date:") {
                out.push_str(line);
            }
        }
        out
    }

    // ------------------------------------------------------------------
    // buildMessage 白盒测试(对应上游 TestBuildMessage)
    // ------------------------------------------------------------------

    #[test]
    fn build_message_single_recipient_bytes() {
        let cfg = SmtpConfig::new("smtp.example.test", 25, "", "", "sender@example.test", "NONE");
        let message = build_message(&cfg, &["rcpt1@example.test"], "unit test subject", "body line 1\r\nbody line 2")
            .unwrap();

        // 与上游一致:逐字节锁定 From/To/Subject/MIME 头、空行分隔与正文。
        // 差异(文档已注明):lettre 额外带 Content-Transfer-Encoding,
        // charset 小写,正文末尾不再补 CRLF。
        assert_eq!(
            formatted_without_date(&message),
            "From: sender@example.test\r\n\
             To: rcpt1@example.test\r\n\
             Subject: unit test subject\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: 7bit\r\n\
             \r\n\
             body line 1\r\nbody line 2",
        );
    }

    #[test]
    fn build_message_multiple_recipients_joined_by_comma() {
        let cfg = SmtpConfig::new("smtp.example.test", 25, "", "", "noreply@example.test", "NONE");
        let message = build_message(
            &cfg,
            &["rcpt1@example.test", "rcpt2@example.test", "rcpt3@example.test"],
            "multi subject",
            "multi body",
        )
        .unwrap();

        assert_eq!(
            formatted_without_date(&message),
            "From: noreply@example.test\r\n\
             To: rcpt1@example.test, rcpt2@example.test, rcpt3@example.test\r\n\
             Subject: multi subject\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: 7bit\r\n\
             \r\n\
             multi body",
        );
    }

    #[test]
    fn build_message_empty_fields_still_emit_every_header_line() {
        // 上游断言空字段也逐条发出头行。lettre 要求 From 必须是合法地址
        // (空 From 场景收紧为报错,见 sender_mailbox 文档),这里保留
        // 空 Subject / 空正文的头部齐备性断言。
        let cfg = SmtpConfig::new("smtp.example.test", 25, "", "", "sender@example.test", "NONE");
        let message = build_message(&cfg, &["rcpt@example.test"], "", "").unwrap();

        assert_eq!(
            formatted_without_date(&message),
            "From: sender@example.test\r\n\
             To: rcpt@example.test\r\n\
             Subject: \r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: 7bit\r\n\
             \r\n\
             ",
        );
    }

    #[test]
    fn build_message_cjk_subject_is_rfc2047_encoded() {
        // 上游把非 ASCII 主题裸写进头部(依赖服务端容忍);lettre 按
        // RFC 2047 编码——语义升级,裸中文毁头部的隐患被消除。
        let cfg = SmtpConfig::new("smtp.example.test", 25, "", "", "sender@example.test", "NONE");
        let message = build_message(&cfg, &["rcpt@example.test"], "单元测试主题", "正文").unwrap();
        let formatted = String::from_utf8(message.formatted()).unwrap();

        assert!(formatted.contains("Subject: =?utf-8?"), "非 ASCII 主题必须走 RFC 2047 编码");
        assert!(!formatted.contains("Subject: 单元测试主题"), "主题不允许裸写");
        // 非 ASCII 正文自动带上非 7bit 的传输编码
        assert!(formatted.contains("Content-Transfer-Encoding: quoted-printable\r\n")
            || formatted.contains("Content-Transfer-Encoding: base64\r\n"));
    }

    // ------------------------------------------------------------------
    // 发件人显示名与 From 回退(对应上游 TestSendMail_FromNameHeader
    // 与明文会话测试里的 from 回退分支)
    // ------------------------------------------------------------------

    #[test]
    fn from_name_with_space_is_quoted_in_from_header() {
        // 带空格的显示名按 RFC 5322 加引号——收件客户端照样显示为 GoWind Shop。
        let cfg = SmtpConfig::new("smtp.example.test", 465, "", "", "noreply@example.test", "SSL")
            .with_from_name("GoWind Shop");
        let message = build_message(&cfg, &["to@example.test"], "s", "b").unwrap();
        let formatted = String::from_utf8(message.formatted()).unwrap();

        assert!(
            formatted.contains("From: \"GoWind Shop\" <noreply@example.test>\r\n"),
            "实际头部: {formatted:?}"
        );
    }

    #[test]
    fn from_name_non_ascii_is_rfc2047_encoded() {
        let cfg = SmtpConfig::new("smtp.example.test", 465, "", "", "noreply@example.test", "SSL")
            .with_from_name("风行商店");
        let message = build_message(&cfg, &["to@example.test"], "s", "b").unwrap();
        let formatted = String::from_utf8(message.formatted()).unwrap();

        assert!(
            formatted.contains("From: =?utf-8?"),
            "非 ASCII 名称必须走 RFC 2047 编码,裸中文会毁掉整个头"
        );
        assert!(formatted.contains("<noreply@example.test>"));
    }

    #[test]
    fn from_name_empty_keeps_bare_address() {
        // FromName 为空时 From 头保持裸地址,与既有对端的解析习惯逐字节兼容。
        let cfg = SmtpConfig::new("smtp.example.test", 25, "", "", "noreply@example.test", "NONE");
        let message = build_message(&cfg, &["to@example.test"], "s", "b").unwrap();
        let formatted = String::from_utf8(message.formatted()).unwrap();

        assert!(formatted.contains("From: noreply@example.test\r\n"));
    }

    #[test]
    fn from_falls_back_to_username() {
        // 对应上游"From/Username 皆空时回退"的显式 From 用例:From 空时
        // 回退为 Username。
        let cfg = SmtpConfig::new("smtp.example.test", 25, "fallback@example.test", "", "", "NONE");
        let mailbox = cfg.sender_mailbox().unwrap();
        assert_eq!(mailbox.email.to_string(), "fallback@example.test");
        assert!(mailbox.name.is_none());

        let message = build_message(&cfg, &["to@example.test"], "s", "b").unwrap();
        let formatted = String::from_utf8(message.formatted()).unwrap();
        assert!(formatted.contains("From: fallback@example.test\r\n"));
    }

    #[test]
    fn from_and_username_both_empty_is_rejected() {
        // Go 版此场景发空 From 头;lettre 需要合法地址,收紧为显式报错。
        let cfg = SmtpConfig::new("smtp.example.test", 25, "", "", "", "NONE");
        let err = cfg.sender_mailbox().unwrap_err();
        assert_eq!(err, "sender address is empty");
    }

    #[test]
    fn from_is_trimmed() {
        // 对应 Go 版 strings.TrimSpace(cfg.From)
        let cfg = SmtpConfig::new("smtp.example.test", 25, "", "", "  sender@example.test  ", "NONE");
        let mailbox = cfg.sender_mailbox().unwrap();
        assert_eq!(mailbox.email.to_string(), "sender@example.test");
    }

    // ------------------------------------------------------------------
    // TLS 模式判定(对应上游 TestIsSupportedTlsMode)
    // ------------------------------------------------------------------

    #[test]
    fn is_supported_tls_mode_matches_go_semantics() {
        for mode in ["", "NONE", "none", "START_TLS", "SSL", "ssl"] {
            assert!(is_supported_tls_mode(mode), "{mode:?} 应被识别");
        }
        // 尤其 SSL_TLS:演示数据/手工改库留下的值,判错会让配置问题伪装成投递失败。
        // 注意 STARTTLS(无下划线)在上游同样不被识别。
        for mode in ["SSL_TLS", "TLS", "STARTTLS", "QUANTUM"] {
            assert!(!is_supported_tls_mode(mode), "{mode:?} 不该被识别");
        }
    }

    #[test]
    fn parse_tls_mode_is_case_insensitive() {
        assert_eq!(parse_tls_mode("SsL"), TlsModeKind::Implicit);
        assert_eq!(parse_tls_mode("Start_Tls"), TlsModeKind::Plaintext);
        assert_eq!(parse_tls_mode("NoNe"), TlsModeKind::Plaintext);
        assert_eq!(parse_tls_mode("ssl_tls"), TlsModeKind::Unrecognized);
    }

    // ------------------------------------------------------------------
    // SendMail 本地校验错误,不依赖网络(对应上游 TestSendMail_InvalidConfig)
    // ------------------------------------------------------------------

    #[test]
    fn send_mail_invalid_config() {
        let cases: &[(&str, SmtpConfig, &[&str], &str)] = &[
            (
                "empty host",
                SmtpConfig::new("", 25, "", "", "", "NONE"),
                &["rcpt@example.test"],
                "smtp host/port is not configured",
            ),
            (
                "zero port",
                SmtpConfig::new("127.0.0.1", 0, "", "", "", "NONE"),
                &["rcpt@example.test"],
                "smtp host/port is not configured",
            ),
            (
                "empty recipient list",
                SmtpConfig::new("127.0.0.1", 25, "", "", "", "NONE"),
                &[],
                "recipient is empty",
            ),
            (
                "unknown tls mode",
                // Rust 版在组包阶段就要求合法发件人地址(先于 TLS 模式判定),
                // 故这里带有效 From;Go 版同场景 From 为空也不影响该错误分支。
                SmtpConfig::new("127.0.0.1", 25, "", "", "sender@example.test", "QUANTUM"),
                &["rcpt@example.test"],
                "unsupported tls mode: QUANTUM",
            ),
        ];

        for (name, cfg, to, want) in cases {
            let err = send_mail(cfg, to, "subject", "body").unwrap_err();
            assert_eq!(err, *want, "用例 {name:?} 的错误文案必须逐字一致");
        }
    }

    #[test]
    fn send_mail_invalid_recipient_address_is_rejected_before_dialing() {
        // Go 版不解析收件人地址;lettre 在组包阶段就会把非法地址判出来,
        // 同样发生在拨号之前。
        let cfg = SmtpConfig::new("127.0.0.1", 25, "", "", "sender@example.test", "NONE");
        let err = send_mail(&cfg, &["not-an-address"], "subject", "body").unwrap_err();
        assert!(err.starts_with("invalid recipient address"), "实际错误: {err}");
    }

    // ------------------------------------------------------------------
    // transport 装配(替代上游 closedPort 四模式矩阵中可离线化的部分:
    // 四种合法模式都能完成配置装配,非法模式在装配期即拒绝;真实拨号
    // 失败与会话拒绝分支依赖 mock SMTP,不在移植范围)
    // ------------------------------------------------------------------

    #[test]
    fn build_transport_accepts_all_supported_modes() {
        for mode in ["NONE", "", "START_TLS", "none", "ssl", "SSL"] {
            let cfg = SmtpConfig::new("smtp.example.test", 25, "user", "pw", "sender@example.test", mode);
            assert!(build_transport(&cfg).is_ok(), "模式 {mode:?} 应能装配 transport");
        }
    }

    #[test]
    fn build_transport_rejects_unsupported_mode() {
        let cfg = SmtpConfig::new("smtp.example.test", 25, "", "", "sender@example.test", "SSL_TLS");
        let err = build_transport(&cfg).unwrap_err();
        assert_eq!(err, "unsupported tls mode: SSL_TLS");
    }

    #[test]
    fn smtp_config_defaults_match_go_zero_value() {
        // Go 的零值 Port=0 在 SendMail 里视为未配置;Rust 的 Default 同样如此。
        let cfg = SmtpConfig::default();
        assert_eq!(cfg.port, 0);
        assert_eq!(cfg.host, "");
        assert!(!is_supported_tls_mode(&cfg.tls_mode) || cfg.tls_mode.is_empty());
        let err = send_mail(&cfg, &["rcpt@example.test"], "s", "b").unwrap_err();
        assert_eq!(err, "smtp host/port is not configured");
    }
}
