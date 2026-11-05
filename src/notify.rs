//! 多渠道通知投递的统一抽象:`Service` 接口 + 渠道注册表 + SSRF 防线。
//!
//! 这里只管"怎么发":给定一个已经解析好的渠道配置(构造渠道时注入)和一条
//! 正文就绪的 [`Message`],把消息发出去并拿回执。渠道配置从哪里来
//! (数据库/环境变量)、失败怎么记账、要不要重试,都不归本包——那是调用方的编排层。
//!
//! 出站 HTTP 一律走 [`new_client`] 构造的 SSRF 守卫客户端:解析发生在本进程,
//! 拦网也发生在连接之前,"校验的地址"与"连接的地址"是同一批(防 DNS 重绑定)。
//!
//! 各渠道实现在 `notify` 子模块(每渠道一个,`Service` 实现见各自文档)。
//!
//! ```
//! use rust_utils::notify::{Message, Registry};
//!
//! let mut registry = Registry::new();
//! // (渠道装配示例见各渠道子模块;这里演示注册表与消息构造)
//! let msg = Message::new("https://target.example.com/callback", "部署完成")
//!     .with_content("main 分支已发布")
//!     .with_param("env", "production");
//! assert_eq!(msg.content, "main 分支已发布");
//! assert!(registry.service("webhook").is_none());
//! ```

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, OnceLock};

// ---------------------------------------------------------------------------
// 渠道子模块
// ---------------------------------------------------------------------------

pub mod bark;
pub mod datadog;
pub mod discord;
pub mod dingtalk;
pub mod email;
pub mod feishu;
pub mod gchat;
pub mod getui;
pub mod gotify;
pub mod homeassistant;
pub mod huaweisms;
pub mod ifttt;
pub mod join;
pub mod jpush;
pub mod line;
pub mod mailgun;
pub mod matrix;
pub mod mattermost;
pub mod ntfy;
pub mod opsgenie;
pub mod pagerduty;
pub mod postmark;
pub mod push;
pub mod pushbullet;
pub mod pushdeer;
pub mod pushover;
pub mod rocketchat;
pub mod sendgrid;
pub mod serverchan;
pub mod slack;
pub mod sms;
pub mod teams;
pub mod telegram;
pub mod twilio;
pub mod vonage;
pub mod webhook;
pub mod webex;
pub mod wechat;
pub mod wecom;
pub mod whatsapp;
pub mod wxpusher;
pub mod yunpian;
pub mod zulip;

// ---------------------------------------------------------------------------
// 错误哨兵
// ---------------------------------------------------------------------------

/// 通知投递错误。对齐上游三个哨兵 + 投递失败:
///
/// 调用方的台账要能区分两种失败——
/// "没尝试过投递"([`NotifyError::NotConfigured`]:配置问题,重试也不会变好,SKIPPED)
/// 与"投递被拒"([`NotifyError::Delivery`]:拨过号/递过单,对端说了不,FAILED)。
/// 实现准则:凡是发生在联系对端**之前**的拒绝,一律 [`NotifyError::NotConfigured`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyError {
    /// 渠道不可用:没配 / 配错 / 停用 / 目标不合法等"一次都没联系到对端"的失败。
    NotConfigured(String),
    /// 厂商侧明确判定的收件令牌失效(设备令牌/regId/别名等;APNs 410、FCM
    /// 404/410、JPush 1011 等都归到这里)。失效令牌重试没有意义,调用方应删行自清理。
    InvalidToken(String),
    /// SSRF 防线主动拒绝:目标地址不合法(拦网发生在拨号之前,从未联系对端)。
    BlockedTarget(String),
    /// 投递失败:传输错误或对端拒绝。已拨过号,重试由调用方决定。
    Delivery(String),
}

impl NotifyError {
    /// 是否"未配置/未尝试"类失败(SKIPPED)。
    pub fn is_not_configured(&self) -> bool {
        matches!(self, NotifyError::NotConfigured(_))
    }

    /// 是否收件令牌失效(应清理而非重试)。
    pub fn is_invalid_token(&self) -> bool {
        matches!(self, NotifyError::InvalidToken(_))
    }

    /// 是否被 SSRF 防线拦截。
    pub fn is_blocked_target(&self) -> bool {
        matches!(self, NotifyError::BlockedTarget(_))
    }
}

impl fmt::Display for NotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotifyError::NotConfigured(m) => {
                write!(f, "notification channel is not configured: {m}")
            }
            NotifyError::InvalidToken(m) => write!(
                f,
                "notification target token is invalid or unregistered: {m}"
            ),
            NotifyError::BlockedTarget(m) => {
                write!(f, "notification target blocked by the ssrf guard: {m}")
            }
            NotifyError::Delivery(m) => write!(f, "delivery failed: {m}"),
        }
    }
}

impl std::error::Error for NotifyError {}

// ---------------------------------------------------------------------------
// 消息与回执
// ---------------------------------------------------------------------------

/// 一次投递意图。不含模板与路由:正文由调用方备好;发给谁、怎么记账也是调用方的事。
#[derive(Debug, Clone, Default)]
pub struct Message {
    /// 投递目标,按渠道解释:email 为收件地址,sms 为手机号,webhook 为回调 URL。
    pub target: String,
    /// 通知标题(邮件为 Subject;短信等无标题渠道忽略)。
    pub title: String,
    /// 通知正文。
    pub content: String,
    /// 渠道原生参数,按渠道解释(短信模板参数 / webhook 模板占位符等)。
    pub params: HashMap<String, String>,
}

impl Message {
    /// 构造一条消息。
    pub fn new(target: impl Into<String>, title: impl Into<String>) -> Self {
        Message {
            target: target.into(),
            title: title.into(),
            content: String::new(),
            params: HashMap::new(),
        }
    }

    /// 设置正文。
    pub fn with_content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// 设置渠道原生参数。
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }
}

/// 渠道回执。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Receipt {
    /// 服务商侧的消息/请求 ID(阿里云 RequestId、腾讯云 SerialNo 等),
    /// 拿得到就带,方便对账;多数渠道没有就留空。
    pub provider_id: String,
}

/// 一种投递渠道。构造时持有自己的配置,`send` 只管发。
///
/// 返回 [`NotifyError`] 即视为投递失败;配置类失败必须用
/// `NotifyError::NotConfigured`(见其注释)。同步设计:上游的
/// `context.Context` 取消传播在本 crate 的阻塞式 API 里不存在。
pub trait Service: Send + Sync {
    /// 渠道名("email" / "webhook" / "sms:aliyun" 等),供注册表与路由分派。
    fn name(&self) -> &str;
    /// 投递一条消息。
    fn send(&self, msg: &Message) -> Result<Receipt, NotifyError>;
}

// ---------------------------------------------------------------------------
// 注册表
// ---------------------------------------------------------------------------

/// 渠道注册表:按 [`Service::name`] 注册与取用。
///
/// [`Registry::register`] 覆盖同名旧实现:装配期一次性写入,运行期只读。
#[derive(Default)]
pub struct Registry {
    services: HashMap<String, Arc<dyn Service>>,
}

impl Registry {
    /// 空注册表。
    pub fn new() -> Self {
        Registry::default()
    }

    /// 注册(或覆盖同名)渠道。
    pub fn register(&mut self, service: impl Service + 'static) {
        self.services
            .insert(service.name().to_string(), Arc::new(service));
    }

    /// 注册已装箱的渠道。
    pub fn register_arc(&mut self, service: Arc<dyn Service>) {
        self.services.insert(service.name().to_string(), service);
    }

    /// 取渠道实现;未注册返回 `None`。
    pub fn service(&self, name: &str) -> Option<Arc<dyn Service>> {
        self.services.get(name).cloned()
    }
}

// ---------------------------------------------------------------------------
// SSRF 防线
// ---------------------------------------------------------------------------

/// 单次出站请求的总超时(拨号 + 写请求 + 读响应)。
/// 出站这件事不需要每个渠道各定一个数,10s 是个对人对己都体面的默认。
pub const GUARDED_CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// 拨号阶段上限(掐在 TCP 握手,不影响慢但对端活着的响应)。
pub const GUARDED_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// 放行内网/环回地址的环境变量名,仅供本机联调。
/// 值 "1" 时整条 SSRF 防线关闭(连环回都能发),生产部署不得设置。
pub const ENV_ALLOW_PRIVATE_TARGET: &str = "NOTIFY_ALLOW_PRIVATE_TARGET";

/// 读环境变量决定要不要关掉 SSRF 防线。
/// 只认精确的 "1":真值判断会让 "false"、"0" 之外的垃圾值也放行,
/// 而这一条开关放行的内容是"本进程可向内网任意地址发请求"。
pub fn allow_private_target() -> bool {
    std::env::var(ENV_ALLOW_PRIVATE_TARGET).as_deref() == Ok("1")
}

/// SSRF 拦网的地址段。
///
/// 为什么是一张显式 CIDR 表而不是一组 `is_loopback`/`is_private` 布尔判断:
/// 布尔法会漏掉 100.64.0.0/10(CGNAT,常见语言的 IsPrivate 只认 RFC1918 三段),
/// 而这张表里每一项都是"本进程真能打到东西"的段:环回、RFC1918、CGNAT、
/// 链路本地(含 169.254.169.254 这块云元数据端点)、组播与保留段。
/// 表还有一个好处:想知道防线是什么,读这一处就够,不必在脑内合成五个布尔判断的并集。
const BLOCKED_NETS: &[(&str, u8)] = &[
    ("0.0.0.0", 8),      // "本网络":部分实现把 0.x 当本地
    ("10.0.0.0", 8),     // RFC1918
    ("100.64.0.0", 10),  // CGNAT:K8s 服务网段常落在这里
    ("127.0.0.0", 8),    // 环回
    ("169.254.0.0", 16), // 链路本地 + 云厂商元数据端点
    ("172.16.0.0", 12),  // RFC1918
    ("192.0.0.0", 24),   // IETF 协议保留
    ("192.168.0.0", 16), // RFC1918
    ("198.18.0.0", 15),  // 基准测试段
    ("224.0.0.0", 4),    // 组播
    ("240.0.0.0", 4),    // 保留
    ("::1", 128),        // IPv6 环回
    ("fc00::", 7),       // IPv6 ULA
    ("fe80::", 10),      // IPv6 链路本地
];

fn blocked_nets() -> &'static Vec<(IpAddr, u8)> {
    static NETS: OnceLock<Vec<(IpAddr, u8)>> = OnceLock::new();
    NETS.get_or_init(|| {
        BLOCKED_NETS
            .iter()
            .filter_map(|(base, prefix)| base.parse::<IpAddr>().ok().map(|ip| (ip, *prefix)))
            .collect()
    })
}

/// 判断 IP 是否落在 SSRF 拦网段内。
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    blocked_nets()
        .iter()
        .any(|(base, prefix)| cidr_contains(base, ip, *prefix))
}

/// CIDR 包含判断(v4/v6 统一按位比较;v4-mapped v6 不混判)。
fn cidr_contains(base: &IpAddr, ip: IpAddr, prefix: u8) -> bool {
    match (base, ip) {
        (IpAddr::V4(b), IpAddr::V4(i)) => {
            prefix <= 32 && (b.to_bits() >> (32 - prefix)) == (i.to_bits() >> (32 - prefix))
        }
        (IpAddr::V6(b), IpAddr::V6(i)) => {
            prefix <= 128 && (b.to_bits() >> (128 - prefix)) == (i.to_bits() >> (128 - prefix))
        }
        _ => false,
    }
}

/// SSRF 守卫解析器:解析后只放行不在拦网段内的地址。
///
/// 为什么防线在解析/拨号而不是在 URL 校验:校验 hostname 只挡得住字面量
/// (127.0.0.1、169.254.169.254),挡不住 `internal.example.com → 10.0.0.5`
/// 这种指到内网的记录。这里自己解析、只放行合规 IP,于是"校验的地址"
/// 与"连接的地址"是同一批,TOCTOU 的窗口只剩 DNS 重绑定这一种形式,
/// 而解析结果已经决定了连接目标。
pub struct GuardedResolver;

impl ureq::Resolver for GuardedResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let all: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
        let allowed: Vec<SocketAddr> = all
            .into_iter()
            .filter(|a| !is_blocked_ip(a.ip()))
            .collect();
        if allowed.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "target blocked by the ssrf guard",
            ));
        }
        Ok(allowed)
    }
}

/// 造一个"拨号前先把地址过一遍内网拦网"的 HTTP 客户端(供各渠道共用)。
///
/// - 不跟随重定向:Location 指到哪就等于绕过了"调用方指定的这条地址",
///   台账/日志里那行 target 也成了假话。3xx 一律当失败处理。
/// - `allow_private=true`(本机联调)时不安装守卫解析器。
pub fn new_client(allow_private: bool) -> ureq::Agent {
    let builder = ureq::AgentBuilder::new()
        .timeout(GUARDED_CLIENT_TIMEOUT)
        .timeout_connect(GUARDED_DIAL_TIMEOUT)
        .redirects(0);
    if allow_private {
        builder.build()
    } else {
        builder.resolver(GuardedResolver).build()
    }
}

/// 把 ureq 的错误归类为 [`NotifyError`]。
///
/// 守卫解析器的拒绝("ssrf guard" 文案)归 [`NotifyError::BlockedTarget`];
/// 其余传输/HTTP 错误一律 [`NotifyError::Delivery`]。渠道应在发请求前先用
/// [`check_target`] 预检以获得更准确的分类。
pub fn map_ureq_error(err: ureq::Error) -> NotifyError {
    let text = err.to_string();
    if text.contains("ssrf guard") {
        NotifyError::BlockedTarget(text)
    } else {
        NotifyError::Delivery(text)
    }
}

/// 投递前的目标预检:URL 必须是 http/https,且解析出的 IP 全部不在拦网段内
/// (全部被拦才拒绝;部分被拦时客户端守卫会只连合规 IP)。
///
/// 这是给渠道在发请求前归类 [`NotifyError::BlockedTarget`] 用的
/// (客户端守卫的错误经过 ureq 包装,文案匹配是兜底而非首选)。
pub fn check_target(url: &str) -> Result<(), NotifyError> {
    let (scheme, rest) = match url.split_once("://") {
        Some(pair) => pair,
        None => return Err(NotifyError::NotConfigured(format!("invalid url: {url}"))),
    };
    if scheme != "http" && scheme != "https" {
        return Err(NotifyError::NotConfigured(format!(
            "unsupported scheme: {scheme}"
        )));
    }
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    if host.is_empty() {
        return Err(NotifyError::NotConfigured(format!("url has no host: {url}")));
    }
    let addrs: Vec<IpAddr> = (host, 0)
        .to_socket_addrs()
        .map_err(|e| NotifyError::NotConfigured(format!("resolve {host}: {e}")))?
        .map(|a| a.ip())
        .collect();
    if addrs.is_empty() {
        return Err(NotifyError::NotConfigured(format!(
            "resolve {host}: no addresses"
        )));
    }
    if addrs.iter().all(|ip| is_blocked_ip(*ip)) {
        return Err(NotifyError::BlockedTarget(format!(
            "{host} resolves into blocked nets"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyService {
        name: String,
    }
    impl Service for DummyService {
        fn name(&self) -> &str {
            &self.name
        }
        fn send(&self, _msg: &Message) -> Result<Receipt, NotifyError> {
            Err(NotifyError::NotConfigured("dummy".into()))
        }
    }

    #[test]
    fn test_registry() {
        let mut registry = Registry::new();
        registry.register(DummyService {
            name: "webhook".into(),
        });
        assert!(registry.service("webhook").is_some());
        assert!(registry.service("sms").is_none());
        // 覆盖同名旧实现
        registry.register(DummyService {
            name: "webhook".into(),
        });
        assert!(registry.service("webhook").is_some());
        let arc: Arc<dyn Service> = Arc::new(DummyService {
            name: "email".into(),
        });
        registry.register_arc(arc);
        assert_eq!(registry.service("email").unwrap().name(), "email");
    }

    #[test]
    fn test_blocked_nets() {
        // 环回 / RFC1918 / CGNAT / 元数据端点 / IPv6 ULA 全拦
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.9",
            "169.254.169.254",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "{ip} should be blocked");
        }
        // 公网放行
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700::1111"] {
            assert!(!is_blocked_ip(ip.parse().unwrap()), "{ip} should be allowed");
        }
        // 边界:100.63.255.255 不在 CGNAT,100.64.0.0 在
        assert!(!is_blocked_ip("100.63.255.255".parse().unwrap()));
        assert!(is_blocked_ip("100.64.0.0".parse().unwrap()));
        // "本网络"段 0.x
        assert!(is_blocked_ip("0.1.2.3".parse().unwrap()));
    }

    #[test]
    fn test_guarded_resolver() {
        use ureq::Resolver as _;
        let resolver = GuardedResolver;
        // 环回被拦
        assert!(resolver.resolve("127.0.0.1:80").is_err());
        // 公网域名(测试环境无外网时解析失败,跳过断言)
        if let Ok(addrs) = resolver.resolve("one.one.one.one:80") {
            assert!(addrs.iter().all(|a| !is_blocked_ip(a.ip())));
        }
    }

    #[test]
    fn test_check_target_classification() {
        // 环回目标 → BlockedTarget
        let err = check_target("http://127.0.0.1:8080/hook").unwrap_err();
        assert!(err.is_blocked_target());
        // 非法 scheme / 无 scheme → NotConfigured
        let err = check_target("ftp://example.com/x").unwrap_err();
        assert!(err.is_not_configured());
        let err = check_target("example.com").unwrap_err();
        assert!(err.is_not_configured());
        // 公网目标(可解析时)放行;解析失败 → NotConfigured
        match check_target("https://one.one.one.one/") {
            Ok(()) => {}
            Err(e) => assert!(e.is_not_configured()),
        }
    }

    #[test]
    fn test_error_sentinels_and_message() {
        let e = NotifyError::NotConfigured("x".into());
        assert!(e.is_not_configured());
        assert!(!e.is_invalid_token());
        assert!(!e.is_blocked_target());
        assert!(NotifyError::InvalidToken("x".into()).is_invalid_token());
        assert!(NotifyError::BlockedTarget("x".into()).is_blocked_target());
        assert!(NotifyError::Delivery("x".into()).to_string().contains("delivery failed"));

        let msg = Message::new("t", "title")
            .with_content("c")
            .with_param("k", "v");
        assert_eq!(msg.target, "t");
        assert_eq!(msg.title, "title");
        assert_eq!(msg.params.get("k").map(String::as_str), Some("v"));
    }
}
