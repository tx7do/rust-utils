//! 网络安全工具:SSRF 防护与防 XFF 伪造的客户端真实 IP 解析。
//!
//! 移植自 Go 库 `tx7do/go-utils/netutil`(client_ip.go + ssrf.go),协议逐式复刻:
//!
//! - **SSRF 防护**:[`validate_url`] 对入口 URL 做静态校验(仅 http/https、拒绝
//!   userinfo、要求 host 非空),[`lookup_and_check_host`] 解析域名后对每个 IP 逐个
//!   过黑名单网段(私有/回环/链路本地/云元数据 169.254.169.254/CGNAT 等),
//!   任一 IP 命中即拒绝,防止借助服务端向内网或元数据服务发起请求;
//! - **客户端真实 IP**:[`client_ip_from_request`] 仅当直连对端(RemoteAddr)属于
//!   可信代理网段时,才从 `X-Forwarded-For` 链"从右向左"跳过可信跳,取第一个非可信
//!   IP 作为客户端 IP;否则一律使用对端 IP,防止攻击者伪造 XFF 绕过限流/审计。
//!
//! 与 Go 版的差异(适配零依赖纯 `std`):
//!
//! 1. 无 HTTP 框架依赖:`client_ip_from_request` 接受最小输入结构
//!    [`RequestInfo`](header 键约定小写存取),入参 `Option<&RequestInfo>` 对应 Go
//!    的 nil `*http.Request`(返回空串);
//! 2. 全局可信代理表用 `OnceLock` + `RwLock` 实现,默认网段清单与 Go 完全一致。
//!    Go 的 `sync.Once` 存在"首次请求会用默认清单覆盖更早 `SetTrustedProxies`"的
//!    顺序耦合,Rust 版不保留该缺陷:`set_trusted_proxies` 之后始终生效;
//! 3. 无 `cidr` crate:CIDR 解析与匹配基于 `Ipv4Addr`/`Ipv6Addr` 手写,IPv4-mapped
//!    IPv6(如 `::ffff:10.1.2.3`)对 IPv4 网段的匹配行为与 Go `IPNet.Contains` 一致;
//! 4. Go `LookupAndCheckHost` 的 `ctx` 超时参数去掉:DNS 走 `std` 的
//!    `ToSocketAddrs`,阻塞式且无超时控制,调用方需自行约束并发与时长;
//! 5. 无 `url` crate:`validate_url` 内置最小 `scheme://host:port` 解析,只服务
//!    SSRF 校验用途,不支持 Go `url.URL` 的全量语义(百分号解码、zone-id、路径/
//!    query 回传等均不提供);端口数值超界(>65535)直接判非法(Go 解析阶段放行);
//!    成功时返回 [`ValidatedUrl`](scheme/host/port/IP 字面量信息)。
//!
//! ```
//! use rust_utils::netutil;
//! use std::collections::HashMap;
//!
//! // 1. SSRF 静态校验:仅接受 http/https,拒绝其它 scheme 与 userinfo
//! let u = netutil::validate_url("http://example.com:8080/api").unwrap();
//! assert_eq!(u.scheme, "http");
//! assert_eq!(u.host, "example.com");
//! assert_eq!(u.port, Some(8080));
//! assert!(netutil::validate_url("gopher://localhost").is_err());
//!
//! // 2. IP 黑名单:回环/内网/云元数据一律拦截
//! assert!(netutil::is_blocked_ip("169.254.169.254"));
//! assert!(netutil::is_blocked_ip("127.0.0.1"));
//! assert!(!netutil::is_blocked_ip("8.8.8.8"));
//!
//! // 3. 客户端真实 IP:对端非可信代理时忽略一切转发头(防伪造)
//! let mut headers = HashMap::new();
//! headers.insert("x-forwarded-for".to_string(), "203.0.113.7".to_string());
//! let req = netutil::RequestInfo {
//!     remote_addr: "8.8.8.8:12345".to_string(),
//!     headers,
//! };
//! assert_eq!(netutil::client_ip_from_request(Some(&req)), "8.8.8.8");
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{OnceLock, RwLock};

// 客户端真实 IP 相关的请求头(存储/查找约定小写)。
const HEADER_X_FORWARDED_FOR: &str = "x-forwarded-for";
const HEADER_X_REAL_IP: &str = "x-real-ip";

// ============================================================================
// 请求抽象(Go *http.Request 的最小替身)
// ============================================================================

/// HTTP 请求的最小输入结构,替代 Go 的 `*http.Request`。
///
/// 字段语义与 `http.Request` 同构:
/// - `remote_addr` 形如 `"host:port"`(IPv6 带方括号,如 `"[::1]:8080"`),
///   也可为无端口的裸 host;
/// - `headers` 的键**约定小写存储**(与 HTTP/2 头字段名规范一致),
///   [`RequestInfo::get_header`] 查找时自动把键转小写,故传入 `"X-Forwarded-For"`
///   与 `"x-forwarded-for"` 等价。多值头只保留第一值语义(对应 Go `Header.Get`)。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RequestInfo {
    /// 直连对端地址(TCP 连接的真实来源)。
    pub remote_addr: String,
    /// 请求头,键约定小写存储。
    pub headers: HashMap<String, String>,
}

impl RequestInfo {
    /// 以给定的直连对端地址构造请求(无任何转发头)。
    pub fn new(remote_addr: impl Into<String>) -> Self {
        Self {
            remote_addr: remote_addr.into(),
            headers: HashMap::new(),
        }
    }

    /// 追加一个请求头(键转为小写存储),支持链式调用。
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.to_ascii_lowercase(), value.into());
        self
    }

    /// 按小写键读取请求头(对应 Go `Header.Get`,缺失返回 `None`)。
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

// ============================================================================
// 可信代理配置(防 XFF 伪造绕过限流/审计)
//
// 默认信任常见内网代理网段。当请求的直连对端(RemoteAddr)属于可信代理时,
// 才从 X-Forwarded-For 链中"从右向左"跳过可信跳,取第一个非可信 IP 作为客户端
// 真实 IP;否则一律使用 RemoteAddr,避免攻击者通过伪造 XFF 头绕过基于 IP 的
// 限流/审计。
//
// 部署时通过 [`set_trusted_proxies`] 用实际的反向代理网段覆盖默认值。
// ============================================================================

/// 默认可信代理网段(RFC1918 私有地址 + 回环)。
/// 生产部署应通过 [`set_trusted_proxies`] 精确指定实际反向代理网段。
fn default_trusted_proxy_cidrs() -> &'static [&'static str] {
    &[
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fc00::/7",
    ]
}

/// 全局可信代理表:进程级单例,首次访问时惰性装载默认清单。
static TRUSTED_PROXIES: OnceLock<RwLock<Vec<IpNet>>> = OnceLock::new();

fn trusted_cell() -> &'static RwLock<Vec<IpNet>> {
    TRUSTED_PROXIES.get_or_init(|| {
        RwLock::new(parse_trusted_cidrs(default_trusted_proxy_cidrs()))
    })
}

/// 解析可信代理配置清单,对应 Go `setTrustedProxiesLocked` 的规则:
/// 合法 CIDR 生效、首尾空白被裁剪、裸 IP 按单地址(`/32` 或 `/128`)生效、
/// 空串/纯空白/非法 IP/非法 CIDR 条目被跳过且不影响其余条目。
fn parse_trusted_cidrs(cidrs: &[&str]) -> Vec<IpNet> {
    let mut nets = Vec::with_capacity(cidrs.len());
    for c in cidrs {
        let c = c.trim();
        if c.is_empty() {
            continue;
        }
        // 允许不带掩码的单 IP(按 /32 或 /128 处理)
        let entry = if c.contains('/') {
            c.to_string()
        } else {
            match c.parse::<IpAddr>() {
                Ok(ip) if ip.is_ipv4() => format!("{ip}/32"),
                Ok(ip) => format!("{ip}/128"),
                // 非法 IP 条目:跳过并忽略
                Err(_) => continue,
            }
        };
        // 非法 CIDR 条目:跳过并忽略
        if let Some(n) = parse_cidr(&entry) {
            nets.push(n);
        }
    }
    nets
}

/// 设置可信代理 CIDR 列表(覆盖默认值)。
///
/// 应在服务启动阶段(main)调用一次。传入空切片表示不信任任何代理
/// (始终用 RemoteAddr)。非法 CIDR 会被跳过并忽略。
///
/// ```
/// use rust_utils::netutil;
///
/// // 只信任实际部署的反向代理网段;裸 IP 按单地址(/32 或 /128)生效
/// netutil::set_trusted_proxies(&["172.16.0.0/12", "10.1.2.3", "::1"]);
/// // 不信任任何代理:
/// netutil::set_trusted_proxies(&[]);
/// ```
pub fn set_trusted_proxies(cidrs: &[&str]) {
    let nets = parse_trusted_cidrs(cidrs);
    let mut guard = trusted_cell().write().unwrap_or_else(|e| e.into_inner());
    *guard = nets;
}

/// 判断 IP 是否属于可信代理网段。
fn is_trusted_proxy(ip: &IpAddr) -> bool {
    let guard = trusted_cell().read().unwrap_or_else(|e| e.into_inner());
    guard.iter().any(|n| n.contains(ip))
}

/// 从请求中解析客户端真实 IP(对应 Go `ClientIPFromRequest`)。
///
/// 解析策略(防 XFF 伪造):
/// 1. 取 `remote_addr` 的直连对端 IP;
/// 2. 若对端 IP 不是可信代理 → 直接返回对端 IP,完全忽略 XFF(防止伪造);
/// 3. 若对端 IP 是可信代理 → 从 `X-Forwarded-For` 链"从右向左"跳过可信跳,
///    第一个非可信 IP 即为客户端真实 IP;若整条链都是可信跳,取最左侧 IP;
/// 4. XFF 为空或全部非法 → 采信 `X-Real-IP`(仅在对端为可信代理时才采信,
///    且优先级低于 XFF 链解析);
/// 5. 兜底:对端 IP(可信代理本身,如直连 nginx)。
///
/// `req` 为 `None` 对应 Go 的 nil `*http.Request`,返回空串。
///
/// ```
/// use rust_utils::netutil::{self, RequestInfo};
///
/// netutil::set_trusted_proxies(&["10.0.0.0/8"]);
/// // 对端是可信代理 → 从 XFF 链从右向左解析,跳过可信跳 10.0.0.9
/// let req = RequestInfo::new("10.0.0.2:443")
///     .with_header("x-forwarded-for", "203.0.113.7, 10.0.0.9");
/// assert_eq!(netutil::client_ip_from_request(Some(&req)), "203.0.113.7");
/// ```
pub fn client_ip_from_request(req: Option<&RequestInfo>) -> String {
    let Some(req) = req else {
        return String::new();
    };

    // 1. 直连对端 IP(TCP 连接的真实来源,无法伪造)
    let peer_ip = ip_from_remote_addr(&req.remote_addr);
    let peer = peer_ip.parse::<IpAddr>().ok();

    // 2. 对端非可信代理(含解析失败)→ 不信任任何转发头,直接用对端 IP
    if !peer.is_some_and(|p| is_trusted_proxy(&p)) {
        return peer_ip;
    }

    // 3. 对端是可信代理 → 从 XFF 链从右向左解析
    if let Some(xff) = req
        .get_header(HEADER_X_FORWARDED_FOR)
        .filter(|v| !v.is_empty())
    {
        let ips = split_and_trim(xff);
        // 从右向左跳过可信跳,第一个非可信 IP 即客户端;
        // 整条链都是可信跳时,循环到最后(i == 0)即使可信也返回最左侧
        for (i, ip_str) in ips.iter().enumerate().rev() {
            let Ok(ip) = ip_str.parse::<IpAddr>() else {
                // 非法条目:跳过,继续向左
                continue;
            };
            if !is_trusted_proxy(&ip) {
                return ip_str.clone();
            }
            if i == 0 {
                return ip_str.clone();
            }
        }
    }

    // 4. XFF 为空或全部非法 → 采信 X-Real-IP(仅在可信代理前提下)
    if let Some(xri) = req.get_header(HEADER_X_REAL_IP).filter(|v| !v.is_empty()) {
        let trimmed = xri.trim();
        if trimmed.parse::<IpAddr>().is_ok() {
            return trimmed.to_string();
        }
    }

    // 5. 兜底:对端 IP(可信代理本身,如直连 nginx)
    peer_ip
}

/// 按逗号切分并去空格,过滤空串(对应 Go `splitAndTrim`)。
fn split_and_trim(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

/// 从 `remote_addr`(`host:port` 形态)中提取 host(对应 Go `ipFromRemoteAddr`)。
fn ip_from_remote_addr(remote_addr: &str) -> String {
    if remote_addr.is_empty() {
        return String::new();
    }
    // 处理可能无端口的情形
    if !remote_addr.contains(':') {
        return remote_addr.to_string();
    }
    match split_host_port(remote_addr.trim()) {
        // Go 源码中 ParseIP 成败两支均返回 host,此处直接返回拆分结果
        Some((host, _port)) => host,
        // 拆分失败(未加方括号的 IPv6、非法端口等)→ 原样返回 Go 返回未 trim 的原始串)
        None => remote_addr.to_string(),
    }
}

/// 拆分 `host:port`(Go `net.SplitHostPort` 的行为子集,本模块够用)。
///
/// 规则:端口在最后一个冒号之后;方括号 IPv6 必须写成 `"[::1]:8080"` 形式
/// (host 去掉方括号返回);未加方括号的 IPv6(多冒号)与非法端口(非全数字)
/// 均返回 `None`;空端口(`"host:"`)合法。
fn split_host_port(addr: &str) -> Option<(String, String)> {
    // 端口在最后一个冒号之后;无冒号 → 缺端口
    let i = addr.rfind(':')?;
    let (host, port) = if addr.starts_with('[') {
        // 方括号 IPv6:']' 必须紧邻最后的冒号("…]:port")
        let end = addr.find(']')?;
        if end + 1 != i {
            return None; // ']' 之后除端口外还有内容(Go: too many colons)
        }
        // ']' 之前若还有 ':' 落在最后一个 ']' 之后 → 多余冒号,拒绝
        let before = &addr[..i];
        if let Some(j) = before.rfind(':') {
            if let Some(k) = before.rfind(']') {
                if j > k {
                    return None;
                }
            }
        }
        (addr[1..end].to_string(), addr[end + 2..].to_string())
    } else {
        // 非方括号:只允许一个冒号;多个冒号按未加括号的 IPv6 处理 → 拒绝
        if addr.find(':') != Some(i) {
            return None;
        }
        (addr[..i].to_string(), addr[i + 1..].to_string())
    };
    // 端口须为空或全数字(Go validOptionalPort)
    if !port.is_empty() && !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((host, port))
}

// ============================================================================
// CIDR(Go net.IPNet / net.ParseCIDR 的手写最小实现)
// ============================================================================

/// 单条 CIDR 网段。IPv4 网段存 `u32`,IPv6 网段存 `u128`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpNet {
    /// IPv4 网段:网络地址 + 前缀长度(0..=32)。
    V4 { addr: u32, prefix: u8 },
    /// IPv6 网段:网络地址 + 前缀长度(0..=128)。
    V6 { addr: u128, prefix: u8 },
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// 解析 `"addr/prefix"` 形式的 CIDR。
///
/// 要求恰好一个 `/`,地址为合法 IP 字面量,前缀为不超过地址位长的非负整数;
/// IPv4-mapped IPv6 基址(如 `"::ffff:10.0.0.0/104"`)归一化为等价的 IPv4 网段
/// (对应 Go `networkNumberAndMask` 对 `To4` 的收敛,前缀减 96)。
fn parse_cidr(s: &str) -> Option<IpNet> {
    let (ip_part, prefix_part) = s.split_once('/')?;
    let ip: IpAddr = ip_part.parse().ok()?;
    let prefix: u8 = prefix_part.parse().ok()?;
    match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return None;
            }
            Some(IpNet::V4 {
                addr: u32::from(v4),
                prefix,
            })
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return None;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                Some(IpNet::V4 {
                    addr: u32::from(v4),
                    prefix: prefix.saturating_sub(96),
                })
            } else {
                Some(IpNet::V6 {
                    addr: u128::from(v6),
                    prefix,
                })
            }
        }
    }
}

impl IpNet {
    /// 判断 `ip` 是否落入本网段(对应 Go `IPNet.Contains`)。
    ///
    /// IPv4-mapped IPv6 地址会按对应 IPv4 参与 IPv4 网段匹配;
    /// 地址族不匹配时返回 `false`。
    fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (IpNet::V4 { addr, prefix }, IpAddr::V4(v)) => {
                (u32::from(*v) & v4_mask(*prefix)) == (addr & v4_mask(*prefix))
            }
            (IpNet::V4 { addr, prefix }, IpAddr::V6(v)) => match v.to_ipv4_mapped() {
                Some(v4) => (u32::from(v4) & v4_mask(*prefix)) == (addr & v4_mask(*prefix)),
                None => false,
            },
            (IpNet::V6 { addr, prefix }, IpAddr::V6(v)) => {
                (u128::from(*v) & v6_mask(*prefix)) == (addr & v6_mask(*prefix))
            }
            (IpNet::V6 { .. }, IpAddr::V4(_)) => false,
        }
    }
}

// ============================================================================
// SSRF 防护
// ============================================================================

/// 禁止服务端访问的 IP 范围(私有/回环/链路本地/未指定/多播等)。
/// 用于阻止 SSRF 攻击者借助服务端向内网或元数据服务(如 169.254.169.254)发起请求。
const BLOCKED_CIDRS: &[&str] = &[
    // IPv4
    "0.0.0.0/8",       // 未指定/本网络
    "10.0.0.0/8",      // 私有 A
    "100.64.0.0/10",   // 运营商级 NAT(CGNAT)
    "127.0.0.0/8",     // 回环
    "169.254.0.0/16",  // 链路本地(含 AWS/Azure/IMDS 元数据 169.254.169.254)
    "172.16.0.0/12",   // 私有 B
    "192.0.0.0/24",    // IETF 协议分配
    "192.0.2.0/24",    // TEST-NET-1(文档用)
    "192.168.0.0/16",  // 私有 C
    "198.18.0.0/15",   // 基准测试
    "198.51.100.0/24", // TEST-NET-2
    "203.0.113.0/24",  // TEST-NET-3
    "224.0.0.0/4",     // 多播
    "240.0.0.0/4",     // 保留
    // IPv6
    "::1/128",       // 回环
    "fc00::/7",      // 唯一本地地址(ULA)
    "fe80::/10",     // 链路本地
    "ff00::/8",      // 多播
    "::/128",        // 未指定
    "2001:db8::/32", // 文档用
];

/// 黑名单网段列表:全部为常量,解析一次后缓存。
fn blocked_cidrs() -> &'static [IpNet] {
    static CELL: OnceLock<Vec<IpNet>> = OnceLock::new();
    // 常量清单全部合法,filter_map 仅为防御性兜底(对应 Go 的解析跳过)
    CELL.get_or_init(|| BLOCKED_CIDRS.iter().filter_map(|c| parse_cidr(c)).collect())
}

/// 判断给定 IP 字符串是否落入禁止访问的网段(对应 Go `IsBlockedIP`)。
///
/// 接受 `"10.1.2.3"` 等字符串;首尾空白会被裁剪。无法解析的输入视为非法,
/// 保守判定为禁止(返回 `true`)。
pub fn is_blocked_ip(ip_str: &str) -> bool {
    match ip_str.trim().parse::<IpAddr>() {
        Ok(ip) => is_blocked_ip_addr(ip),
        // 无法解析的 IP 视为非法,保守判定为禁止
        Err(_) => true,
    }
}

/// 同 [`is_blocked_ip`],接受已解析的 `IpAddr` 入参(对应 Go `IsBlockedIPAddr`)。
pub fn is_blocked_ip_addr(ip: IpAddr) -> bool {
    // 未指定地址(0.0.0.0 / ::)
    if ip.is_unspecified() {
        return true;
    }
    // 接口本地多播 ffX1::/16(Go ip.IsInterfaceLocalMulticast)
    if let IpAddr::V6(v6) = &ip {
        let o = v6.octets();
        if o[0] == 0xff && (o[1] & 0x0f) == 0x01 {
            return true;
        }
    }
    blocked_cidrs().iter().any(|n| n.contains(&ip))
}

/// SSRF 校验通过后的 URL 信息(`scheme://host:port` 的最小解析结果)。
///
/// Go 版 `ValidateURL` 返回 `*url.URL`;这里不引入 `url` crate,只保留
/// SSRF 校验与后续建连所需的字段。`host` 为去方括号后的主机(IPv6 字面量、
/// IPv4 字面量或域名,保留原样大小写);`ip` 仅当 host 为 IP 字面量时有值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUrl {
    /// 小写化的 scheme,恒为 `"http"` 或 `"https"`。
    pub scheme: String,
    /// 主机(去方括号,不携带端口;保留原样大小写)。
    pub host: String,
    /// 显式端口;URL 未携带(或端口为空)时为 `None`,不按 scheme 补默认值。
    pub port: Option<u16>,
    /// host 为 IP 字面量时的解析结果;域名时为 `None`(需走 DNS 检查)。
    pub ip: Option<IpAddr>,
}

/// 对 SSRF 入口 URL 做静态校验(对应 Go `ValidateURL`)。
///
/// 规则:scheme 必须(大小写不敏感地)为 `http`/`https`;host 非空;
/// 拒绝携带用户信息(`user:pass@host`)的 URL——常见 SSRF 混淆手法;
/// 解析失败(如缺 scheme、缺 `]`、端口非数字)一律报错。
///
/// 注意:本函数只做静态检查,IP 黑名单由 [`is_blocked_ip`] /
/// [`lookup_and_check_host`] 负责,两者应配合使用。
///
/// ```
/// use rust_utils::netutil::validate_url;
///
/// assert!(validate_url("https://8.8.8.8/").is_ok());
/// assert!(validate_url("file:///etc/passwd").is_err());
/// assert!(validate_url("http://user:pass@example.com/").is_err());
/// ```
pub fn validate_url(raw_url: &str) -> Result<ValidatedUrl, String> {
    if raw_url.is_empty() {
        return Err("empty url".to_string());
    }
    // Go url.Parse 先切掉 #fragment
    let no_frag = match raw_url.split_once('#') {
        Some((u, _)) => u,
        None => raw_url,
    };
    let (scheme, rest) = get_scheme(no_frag)?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme {scheme:?} (only http/https allowed)"));
    }
    // Go 在解析 authority 前先切掉 ?query
    let rest = match rest.split_once('?') {
        Some((r, _)) => r,
        None => rest,
    };
    // authority 必须以 "//" 开头;否则为 opaque URL(Go 语义下 Host 为空)
    let after_slashes = match rest.strip_prefix("//") {
        Some(a) => a,
        None => return Err("missing host".to_string()),
    };
    let authority = match after_slashes.find('/') {
        Some(end) => &after_slashes[..end],
        None => after_slashes,
    };
    // 拒绝携带用户信息(user:pass@host),常见 SSRF 混淆手法
    let has_userinfo = authority.contains('@');
    let host_port = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    if host_port.is_empty() {
        return Err("missing host".to_string());
    }
    let (host, port) = parse_host_port(host_port)?;
    if has_userinfo {
        return Err("userinfo not allowed in url".to_string());
    }
    let ip = host.parse::<IpAddr>().ok();
    Ok(ValidatedUrl {
        scheme,
        host,
        port,
        ip,
    })
}

/// 提取 scheme(对应 Go `getScheme`)。
///
/// scheme 只允许 `[A-Za-z0-9+.-]`;首个非法字符视为无 scheme;
/// 位置 0 处的 `':'` 为畸形输入(Go: missing protocol scheme)。
fn get_scheme(raw: &str) -> Result<(&str, &str), String> {
    for (i, c) in raw.char_indices() {
        match c {
            'a'..='z' | 'A'..='Z' => {}
            '0'..='9' | '+' | '-' | '.' => {
                if i == 0 {
                    // 数字/+/-.开头的不是合法 scheme
                    return Ok(("", raw));
                }
            }
            ':' => {
                if i == 0 {
                    return Err("invalid url: missing protocol scheme".to_string());
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

/// 拆出 host 与端口(对应 Go `parseHost` 的行为子集)。
///
/// IPv6 字面量必须带方括号,返回的 host 去掉方括号;端口须为
/// `":digits"` / `":"`(空端口视为未携带)/ 无端口;其余一律报错。
fn parse_host_port(host_port: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = host_port.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| "invalid url: missing ']' in host".to_string())?;
        let host = rest[..end].to_string();
        let colon_port = &rest[end + 1..];
        let port = parse_optional_port(colon_port)?;
        Ok((host, port))
    } else if let Some(i) = host_port.rfind(':') {
        let host = host_port[..i].to_string();
        let colon_port = &host_port[i..];
        let port = parse_optional_port(colon_port)?;
        Ok((host, port))
    } else {
        Ok((host_port.to_string(), None))
    }
}

/// 校验 `":port"` 片段(对应 Go `validOptionalPort`),返回端口号。
/// 空端口(`""` / `":"`)视为未携带端口,返回 `None`。
fn parse_optional_port(colon_port: &str) -> Result<Option<u16>, String> {
    if colon_port.is_empty() {
        return Ok(None);
    }
    let Some(digits) = colon_port.strip_prefix(':') else {
        return Err(format!("invalid url: invalid port {colon_port:?} after host"));
    };
    if digits.is_empty() {
        return Ok(None);
    }
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid url: invalid port {colon_port:?} after host"));
    }
    digits
        .parse::<u16>()
        .map(Some)
        .map_err(|_| format!("invalid url: port {digits:?} out of range"))
}

/// 解析 hostname,返回所有解析到的 IP(对应 Go `LookupAndCheckHost`)。
///
/// 若任一 IP 落入禁止网段,返回 `Err`(阻止 SSRF)。host 可携带端口
/// (`"example.com:8080"`、`"[::1]:8080"`),解析前会剥离。
///
/// 与 Go 的差异:无 `ctx` 参数,DNS 走 `std` 的 `ToSocketAddrs`,阻塞式且
/// **无超时控制**。调用方在真正建连时,应使用解析得到的合法 IP 拨号
/// (pin IP),以避免 DNS rebinding 在校验通过后篡改解析结果。
pub fn lookup_and_check_host(host: &str) -> Result<Vec<IpAddr>, String> {
    // 先去掉可能存在的端口
    let hostname = match split_host_port(host) {
        Some((h, _)) => h,
        None => host.to_string(),
    };

    // 如果 host 本身就是 IP 字面量,直接校验
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return if is_blocked_ip_addr(ip) {
            Err(format!("host {} is a blocked address", hostname))
        } else {
            Ok(vec![ip])
        };
    }

    // 域名:阻塞式 DNS 解析(端口仅用于满足 ToSocketAddrs 的 形式)
    let addrs = (hostname.as_str(), 80)
        .to_socket_addrs()
        .map_err(|e| format!("resolve host {hostname:?} failed: {e}"))?;
    let mut result = Vec::new();
    for addr in addrs {
        let ip = addr.ip();
        if is_blocked_ip_addr(ip) {
            return Err(format!("host {hostname:?} resolves to blocked address {ip}"));
        }
        result.push(ip);
    }
    if result.is_empty() {
        return Err(format!("host {hostname:?} has no resolvable address"));
    }
    Ok(result)
}

// ============================================================================
// 测试(移植自上游 client_ip_test.go / client_ip_extra_test.go / ssrf_test.go /
// ssrf_extra_test.go / url_validate_test.go,另加 CIDR 解析单元测试)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;

    /// 可信代理表是进程级单例,串行化用例避免并行测试相互覆盖配置。
    static TRUSTED_GUARD: Mutex<()> = Mutex::new(());

    /// 测试用可信代理网段(私有地址)。与 Go trustedV4CIDRs 一致,
    /// 每个用例显式设置以保证可重复。
    fn trusted_v4_cidrs() -> &'static [&'static str] {
        &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
    }

    fn build_req(remote_addr: &str, headers: &[(&str, &str)]) -> RequestInfo {
        let mut req = RequestInfo::new(remote_addr);
        for (k, v) in headers {
            req = req.with_header(k, *v);
        }
        req
    }

    // ------------------------------------------------------------------
    // client_ip.go
    // ------------------------------------------------------------------

    /// 对端非可信代理时,必须忽略 XFF,直接返回对端 IP
    /// (防止攻击者伪造 XFF 头绕过基于 IP 的限流/审计)。
    #[test]
    fn test_client_ip_non_trusted_peer_ignores_xff() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        // 对端 8.8.8.8 是公网 IP(非可信代理),即使携带伪造的 XFF 也应忽略
        let req = build_req(
            "8.8.8.8:12345",
            &[("x-forwarded-for", "10.0.0.1, 8.8.8.8"), ("x-real-ip", "127.0.0.1")],
        );
        assert_eq!(client_ip_from_request(Some(&req)), "8.8.8.8");
    }

    /// 对端是可信代理时,从 XFF 链从右向左跳过可信跳,
    /// 取第一个非可信 IP 作为客户端真实 IP。
    #[test]
    fn test_client_ip_trusted_proxy_parses_xff() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        // 对端 10.0.0.1 是可信代理;XFF 链 [8.8.8.8, 10.0.0.2]
        // 从右向左:10.0.0.2 是可信跳(跳过),8.8.8.8 是非可信 → 返回 8.8.8.8
        let req = build_req("10.0.0.1:12345", &[("x-forwarded-for", "8.8.8.8, 10.0.0.2")]);
        assert_eq!(client_ip_from_request(Some(&req)), "8.8.8.8");
    }

    /// XFF 链全是可信跳时,取最左侧 IP(按实现约定)。
    #[test]
    fn test_client_ip_all_trusted_hops_returns_leftmost() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        // 对端 10.0.0.1 可信;XFF [10.0.0.2, 10.0.0.3] 全可信 → 返回最左侧 10.0.0.2
        let req = build_req("10.0.0.1:12345", &[("x-forwarded-for", "10.0.0.2, 10.0.0.3")]);
        assert_eq!(client_ip_from_request(Some(&req)), "10.0.0.2");
    }

    /// 对端是可信代理且无 XFF 时,采信 X-Real-IP(仅在可信代理前提下)。
    #[test]
    fn test_client_ip_no_xff_falls_back_to_x_real_ip() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        let req = build_req("10.0.0.1:12345", &[("x-real-ip", "203.0.113.5")]);
        assert_eq!(client_ip_from_request(Some(&req)), "203.0.113.5");
    }

    /// 对端是可信代理但无任何转发头,兜底返回对端 IP(可信代理本身,如直连 nginx)。
    #[test]
    fn test_client_ip_trusted_proxy_no_headers_returns_peer() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        let req = build_req("10.0.0.1:12345", &[]);
        assert_eq!(client_ip_from_request(Some(&req)), "10.0.0.1");
    }

    /// 对端非可信代理且无转发头,返回对端 IP。
    #[test]
    fn test_client_ip_non_trusted_peer_no_headers_returns_peer() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        let req = build_req("114.114.114.114:12345", &[]);
        assert_eq!(client_ip_from_request(Some(&req)), "114.114.114.114");
    }

    /// nil 请求(Option::None)返回空串。
    #[test]
    fn test_client_ip_nil_request() {
        assert_eq!(client_ip_from_request(None), "");
    }

    /// 空的 RemoteAddr 返回空串。
    #[test]
    fn test_client_ip_empty_remote_addr() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        let req = build_req("", &[]);
        assert_eq!(client_ip_from_request(Some(&req)), "");
    }

    /// XFF 链中混入非法条目时,解析应跳过非法项,
    /// 仍从合法项中取第一个非可信 IP。
    #[test]
    fn test_client_ip_xff_with_invalid_entries_skipped() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        // 链:["not-an-ip", "8.8.8.8", "10.0.0.2"]
        // 从右向左:10.0.0.2 可信跳(跳过)→ 8.8.8.8 非可信 → 返回 8.8.8.8
        // "not-an-ip" 因解析失败被跳过
        let req = build_req(
            "10.0.0.1:12345",
            &[("x-forwarded-for", "not-an-ip, 8.8.8.8, 10.0.0.2")],
        );
        assert_eq!(client_ip_from_request(Some(&req)), "8.8.8.8");
    }

    /// 配置为不信任任何代理时,无论是否有 XFF,都返回对端 IP。
    #[test]
    fn test_client_ip_no_trusted_proxies_always_peer() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(&[]); // 空切片表示不信任任何代理
        let req = build_req("10.0.0.1:12345", &[("x-forwarded-for", "8.8.8.8")]);
        assert_eq!(
            client_ip_from_request(Some(&req)),
            "10.0.0.1",
            "不信任任何代理时应返回对端 IP"
        );
    }

    // ------------------------------------------------------------------
    // client_ip_extra_test.go
    // ------------------------------------------------------------------

    /// 可信代理配置解析规则表:合法 CIDR 生效、首尾空白被裁剪、
    /// 裸 IP 按单地址(/32 或 /128)生效、空串/纯空白/非法 IP/非法 CIDR
    /// 条目被跳过且不影响其余条目。
    #[test]
    fn test_set_trusted_proxies_parsing_rules() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        struct ParsingCase {
            name: &'static str,
            config: &'static [&'static str],
            trusted: &'static [&'static str],
            untrusted: &'static [&'static str],
        }
        let cases = [
            ParsingCase {
                name: "cidr with surrounding whitespace",
                config: &["  172.16.0.0/12  "],
                trusted: &["172.16.16.16"],
                untrusted: &["10.0.0.1", "192.168.1.1", "8.8.8.8"],
            },
            ParsingCase {
                name: "bare IPv4 acts as /32",
                config: &["8.8.8.8"],
                trusted: &["8.8.8.8"],
                untrusted: &["8.8.8.9", "10.0.0.1"],
            },
            ParsingCase {
                name: "bare IPv6 acts as /128",
                config: &["::1"],
                trusted: &["::1"],
                untrusted: &["::2", "fe80::1", "10.0.0.1"],
            },
            ParsingCase {
                name: "invalid entries skipped, valid kept",
                config: &["", "   ", "999.999.1.1", "not-an-ip", "10.0.0.0/33", "10.0.0.0/8"],
                trusted: &["10.0.0.1"],
                untrusted: &["192.168.1.1", "172.16.0.1"],
            },
        ];
        for case in &cases {
            set_trusted_proxies(case.config);
            for ip_str in case.trusted {
                let ip: IpAddr = ip_str.parse().unwrap();
                assert!(
                    is_trusted_proxy(&ip),
                    "[{}] {ip_str} 应按配置视为可信代理",
                    case.name
                );
            }
            for ip_str in case.untrusted {
                let ip: IpAddr = ip_str.parse().unwrap();
                assert!(
                    !is_trusted_proxy(&ip),
                    "[{}] {ip_str} 不应视为可信代理",
                    case.name
                );
            }
        }
    }

    /// 全部条目非法时,可信代理表为空,任何 IP 都不被信任
    /// (此后一律采用直连对端 IP)。
    #[test]
    fn test_set_trusted_proxies_all_invalid_yields_empty_trust() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(&["garbage", "1.2.3.4/99", "  "]);
        for ip_str in ["10.0.0.1", "127.0.0.1", "192.168.0.1", "8.8.8.8"] {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(!is_trusted_proxy(&ip), "全部条目非法时 {ip_str} 不应被信任");
        }
    }

    /// RemoteAddr(host:port 形态)提取 host 的边界:空串、无端口的裸 host、
    /// 标准 host:port、非 IP 域名、无法拆分的 IPv6 字面量与多冒号串。
    #[test]
    fn test_ip_from_remote_addr_variants() {
        let cases = [
            ("empty", "", ""),
            ("bare host without port", "8.8.8.8", "8.8.8.8"),
            ("host port pair", "1.2.3.4:5678", "1.2.3.4"),
            ("domain host", "example.com:80", "example.com"),
            ("ipv6 literal without brackets", "2001:db8::1", "2001:db8::1"),
            ("too many colons", "1:2:3", "1:2:3"),
            ("bracketed ipv6 with port", "[::1]:8080", "::1"),
        ];
        for (name, remote_addr, want) in cases {
            assert_eq!(ip_from_remote_addr(remote_addr), want, "case: {name}");
        }
    }

    /// 直连对端不是 IP(如域名形态的 RemoteAddr)时,对端解析失败,
    /// 必须忽略一切转发头直接返回对端 host,防伪造语义与"非可信代理"一致。
    #[test]
    fn test_client_ip_non_ip_remote_addr() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        let req = build_req(
            "example.com:80",
            &[("x-forwarded-for", "203.0.113.7"), ("x-real-ip", "203.0.113.8")],
        );
        assert_eq!(
            client_ip_from_request(Some(&req)),
            "example.com",
            "非 IP 对端必须忽略转发头并返回对端 host"
        );
    }

    /// XFF 链全部条目不可解析时,不得采信任何条目,回退对端 IP(可信代理本身)。
    #[test]
    fn test_client_ip_xff_all_unparseable() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        let req = build_req(
            "10.0.0.1:12345",
            &[("x-forwarded-for", "not-an-ip, also-not-an-ip")],
        );
        assert_eq!(
            client_ip_from_request(Some(&req)),
            "10.0.0.1",
            "全非法 XFF 必须回退对端 IP"
        );
    }

    /// X-Real-IP 不可解析时回退对端 IP。
    #[test]
    fn test_client_ip_x_real_ip_invalid_falls_back_to_peer() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        let req = build_req("10.0.0.1:12345", &[("x-real-ip", "bogus-host-name")]);
        assert_eq!(client_ip_from_request(Some(&req)), "10.0.0.1");
    }

    /// 带首尾空白的有效 X-Real-IP 被裁剪后采信。
    #[test]
    fn test_client_ip_x_real_ip_padded_trimmed_and_trusted() {
        let _g = TRUSTED_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_trusted_proxies(trusted_v4_cidrs());
        let req = build_req("10.0.0.1:12345", &[("x-real-ip", "  203.0.113.9  ")]);
        assert_eq!(client_ip_from_request(Some(&req)), "203.0.113.9");
    }

    // ------------------------------------------------------------------
    // ssrf.go(黑名单)
    // ------------------------------------------------------------------

    /// 私有/保留/回环/链路本地等地址必须被拦截。
    #[test]
    fn test_is_blocked_ip_blocks_private_and_reserved() {
        let blocked = [
            // IPv4 私有
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "192.168.0.0",
            // 回环
            "127.0.0.1",
            "127.255.255.255",
            // 链路本地(含云元数据 169.254.169.254)
            "169.254.169.254",
            "169.254.0.1",
            // CGNAT
            "100.64.0.1",
            // 未指定 / 本网络
            "0.0.0.0",
            "0.1.2.3",
            // 文档/测试网段
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            // 多播 / 保留
            "224.0.0.1",
            "240.0.0.1",
            // IPv6
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00::1",
            "ff00::1",
            "2001:db8::1",
        ];
        for ip in blocked {
            assert!(is_blocked_ip(ip), "期望 {ip} 被拦截");
        }
    }

    /// 公网地址不应被拦截。
    #[test]
    fn test_is_blocked_ip_public_addr_allowed() {
        let public = [
            "8.8.8.8",
            "1.1.1.1",
            "114.114.114.114",
            "2606:4700:4700::1111", // Cloudflare IPv6
        ];
        for ip in public {
            assert!(!is_blocked_ip(ip), "公网地址 {ip} 不应被拦截");
        }
    }

    /// 非法 IP 字符串应保守判定为拦截。
    #[test]
    fn test_is_blocked_ip_invalid_addr_conservatively_blocked() {
        let invalid = ["", "not-an-ip", "999.999.999.999", "   ", "192.168.1.1.1"];
        for ip in invalid {
            assert!(is_blocked_ip(ip), "非法输入 {ip:?} 应判定为拦截");
        }
    }

    /// `IpAddr` 形式与字符串形式判定一致(Go TestIsBlockedIPAddr_CoversPrivate;
    /// Go 另有 nil 入参用例,Rust 无 nil IP,不存在该分支)。
    #[test]
    fn test_is_blocked_ip_addr_matches_string_form() {
        for s in ["10.1.2.3", "127.0.0.1", "169.254.169.254", "192.168.0.1"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_blocked_ip_addr(ip), "{s} 应被拦截");
        }
    }

    // ------------------------------------------------------------------
    // ssrf.go(LookupAndCheckHost)
    // ------------------------------------------------------------------

    /// IP 字面量形式的 host 校验:公网放行、回环/链路本地拦截、带端口先剥端口。
    #[test]
    fn test_lookup_and_check_host_ip_literal() {
        // public IP literal
        let ips = lookup_and_check_host("8.8.8.8").unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]);
        // blocked IP literal(链路本地)
        assert!(lookup_and_check_host("169.254.169.254").is_err());
        // 回环地址(带端口,应先剥端口再判禁)
        assert!(lookup_and_check_host("127.0.0.1:8080").is_err());
        // 裸回环字面量
        assert!(lookup_and_check_host("127.0.0.1").is_err());
    }

    /// 带端口与方括号的 IPv6 字面量:剥壳后得到 ::1,必须按禁投地址拦截。
    #[test]
    fn test_lookup_and_check_host_bracketed_ipv6_with_port_blocked() {
        assert!(lookup_and_check_host("[::1]:8080").is_err());
    }

    /// localhost 由本机解析为回环地址,属于 SSRF 高危目标,必须被拦。
    /// (上游 ssrf_extra_test.go 的假 DNS 用例在 Rust 侧改造为对
    /// localhost 的等价用例:同样覆盖"域名 → DNS 解析 → 逐 IP 判禁"分支,
    /// 且无外网依赖。)
    #[test]
    fn test_lookup_and_check_host_localhost_blocked() {
        assert!(
            lookup_and_check_host("localhost").is_err(),
            "localhost 解析到回环地址,必须被拦截"
        );
    }

    /// 域名 + 端口形态:端口应被剥离后按主机名解析(仍解析到回环被拦)。
    #[test]
    fn test_lookup_and_check_host_localhost_with_port_blocked() {
        assert!(lookup_and_check_host("localhost:8080").is_err());
    }

    /// 无法解析的域名应返回错误(上游 unmapped/unresolvable 分支;
    /// `.invalid` 为 RFC 2606 保留 TLD,任何环境都不可解析)。
    #[test]
    fn test_lookup_and_check_host_unresolvable_errors() {
        assert!(lookup_and_check_host("nonexistent.invalid").is_err());
    }

    // ------------------------------------------------------------------
    // url_validate_test.go
    // ------------------------------------------------------------------

    /// 合法 http/https URL 应通过校验。
    #[test]
    fn test_validate_url_accepts_http_https() {
        for u in [
            "http://example.com/path",
            "https://example.com:443/path?q=1",
            "https://8.8.8.8/",
            "http://example.com",
        ] {
            assert!(validate_url(u).is_ok(), "{u} 应通过校验");
        }
    }

    /// 非 http/https scheme 应被拒。
    #[test]
    fn test_validate_url_rejects_other_schemes() {
        for u in [
            "file:///etc/passwd",
            "gopher://localhost",
            "ftp://example.com",
            "dict://localhost:6379",
            "javascript:alert(1)",
        ] {
            assert!(validate_url(u).is_err(), "scheme {u:?} 应被拒");
        }
    }

    /// 空 URL 应报错。
    #[test]
    fn test_validate_url_rejects_empty() {
        assert!(validate_url("").is_err());
    }

    /// 缺少 host 应报错。
    #[test]
    fn test_validate_url_rejects_missing_host() {
        for u in ["http://", "https:///path"] {
            assert!(validate_url(u).is_err(), "缺少 host 的 URL {u:?} 应被拒");
        }
    }

    /// 携带 userinfo 的 URL 应被拒(防 SSRF 混淆)。
    #[test]
    fn test_validate_url_rejects_userinfo() {
        for u in [
            "http://user:pass@example.com/",
            "http://admin@example.com/",
            "https://user%40host:pass@evil.com/",
        ] {
            assert!(validate_url(u).is_err(), "携带 userinfo 的 URL {u:?} 应被拒");
        }
    }

    /// 解析失败的 URL 应报错。
    #[test]
    fn test_validate_url_rejects_malformed() {
        for u in ["http://example.com:badport", "://missing-scheme"] {
            assert!(validate_url(u).is_err(), "{u:?} 应报错");
        }
    }

    /// 结构体字段解析(Rust 版适配点):scheme 小写化、IPv6 去方括号、
    /// IP 字面量回填 `ip`、域名 `ip` 为 `None`、缺端口为 `None`。
    #[test]
    fn test_validate_url_struct_fields() {
        let u = validate_url("https://8.8.8.8/").unwrap();
        assert_eq!(u.scheme, "https");
        assert_eq!(u.host, "8.8.8.8");
        assert_eq!(u.port, None);
        assert_eq!(u.ip, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));

        let u = validate_url("HTTP://Example.COM:8080/path").unwrap();
        assert_eq!(u.scheme, "http");
        assert_eq!(u.host, "Example.COM");
        assert_eq!(u.port, Some(8080));
        assert_eq!(u.ip, None);

        let u = validate_url("http://[::1]/").unwrap();
        assert_eq!(u.host, "::1");
        assert_eq!(u.port, None);
        assert_eq!(u.ip, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    // ------------------------------------------------------------------
    // CIDR 解析与匹配(Rust 版手写实现的单元测试,上游无对应文件)
    // ------------------------------------------------------------------

    /// parse_cidr:合法 CIDR 生效(含 IPv4-mapped 归一化),
    /// 非法条目(缺 `/`、前缀越界/非数字、地址非法、多余 `/`)返回 `None`。
    #[test]
    fn test_parse_cidr_valid_and_invalid() {
        assert_eq!(
            parse_cidr("10.0.0.0/8"),
            Some(IpNet::V4 {
                addr: u32::from(Ipv4Addr::new(10, 0, 0, 0)),
                prefix: 8
            })
        );
        assert_eq!(
            parse_cidr("203.0.113.0/24"),
            Some(IpNet::V4 {
                addr: u32::from(Ipv4Addr::new(203, 0, 113, 0)),
                prefix: 24
            })
        );
        assert_eq!(
            parse_cidr("::1/128"),
            Some(IpNet::V6 {
                addr: u128::from(Ipv6Addr::LOCALHOST),
                prefix: 128
            })
        );
        // IPv4-mapped 基址归一化为 IPv4 网段:104 - 96 = 8
        assert_eq!(
            parse_cidr("::ffff:10.0.0.0/104"),
            Some(IpNet::V4 {
                addr: u32::from(Ipv4Addr::new(10, 0, 0, 0)),
                prefix: 8
            })
        );
        // 纯 IPv6(非 mapped)不归一化
        assert_eq!(
            parse_cidr("2001:db8::/32"),
            Some(IpNet::V6 {
                addr: u128::from("2001:db8::".parse::<Ipv6Addr>().unwrap()),
                prefix: 32
            })
        );
        for bad in [
            "10.0.0.0",     // 缺 /
            "10.0.0.0/33",  // 前缀越界
            "::1/129",      // 前缀越界
            "10.0.0.0/-1",  // 负前缀
            "10.0.0.0/abc", // 非数字前缀
            "10.0.0.0/",    // 空前缀
            "/8",           // 空地址
            "999.1.1.1/8",  // 非法地址
            "example.com/8", // 非法地址
            "1.2.3.4/8/8",  // 多余 /
            "",             // 空串
        ] {
            assert_eq!(parse_cidr(bad), None, "{bad:?} 应解析失败");
        }
    }

    /// 网段匹配语义:边界(前缀 0/最大前缀)、地址族不匹配、
    /// IPv4-mapped IPv6 参与 IPv4 网段匹配(对齐 Go IPNet.Contains 的 To4 行为)。
    #[test]
    fn test_ipnet_contains_semantics() {
        let v4 = parse_cidr("10.0.0.0/8").unwrap();
        assert!(v4.contains(&IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(v4.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
        assert!(!v4.contains(&IpAddr::V4(Ipv4Addr::new(11, 0, 0, 0))));

        // /0 匹配全部,/32 精确单地址
        let all = parse_cidr("0.0.0.0/0").unwrap();
        assert!(all.contains(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
        let single = parse_cidr("8.8.8.8/32").unwrap();
        assert!(single.contains(&"8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!single.contains(&"8.8.8.9".parse::<IpAddr>().unwrap()));

        // IPv4 网段不匹配纯 IPv6,但匹配 IPv4-mapped 形式
        assert!(!v4.contains(&"::1".parse::<IpAddr>().unwrap()));
        assert!(v4.contains(&"::ffff:10.1.2.3".parse::<IpAddr>().unwrap()));
        assert!(!v4.contains(&"::ffff:11.1.2.3".parse::<IpAddr>().unwrap()));

        // IPv6 网段
        let v6 = parse_cidr("fc00::/7").unwrap();
        assert!(v6.contains(&"fd00::1".parse::<IpAddr>().unwrap()));
        assert!(!v6.contains(&"fe80::1".parse::<IpAddr>().unwrap()));
        // IPv6 网段不匹配 IPv4
        assert!(!v6.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        // 前缀 0 匹配全部 IPv6
        let all6 = parse_cidr("::/0").unwrap();
        assert!(all6.contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    /// 内置黑名单/默认可信代理清单全部可解析,且与上游清单条数一致。
    #[test]
    fn test_builtin_lists_parse_and_match_go() {
        assert_eq!(BLOCKED_CIDRS.len(), 20);
        assert_eq!(blocked_cidrs().len(), BLOCKED_CIDRS.len());
        assert_eq!(default_trusted_proxy_cidrs().len(), 6);
        assert_eq!(
            default_trusted_proxy_cidrs(),
            &[
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "127.0.0.0/8",
                "::1/128",
                "fc00::/7"
            ]
        );
    }
}
