//! auditutil —— HTTP 审计日志信息采集与防篡改证据链(移植自 go-utils `auditutil`
//! 包:client_ip.go + platform.go + request.go + sign.go),feature `auditutil`。
//!
//! 覆盖能力:
//! - 客户端真实 IP 归一化提取([`client_real_ip`] / [`ip_from_remote_addr`] /
//!   [`is_private_ip`]),X-Forwarded-For / X-Real-IP → RemoteAddr 的逐级回退;
//! - 请求 ID 提取与兜底生成([`request_id`])、请求体用户名解析与日志行注入
//!   清洗([`parse_username_from_bytes`] / [`extract_username_from_request`] /
//!   [`strip_line_breaks`]);
//! - User-Agent 平台启发式识别([`detect_platform_from_ua`]);
//! - 篡改证据链:审计日志的确定性 prost 序列化 SHA-256 哈希([`hash_log`],
//!   排除 `log_hash`/`signature` 字段,防自引用)、ECDSA-P256 对签名内容的
//!   DER 签名([`sign_log_content`] / [`encode_ecdsa_der`] /
//!   [`generate_ecdsa_key_pair`]),构成"签名(hash(body))"的两级防篡改约定。
//!
//! # 与上游(Go)的差异
//!
//! 1. **哈希范围收窄**:上游 [`hash_log`] 作用于任意 `proto.Message`
//!    (protoreflect 克隆 + 按描述符清字段 + `proto.Marshal`);Rust 侧无
//!    protoreflect,改为手写上游 `testpb/testlog.proto` 对应的 [`AuditLog`]
//!    消息结构体(prost 0.14 derive,字段号逐一对齐,含 wire 兼容
//!    `google.protobuf.Timestamp` 的 [`Timestamp`] 占位)。排除字段的匹配
//!    语义保持一致:proto 字段名(snake_case)与 json_name(camelCase)两种
//!    拼写都命中,缺省排除集同上游 `defaultExcludedFields` =
//!    `["log_hash", "logHash", "signature"]`。
//! 2. **createdAt 形态**:上游签名内容中的时间为 `timestamppb.Timestamp`
//!    (秒 + 纳秒);本模块签名接口收窄为 `Option<i64>` 秒级时间戳
//!    (prost-types 不在依赖内),签名字节中的 `nanos` 位恒为 `0`。签名内容
//!    仍按上游语义为 Go `json.Marshal` 的
//!    `{"tenant_id":..,"user_id":..,"sec":..,"nanos":..,"log_hash":".."}`,
//!    含 Go 默认的 HTML 转义(`<`/`>`/`&` → `\u00xx`)。
//! 3. **HTTP 输入结构**:Rust 侧无 `net/http`,照最小输入约定提供
//!    [`HttpRequest`](header 键小写的 `HashMap` + `remote_addr` + `body`)。
//! 4. **nil 分支由类型系统排除**:上游 `ClientRealIP(nil)`、
//!    `HashLog(nil)`、`SignLogContent(nil, ...)` 等空指针防御在 Rust 中
//!    (引用不可为空)不再成立,不设 `Option` 形参;对应测试用例不复刻。
//!    [`extract_username_from_request`]"读取后恢复 Body"的机制同样不需要——
//!    请求体本就存放在结构体内。
//! 5. **RequestID 兜底 GUID**:`id.NewGUIDv4(false)` 需 `uuid` feature,
//!    改为经 p256 重导出的 `rand_core::OsRng` 自实现 UUID v4
//!    (版本/变体位照 RFC 4122 置位),输出同为 32 个小写十六进制字符。
//! 6. **regexp 手写化**:`platform.go` 的 `\bcom\.[a-z0-9_.]+` 与
//!    `request.go` 的 `"username"\s*:\s*"([^"]+)"` 均以手写扫描器逐式复刻
//!    (审计模块依赖集只有 prost/p256/sha2,不引入 regex)。
//!
//! # Examples
//!
//! ```
//! use rust_utils::auditutil::{self, AuditLog, HttpRequest, Timestamp};
//! use p256::ecdsa::{DerSignature, Signature};
//! use p256::ecdsa::signature::Verifier;
//!
//! // —— 请求信息采集 ——
//! let req = HttpRequest {
//!     headers: [(
//!         "x-forwarded-for".to_string(),
//!         "203.0.113.7, 10.0.0.2".to_string(),
//!     )]
//!     .into(),
//!     remote_addr: "10.0.0.1:4000".to_string(),
//!     body: br#"{"username":"alice"}"#.to_vec(),
//! };
//! assert_eq!(auditutil::client_real_ip(&req), "203.0.113.7");
//! assert_eq!(auditutil::request_id(&req).len(), 32);
//! assert_eq!(
//!     auditutil::detect_platform_from_ua("Mozilla/5.0 (Linux; Android 10; wv)"),
//!     auditutil::PLATFORM_ANDROID_APP
//! );
//! assert_eq!(auditutil::parse_username_from_bytes(&req.body).unwrap(), "alice");
//!
//! // —— 防篡改证据链 ——
//! let log = AuditLog {
//!     tenant_id: 7,
//!     user_id: 42,
//!     action: "login".to_string(),
//!     created_at: Some(Timestamp { seconds: 1735689600, nanos: 0 }),
//!     log_hash: None,
//!     signature: None,
//! };
//! let hash = auditutil::hash_log(&log, &[]); // 空切片 = 缺省排除集
//! let (sk, vk) = auditutil::generate_ecdsa_key_pair().unwrap();
//! let sig = auditutil::sign_log_content(&sk, 7, 42, Some(1735689600), &hash).unwrap();
//! assert_eq!(sig[0], 0x30, "签名应为 DER 序列(0x30 开头)");
//!
//! // 验签:DER 解码后按标准 Verifier 校验(签名内容 = 签名 JSON 的 sha256)
//! let content = format!(
//!     "{{\"tenant_id\":7,\"user_id\":42,\"sec\":1735689600,\"nanos\":0,\"log_hash\":\"{hash}\"}}"
//! );
//! let parsed = Signature::try_from(DerSignature::try_from(&sig[..]).unwrap()).unwrap();
//! assert!(vk.verify(content.as_bytes(), &parsed).is_ok());
//! ```

use std::collections::HashMap;
use std::net::IpAddr;

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use prost::Message as _;
use sha2::{Digest, Sha256};

// ============================================================================
// 请求输入结构(Rust 侧无 net/http 的最小化替身)
// ============================================================================

/// 审计信息采集所需的最小 HTTP 请求输入(Rust 侧无 `net/http.Request` 的替身)。
///
/// 约定:
/// - `headers` 的键为**小写**请求头名(如 `"x-forwarded-for"`),模拟 HTTP 头
///   经大小写归一化后的形态;[`HttpRequest::header`] 会对查询名再做一次小写化
///   兜底。
/// - `remote_addr` 为 `host:port` 形态(如 `"192.0.2.1:5566"`、`"[::1]:7788"`)。
/// - `body` 为请求体原始字节,供用户名解析;存储于结构体内、不可变借用,
///   上游"读取后恢复 Body"的机制在此不适用。
#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    /// 请求头,键约定为小写。
    pub headers: HashMap<String, String>,
    /// 远端地址(host:port)。
    pub remote_addr: String,
    /// 请求体原始字节。
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// 按头名取第一个值(模拟 Go `Header.Get` 的语义);头名按小写归一化。
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

// ============================================================================
// client_ip.go
// ============================================================================

/// 审计信息采集涉及的请求头名(存储键为小写形态)。
const HEADER_X_FORWARDED_FOR: &str = "x-forwarded-for";
const HEADER_X_REAL_IP: &str = "x-real-ip";
const HEADER_X_REQUEST_ID: &str = "x-request-id";
const HEADER_X_CORRELATION_ID: &str = "x-correlation-id";
const HEADER_X_FC_REQUEST_ID: &str = "x-fc-request-id";

/// 获取客户端真实 IP。
///
/// 依次检查 X-Forwarded-For 与 X-Real-IP 头(取第一个合法 IP),都取不到时
/// 回退 RemoteAddr。注意:这是"按转发头如实记录"的审计口径——最外层反向代理
/// 必须覆写(而非追加)X-Forwarded-For 以防伪造。若需要防伪造的安全判定
/// (可信代理链从右向左解析),应使用 netutil 的可信代理链实现。
pub fn client_real_ip(request: &HttpRequest) -> String {
    if let Some(xff) = request.header(HEADER_X_FORWARDED_FOR) {
        if !xff.is_empty() {
            // X-Forwarded-For 是逗号分隔的 IP 列表,取第一个合法 IP
            for part in xff.split(',') {
                let ip = part.trim();
                if ip.parse::<IpAddr>().is_ok() {
                    return ip.to_string();
                }
            }
        }
    }

    if let Some(xri) = request.header(HEADER_X_REAL_IP) {
        if !xri.is_empty() && xri.parse::<IpAddr>().is_ok() {
            return xri.to_string();
        }
    }

    ip_from_remote_addr(&request.remote_addr)
}

/// 从 RemoteAddr(host:port)中提取合法 IP。无法解析出 IP 时返回空串。
pub fn ip_from_remote_addr(host_address: &str) -> String {
    // 与 Go net.SplitHostPort 一致:仅拆分分支对输入做 TrimSpace
    if host_address.contains(':') {
        if let Some((host, _port)) = split_host_port(host_address.trim()) {
            if host.parse::<IpAddr>().is_ok() {
                return host.to_string();
            }
        }
    }
    if host_address.parse::<IpAddr>().is_ok() {
        host_address.to_string()
    } else {
        String::new()
    }
}

/// 手写 `net.SplitHostPort` 的核心语义:拆出 host 与 port,
/// 支持方括号 IPv6 字面量;无法拆分时返回 `None`。
fn split_host_port(addr: &str) -> Option<(&str, &str)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let port = rest[close + 1..].strip_prefix(':')?;
        return Some((host, port));
    }
    // 非括号形态:恰有一个冒号才是 host:port(再多即"too many colons")
    let colon = addr.find(':')?;
    if addr[colon + 1..].contains(':') {
        return None;
    }
    Some((&addr[..colon], &addr[colon + 1..]))
}

/// 检查 IP 是否属于常见内网或链路本地地址。无法解析的地址返回 `false`
/// (由调用方决定如何处理未知形态)。
///
/// 覆盖网段(与上游一致):`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、
/// `127.0.0.0/8`、`169.254.0.0/16`、`::1/128`、`fc00::/7`;
/// IPv4-mapped IPv6(`::ffff:a.b.c.d`)按 Go `net.IP.Contains` 的行为还原为
/// IPv4 后判定。
pub fn is_private_ip(ip_str: &str) -> bool {
    let Ok(ip) = ip_str.trim().parse::<IpAddr>() else {
        return false;
    };
    let ip = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => PRIVATE_V4_CIDRS
            .iter()
            .any(|(net, len)| cidr_contains(net, *len, &v4.octets())),
        IpAddr::V6(v6) => PRIVATE_V6_CIDRS
            .iter()
            .any(|(net, len)| cidr_contains(net, *len, &v6.octets())),
    }
}

/// 常见内网 IPv4 网段表(移植自 client_ip.go 的 cidrs)。
const PRIVATE_V4_CIDRS: [([u8; 4], u8); 5] = [
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
];

/// 常见内网 IPv6 网段表:`::1/128` 与 `fc00::/7`。
const PRIVATE_V6_CIDRS: [([u8; 16], u8); 2] = [IPV6_LOOPBACK_NET, FC00_V7_NET];

/// `::1/128` 的网络字节。
const IPV6_LOOPBACK_NET: ([u8; 16], u8) = ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128);

/// `fc00::/7` 的网络字节(fc00:: 前 16 字节)。
const FC00_V7_NET: ([u8; 16], u8) = ([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7);

/// 判断 `ip` 是否落在 `net/prefix_len` 网段内(`ip` 与 `net` 等长的大端字节)。
fn cidr_contains(net: &[u8], prefix_len: u8, ip: &[u8]) -> bool {
    if net.len() != ip.len() {
        return false;
    }
    let full = (prefix_len / 8) as usize;
    if full > ip.len() || ip[..full] != net[..full] {
        return false;
    }
    let rem = prefix_len % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem);
    (ip[full] & mask) == (net[full] & mask)
}

/// 获取请求 ID:依次检查 X-Request-ID / X-Correlation-ID / x-fc-request-id
/// (函数计算),都没有时生成新的 GUID(v4,32 位小写十六进制)。
pub fn request_id(request: &HttpRequest) -> String {
    for key in [
        HEADER_X_REQUEST_ID,
        HEADER_X_CORRELATION_ID,
        HEADER_X_FC_REQUEST_ID,
    ] {
        if let Some(v) = request.header(key) {
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    new_guid_v4_hex()
}

/// 生成 UUID v4 的去横线小写十六进制形态(`id.NewGUIDv4(false)` 的替身:
/// 经 p256 重导出的 `rand_core::OsRng` 取随机数,版本/变体位照 RFC 4122 置位)。
fn new_guid_v4_hex() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant 10xx
    hex_lower(&bytes)
}

// ============================================================================
// platform.go
// ============================================================================

/// 平台类型:原生 Android 应用。
pub const PLATFORM_ANDROID_APP: &str = "AndroidApp";
/// 平台类型:原生 iOS 应用。
pub const PLATFORM_IOS_APP: &str = "iOSApp";
/// 平台类型:Windows 桌面(原生/混合)。
pub const PLATFORM_DESKTOP_WINDOWS: &str = "DesktopWindows";
/// 平台类型:macOS 桌面(原生/混合)。
pub const PLATFORM_DESKTOP_MAC: &str = "DesktopMac";
/// 平台类型:Linux 桌面(原生/混合)。
pub const PLATFORM_DESKTOP_LINUX: &str = "DesktopLinux";
/// 平台类型:常见 Web 浏览器。
pub const PLATFORM_WEB: &str = "Web";
/// 平台类型:其他/未知。
pub const PLATFORM_OTHER: &str = "Other";

/// 根据 UA 字符串启发式判断平台类型。
/// 说明:仅作为补充判断,优先使用客户端上报字段(platform/os_name)。
pub fn detect_platform_from_ua(ua: &str) -> String {
    if ua.is_empty() {
        return PLATFORM_OTHER.to_string();
    }
    let s = ua.trim().to_lowercase();

    // 原生 Android app 指示器
    if s.contains("okhttp")
        || s.contains("dalvik")
        || s.contains("; wv")
        || s.contains(" ;wv")
        || s.contains("build/")
    {
        return PLATFORM_ANDROID_APP.to_string();
    }
    // 包名模式(com.xxx)且含 android
    if s.contains("android") && (matches_android_package(&s) || s.contains("wv")) {
        return PLATFORM_ANDROID_APP.to_string();
    }

    // 原生 iOS 指示器
    if s.contains("iphone")
        || s.contains("ipad")
        || s.contains("ipod")
        || s.contains("cfnetwork")
        || s.contains("darwin")
        || s.contains("cpu iphone os")
    {
        return PLATFORM_IOS_APP.to_string();
    }

    // 桌面原生/混合应用(例如 Electron、nwjs、desktop)
    if s.contains("electron")
        || s.contains("nwjs")
        || s.contains("node.js")
        || s.contains("nodejs")
        || s.contains("desktop")
        || s.contains("appname")
    {
        // 根据 UA 中的 OS 关键词区分具体桌面系统
        if s.contains("windows nt")
            || s.contains("win64")
            || s.contains("win32")
            || s.contains("windows")
        {
            return PLATFORM_DESKTOP_WINDOWS.to_string();
        }
        if s.contains("macintosh") || s.contains("mac os x") || s.contains("darwin") {
            return PLATFORM_DESKTOP_MAC.to_string();
        }
        if s.contains("x11")
            || s.contains("linux")
            || s.contains("ubuntu")
            || s.contains("debian")
            || s.contains("fedora")
        {
            return PLATFORM_DESKTOP_LINUX.to_string();
        }
        // 若未直接包含 OS 关键字,尝试从常见标识推断
        if s.contains("win") {
            return PLATFORM_DESKTOP_WINDOWS.to_string();
        }
        if s.contains("mac") || s.contains("os x") {
            return PLATFORM_DESKTOP_MAC.to_string();
        }
        if s.contains("linux") || s.contains("x11") {
            return PLATFORM_DESKTOP_LINUX.to_string();
        }
        // 仍无法判定,视作桌面类但未知系统
        return PLATFORM_OTHER.to_string();
    }

    // 常见 Web 浏览器识别(Mozilla+桌面/移动系统且无明显原生 app 标志)
    if s.contains("mozilla")
        && (s.contains("windows nt")
            || s.contains("macintosh")
            || s.contains("x11")
            || s.contains("linux")
            || s.contains("android")
            || s.contains("iphone"))
    {
        // 排除明显的原生 app 标志
        if !s.contains("okhttp")
            && !s.contains("dalvik")
            && !s.contains("cfnetwork")
            && !s.contains("electron")
        {
            return PLATFORM_WEB.to_string();
        }
    }

    PLATFORM_OTHER.to_string()
}

/// 手写正则 `\bcom\.[a-z0-9_.]+` 的匹配:是否存在 word 边界上的 `com.`
/// 且其后至少一个 `[a-z0-9_.]` 字符(输入须已小写)。
fn matches_android_package(lowercased: &str) -> bool {
    let bytes = lowercased.as_bytes();
    for (idx, _) in lowercased.match_indices("com.") {
        let boundary = idx == 0 || !is_ascii_word_byte(bytes[idx - 1]);
        let tail = idx + "com.".len();
        let has_payload = tail < bytes.len() && is_android_package_byte(bytes[tail]);
        if boundary && has_payload {
            return true;
        }
    }
    false
}

/// Go 正则 `\b` 的 word 字符(`[0-9A-Za-z_]`)。
fn is_ascii_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// 正则字符类 `[a-z0-9_.]`(输入已小写)。
fn is_android_package_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.')
}

// ============================================================================
// request.go
// ============================================================================

/// 从请求体中解析用户名(先按 JSON 字段、再按表单键)。
/// 返回前剥离 CR/LF,防止含换行的用户名注入文本日志行(伪造条目/行内注入)。
pub fn parse_username_from_bytes(body: &[u8]) -> Result<String, String> {
    if let Some(raw) = find_json_username(body) {
        return Ok(strip_line_breaks(&String::from_utf8_lossy(raw)));
    }
    if let Ok(values) = parse_query(body) {
        if let Some(u) = values.iter().find(|(k, _)| k == "username") {
            if !u.1.is_empty() {
                return Ok(strip_line_breaks(&u.1));
            }
        }
    }
    Err("username not found".to_string())
}

/// 从 HTTP 请求体中提取用户名。
///
/// 上游会读取并恢复 `r.Body` 以免影响后续中间件;Rust 侧请求体本就存放于
/// [`HttpRequest::body`] 中,无需恢复机制,直接解析。与上游一致:JSON 解析
/// 失败时再按表单键兜底一次,此时即便取不到用户名也不报错(返回空串)。
pub fn extract_username_from_request(request: &HttpRequest) -> Result<String, String> {
    match parse_username_from_bytes(&request.body) {
        Ok(u) => Ok(u),
        Err(err) => match parse_query(&request.body) {
            Ok(values) => Ok(values
                .iter()
                .find(|(k, _)| k == "username")
                .map(|(_, v)| v.clone())
                .unwrap_or_default()),
            Err(_) => Err(err),
        },
    }
}

/// 移除所有 CR/LF,阻断日志行注入。
pub fn strip_line_breaks(s: &str) -> String {
    s.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

/// 手写正则 `"username"\s*:\s*"([^"]+)"` 的匹配:返回第一个命中的捕获组
/// (原始字节,未解码)。
fn find_json_username(body: &[u8]) -> Option<&[u8]> {
    let pattern = b"\"username\"";
    let mut start = 0;
    while let Some(pos) = find_sub(body, pattern, start) {
        let mut i = pos + pattern.len();
        // \s* —— Go regexp 的 \s == [\t\n\f\r ]
        while i < body.len() && is_regex_space(body[i]) {
            i += 1;
        }
        if i >= body.len() || body[i] != b':' {
            start = pos + 1;
            continue;
        }
        i += 1;
        while i < body.len() && is_regex_space(body[i]) {
            i += 1;
        }
        if i >= body.len() || body[i] != b'"' {
            start = pos + 1;
            continue;
        }
        i += 1;
        let cap_start = i;
        while i < body.len() && body[i] != b'"' {
            i += 1;
        }
        // `([^"]+)` 至少一个字符;空捕获视为该位置不匹配,继续向后扫描
        if i > cap_start && i < body.len() {
            return Some(&body[cap_start..i]);
        }
        start = pos + 1;
    }
    None
}

/// Go regexp `\s`:`[\t\n\f\r ]`。
fn is_regex_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

/// 在 `haystack[from..]` 中查找 `needle` 首次出现的字节偏移。
fn find_sub(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if haystack.len() < needle.len() || from > haystack.len() - needle.len() {
        return None;
    }
    (from..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// 手写 `url.ParseQuery` 的核心语义:按 `&` 分隔、每段首个 `=` 分出键值,
/// 对键值做 `+`→空格与 `%XX` 百分号解码;非法百分号序列整体报错
/// (上游在 err != nil 时跳过该路径)。空段跳过,无 `=` 的段取空值。
fn parse_query(body: &[u8]) -> Result<Vec<(String, String)>, String> {
    let text = String::from_utf8_lossy(body);
    let mut values = Vec::new();
    for part in text.split('&') {
        if part.is_empty() {
            continue;
        }
        let (key, value) = match part.split_once('=') {
            Some((k, v)) => (k, v),
            None => (part, ""),
        };
        values.push((
            unescape_query_component(key)?,
            unescape_query_component(value)?,
        ));
    }
    Ok(values)
}

/// `url.QueryUnescape` 的核心语义:`+` → 空格,`%XX` → 字节;
/// 缺位或非法十六进制时返回错误。
fn unescape_query_component(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let hi = bytes.get(i + 1).copied().and_then(hex_val);
                let lo = bytes.get(i + 2).copied().and_then(hex_val);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        let escape = &s[i..(i + 3).min(s.len())];
                        return Err(format!("invalid URL escape: {escape:?}"));
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// 十六进制字符 → 半字节。
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ============================================================================
// sign.go —— 篡改证据链
// ============================================================================

/// 审计日志防篡改约定:日志体在计算哈希时排除的字段名(proto 字段名与
/// json_name 两种拼写都命中)。哈希随日志落库,签名覆盖哈希,形成
/// "签名(hash(body))"的两级防篡改链。
const DEFAULT_EXCLUDED_FIELDS: &[&str] = &["log_hash", "logHash", "signature"];

/// `google.protobuf.Timestamp` 的 wire 兼容占位(字段号与类型一致:
/// `seconds` int64 = 1、`nanos` int32 = 2;prost-types 不在本模块依赖内)。
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, ::prost::Message)]
pub struct Timestamp {
    /// Unix 纪元起的 UTC 秒数(字段号 1)。
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    /// 秒的纳秒小数部分,0..=999_999_999(字段号 2)。
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

/// 审计日志消息(上游 `testpb/testlog.proto` 的 `TestLog` 逐字段移植,
/// 字段号与类型对齐;哈希/签名的排除字段约定保持同名 `log_hash`/`signature`)。
///
/// 上游 [`hash_log`] 接受任意 `proto.Message`;Rust 侧无 protoreflect,
/// 哈希范围**收窄为本结构体**(见模块头"与上游的差异")。
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuditLog {
    /// 租户 ID(字段号 1)。
    #[prost(uint32, tag = "1")]
    pub tenant_id: u32,
    /// 用户 ID(字段号 2)。
    #[prost(uint32, tag = "2")]
    pub user_id: u32,
    /// 动作,如 login / logout(字段号 3)。
    #[prost(string, tag = "3")]
    pub action: String,
    /// 创建时间(字段号 4;[`Timestamp`] 与 google.protobuf.Timestamp wire 兼容)。
    #[prost(message, optional, tag = "4")]
    pub created_at: Option<Timestamp>,
    /// 日志哈希(字段号 15,proto3 optional;参与签名但**排除出哈希**)。
    #[prost(string, optional, tag = "15")]
    pub log_hash: Option<String>,
    /// 日志签名(字段号 16,proto3 optional;**排除出哈希**)。
    #[prost(bytes = "vec", optional, tag = "16")]
    pub signature: Option<Vec<u8>>,
}

/// 计算日志消息的 SHA256 哈希(十六进制小写字符串)。
///
/// 规则(与上游一致):先在消息副本上清除 `exclude_fields` 命中的字段
/// (proto 字段名与 json_name 两种拼写都命中;传空切片等价于缺省排除集
/// `log_hash`/`logHash`/`signature`),再对 Protobuf 确定性序列化结果哈希
/// ——哈希值不依赖日志自身的哈希/签名字段,防止自引用。消息本身不被修改。
///
/// prost 的 `encode_to_vec` 不会失败,故无上游 Marshal 失败返回空串的分支;
/// 上游对 nil 消息返回空串的分支由 Rust 引用类型排除。
pub fn hash_log(log: &AuditLog, exclude_fields: &[&str]) -> String {
    let mut clone = log.clone();
    clear_excluded_fields(&mut clone, exclude_fields);
    let raw = clone.encode_to_vec();
    let hash = Sha256::digest(&raw);
    hex_lower(&hash)
}

/// 在消息副本上清除被排除字段(对齐上游 protoreflect 的"按描述符字段名 /
/// json_name 命中即 Clear")。
fn clear_excluded_fields(log: &mut AuditLog, exclude_fields: &[&str]) {
    let excluded: &[&str] = if exclude_fields.is_empty() {
        DEFAULT_EXCLUDED_FIELDS
    } else {
        exclude_fields
    };
    let hit = |snake: &str| {
        let json = json_name(snake);
        excluded
            .iter()
            .any(|want| *want == snake || *want == json.as_str())
    };
    if hit("tenant_id") {
        log.tenant_id = 0;
    }
    if hit("user_id") {
        log.user_id = 0;
    }
    if hit("action") {
        log.action.clear();
    }
    if hit("created_at") {
        log.created_at = None;
    }
    if hit("log_hash") {
        log.log_hash = None;
    }
    if hit("signature") {
        log.signature = None;
    }
}

/// proto 字段名的 json_name 归一化(对齐 protoreflect `fd.JSONName()`:
/// 去下划线并大写每个后继段首字母,如 `tenant_id` → `tenantId`)。
fn json_name(snake: &str) -> String {
    let mut out = String::with_capacity(snake.len());
    let mut cap = false;
    for c in snake.chars() {
        if c == '_' {
            cap = true;
        } else if cap {
            out.push(c.to_ascii_uppercase());
            cap = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// 生成 ECDSA 密钥对(secp256r1 曲线),用于审计日志签名。
///
/// 返回 `(SigningKey, VerifyingKey)`,对应上游的 `(*ecdsa.PrivateKey,
/// *ecdsa.PublicKey)`;上游密钥生成失败返回 error 的分支在 OsRng 下不发生,
/// 保留 `Result` 形态以便与上游签名一致。
pub fn generate_ecdsa_key_pair() -> Result<(SigningKey, VerifyingKey), String> {
    let private_key = SigningKey::random(&mut OsRng);
    let public_key = VerifyingKey::from(&private_key);
    Ok((private_key, public_key))
}

/// 将 ECDSA 的 r、s 转为 DER 格式字节数组(标准签名字段,可被 Go
/// `ecdsa.VerifyASN1` / p256 `PrehashVerifier` 校验)。
///
/// `r`/`s` 为**大端字节**,内部先按 `big.Int.Bytes()` 语义剥离前导零
/// (上游依赖 `big.Int.Bytes()` 的这一性质),再按上游手写规则编码:
/// `0x30 + 总长度 + 0x02 + r长度 + r值 + 0x02 + s长度 + s值`,
/// 高位字节最高位为 1 的正整数前置 `0x00`。上游恒不失败,故返回值不带
/// `Result`。
///
/// ```
/// use rust_utils::auditutil::encode_ecdsa_der;
/// // r = 0x01,s = 0xFF80(高位为 1,补 0x00 前缀)
/// assert_eq!(
///     encode_ecdsa_der(&[0x01], &[0xFF, 0x80]),
///     [0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xFF, 0x80]
/// );
/// ```
pub fn encode_ecdsa_der(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut r_bytes = strip_leading_zeros(r);
    let mut s_bytes = strip_leading_zeros(s);

    // 确保 r/s 是正整数(补 0 前缀)
    if r_bytes.first().is_some_and(|first| first & 0x80 != 0) {
        r_bytes.insert(0, 0x00);
    }
    if s_bytes.first().is_some_and(|first| first & 0x80 != 0) {
        s_bytes.insert(0, 0x00);
    }

    // 拼接 DER 字节
    let mut der = Vec::with_capacity(2 + r_bytes.len() + 2 + s_bytes.len() + 2);
    der.push(0x30); // 序列标签
    der.push((2 + r_bytes.len() + 2 + s_bytes.len()) as u8); // 总长度
    der.push(0x02); // 整数标签(r)
    der.push(r_bytes.len() as u8); // r 长度
    der.extend_from_slice(&r_bytes);
    der.push(0x02); // 整数标签(s)
    der.push(s_bytes.len() as u8); // s 长度
    der.extend_from_slice(&s_bytes);
    der
}

/// `big.Int.Bytes()` 语义:大端绝对值、剥离前导零(全零输入得空切片)。
fn strip_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

/// 生成审计日志的 ECDSA 数字签名(DER 格式)。
///
/// 签名内容:与上游一致的 `signContent` JSON 序列化
/// `{"tenant_id":..,"user_id":..,"sec":..,"nanos":..,"log_hash":".."}`
/// 的 SHA256。`created_at` 为秒级时间戳(`None` 置 `sec=0`、`nanos=0`;
/// 纳秒位恒为 0,见模块头"与上游的差异"第 2 条)。私钥不可为空由引用类型
/// 保证——签名即凭证,调用方不应降级为无签名落库。
pub fn sign_log_content(
    private_key: &SigningKey,
    tenant_id: u32,
    user_id: u32,
    created_at: Option<i64>,
    log_hash: &str,
) -> Result<Vec<u8>, String> {
    let sc = sign_content_json(tenant_id, user_id, created_at.unwrap_or(0), 0, log_hash);
    let sc_hash = Sha256::digest(sc.as_bytes());

    let signature: Signature = private_key
        .sign_prehash(&sc_hash)
        .map_err(|e| format!("ECDSA sign failed: {e}"))?;

    let sig_bytes = signature.to_bytes();
    Ok(encode_ecdsa_der(&sig_bytes[..32], &sig_bytes[32..]))
}

/// 构造与上游 `signContent` 结构体 `json.Marshal` 逐字节一致的签名内容
/// (字段序固定、无空白;字符串按 Go encoding/json 默认转义)。
fn sign_content_json(tenant_id: u32, user_id: u32, sec: i64, nanos: i32, log_hash: &str) -> String {
    format!(
        "{{\"tenant_id\":{tenant_id},\"user_id\":{user_id},\"sec\":{sec},\"nanos\":{nanos},\"log_hash\":\"{}\"}}",
        json_escape_string(log_hash)
    )
}

/// Go `encoding/json.Marshal` 默认字符串转义:引号/反斜杠、控制字符
/// (`\n`/`\r`/`\t` 具名、其余 `\u00xx` 小写十六进制)、HTML 字符
/// (`<`/`>`/`&` → `\u00xx`)以及 U+2028/U+2029。
fn json_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// 小写十六进制编码。
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

// ============================================================================
// tests(移植 sign_test.go / auditutil_test.go 的语义用例)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_strip_line_breaks() {
        // CR/LF 注入剥离:审计字段的日志注入防线
        assert_eq!(strip_line_breaks("alice\r\nbob"), "alicebob");
        assert_eq!(strip_line_breaks("no-breaks"), "no-breaks");
        assert_eq!(strip_line_breaks("\r\n"), "");
        assert_eq!(strip_line_breaks(""), "");
        // 其他控制字符与内容不受影响
        assert_eq!(strip_line_breaks("a\tb\rc\nd\u{0}"), "a\tbcd\u{0}");
    }

    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::signature::Verifier;

    /// 构建 [Go] httptest.NewRequest 的替身请求。
    fn build(remote: &str, headers: &[(&str, &str)]) -> HttpRequest {
        HttpRequest {
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            remote_addr: remote.to_string(),
            body: Vec::new(),
        }
    }

    /// [Go] newTestLog:tenant=7 user=42 action=login,created_at=2025-01-01。
    fn new_test_log() -> AuditLog {
        AuditLog {
            tenant_id: 7,
            user_id: 42,
            action: "login".to_string(),
            created_at: Some(Timestamp {
                seconds: 1735689600,
                nanos: 0,
            }),
            log_hash: None,
            signature: None,
        }
    }

    /// [Go] signContentJSON:与 sign_log_content 相同的签名内容序列化。
    fn sign_content_json_for_verify(
        tenant_id: u32,
        user_id: u32,
        sec: i64,
        nanos: i32,
        log_hash: &str,
    ) -> String {
        sign_content_json(tenant_id, user_id, sec, nanos, log_hash)
    }

    #[test]
    fn test_ip_from_remote_addr() {
        assert_eq!(ip_from_remote_addr("[::1]:7788"), "::1");
        assert_eq!(ip_from_remote_addr("127.0.0.1:7788"), "127.0.0.1");
        assert_eq!(ip_from_remote_addr("127.0.0.1"), "127.0.0.1");
        assert_eq!(ip_from_remote_addr("::1"), "::1");
        assert_eq!(ip_from_remote_addr("127.0.0.1:12456"), "127.0.0.1");
        assert_eq!(ip_from_remote_addr("192.0.2.1:5566"), "192.0.2.1");
        assert_eq!(ip_from_remote_addr("2001:db8::68"), "2001:db8::68");

        assert_eq!(ip_from_remote_addr("192.0.2"), "");
    }

    #[test]
    fn test_client_real_ip_xff_first_valid_ip_wins() {
        let req = build("10.0.0.1:1000", &[("x-forwarded-for", "8.8.8.8, 10.0.0.2")]);
        assert_eq!(client_real_ip(&req), "8.8.8.8");
    }

    #[test]
    fn test_client_real_ip_xff_invalid_entries_skipped() {
        let req = build("10.0.0.1:1000", &[("x-forwarded-for", "garbage, 8.8.8.8")]);
        assert_eq!(client_real_ip(&req), "8.8.8.8");
    }

    #[test]
    fn test_client_real_ip_x_real_ip_fallback() {
        let req = build("10.0.0.1:1000", &[("x-real-ip", "203.0.113.5")]);
        assert_eq!(client_real_ip(&req), "203.0.113.5");
    }

    #[test]
    fn test_client_real_ip_remote_addr_fallback() {
        let req = build("192.0.2.1:5566", &[]);
        assert_eq!(client_real_ip(&req), "192.0.2.1");
    }

    #[test]
    fn test_is_private_ip() {
        for ip in [
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fc00::1",
            "fd12::1", // fc00::/7 的另一半
        ] {
            assert!(is_private_ip(ip), "{ip} 应判定为内网");
        }
        for ip in ["8.8.8.8", "192.0.2.1", "172.32.0.1", "not-an-ip", ""] {
            assert!(!is_private_ip(ip), "{ip} 不应判定为内网");
        }
    }

    #[test]
    fn test_request_id_priority() {
        let mut req = build("10.0.0.1:1000", &[("x-request-id", "req-1")]);
        assert_eq!(request_id(&req), "req-1");

        req.headers.remove("x-request-id");
        req.headers
            .insert("x-correlation-id".to_string(), "corr-1".to_string());
        assert_eq!(request_id(&req), "corr-1");

        req.headers.remove("x-correlation-id");
        req.headers
            .insert("x-fc-request-id".to_string(), "fc-1".to_string());
        assert_eq!(request_id(&req), "fc-1");

        // 无请求头时应生成 GUID
        req.headers.remove("x-fc-request-id");
        assert_eq!(request_id(&req).len(), 32);
    }

    #[test]
    fn test_request_id_generated_is_32_hex() {
        // [Go] assert.Regexp(`^[0-9a-f]{32}$`)
        let generated = new_guid_v4_hex();
        assert_eq!(generated.len(), 32);
        assert!(
            generated
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "应为 32 位小写十六进制: {generated}"
        );
    }

    #[test]
    fn test_parse_username_json_body() {
        let u = parse_username_from_bytes(br#"{"username":"alice","password":"x"}"#).unwrap();
        assert_eq!(u, "alice");
    }

    #[test]
    fn test_parse_username_form_body() {
        let u = parse_username_from_bytes(b"username=bob&password=x").unwrap();
        assert_eq!(u, "bob");
    }

    #[test]
    fn test_parse_username_line_break_injection_stripped() {
        // 与上游一致:反引号原始串中的 \r\n 是字面反斜杠字符,不含真实 CR/LF
        let u = parse_username_from_bytes(br#"{"username":"evil\r\nINJECTED"}"#).unwrap();
        assert!(!u.contains('\r') && !u.contains('\n'), "CR/LF 必须被剥离");
        // 真实 CR/LF 字节必须被剥除,阻断日志行注入
        let v = parse_username_from_bytes(b"{\"username\":\"evil\r\nINJECTED\"}").unwrap();
        assert_eq!(v, "evilINJECTED");
    }

    #[test]
    fn test_parse_username_missing_errors() {
        assert!(parse_username_from_bytes(br#"{"other":"x"}"#).is_err());
        assert!(parse_username_from_bytes(b"").is_err());
    }

    #[test]
    fn test_extract_username_from_request_and_repeat_read() {
        let req = HttpRequest {
            headers: HashMap::new(),
            remote_addr: "192.0.2.1:5566".to_string(),
            body: br#"{"username":"carol"}"#.to_vec(),
        };
        assert_eq!(extract_username_from_request(&req).unwrap(), "carol");
        // Body 必须已"恢复",可重复读取(结构体字段天然满足)
        assert_eq!(extract_username_from_request(&req).unwrap(), "carol");
        assert_eq!(req.body, br#"{"username":"carol"}"#);
    }

    #[test]
    fn test_extract_username_form_fallback_returns_empty_without_error() {
        // 上游:二次 ParseQuery 成功但无 username 键 → ("", nil)
        let req = HttpRequest {
            headers: HashMap::new(),
            remote_addr: "192.0.2.1:5566".to_string(),
            body: b"foo=bar".to_vec(),
        };
        assert_eq!(extract_username_from_request(&req).unwrap(), "");
    }

    #[test]
    fn test_detect_platform_from_ua() {
        let cases = [
            ("", PLATFORM_OTHER),
            ("okhttp/4.9.0", PLATFORM_ANDROID_APP),
            ("Mozilla/5.0 (Linux; Android 10; wv)", PLATFORM_ANDROID_APP),
            ("com.example.app/1.0 (Android)", PLATFORM_ANDROID_APP),
            ("MyApp/1.0 CFNetwork/1206 Darwin/20.0.0", PLATFORM_IOS_APP),
            ("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0", PLATFORM_IOS_APP),
            (
                "Mozilla/5.0 (Windows NT 10.0) Electron/9.0",
                PLATFORM_DESKTOP_WINDOWS,
            ),
            ("Mozilla/5.0 (Macintosh) Electron/9.0", PLATFORM_DESKTOP_MAC),
            (
                "Mozilla/5.0 (X11; Linux) Electron/9.0",
                PLATFORM_DESKTOP_LINUX,
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                PLATFORM_WEB,
            ),
        ];
        for (ua, want) in cases {
            assert_eq!(detect_platform_from_ua(ua), want, "UA {ua:?}");
        }
    }

    #[test]
    fn test_hash_log_deterministic() {
        // 同消息同哈希
        assert_eq!(
            hash_log(&new_test_log(), &[]),
            hash_log(&new_test_log(), &[])
        );
    }

    #[test]
    fn test_hash_log_excludes_hash_and_signature_fields() {
        let mut log = new_test_log();
        let base = hash_log(&log, &[]);

        // 填上 log_hash / signature 后哈希不变——这两字段被排除
        log.log_hash = Some("deadbeef".to_string());
        log.signature = Some(vec![1, 2, 3]);
        assert_eq!(
            base,
            hash_log(&log, &[]),
            "log_hash/signature 不得影响哈希值"
        );

        // 其他字段变化必须改变哈希
        log.action = "logout".to_string();
        assert_ne!(base, hash_log(&log, &[]));
    }

    #[test]
    fn test_hash_log_original_message_unmodified() {
        let mut log = new_test_log();
        log.log_hash = Some("keepme".to_string());
        let _ = hash_log(&log, &[]);
        assert_eq!(
            log.log_hash.as_deref(),
            Some("keepme"),
            "哈希不得修改原消息"
        );
    }

    #[test]
    fn test_hash_log_custom_exclude_fields() {
        let log = new_test_log();
        let base = hash_log(&log, &[]);

        assert_eq!(
            base,
            hash_log(&log, &["log_hash", "logHash", "signature"]),
            "显式默认排除集应等价"
        );
        assert_ne!(
            base,
            hash_log(&log, &["tenant_id"]),
            "排除 tenant_id 后哈希必须不同"
        );
    }

    #[test]
    fn test_hash_log_empty_message_is_sha256_of_empty_bytes() {
        // prost 确定性序列化的锚点:全缺省消息编码为空字节串
        assert_eq!(
            hash_log(&AuditLog::default(), &[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_audit_log_wire_format_and_roundtrip() {
        // 手工拼装期望字节,钉死字段号/类型/顺序:
        // tenant_id=7, user_id=42, action="login",
        // created_at=Timestamp{seconds=1735689600, nanos=0}(nanos 缺省不编码)
        let varint = |mut n: u64| {
            let mut out = Vec::new();
            loop {
                let b = (n & 0x7F) as u8;
                n >>= 7;
                out.push(if n == 0 { b } else { b | 0x80 });
                if n == 0 {
                    break;
                }
            }
            out
        };
        let ts_payload = [vec![0x08], varint(1735689600)].concat();
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x08, 0x07]); // tenant_id
        expected.extend_from_slice(&[0x10, 0x2A]); // user_id
        expected.extend_from_slice(&[0x1A, 0x05, b'l', b'o', b'g', b'i', b'n']); // action
        expected.push(0x22); // created_at(message)
        expected.push(ts_payload.len() as u8);
        expected.extend_from_slice(&ts_payload);

        let log = new_test_log();
        assert_eq!(log.encode_to_vec(), expected);

        // optional 字段(15/16)编解码回环
        let mut log = log;
        log.log_hash = Some("deadbeef".to_string());
        log.signature = Some(vec![1, 2, 3]);
        let decoded = AuditLog::decode(&log.encode_to_vec()[..]).unwrap();
        assert_eq!(decoded, log);
        assert_eq!(decoded.log_hash.as_deref(), Some("deadbeef"));
        assert_eq!(decoded.signature, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_encode_ecdsa_der_golden_vectors() {
        // r = 0x01;s = 0xFF80 高位为 1 → 补 0x00
        assert_eq!(
            encode_ecdsa_der(&[0x01], &[0xFF, 0x80]),
            [0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xFF, 0x80]
        );
        // big.Int.Bytes() 语义:前导零先剥离,再按高位规则补前缀
        assert_eq!(
            encode_ecdsa_der(&[0x00, 0x80, 0x01], &[0x00, 0x01]),
            [0x30, 0x08, 0x02, 0x03, 0x00, 0x80, 0x01, 0x02, 0x01, 0x01]
        );
        // 零值:INTEGER 长度为 0(上游 r/s == 0 的极端分支)
        assert_eq!(
            encode_ecdsa_der(&[0x00], &[0x00]),
            [0x30, 0x04, 0x02, 0x00, 0x02, 0x00]
        );
    }

    #[test]
    fn test_encode_ecdsa_der_matches_rustcrypto() {
        // 手写 DER 与 RustCrypto 自带的 DER 编码器逐字节对拍
        use p256::ecdsa::signature::SignatureEncoding;
        use p256::ecdsa::DerSignature;
        for i in 0..8u64 {
            let (sk, _) = generate_ecdsa_key_pair().unwrap();
            let msg = Sha256::digest(format!("audit-der-cross-check-{i}").as_bytes());
            let sig: Signature = sk.sign_prehash(&msg).unwrap();
            let bytes = sig.to_bytes();
            let mine = encode_ecdsa_der(&bytes[..32], &bytes[32..]);
            let reference = DerSignature::from(sig);
            assert_eq!(mine, reference.to_vec(), "DER 编码与 RustCrypto 不一致");
            // 且能被 RustCrypto 的 ASN.1 解析器解码
            assert!(DerSignature::try_from(&mine[..]).is_ok());
        }
    }

    #[test]
    fn test_sign_log_content_roundtrip_and_tamper() {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        let (priv_key, pub_key) = generate_ecdsa_key_pair().unwrap();

        let log_hash = hash_log(&new_test_log(), &[]);

        let sig = sign_log_content(&priv_key, 7, 42, Some(1735689600), &log_hash).unwrap();
        assert!(!sig.is_empty());
        assert_eq!(sig[0], 0x30, "签名应为 DER 序列(0x30 开头)");

        // 签名必须可通过 DER 校验(与签名内容逐字节一致的重算路径)
        let sc_json = sign_content_json_for_verify(7, 42, 1735689600, 0, &log_hash);
        let sc_hash = Sha256::digest(sc_json.as_bytes());

        let der_sig = p256::ecdsa::DerSignature::try_from(&sig[..]).unwrap();
        let parsed: Signature = Signature::try_from(der_sig).unwrap();

        // 标准 Verifier:内部对内容做 sha256 后验签(Go verifyECDSA 的等价物)
        pub_key
            .verify(sc_json.as_bytes(), &parsed)
            .expect("签名必须能被标准验签");
        // PrehashVerifier:直接对 sha256 结果验签(Go ecdsa.VerifyASN1 的等价物)
        pub_key
            .verify_prehash(&sc_hash, &parsed)
            .expect("prehash 验签必须成功");

        // 内容篡改后验签必须失败
        let tampered = sign_content_json_for_verify(7, 42, 1735689600, 0, "tampered");
        assert!(
            pub_key.verify(tampered.as_bytes(), &parsed).is_err(),
            "篡改 log_hash 后验签必须失败"
        );
    }

    #[test]
    fn test_sign_log_content_wrong_key_fails() {
        let (_sk_a, vk_a) = generate_ecdsa_key_pair().unwrap();
        let sk_b = SigningKey::random(&mut OsRng);
        let vk_b = VerifyingKey::from(&sk_b);
        let sig = sign_log_content(&sk_b, 7, 42, Some(1735689600), "hash").unwrap();
        let parsed: Signature =
            Signature::try_from(p256::ecdsa::DerSignature::try_from(&sig[..]).unwrap()).unwrap();
        let content = sign_content_json_for_verify(7, 42, 1735689600, 0, "hash");
        assert!(
            vk_a.verify(content.as_bytes(), &parsed).is_err(),
            "他人密钥的签名不得通过验签"
        );
        // 自验通过,确证失败源于密钥不匹配而非签名内容
        assert!(vk_b.verify(content.as_bytes(), &parsed).is_ok());
    }

    #[test]
    fn test_generate_ecdsa_key_pair_usable() {
        let (sk, vk) = generate_ecdsa_key_pair().unwrap();
        // 密钥对内部一致:签名可用公钥验证
        let digest = Sha256::digest(b"audit-keygen-check");
        let sig: Signature = sk.sign_prehash(&digest).unwrap();
        assert!(vk.verify_prehash(&digest, &sig).is_ok());
    }
}
