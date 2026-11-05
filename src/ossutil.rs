//! 对象存储辅助(移植自 go-utils `ossutil` 包:constants.go + utils.go),feature `ossutil`。
//!
//! 覆盖能力:MIME/扩展名 → 桶名映射、MIME → 扩展名映射、魔数文件类型检测
//! ([`detect_file_type`])、文件名生成策略(UUID / 内容 SHA-256 / HMAC-内容 /
//! 时间基,按 [`GenerateFileNameType`] 分派)、对象名与 URL 拼装
//! ([`join_object_name`] / [`join_object_url`] / [`replace_endpoint_host`])、
//! 扩展名补全([`ensure_file_extension`])、上传守卫
//! ([`is_allowed_mime_type`] / [`is_file_directory_safe`])。
//!
//! 对上游的适配点:
//! - `id.NewGUIDv4` 改由 `getrandom` 自实现 UUID v4(版本/变体位照 RFC 4122
//!   置位);上游 ossutil 一律使用去横线形式(32 个十六进制字符)。
//! - `SetHMACSecret` 的包级密钥改为 `static RwLock<Option<Vec<u8>>>`;
//!   未注入密钥时 HMAC 命名策略按上游语义退化为 UUID 命名。
//! - 为让 [`detect_file_type`] 的行为不依赖宿主机,内嵌复刻了 Go 标准库的
//!   `mime.ParseMediaType`、`mime.ExtensionsByType`(仅内置映射表,**不**读取
//!   系统 `/etc/mime.types` 等 OS 级数据库)与 `net/http.DetectContentType`
//!   (WHATWG mimesniff 签名表逐条照抄)。Go 版在 Linux 上会叠加 OS 级 MIME
//!   映射,属平台差异;本移植恒定使用内置表,结果跨平台确定。
//! - `GenerateFileNameType` 由上游的字符串类型改为枚举(未知字符串按上游
//!   `GenerateFileName` 的 default 分支回落到 UUID,见 `From<&str>`);
//!   `JoinObjectName` 的 `*string` 参数改为 `Option<&str>`。
//! - 上游函数名里的历史拼写(`GeneraUUIDFileName`、`GeneraContentSHA265FileName`)
//!   在 Rust 侧按原义保留为 `genera_*` 前缀,便于对照。
//!
//! ```
//! use rust_utils::ossutil;
//!
//! // MIME → 桶
//! assert_eq!(ossutil::content_type_to_bucket_name("image/png"), "images");
//! assert_eq!(ossutil::content_type_to_bucket_name("application/pdf"), "docs");
//! assert_eq!(ossutil::content_type_to_bucket_name("not-a-mime"), "files");
//!
//! // 魔数检测
//! let png = b"\x89PNG\r\n\x1a\n\x00\x00".to_vec();
//! assert_eq!(ossutil::detect_file_type(&png), ("image/png".to_string(), ".png".to_string()));
//!
//! // 上传守卫
//! assert!(ossutil::is_allowed_mime_type("application/pdf"));
//! assert!(!ossutil::is_allowed_mime_type("application/x-msdownload"));
//! assert!(ossutil::is_file_directory_safe("images/2026"));
//! assert!(!ossutil::is_file_directory_safe("../etc"));
//! ```

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

// ============================================================================
// 上传安全约束常量(移植自 constants.go)
// ============================================================================

/// 单次直传文件最大字节数(50 MiB)。
pub const MAX_UPLOAD_SIZE: i64 = 50 << 20;

/// 从外部 URL 下载文件的最大字节数(50 MiB),用于 SSRF 路径防 DoS。
pub const MAX_DOWNLOAD_SIZE: i64 = 50 << 20;

/// 允许上传的 MIME 类型前缀白名单。内容嗅探得到 MIME 后需命中其中之一
/// (或 [`ALLOWED_EXACT_MIME_TYPES`] 中的精确值)才允许上传。
pub const ALLOWED_MIME_PREFIXES: &[&str] = &[
    "image/", // png / jpg / gif / webp / bmp ...
    "video/", // mp4 / webm / quicktime ...
    "audio/", // mpeg / wav / ogg ...
              // 常见文档类型(精确值而非前缀)见 ALLOWED_EXACT_MIME_TYPES
];

/// 允许上传的精确 MIME 类型(非前缀匹配)。
pub const ALLOWED_EXACT_MIME_TYPES: &[&str] = &[
    "text/plain",
    "text/markdown",
    "application/json",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    // Office 文档
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
];

// ============================================================================
// 桶名常量
// ============================================================================

/// 图片桶。
pub const BUCKET_IMAGES: &str = "images";
/// 视频桶。
pub const BUCKET_VIDEOS: &str = "videos";
/// 音频桶。
pub const BUCKET_AUDIOS: &str = "audios";
/// 文档桶。
pub const BUCKET_DOCS: &str = "docs";
/// 默认桶。
pub const BUCKET_FILES: &str = "files";

// ============================================================================
// 文件名生成策略(上游 `GenerateFileNameType` 字符串枚举)
// ============================================================================

/// 文件名生成策略。
///
/// 上游为 `type GenerateFileNameType string`,此处改为枚举;
/// [`GenerateFileNameType::as_str`] 保留上游字符串值以便线上协议兼容。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenerateFileNameType {
    /// `uuid` —— 随机 UUID,最大唯一性、低延迟、不泄露内容指纹。
    Uuid,
    /// `content_sha256` —— 内容 SHA-256 摘要,确定性、可去重/校验,
    /// 但可被离线匹配(泄露内容指纹)。
    ContentSha256,
    /// `hmac_content` —— 先 SHA-256 再以全局密钥做 HMAC;可去重且抗探测;
    /// 未注入密钥时按上游语义退化为 UUID 命名。
    HmacContent,
    /// `time_base` —— 纳秒时间戳 + 8 位十六进制随机后缀,可读、按时间排序。
    TimeBase,
}

impl GenerateFileNameType {
    /// 对应的上游字符串值。
    pub fn as_str(self) -> &'static str {
        match self {
            GenerateFileNameType::Uuid => "uuid",
            GenerateFileNameType::ContentSha256 => "content_sha256",
            GenerateFileNameType::HmacContent => "hmac_content",
            GenerateFileNameType::TimeBase => "time_base",
        }
    }
}

/// 从上游字符串值构造策略;未知值按上游 `GenerateFileName` 的 default 分支
/// 回落到 [`GenerateFileNameType::Uuid`]。
impl From<&str> for GenerateFileNameType {
    fn from(s: &str) -> Self {
        match s {
            "content_sha256" => GenerateFileNameType::ContentSha256,
            "hmac_content" => GenerateFileNameType::HmacContent,
            "time_base" => GenerateFileNameType::TimeBase,
            // "uuid" 与其他未知值
            _ => GenerateFileNameType::Uuid,
        }
    }
}

// ============================================================================
// HMAC 内容命名策略的全局密钥(上游包级变量的线程安全版)
// ============================================================================

/// 供 [`GenerateFileNameType::HmacContent`] 命名策略使用的内容指纹混淆密钥。
/// 默认为空:该策略下退化为 UUID 命名。部署方应在启动阶段通过
/// [`set_hmac_secret`] 注入。
static HMAC_SECRET: RwLock<Option<Vec<u8>>> = RwLock::new(None);

/// 注入 HMAC 内容命名策略使用的密钥(应在服务启动阶段调用一次)。
/// 上游 `SetHMACSecret`:值会被完整拷贝。
pub fn set_hmac_secret(secret: &[u8]) {
    // 写锁不会在持锁期间 panic,不存在毒锁;此处仍做兜底恢复以策安全。
    let mut guard = HMAC_SECRET.write().unwrap_or_else(|e| e.into_inner());
    *guard = Some(secret.to_vec());
}

/// 读取全局 HMAC 密钥(未设置时返回空串,调用方以 `is_empty` 判定回退)。
fn global_hmac_secret() -> Vec<u8> {
    let guard = HMAC_SECRET.read().unwrap_or_else(|e| e.into_inner());
    guard.as_deref().unwrap_or(&[]).to_vec()
}

// ============================================================================
// Go mime.ParseMediaType 的行为复刻
// ============================================================================

/// RFC 2045 tspecials:不允许出现在 token 中的字符。
fn is_tspecial(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'@' | b',' | b';' | b':' | b'\\' | b'"' | b'[' | b']' | b'?'
            | b'=' | b'/'
    )
}

/// RFC 2045 token 字符:ASCII 可见字符,排除空格、控制符与 tspecials。
fn is_token_char(b: u8) -> bool {
    (0x21..0x7f).contains(&b) && !is_tspecial(b)
}

/// 从字符串头部消费一个 token,返回 (token, 剩余)。
/// 对应 Go mime.consumeToken;消费失败时 token 为空串。
fn consume_token(v: &str) -> (&str, &str) {
    for (i, &b) in v.as_bytes().iter().enumerate() {
        if !is_token_char(b) {
            return (&v[..i], &v[i..]);
        }
    }
    (v, "")
}

/// 消费一个 RFC 2045 "值"(token 或带引号的字符串),返回 (值, 剩余)。
/// 对应 Go mime.consumeValue,含 MSIE 未转义反斜杠的兼容行为:
/// 未能闭合引号或出现裸 CR/LF 时整体失败。
fn consume_value(v: &str) -> (String, String) {
    if v.is_empty() {
        return (String::new(), v.to_string());
    }
    if !v.starts_with('"') {
        let (tok, rest) = consume_token(v);
        return (tok.to_string(), rest.to_string());
    }
    let bytes = v.as_bytes();
    let mut buf: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 1;
    while i < bytes.len() {
        let r = bytes[i];
        if r == b'"' {
            // 结束引号;'"' 为 ASCII,切点必在字符边界上
            return (String::from_utf8_lossy(&buf).into_owned(), v[i + 1..].to_string());
        }
        if r == b'\\' && i + 1 < bytes.len() && is_tspecial(bytes[i + 1]) {
            // 形如 "\"."" 的合法转义;MSIE 的裸反斜杠路径按 Go 同款规则处理
            buf.push(bytes[i + 1]);
            i += 2;
            continue;
        }
        if r == b'\r' || r == b'\n' {
            return (String::new(), v.to_string());
        }
        buf.push(r);
        i += 1;
    }
    // 没找到结束引号
    (String::new(), v.to_string())
}

/// 消费一个 `; name=value` 形式的媒体类型参数,返回 (参数名, 值, 剩余)。
/// 对应 Go mime.consumeMediaParam;失败时返回原串且参数名为空。
fn consume_media_param(v: &str) -> (String, String, String) {
    let ws = |c: char| c.is_whitespace();
    let mut rest = v.trim_start_matches(ws);
    let Some(after_semi) = rest.strip_prefix(';') else {
        return (String::new(), String::new(), v.to_string());
    };
    rest = after_semi.trim_start_matches(ws);
    let (param, r) = consume_token(rest);
    let param = param.to_lowercase();
    if param.is_empty() {
        return (String::new(), String::new(), v.to_string());
    }
    rest = r.trim_start_matches(ws);
    let Some(after_eq) = rest.strip_prefix('=') else {
        return (String::new(), String::new(), v.to_string());
    };
    rest = after_eq.trim_start_matches(ws);
    let (value, rest2) = consume_value(rest);
    if value.is_empty() && rest2 == rest {
        // 一个字符都没消费出去,视为失败
        return (String::new(), String::new(), v.to_string());
    }
    (param, value, rest2)
}

/// 校验 `type/subtype` 主类型结构,对应 Go mime.checkMediaTypeDisposition。
/// 单个 token(无斜杠)同样合法——"not-a-mime" 由此通过解析、再由桶映射的
/// 主类型分派落入默认桶,与上游一致。
fn check_media_type_disposition(s: &str) -> bool {
    let (typ, mut rest) = consume_token(s);
    if typ.is_empty() {
        return false; // mime: no media type
    }
    if rest.is_empty() {
        return true;
    }
    let Some(r) = rest.strip_prefix('/') else {
        return false; // mime: expected slash after first token
    };
    rest = r;
    let (subtype, rest2) = consume_token(rest);
    if subtype.is_empty() {
        return false; // mime: expected token after slash
    }
    rest2.is_empty() // 剩余内容非空 → mime: unexpected content after media subtype
}

/// 复刻 Go `mime.ParseMediaType`:剥离参数(含空白)并将媒体类型整体转小写。
/// 返回 `None` 表示解析失败(畸形类型串、非法参数、重复且不等的参数名),
/// 调用方按上游语义落默认桶/拒绝。
///
/// 简化说明:RFC 2231 星号续传参数(`foo*0` / `foo*0*`)不做拼接与 percent
/// 解码,按普通参数名收录;上游对 `multipart/*`、`charset*`、`boundary*`
/// 的跳过行为在本模块关注的"解析成败"维度上等价。
fn parse_media_type(v: &str) -> Option<String> {
    let base = v.split(';').next().unwrap_or("");
    let mediatype = base.trim().to_lowercase();

    if !check_media_type_disposition(&mediatype) {
        return None;
    }

    let mut params: Vec<(String, String)> = Vec::new();
    let ws = |c: char| c.is_whitespace();
    let mut rest = v[base.len()..].to_string();
    loop {
        if rest.trim_start_matches(ws).is_empty() {
            break;
        }
        let (key, value, next) = consume_media_param(&rest);
        if key.is_empty() {
            if rest.trim() == ";" {
                // 忽略结尾多余的分号,不是错误
                break;
            }
            return None; // mime: invalid media parameter
        }
        // 重复参数名不合法,但值相等时容忍(与上游一致)
        if let Some(prev) = params.iter().find(|(k, _)| *k == key) {
            if prev.1 != value {
                return None; // mime: duplicate parameter name
            }
        } else {
            params.push((key, value));
        }
        rest = next;
    }

    Some(mediatype)
}

// ============================================================================
// Go mime.ExtensionsByType 的行为复刻(仅内置表)
// ============================================================================

/// Go `mime` 包 `builtinTypesLower` 的逐条复刻(扩展名 → MIME,含 charset 参数)。
/// 上游在 Linux 上还会叠加系统 mime.types/globs2 的映射,本移植不读取 OS 数据。
const BUILTIN_TYPES_LOWER: &[(&str, &str)] = &[
    (".ai", "application/postscript"),
    (".apk", "application/vnd.android.package-archive"),
    (".apng", "image/apng"),
    (".avif", "image/avif"),
    (".bin", "application/octet-stream"),
    (".bmp", "image/bmp"),
    (".com", "application/octet-stream"),
    (".css", "text/css; charset=utf-8"),
    (".csv", "text/csv; charset=utf-8"),
    (".doc", "application/msword"),
    (
        ".docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    (".ehtml", "text/html; charset=utf-8"),
    (".eml", "message/rfc822"),
    (".eps", "application/postscript"),
    (".exe", "application/octet-stream"),
    (".flac", "audio/flac"),
    (".gif", "image/gif"),
    (".gz", "application/gzip"),
    (".htm", "text/html; charset=utf-8"),
    (".html", "text/html; charset=utf-8"),
    (".ico", "image/vnd.microsoft.icon"),
    (".ics", "text/calendar; charset=utf-8"),
    (".jfif", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".jpg", "image/jpeg"),
    (".js", "text/javascript; charset=utf-8"),
    (".json", "application/json"),
    (".m4a", "audio/mp4"),
    (".mjs", "text/javascript; charset=utf-8"),
    (".mp3", "audio/mpeg"),
    (".mp4", "video/mp4"),
    (".oga", "audio/ogg"),
    (".ogg", "audio/ogg"),
    (".ogv", "video/ogg"),
    (".opus", "audio/ogg"),
    (".pdf", "application/pdf"),
    (".pjp", "image/jpeg"),
    (".pjpeg", "image/jpeg"),
    (".png", "image/png"),
    (".ppt", "application/vnd.ms-powerpoint"),
    (
        ".pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
    (".ps", "application/postscript"),
    (".rdf", "application/rdf+xml"),
    (".rtf", "application/rtf"),
    (".shtml", "text/html; charset=utf-8"),
    (".svg", "image/svg+xml"),
    (".text", "text/plain; charset=utf-8"),
    (".tif", "image/tiff"),
    (".tiff", "image/tiff"),
    (".txt", "text/plain; charset=utf-8"),
    (".vtt", "text/vtt; charset=utf-8"),
    (".wasm", "application/wasm"),
    (".wav", "audio/wav"),
    (".weba", "audio/webm"),
    (".webm", "video/webm"),
    (".webp", "image/webp"),
    (".xbl", "text/xml; charset=utf-8"),
    (".xbm", "image/x-xbitmap"),
    (".xht", "application/xhtml+xml"),
    (".xhtml", "application/xhtml+xml"),
    (".xls", "application/vnd.ms-excel"),
    (
        ".xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    (".xml", "text/xml; charset=utf-8"),
    (".xsl", "text/xml; charset=utf-8"),
    (".zip", "application/zip"),
];

/// 反查表:MIME 类型 → 排序后的扩展名列表(均带前导点)。
/// 构建逻辑对应 Go mime.setMimeTypes 的 extensions 反向索引。
fn extensions_map() -> &'static HashMap<String, Vec<&'static str>> {
    static MAP: OnceLock<HashMap<String, Vec<&'static str>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m: HashMap<String, Vec<&'static str>> = HashMap::new();
        for (ext, typ) in BUILTIN_TYPES_LOWER {
            let just_type = parse_media_type(typ).unwrap_or_else(|| (*typ).to_string());
            m.entry(just_type).or_default().push(ext);
        }
        // Go 在 ExtensionsByType 调用时排序,这里初始化时排好,结果一致
        for exts in m.values_mut() {
            exts.sort_unstable();
        }
        m
    })
}

/// 复刻 Go `mime.ExtensionsByType`:返回该 MIME 类型关联的扩展名
/// (带前导点、已排序);类型无法解析或查无映射时返回 `None`。
fn extensions_by_type(typ: &str) -> Option<&'static [&'static str]> {
    let just_type = parse_media_type(typ)?;
    extensions_map()
        .get(just_type.as_str())
        .map(|v| v.as_slice())
}

// ============================================================================
// Go net/http DetectContentType(WHATWG mimesniff)的行为复刻
// ============================================================================

/// 嗅探算法最多使用前 512 字节(Go net/http internal.SniffLen)。
const SNIFF_LEN: usize = 512;

/// WHATWG mimesniff 的空白字节。
fn is_ws(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

/// WHATWG mimesniff 的标签终止字节(0xTT)。
fn is_tt(b: u8) -> bool {
    matches!(b, b' ' | b'>')
}

/// 嗅探签名,对应 Go net/http/internal sniffSignatures 的分类。
enum SniffSig {
    /// HTML 标签前缀(大小写不敏感,后跟 0xTT)。
    Html(&'static str),
    /// 精确前缀。
    Exact(&'static [u8], &'static str),
    /// 掩码匹配:逐字节 `data[i] & mask[i] == pat[i]`。
    Masked {
        mask: &'static [u8],
        pat: &'static [u8],
        skip_ws: bool,
        ct: &'static str,
    },
    /// MP4 ftyp box 的专门检测。
    Mp4,
    /// 兜底:按二进制控制字节判定 text/plain 或失败(最终落 octet-stream)。
    Text,
}

use self::SniffSig::*;

/// 嗅探签名表,逐条照抄 Go net/http/internal sniff.go(顺序敏感,勿调整)。
const SNIFF_SIGNATURES: &[SniffSig] = &[
    Html("<!DOCTYPE HTML"),
    Html("<HTML"),
    Html("<HEAD"),
    Html("<SCRIPT"),
    Html("<IFRAME"),
    Html("<H1"),
    Html("<DIV"),
    Html("<FONT"),
    Html("<TABLE"),
    Html("<A"),
    Html("<STYLE"),
    Html("<TITLE"),
    Html("<B"),
    Html("<BODY"),
    Html("<BR"),
    Html("<P"),
    Html("<!--"),
    Masked {
        mask: b"\xFF\xFF\xFF\xFF\xFF",
        pat: b"<?xml",
        skip_ws: true,
        ct: "text/xml; charset=utf-8",
    },
    Exact(b"%PDF-", "application/pdf"),
    Exact(b"%!PS-Adobe-", "application/postscript"),
    // UTF BOM
    Masked {
        mask: b"\xFF\xFF\x00\x00",
        pat: b"\xFE\xFF\x00\x00",
        skip_ws: false,
        ct: "text/plain; charset=utf-16be",
    },
    Masked {
        mask: b"\xFF\xFF\x00\x00",
        pat: b"\xFF\xFE\x00\x00",
        skip_ws: false,
        ct: "text/plain; charset=utf-16le",
    },
    Masked {
        mask: b"\xFF\xFF\xFF\x00",
        pat: b"\xEF\xBB\xBF\x00",
        skip_ws: false,
        ct: "text/plain; charset=utf-8",
    },
    // 图像类型(上游注释:曾按 draft-ietf-websec-mime-sniff-03 返回
    // "image/vnd.microsoft.icon",现按 WHATWG §6.2 统一为 "image/x-icon")
    Exact(b"\x00\x00\x01\x00", "image/x-icon"),
    Exact(b"\x00\x00\x02\x00", "image/x-icon"),
    Exact(b"BM", "image/bmp"),
    Exact(b"GIF87a", "image/gif"),
    Exact(b"GIF89a", "image/gif"),
    Masked {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00WEBPVP",
        skip_ws: false,
        ct: "image/webp",
    },
    Exact(b"\x89PNG\x0D\x0A\x1A\x0A", "image/png"),
    Exact(b"\xFF\xD8\xFF", "image/jpeg"),
    // 音频与视频类型(顺序遵循 WHATWG mimesniff §6.1 的音频/视频匹配次序)
    Masked {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        pat: b"FORM\x00\x00\x00\x00AIFF",
        skip_ws: false,
        ct: "audio/aiff",
    },
    Masked {
        mask: b"\xFF\xFF\xFF",
        pat: b"ID3",
        skip_ws: false,
        ct: "audio/mpeg",
    },
    Masked {
        mask: b"\xFF\xFF\xFF\xFF\xFF",
        pat: b"OggS\x00",
        skip_ws: false,
        ct: "application/ogg",
    },
    Masked {
        mask: b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        pat: b"MThd\x00\x00\x00\x06",
        skip_ws: false,
        ct: "audio/midi",
    },
    Masked {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00AVI ",
        skip_ws: false,
        ct: "video/avi",
    },
    Masked {
        mask: b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        pat: b"RIFF\x00\x00\x00\x00WAVE",
        skip_ws: false,
        ct: "audio/wave",
    },
    // WHATWG mimesniff §6.2.0.2 video/mp4
    Mp4,
    // WHATWG mimesniff §6.2.0.3 video/webm
    Exact(b"\x1A\x45\xDF\xA3", "video/webm"),
    // 字体类型
    Masked {
        // 34 个 NUL 字节后跟 "LP"
        pat: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP",
        // 34 个 NUL 字节后跟任意两字节
        mask: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF",
        skip_ws: false,
        ct: "application/vnd.ms-fontobject",
    },
    Exact(b"\x00\x01\x00\x00", "font/ttf"),
    Exact(b"OTTO", "font/otf"),
    Exact(b"ttcf", "font/collection"),
    Exact(b"wOFF", "font/woff"),
    Exact(b"wOF2", "font/woff2"),
    // 压缩包类型
    Exact(b"\x1F\x8B\x08", "application/x-gzip"),
    Exact(b"PK\x03\x04", "application/zip"),
    // RAR 签名按 RAR Labs 官方定义(与 MIME 规范的笔误不同,见上游注释)
    Exact(b"Rar!\x1A\x07\x00", "application/x-rar-compressed"), // RAR v1.5-v4.0
    Exact(b"Rar!\x1A\x07\x01\x00", "application/x-rar-compressed"), // RAR v5+
    Exact(b"\x00\x61\x73\x6D", "application/wasm"),
    Text, // 必须最后
];

/// HTML 签名匹配:跳过前导空白后做大小写不敏感前缀比较,
/// 且签名后的首字节必须是标签终止字节(0xTT)。
fn match_html(sig: &str, data: &[u8], first_non_ws: usize) -> &'static str {
    let data = &data[first_non_ws..];
    if data.len() < sig.len() + 1 {
        return "";
    }
    for (i, &b) in sig.as_bytes().iter().enumerate() {
        let mut db = data[i];
        if b.is_ascii_uppercase() {
            db &= 0xDF; // 数据字节归一为大写
        }
        if b != db {
            return "";
        }
    }
    if !is_tt(data[sig.len()]) {
        return "";
    }
    "text/html; charset=utf-8"
}

/// 掩码签名匹配(WHATWG mimesniff §6 的逐字节掩码比较)。
fn match_masked(
    mask: &[u8],
    pat: &[u8],
    skip_ws: bool,
    ct: &'static str,
    data: &[u8],
    first_non_ws: usize,
) -> &'static str {
    let data = if skip_ws { &data[first_non_ws..] } else { data };
    if pat.len() != mask.len() || data.len() < pat.len() {
        return "";
    }
    for (i, &pb) in pat.iter().enumerate() {
        if data[i] & mask[i] != pb {
            return "";
        }
    }
    ct
}

/// MP4 ftyp box 检测(WHATWG mimesniff §6.2.0.2):box 大小为 4 的倍数且
/// 不超过数据长度,box 类型为 "ftyp",brand 列表(跳过 4 字节版本号)中
/// 出现 "mp4" 前缀才判为 video/mp4。
fn match_mp4(data: &[u8]) -> &'static str {
    if data.len() < 12 {
        return "";
    }
    let box_size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    // 保留 Go 原式(box_size % 4 != 0);is_multiple_of 需要 1.87+,高于本 crate MSRV
    #[allow(clippy::manual_is_multiple_of)]
    if data.len() < box_size || box_size % 4 != 0 {
        return "";
    }
    if data[4..8] != *b"ftyp" {
        return "";
    }
    let mut st = 8;
    while st < box_size {
        if st != 12 {
            // 跳过对应 "major brand" 版本号的四个字节
            if data[st..st + 3] == *b"mp4" {
                return "video/mp4";
            }
        }
        st += 4;
    }
    ""
}

/// 兜底文本检测(WHATWG mimesniff §5 步骤 4):出现二进制控制字节则不匹配
/// (调用方最终回落 application/octet-stream),否则判为 UTF-8 文本。
fn match_text(data: &[u8], first_non_ws: usize) -> &'static str {
    for &b in &data[first_non_ws..] {
        if b <= 0x08 || b == 0x0B || (0x0E..=0x1A).contains(&b) || (0x1C..=0x1F).contains(&b) {
            return "";
        }
    }
    "text/plain; charset=utf-8"
}

/// 复刻 Go `http.DetectContentType`(WHATWG mimesniff 算法):最多看前
/// [`SNIFF_LEN`] 字节;恒返回一个合法 MIME,无法细分时为
/// `application/octet-stream`。
fn detect_content_type(data: &[u8]) -> String {
    let data = if data.len() > SNIFF_LEN {
        &data[..SNIFF_LEN]
    } else {
        data
    };

    // 首个非空白字节的下标
    let mut first_non_ws = 0;
    while first_non_ws < data.len() && is_ws(data[first_non_ws]) {
        first_non_ws += 1;
    }

    for sig in SNIFF_SIGNATURES {
        let ct = match sig {
            Html(h) => match_html(h, data, first_non_ws),
            Exact(s, ct) => {
                if data.starts_with(s) {
                    ct
                } else {
                    ""
                }
            }
            Masked {
                mask,
                pat,
                skip_ws,
                ct,
            } => match_masked(mask, pat, *skip_ws, ct, data, first_non_ws),
            Mp4 => match_mp4(data),
            Text => match_text(data, first_non_ws),
        };
        if !ct.is_empty() {
            return ct.to_string();
        }
    }

    "application/octet-stream".to_string() // 兜底
}

// ============================================================================
// 桶名映射(移植自 utils.go)
// ============================================================================

/// 根据文件类型获取存储桶名称(上游 `ContentTypeToBucketName`)。
///
/// 空串/纯空白直接落默认桶;解析 media type 忽略参数(如 charset),
/// 解析失败(畸形类型串,如 `image/`)不再从原始串推断主类型,直接落默认桶。
pub fn content_type_to_bucket_name(content_type: &str) -> String {
    if content_type.trim().is_empty() {
        return BUCKET_FILES.to_string();
    }

    let Some(mt) = parse_media_type(content_type) else {
        return BUCKET_FILES.to_string();
    };

    // parse_media_type 已校验主类型结构,此处必含一个 '/'
    let (main, sub) = mt.split_once('/').unwrap_or((mt.as_str(), ""));

    match main {
        "image" => BUCKET_IMAGES.to_string(),
        "video" => BUCKET_VIDEOS.to_string(),
        "audio" => BUCKET_AUDIOS.to_string(),
        "text" => BUCKET_DOCS.to_string(),
        "application" => {
            // 常见文档/办公类型映射到 docs,其余为 files
            match sub {
                "pdf" | "json" => BUCKET_DOCS.to_string(),
                _ => {
                    if sub.starts_with("vnd.ms-")
                        || sub.contains("officedocument")
                        || sub.contains("word")
                        || sub.contains("excel")
                        || sub.contains("powerpoint")
                    {
                        BUCKET_DOCS.to_string()
                    } else {
                        BUCKET_FILES.to_string()
                    }
                }
            }
        }
        _ => BUCKET_FILES.to_string(),
    }
}

/// 根据文件后缀获取存储桶名称(上游 `FileExtensionToBucketName`)。
/// 传入形如 MIME 的串(含 '/')时复用 [`content_type_to_bucket_name`]。
pub fn file_extension_to_bucket_name(ext: &str) -> String {
    if ext.trim().is_empty() {
        return BUCKET_FILES.to_string();
    }

    let s = ext.trim();

    // 如果看起来像 MIME 类型,复用按内容类型的映射
    if s.contains('/') {
        return content_type_to_bucket_name(s);
    }

    let e = s.strip_prefix('.').unwrap_or(s).to_lowercase();

    match e.as_str() {
        // images
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" | "ico" | "svg" | "tif" | "tiff"
        | "heic" => BUCKET_IMAGES.to_string(),
        // videos
        "mp4" | "webm" | "mov" | "mkv" | "avi" | "flv" | "mpeg" | "mpg" => BUCKET_VIDEOS.to_string(),
        // audios
        "mp3" | "wav" | "ogg" | "m4a" | "flac" | "aac" => BUCKET_AUDIOS.to_string(),
        // text / docs
        "txt" | "html" | "htm" | "css" | "js" | "csv" | "md" | "xml" | "json" => {
            BUCKET_DOCS.to_string()
        }
        // common office / documents
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" => BUCKET_DOCS.to_string(),
        // archives / binaries -> 默认 files(可按需改为 archives)
        "zip" | "tar" | "gz" | "tgz" | "7z" | "rar" | "bz2" | "bin" | "exe" => {
            BUCKET_FILES.to_string()
        }
        _ => BUCKET_FILES.to_string(),
    }
}

/// 根据文件类型获取文件后缀,统一返回**不带点**的扩展名
/// (上游 `ContentTypeToFileExtension`)。未知类型返回空串。
///
/// 参数剥离后按常见类型精确映射;未命中时回落到内置 MIME↔扩展名表
/// (Go `mime.ExtensionsByType`),再未命中返回空串,由调用方决定。
pub fn content_type_to_file_extension(content_type: &str) -> String {
    if content_type.trim().is_empty() {
        return String::new();
    }

    // 忽略参数(如 charset)并转为小写;解析失败时退回原始串(小写、去首尾空白)
    let mt = match parse_media_type(content_type) {
        Some(t) => t,
        None => content_type.trim().to_lowercase(),
    };

    // 常见类型映射
    match mt.as_str() {
        // images
        "image/jpeg" | "image/jpg" => return "jpg".to_string(),
        "image/png" => return "png".to_string(),
        "image/gif" => return "gif".to_string(),
        "image/webp" => return "webp".to_string(),
        "image/bmp" => return "bmp".to_string(),
        "image/x-icon" | "image/vnd.microsoft.icon" => return "ico".to_string(),
        "image/svg+xml" => return "svg".to_string(),

        // video
        "video/mp4" => return "mp4".to_string(),
        "video/webm" => return "webm".to_string(),
        "video/quicktime" => return "mov".to_string(),
        "video/x-matroska" | "video/mkv" => return "mkv".to_string(),

        // audio
        "audio/mpeg" => return "mp3".to_string(),
        "audio/wav" | "audio/x-wav" => return "wav".to_string(),
        "audio/ogg" | "audio/vorbis" => return "ogg".to_string(),
        "audio/mp4" => return "m4a".to_string(),

        // text
        "text/plain" => return "txt".to_string(),
        "text/html" => return "html".to_string(),
        "text/css" => return "css".to_string(),
        "text/csv" => return "csv".to_string(),
        "text/xml" => return "xml".to_string(),

        // JavaScript
        "text/javascript" | "application/javascript" | "application/x-javascript" => {
            return "js".to_string()
        }

        // Lua
        "text/x-lua" | "application/x-lua" => return "lua".to_string(),

        // Python
        "text/x-python" | "application/x-python" | "text/python" => return "py".to_string(),

        // Shell scripts
        "text/x-shellscript" | "application/x-sh" | "application/x-shellscript" | "text/x-sh"
        | "text/x-bash" | "application/x-bash" => return "sh".to_string(),

        // application / documents / archives
        "application/pdf" => return "pdf".to_string(),
        "application/json" => return "json".to_string(),
        "application/zip" => return "zip".to_string(),
        "application/x-tar" => return "tar".to_string(),
        "application/gzip" | "application/x-gzip" => return "gz".to_string(),
        "application/x-7z-compressed" | "application/7z" => return "7z".to_string(),
        "application/msword" => return "doc".to_string(),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            return "docx".to_string()
        }
        "application/vnd.ms-excel" => return "xls".to_string(),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => {
            return "xlsx".to_string()
        }
        "application/vnd.ms-powerpoint" => return "ppt".to_string(),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
            return "pptx".to_string()
        }
        "application/octet-stream" => return "bin".to_string(),
        _ => {}
    }

    // 回退:使用内置 MIME↔扩展名表(标准表返回的扩展名恒带前导点,
    // 与本函数"不带点"的统一约定对齐后剥离)
    if let Some(exts) = extensions_by_type(&mt) {
        if let Some(first) = exts.first() {
            return first.strip_prefix('.').unwrap_or(first).to_string();
        }
    }

    // 未知类型,返回空串(调用方可据此决定)
    String::new()
}

// ============================================================================
// 魔数文件类型检测(上游 `DetectFileType`)
// ============================================================================

/// 根据文件内容推断 MIME 类型和带前导点的扩展名(上游 `DetectFileType`)。
///
/// 输入为文件内容的字节切片(可为整个文件或前若干字节);返回
/// `(mime_type, ext)`,例如 `("image/png", ".png")`;扩展名未知时为空串。
///
/// 检测流程:先以内容前 512 字节做 WHATWG mimesniff 嗅探得到 MIME,再按
/// 上游魔数表逐一判定(命中即返回);魔数未命中时从嗅探 MIME 反查扩展名。
pub fn detect_file_type(file_content: &[u8]) -> (String, String) {
    // 使用前 512 字节进行内容嗅探判断
    let head = if file_content.len() > 512 {
        &file_content[..512]
    } else {
        file_content
    };
    let mime_type = detect_content_type(head);

    let c = file_content;
    // 常见魔术头优先判定(顺序与上游一致)
    if c.len() >= 8 && c[..8] == *b"\x89PNG\r\n\x1a\n" {
        return ("image/png".to_string(), ".png".to_string());
    }
    if c.len() >= 3 && c[..3] == [0xFF, 0xD8, 0xFF] {
        // JPG 可以以 FF D8 FF 开头
        return ("image/jpeg".to_string(), ".jpg".to_string());
    }
    if c.len() >= 6 && (c[..6] == *b"GIF87a" || c[..6] == *b"GIF89a") {
        return ("image/gif".to_string(), ".gif".to_string());
    }
    if c.len() >= 5 && c[..5] == *b"%PDF-" {
        return ("application/pdf".to_string(), ".pdf".to_string());
    }
    if c.len() >= 4 && c[..4] == *b"PK\x03\x04" {
        // zip / docx / xlsx / jar 等基于 zip 的格式,默认返回 .zip
        return ("application/zip".to_string(), ".zip".to_string());
    }
    if c.len() >= 12 && c[4..8] == *b"ftyp" {
        // ftyp box 常见于 MP4/ISO media files;更细分需要读取 brand 字段
        return ("video/mp4".to_string(), ".mp4".to_string());
    }
    if c.len() >= 3 && c[..3] == *b"ID3" {
        return ("audio/mpeg".to_string(), ".mp3".to_string());
    }
    if c.len() >= 2 && c[0] == 0xFF && (c[1] & 0xE0) == 0xE0 {
        // 另一种 MP3 帧头判定(0xFF Ex)
        return ("audio/mpeg".to_string(), ".mp3".to_string());
    }
    if c.len() >= 12 && c[..4] == *b"RIFF" && c[8..12] == *b"WAVE" {
        return ("audio/wav".to_string(), ".wav".to_string());
    }
    if c.len() >= 2 && c[..2] == *b"BM" {
        return ("image/bmp".to_string(), ".bmp".to_string());
    }

    // 若魔术头未命中,尝试从嗅探得到的 MIME 类型反查扩展名
    if !mime_type.is_empty() {
        if let Some(exts) = extensions_by_type(&mime_type) {
            if let Some(ext) = exts.first() {
                // 内置表可能返回多种扩展,取第一个
                return (mime_type, (*ext).to_string());
            }
        }
    }

    // 额外的简单映射(在 MIME 映射不可用时);与上游 switch 的分派语义一致:
    // 命中前缀但未命中具体类型时直接落最终返回,不再尝试其余前缀
    if mime_type.starts_with("image/") && mime_type == "image/svg+xml" {
        // 常见 image 类型再尝试映射
        return (mime_type, ".svg".to_string());
    } else if mime_type.starts_with("video/") && mime_type == "video/mp4" {
        return (mime_type, ".mp4".to_string());
    } else if mime_type.starts_with("audio/") && mime_type == "audio/mpeg" {
        return (mime_type, ".mp3".to_string());
    }

    // 未知扩展,返回检测到的 mimeType(ext 为空)
    (mime_type, String::new())
}

// ============================================================================
// 文件名生成(移植自 utils.go)
// ============================================================================

/// 字节转小写十六进制字符串。
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// 生成 v4 UUID(对应上游 `id.NewGUIDv4(dashed)`):16 个随机字节,按
/// RFC 4122 置版本位(0x40)与变体位(10xx);`dashed` 决定是否输出
/// 8-4-4-4-12 连字符格式。上游 ossutil 一律使用无横线形式。
///
/// 随机源故障(理论上仅在系统熵源不可用时发生)会直接 panic,与上游
/// 同类实现一致。
fn new_uuid_v4(dashed: bool) -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("getrandom 生成随机字节失败");
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx

    if dashed {
        format!(
            "{}-{}-{}-{}-{}",
            to_hex(&b[..4]),
            to_hex(&b[4..6]),
            to_hex(&b[6..8]),
            to_hex(&b[8..10]),
            to_hex(&b[10..])
        )
    } else {
        to_hex(&b)
    }
}

/// 生成基于 UUID 的文件名(上游 `GeneraUUIDFileName`,函数名拼写照原义保留)。
///
/// - 描述:生成去掉横线的 UUID v4(128-bit 随机)。
/// - 优点:几乎无碰撞、不依赖内容、生成快、安全性高(不泄露内容指纹)。
/// - 缺点:名字较长、不可按时间排序、不能用于内容去重。
/// - 适用:高并发、无需去重、希望最小碰撞风险的通用场景。
pub fn genera_uuid_file_name(file_ext: &str) -> String {
    // 生成 UUID 并去除横线
    let name = new_uuid_v4(false);

    // 确保扩展名没有开头的点
    let clean_ext = file_ext.strip_prefix('.').unwrap_or(file_ext);
    if clean_ext.is_empty() {
        return name;
    }

    format!("{name}.{clean_ext}")
}

/// 生成基于内容 SHA256 的文件名(上游 `GeneraContentSHA265FileName`,
/// "SHA265" 为上游历史拼写,照原义保留)。
///
/// - 描述:内容的 SHA-256 十六进制摘要(明文哈希)。
/// - 优点:确定性、极低碰撞、便于去重和校验。
/// - 缺点:容易被离线匹配(泄露内容指纹);需要读取并哈希整个文件。
/// - 适用:去重、缓存命中、内容可验证,但不适合对隐私敏感的公开键。
pub fn genera_content_sha265_file_name(file_content: &[u8], file_ext: &str) -> String {
    // 计算内容的 SHA256 摘要并编码为十六进制字符串
    let hash = to_hex(&Sha256::digest(file_content));

    // 清理扩展名中的前导点
    let clean_ext = file_ext.strip_prefix('.').unwrap_or(file_ext);
    if clean_ext.is_empty() {
        return hash;
    }

    format!("{hash}.{clean_ext}")
}

/// 生成基于 HMAC 内容的文件名(上游 `GenerateHMACContentFileName`)。
///
/// - 描述:先对内容做 SHA-256,再用 `secret` 做 HMAC-SHA256 生成文件名。
/// - 优点:对同样内容一致(可去重),但没有 secret 时不可被离线匹配,抗探测。
/// - 缺点:需要管理 secret(泄露则失效);计算开销中等(一次哈希 + HMAC)。
/// - 适用:需要去重同时又要防止哈希被猜测/探测的场景。
pub fn generate_hmac_content_file_name(secret: &[u8], file_content: &[u8], file_ext: &str) -> String {
    // 先计算内容 SHA256
    let sum = Sha256::digest(file_content);

    // 用 secret 做 HMAC-SHA256
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(&sum);
    let name = to_hex(&mac.finalize().into_bytes());

    let clean_ext = file_ext.strip_prefix('.').unwrap_or(file_ext);
    if clean_ext.is_empty() {
        return name;
    }
    format!("{name}.{clean_ext}")
}

/// 生成基于时间戳的文件名(上游 `GeneraTimeBaseFileName`)。
///
/// - 描述:纳秒级 Unix 时间戳 + 短随机后缀(8 位十六进制,取自去横线 UUID)。
/// - 优点:可读、按时间排序、生成成本低。
/// - 缺点:同一纳秒高并发下碰撞概率上升;不可用于内容去重;暴露时间信息。
/// - 改进建议(上游附注):改用 ULID(时间有序且高熵)。
pub fn genera_time_base_file_name(file_ext: &str) -> String {
    // 清理扩展名中的前导点
    let clean_ext = file_ext.strip_prefix('.').unwrap_or(file_ext);

    // 使用 UUID 去掉横线后取前 8 字符作为随机后缀
    let suffix = new_uuid_v4(false);
    let suffix = &suffix[..suffix.len().min(8)];

    // 纳秒时间戳(时钟回退等异常时按 0 处理)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);

    if clean_ext.is_empty() {
        return format!("{timestamp}_{suffix}");
    }

    format!("{timestamp}_{suffix}.{clean_ext}")
}

/// 生成文件名,按策略分派(上游 `GenerateFileName`)。
pub fn generate_file_name(file_content: &[u8], file_ext: &str, typ: GenerateFileNameType) -> String {
    match typ {
        GenerateFileNameType::Uuid => {
            // 要最大唯一性、低延迟、高并发
            genera_uuid_file_name(file_ext)
        }
        GenerateFileNameType::ContentSha256 => {
            // 要去重/验证且不关心能被离线匹配
            genera_content_sha265_file_name(file_content, file_ext)
        }
        GenerateFileNameType::HmacContent => {
            // 要去重但需防止被猜测;未注入密钥时退化为 UUID 命名(不再有
            // 可去重性),避免静默使用内置弱密钥
            let secret = global_hmac_secret();
            if !secret.is_empty() {
                generate_hmac_content_file_name(&secret, file_content, file_ext)
            } else {
                genera_uuid_file_name(file_ext)
            }
        }
        GenerateFileNameType::TimeBase => {
            // 要可读且按时间排序
            genera_time_base_file_name(file_ext)
        }
    }
}

/// 生成对象名:目录(清理首尾斜杠)+ 文件名(上游 `GenerateObjectName`)。
pub fn generate_object_name(
    file_directory: &str,
    file_content: &[u8],
    file_ext: &str,
    typ: GenerateFileNameType,
) -> String {
    // 生成文件名
    let name = generate_file_name(file_content, file_ext, typ);

    // 清理首尾斜杠,避免出现双斜杠或以斜杠开头的对象名
    let dir = file_directory.trim_matches('/');

    if dir.is_empty() {
        return name;
    }
    format!("{dir}/{name}")
}

/// 生成对象名,扩展名按"文件名 → 内容类型 → 文件内容魔数"顺序补全
/// (上游 `EnsureObjectName`)。
///
/// 上游允许 `typ` 传空串(此时按 UUID 策略);Rust 枚举无空值,
/// `GenerateFileNameType::from("")` 已回落到 UUID,语义等价。
pub fn ensure_object_name(
    file_directory: &str,
    source_file_name: &str,
    content_type: &str,
    file_content: &[u8],
    typ: GenerateFileNameType,
) -> String {
    let file_ext = ensure_file_extension(source_file_name, content_type, file_content);
    generate_object_name(file_directory, file_content, &file_ext, typ)
}

// ============================================================================
// 对象名与 URL 拼装(移植自 utils.go)
// ============================================================================

/// 拼接对象名(上游 `JoinObjectName`)。返回 `(objectName, fileName)`。
///
/// [`content_type_to_file_extension`] 统一返回不带点的扩展名,分隔点由本函数
/// 补上;`file_name` 为 `None` 时生成去横线 UUID 文件名并追加扩展名,
/// `file_path` 为 `None` 时对象名即文件名本身。
pub fn join_object_name(
    content_type: &str,
    file_path: Option<&str>,
    file_name: Option<&str>,
) -> (String, String) {
    let file_suffix = content_type_to_file_extension(content_type);

    let file_name = match file_name {
        None => {
            let name = new_uuid_v4(false);
            if file_suffix.is_empty() {
                name
            } else {
                format!("{name}.{file_suffix}")
            }
        }
        Some(name) => name.to_string(),
    };

    let object_name = match file_path {
        Some(path) => format!("{path}/{file_name}"),
        None => file_name.clone(),
    };

    (object_name, file_name)
}

/// 拼接对象 URL:`endpoint/bucket/object`(上游 `JoinObjectUrl`)。
/// endpoint 去右侧斜杠、bucket 去两侧斜杠、object 去左侧斜杠。
pub fn join_object_url(endpoint: &str, bucket_name: &str, object_name: &str) -> String {
    let trimmed_endpoint = endpoint.trim_end_matches('/');
    let trimmed_bucket = bucket_name.trim_matches('/');
    let trimmed_object = object_name.trim_start_matches('/');

    format!("{trimmed_endpoint}/{trimmed_bucket}/{trimmed_object}")
}

/// 替换 URL 中的 Host 部分(上游 `ReplaceEndpointHost`)。
/// `raw_url` 或 `host` 为空时原样返回,否则把其中出现的 `endpoint` 全部替换为 `host`。
pub fn replace_endpoint_host(raw_url: &str, host: &str, endpoint: &str) -> String {
    if raw_url.is_empty() || host.is_empty() {
        return raw_url.to_string();
    }
    raw_url.replace(endpoint, host)
}

// ============================================================================
// 扩展名补全(移植自 utils.go)
// ============================================================================

/// 从文件名提取小写扩展名(不带点;上游 `ExtractFileExtension`)。
/// 以最后一个点为分隔,点在首位(`.hidden`)或无点时返回空串。
pub fn extract_file_extension(file_name: &str) -> String {
    // 查找最后一个点作为扩展名分隔(点在开头不算)
    match file_name.rfind('.') {
        Some(idx) if idx > 0 => file_name[idx + 1..].to_lowercase(),
        _ => String::new(), // 无扩展名或点在首位
    }
}

/// 确保文件后缀存在,按"文件名 → 内容类型 → 文件内容魔数"顺序检测
/// (上游 `EnsureFileExtension`);全部失败时回落 `"bin"`。
pub fn ensure_file_extension(file_name: &str, content_type: &str, file_content: &[u8]) -> String {
    let ext = extract_file_extension(file_name);
    if !ext.is_empty() {
        return ext;
    }

    let ext = content_type_to_file_extension(content_type);
    if !ext.is_empty() {
        return ext;
    }

    let (_, ext) = detect_file_type(file_content);
    if !ext.is_empty() {
        return ext.strip_prefix('.').unwrap_or(&ext).to_string();
    }

    "bin".to_string()
}

// ============================================================================
// 上传守卫(移植自 constants.go)
// ============================================================================

/// 判断某 MIME 类型是否在上传白名单内(上游 `IsAllowedMimeType`)。
///
/// 同时支持前缀(`image/*` 等,见 [`ALLOWED_MIME_PREFIXES`])与精确匹配
/// ([`ALLOWED_EXACT_MIME_TYPES`])。输入先经 `mime.ParseMediaType` 语义归一:
/// 剥离参数(charset 等)与空白、整体转小写后再比对——内容嗅探器对文本恒产
/// `text/plain; charset=utf-8` 带参形式,按原串匹配会把白名单内的文本类型
/// 整体误拒;解析失败的畸形类型串(如 `image/`)结构不合法,直接拒绝。
pub fn is_allowed_mime_type(mime_type: &str) -> bool {
    if mime_type.is_empty() {
        return false;
    }
    let Some(mt) = parse_media_type(mime_type) else {
        return false;
    };

    if ALLOWED_EXACT_MIME_TYPES.contains(&mt.as_str()) {
        return true;
    }
    for prefix in ALLOWED_MIME_PREFIXES {
        if mt.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// 校验客户端传入的 FileDirectory 是否安全(上游 `IsFileDirectorySafe`)。
///
/// 仅允许字母、数字、下划线、连字符与斜杠;拒绝 `..`、绝对路径等穿越/注入
/// 手法;空目录视为安全(落到根命名空间)。
pub fn is_file_directory_safe(dir: &str) -> bool {
    if dir.is_empty() {
        return true; // 空目录允许(落到根命名空间)
    }
    // 整体字符白名单
    for r in dir.chars() {
        match r {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '/' => {}
            _ => return false,
        }
    }
    // 拒绝路径穿越段
    if dir.contains("..") {
        return false;
    }
    // 拒绝绝对路径样式
    if dir.starts_with('/') {
        return false;
    }
    true
}

// ============================================================================
// 测试(移植上游 ossutil_test.go,并补充魔数/嗅探用例)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 判断字符串是否为小写十六进制(Go 测试中 `^[0-9a-f]+$` 正则的等价物)。
    fn is_lower_hex(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    #[test]
    fn test_content_type_to_bucket_name() {
        let cases = [
            ("image/png", "images"),
            ("video/mp4; charset=bogus", "videos"),
            ("audio/mpeg", "audios"),
            ("text/plain", "docs"),
            ("application/pdf", "docs"),
            (
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "docs",
            ),
            ("application/json", "docs"),
            ("application/octet-stream", "files"),
            ("", "files"),
            ("image/", "files"), // 畸形串不按主类型落图片桶
            ("not-a-mime", "files"),
            ("TEXT/Plain", "docs"), // 解析时整体转小写
        ];
        for (ct, want) in cases {
            assert_eq!(content_type_to_bucket_name(ct), want, "input: {ct}");
        }
    }

    #[test]
    fn test_file_extension_to_bucket_name() {
        assert_eq!(file_extension_to_bucket_name(".jpg"), "images");
        assert_eq!(file_extension_to_bucket_name("jpg"), "images");
        assert_eq!(file_extension_to_bucket_name(".mp4"), "videos");
        assert_eq!(file_extension_to_bucket_name(".pdf"), "docs");
        assert_eq!(file_extension_to_bucket_name(".zip"), "files");
        assert_eq!(file_extension_to_bucket_name(""), "files");
        // 补充:MIME 形态的输入复用按内容类型的映射
        assert_eq!(file_extension_to_bucket_name("image/png"), "images");
        assert_eq!(file_extension_to_bucket_name("video/quicktime"), "videos");
    }

    #[test]
    fn test_content_type_to_file_extension() {
        assert_eq!(content_type_to_file_extension("image/jpeg"), "jpg");
        assert_eq!(content_type_to_file_extension("image/png"), "png");
        assert_eq!(content_type_to_file_extension("application/pdf"), "pdf");
        assert_eq!(content_type_to_file_extension(""), "");
        // 补充:参数剥离、脚本类型与回落表
        assert_eq!(
            content_type_to_file_extension("image/jpeg; charset=bogus"),
            "jpg"
        );
        assert_eq!(content_type_to_file_extension("text/x-python"), "py");
        assert_eq!(content_type_to_file_extension("application/x-sh"), "sh");
        assert_eq!(content_type_to_file_extension("video/quicktime"), "mov");
        assert_eq!(content_type_to_file_extension("audio/mp4"), "m4a");
        assert_eq!(content_type_to_file_extension("image/tiff"), "tif"); // 内置表回落
        assert_eq!(content_type_to_file_extension("application/unknown-type"), ""); // 查无映射
    }

    #[test]
    fn test_detect_file_type() {
        // 上游用例
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            detect_file_type(&png),
            ("image/png".to_string(), ".png".to_string())
        );

        let jpg = [0xff, 0xd8, 0xff, 0xe0];
        assert_eq!(
            detect_file_type(&jpg),
            ("image/jpeg".to_string(), ".jpg".to_string())
        );
    }

    #[test]
    fn test_detect_file_type_magic_headers() {
        // 按源码魔数清单自造字节串
        assert_eq!(
            detect_file_type(b"GIF87a\x00\x00"),
            ("image/gif".to_string(), ".gif".to_string())
        );
        assert_eq!(
            detect_file_type(b"GIF89a\x00\x00"),
            ("image/gif".to_string(), ".gif".to_string())
        );
        assert_eq!(
            detect_file_type(b"%PDF-1.4\n"),
            ("application/pdf".to_string(), ".pdf".to_string())
        );
        assert_eq!(
            detect_file_type(b"PK\x03\x04rest"),
            ("application/zip".to_string(), ".zip".to_string())
        );
        // ftyp box:boxSize=20,仅要求 [4..8] == "ftyp"
        let mp4 = b"\x00\x00\x00\x14ftypisom\x00\x00\x00\x00";
        assert_eq!(
            detect_file_type(mp4),
            ("video/mp4".to_string(), ".mp4".to_string())
        );
        assert_eq!(
            detect_file_type(b"ID3\x04\x00tag"),
            ("audio/mpeg".to_string(), ".mp3".to_string())
        );
        // MP3 帧头 0xFF Ex
        assert_eq!(
            detect_file_type(&[0xFF, 0xE3, 0x00]),
            ("audio/mpeg".to_string(), ".mp3".to_string())
        );
        assert_eq!(
            detect_file_type(b"RIFF\x24\x00\x00\x00WAVEfmt "),
            ("audio/wav".to_string(), ".wav".to_string())
        );
        assert_eq!(
            detect_file_type(b"BM\x36\x00"),
            ("image/bmp".to_string(), ".bmp".to_string())
        );
    }

    #[test]
    fn test_detect_file_type_sniff_fallback() {
        // 魔数表未命中时,由嗅探签名表与内置扩展名表给出结果
        // 空内容 → text/plain(内置表首个扩展为 .text)
        assert_eq!(
            detect_file_type(b""),
            (
                "text/plain; charset=utf-8".to_string(),
                ".text".to_string()
            )
        );
        // 二进制控制字节 → octet-stream(内置表首个扩展为 .bin)
        assert_eq!(
            detect_file_type(&[0x00, 0x01, 0x02]),
            (
                "application/octet-stream".to_string(),
                ".bin".to_string()
            )
        );
        // HTML 签名(大小写不敏感 + 0xTT 终止)
        assert_eq!(
            detect_file_type(b"<html><body>hi"),
            (
                "text/html; charset=utf-8".to_string(),
                ".ehtml".to_string()
            )
        );
        // XML 签名允许前导空白(skip_ws)
        assert_eq!(
            detect_file_type(b"  <?xml version=\"1.0\"?>"),
            ("text/xml; charset=utf-8".to_string(), ".xbl".to_string())
        );
        // UTF-16LE BOM:嗅探本判为 text/plain; charset=utf-16le,但上游魔数表
        // 的 0xFF Ex MP3 帧头判定优先命中(FF FE 满足 0xFE & 0xE0 == 0xE0),
        // 按上游语义返回 audio/mpeg —— 这是上游既有的行为,原样保留。
        assert_eq!(
            detect_file_type(b"\xFF\xFE\x41\x00"),
            ("audio/mpeg".to_string(), ".mp3".to_string())
        );
        // Ogg 容器:嗅探命中 application/ogg,但内置表无对应扩展
        assert_eq!(
            detect_file_type(b"OggS\x00\x02\x00"),
            ("application/ogg".to_string(), String::new())
        );
        // WebM(EBML 头)
        assert_eq!(
            detect_file_type(b"\x1A\x45\xDF\xA3\x01"),
            ("video/webm".to_string(), ".webm".to_string())
        );
        // gzip
        assert_eq!(
            detect_file_type(b"\x1F\x8B\x08\x00"),
            (
                "application/x-gzip".to_string(),
                String::new() // 内置表 .gz 映射的是 application/gzip,非 x-gzip
            )
        );
    }

    #[test]
    fn test_generate_uuid_file_name() {
        let name = genera_uuid_file_name(".png");
        assert_eq!(name.len(), 32 + 4); // 去横线 UUID + ".png"
        assert!(name.ends_with(".png"));
        let bare = &name[..32];
        assert!(is_lower_hex(bare));
        // v4 版本位:第 13 个十六进制字符恒为 '4'
        assert_eq!(bare.as_bytes()[12], b'4');
        // v4 变体位:第 17 个十六进制字符 ∈ {8, 9, a, b}
        assert!(matches!(bare.as_bytes()[16], b'8' | b'9' | b'a' | b'b'));
        // 不带点扩展名等价于带点(各自独立生成,仅校验形态)
        let no_dot = genera_uuid_file_name("png");
        assert_eq!(no_dot.len(), 36);
        assert!(no_dot.ends_with(".png"));
        assert!(is_lower_hex(&no_dot[..32]));
        assert_eq!(genera_uuid_file_name("").len(), 32);
        assert_ne!(genera_uuid_file_name(""), genera_uuid_file_name(""));
    }

    #[test]
    fn test_generate_content_sha265_file_name() {
        // SHA-256("hello world") 的公开已知向量
        assert_eq!(
            genera_content_sha265_file_name(b"hello world", ""),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        // 确定性 + 扩展名清理
        assert_eq!(
            genera_content_sha265_file_name(b"x", ".png"),
            genera_content_sha265_file_name(b"x", "png")
        );
        let name = genera_content_sha265_file_name(b"x", "png");
        assert!(name.ends_with(".png"));
        assert!(is_lower_hex(&name[..name.len() - 4]));
    }

    #[test]
    fn test_generate_hmac_content_file_name() {
        let content = b"hello world";
        let a = generate_hmac_content_file_name(b"secret-a", content, "");
        let b = generate_hmac_content_file_name(b"secret-a", content, "");
        // 同密钥同内容确定性
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(is_lower_hex(&a));
        // 不同密钥产生不同指纹
        assert_ne!(
            a,
            generate_hmac_content_file_name(b"secret-b", content, "")
        );
        // 扩展名清理
        assert_eq!(
            generate_hmac_content_file_name(b"k", content, ".jpg"),
            format!("{}.jpg", generate_hmac_content_file_name(b"k", content, ""))
        );
    }

    #[test]
    fn test_generate_time_base_file_name() {
        let name = genera_time_base_file_name(".jpg");
        assert!(name.ends_with(".jpg"));
        assert!(name.contains('_'));
        let (ts, rest) = name.rsplit_once('.').unwrap();
        let (ts, suffix) = ts.split_once('_').unwrap();
        // 时间戳为十进制数字;后缀为 8 位十六进制
        assert!(!ts.is_empty() && ts.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(suffix.len(), 8);
        assert!(is_lower_hex(suffix));
        assert!(rest.starts_with("jpg"));
        // 无扩展名形态
        let bare = genera_time_base_file_name("");
        assert!(!bare.contains('.'));
        assert!(bare.contains('_'));
    }

    #[test]
    fn test_generate_file_name() {
        // 注意:本用例会写入全局 HMAC 密钥(与上游测试一致)
        let content = b"hello world";

        let uuid_name = generate_file_name(content, ".png", GenerateFileNameType::Uuid);
        assert!(!uuid_name.is_empty());
        assert!(uuid_name.ends_with(".png"));
        assert_ne!(
            uuid_name,
            generate_file_name(content, ".png", GenerateFileNameType::Uuid)
        );

        let sha1 = generate_file_name(content, "", GenerateFileNameType::ContentSha256);
        let sha2 = generate_file_name(content, "", GenerateFileNameType::ContentSha256);
        assert_eq!(sha1, sha2, "内容哈希命名必须确定");

        // 未注入密钥:HMAC 策略退化为 UUID 命名(32 位十六进制、无扩展名)
        let hmac_fallback = generate_file_name(content, "", GenerateFileNameType::HmacContent);
        assert_eq!(hmac_fallback.len(), 32);
        assert!(is_lower_hex(&hmac_fallback), "退化命名应为不带横线的 UUID");

        // 注入密钥后:确定性命名
        set_hmac_secret(b"0123456789abcdef0123456789abcdef");
        let h1 = generate_file_name(content, "", GenerateFileNameType::HmacContent);
        let h2 = generate_file_name(content, "", GenerateFileNameType::HmacContent);
        assert_eq!(h1, h2, "同密钥同内容的 HMAC 命名必须确定");
        assert_ne!(h1, hmac_fallback);

        let time_name = generate_file_name(content, ".jpg", GenerateFileNameType::TimeBase);
        assert!(time_name.ends_with(".jpg"));
        assert!(time_name.contains('_'));

        // 字符串值与分派回落
        assert_eq!(GenerateFileNameType::from("time_base"), GenerateFileNameType::TimeBase);
        assert_eq!(GenerateFileNameType::from("unknown"), GenerateFileNameType::Uuid);
        assert_eq!(GenerateFileNameType::ContentSha256.as_str(), "content_sha256");
    }

    #[test]
    fn test_generate_object_name() {
        let name = generate_object_name("images/2026/", b"x", ".png", GenerateFileNameType::Uuid);
        assert!(name.starts_with("images/2026/"), "应保留目录前缀: {name}");
        assert!(!name.starts_with("//"));
        let pure = generate_object_name("/", b"x", ".png", GenerateFileNameType::Uuid);
        assert!(!pure.contains("//"), "目录仅含斜杠时不应产生双斜杠: {pure}");
    }

    #[test]
    fn test_ensure_object_name() {
        let name = ensure_object_name("docs", "report", "application/pdf", &[], GenerateFileNameType::Uuid);
        assert!(name.ends_with(".pdf"), "应从 content-type 推断扩展名: {name}");
        assert!(name.starts_with("docs/"));
    }

    #[test]
    fn test_join_object_name_and_url() {
        let (object, file) = join_object_name("image/png", Some("imgs"), None);
        assert!(object.starts_with("imgs/"));
        assert!(file.ends_with(".png"));

        // 显式文件名:不做改写,仅拼路径
        let (object2, file2) = join_object_name("application/pdf", None, Some("a.pdf"));
        assert_eq!(object2, "a.pdf");
        assert_eq!(file2, "a.pdf");

        let url = join_object_url("http://minio:9000/", "/images/", "/a/b.png");
        assert_eq!(url, "http://minio:9000/images/a/b.png");

        assert_eq!(
            replace_endpoint_host("http://minio:9000/a.png", "http://host", "http://minio:9000"),
            "http://host/a.png"
        );
    }

    #[test]
    fn test_extract_file_extension() {
        assert_eq!(extract_file_extension("a.b.png"), "png");
        assert_eq!(extract_file_extension("noext"), "");
        assert_eq!(extract_file_extension(".hidden"), "");
        // 补充:大小写归一与普通点位置
        assert_eq!(extract_file_extension("FILE.TXT"), "txt");
        assert_eq!(extract_file_extension(""), "");
    }

    #[test]
    fn test_ensure_file_extension() {
        assert_eq!(ensure_file_extension("photo.jpg", "", &[]), "jpg");
        assert_eq!(ensure_file_extension("photo", "image/png", &[]), "png");
        // 空内容经嗅探为 text/plain,由内置表给出确定性扩展名
        // (Go 版会叠加 OS 级 mime.types,结果随平台变化,这里锁定内置表行为)
        let fallback = ensure_file_extension("", "", &[]);
        assert_eq!(fallback, "text");
        assert!(!fallback.contains('.'), "扩展名不应带前导点: {fallback}");
        // 内容魔数兜底:PNG 头
        assert_eq!(ensure_file_extension("", "", b"\x89PNG\r\n\x1a\n"), "png");
        // 二进制内容 → octet-stream → .bin
        assert_eq!(ensure_file_extension("", "", &[0x00, 0x01, 0x02]), "bin");
    }

    #[test]
    fn test_is_file_directory_safe() {
        assert!(is_file_directory_safe("images/2026"));
        assert!(!is_file_directory_safe("../etc"));
        assert!(!is_file_directory_safe("a/../../b"));
        // 补充
        assert!(is_file_directory_safe(""));
        assert!(is_file_directory_safe("a-b_c1"));
        assert!(!is_file_directory_safe("/abs"));
        assert!(!is_file_directory_safe("a b/c"));
        assert!(!is_file_directory_safe("图片"));
        assert!(!is_file_directory_safe("a..b"));
    }

    #[test]
    fn test_is_allowed_mime_type() {
        // 上游用例
        assert!(is_allowed_mime_type("image/png"));
        assert!(is_allowed_mime_type("application/pdf"));
        assert!(!is_allowed_mime_type("application/x-msdownload"));
        assert!(!is_allowed_mime_type("text/html"));
        // 补充:参数剥离、前缀白名单、畸形串拒绝
        assert!(is_allowed_mime_type("text/plain; charset=utf-8"));
        assert!(is_allowed_mime_type("video/mp4; charset=bogus"));
        assert!(is_allowed_mime_type("application/zip"));
        assert!(!is_allowed_mime_type(""));
        assert!(!is_allowed_mime_type("image/"));
        assert!(!is_allowed_mime_type("application/x-unknown-format"));
    }

    #[test]
    fn test_builtin_extensions_table_loaded() {
        // 内置反查表条目数与已知映射(锁定移植不缺项):
        // Go builtinTypesLower 共 65 个扩展名,去重到 46 个 MIME 键
        let map = extensions_map();
        assert_eq!(map.len(), 46);
        let ext_count: usize = map.values().map(|v| v.len()).sum();
        assert_eq!(ext_count, 65);
        assert_eq!(
            map.get("image/jpeg").map(Vec::as_slice),
            Some(&[".jfif", ".jpeg", ".jpg", ".pjp", ".pjpeg"][..])
        );
        assert_eq!(
            map.get("application/octet-stream").map(Vec::as_slice),
            Some(&[".bin", ".com", ".exe"][..])
        );
        assert!(extensions_by_type("text/plain; charset=utf-8").is_some());
        assert!(extensions_by_type("application/x-nope").is_none());
    }

    #[test]
    fn test_size_bucket_and_mime_constants() {
        // 直传/SSRF 下载上限 50 MiB(52_428_800 字节)。
        assert_eq!(MAX_UPLOAD_SIZE, 52_428_800);
        assert_eq!(MAX_DOWNLOAD_SIZE, 52_428_800);

        // 五个业务桶名。
        assert_eq!(BUCKET_IMAGES, "images");
        assert_eq!(BUCKET_VIDEOS, "videos");
        assert_eq!(BUCKET_AUDIOS, "audios");
        assert_eq!(BUCKET_DOCS, "docs");
        assert_eq!(BUCKET_FILES, "files");

        // MIME 白名单不缺项:前缀 3 条(首 image/ 尾 audio/),精确表 16 条(首 text/plain 尾 pptx)。
        assert_eq!(ALLOWED_MIME_PREFIXES.len(), 3);
        assert_eq!(ALLOWED_MIME_PREFIXES[0], "image/");
        assert_eq!(ALLOWED_MIME_PREFIXES[ALLOWED_MIME_PREFIXES.len() - 1], "audio/");
        assert_eq!(ALLOWED_EXACT_MIME_TYPES.len(), 16);
        assert_eq!(ALLOWED_EXACT_MIME_TYPES[0], "text/plain");
        assert_eq!(
            ALLOWED_EXACT_MIME_TYPES[ALLOWED_EXACT_MIME_TYPES.len() - 1],
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        );
    }
}
