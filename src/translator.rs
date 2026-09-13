//! 翻译器(对应 Go 版 `translator` 包,feature `translator`)。
//!
//! 四个后端与 Go 版一一对应:
//!
//! - [`baidu`]:百度翻译开放平台(表单 POST,MD5 签名);
//! - [`alibaba`]:阿里云机器翻译(官方 SDK 的 RPC 签名与表单
//!   POST 线上形态逐式复刻);
//! - [`google`]:谷歌翻译(v1 为上游的裸 HTTP 端点,v2/v3 为上游
//!   官方客户端库的 REST 等价实现);
//! - [`volc`]:火山引擎翻译(HMAC-SHA256 四级密钥派生链签名 +
//!   JSON POST;另有批量入口)。
//!
//! 各后端的差异细节见各自模块文档;与上游的整体差异:
//!
//! - 上游各官方 SDK 的重试/退避与内部错误对象未移植(单次请求,
//!   错误一律为字符串);
//! - `google` 上游的 `language.Parse` BCP47 校验未移植(语言标签
//!   原样透传);其 `encodeURI` 实为 `url.QueryEscape`(注释与
//!   实现不符),按实现语义移植;
//! - 各响应解析中的越界访问(上游切片索引 panic)一律返回错误;
//! - `alibaba` 的 `SignatureNonce` 上游为杂凑值的 32 位十六进制,
//!   此处取 UUID v4 的 32 位十六进制,唯一性等价;
//! - 上游的请求调试打印(含凭据与签名头)未移植;
//! - 各上游 `Close`/`String` 等杂项中,仅 `volc` 的脱敏字符串
//!   (`Display`)被移植;
//! - 语言代码表见上游 `translator/README.md`。

pub mod alibaba;
pub mod baidu;
pub mod google;
pub mod volc;

/// 翻译器接口(上游 `translator.Translator`)。
pub trait Translator {
    /// 翻译(上游 `Translate`)。
    fn translate(
        &self,
        source: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> Result<String, String>;
}

/// URL 查询/表单成分编码(上游 `url.QueryEscape` 的字节语义:
/// ASCII 字母数字与 `-_.~` 直通,空格作 `+`,其余 `%XX` 大写
/// 十六进制)。
pub(crate) fn query_escape(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// 参数对的有序表单/查询串编码(上游 `url.Values.Encode`:按原键
/// 排序,键与值均经 `query_escape`)。
pub(crate) fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut pairs: Vec<_> = pairs.to_vec();
    pairs.sort();
    let mut out = String::new();
    for (key, value) in &pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&query_escape(key));
        out.push('=');
        out.push_str(&query_escape(value));
    }
    out
}

/// 小写十六进制(上游 `hex.EncodeToString`)。
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
